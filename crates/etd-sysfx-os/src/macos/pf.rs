//! The kernel anchor is the source of truth across writer and host restarts.
//! Mutate only its filter rules and read them back before returning.
use super::{COMMAND_TIMEOUT, boot, capture, command, holders::CoreIdentity, output, status};
use crate::service::{HostFilesystem, NativeHostFilesystem};
use etd_sysfx::{FenceSpec, ObjectKey};
use nix::unistd::Uid;
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{self, Seek, Write},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
            process::CommandExt,
        },
    },
    process::Command,
};

pub(super) const ANCHOR: &str = "com.apple/easytier-desk";
const PF: &str = "/sbin/pfctl";
const OWNER: &str = "pf-reference";

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct Rule {
    pub(super) label: String,
    pub(super) port: u16,
}

impl Rule {
    pub(super) fn for_spec(spec: &FenceSpec) -> Self {
        let identity = format!("{}:{}", spec.instance.as_str(), spec.epoch.0);
        let id = uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, identity.as_bytes());
        Self {
            label: format!("etd-{}", id.simple()),
            port: spec.address.port(),
        }
    }
    pub(super) fn from_key(key: &ObjectKey) -> io::Result<Self> {
        if let ObjectKey::Fence {
            container,
            rule,
            port,
        } = key
            && container == ANCHOR
            && *port != 0
            && valid_label(rule)
        {
            return Ok(Self {
                label: rule.clone(),
                port: *port,
            });
        }
        Err(io::Error::other("invalid macOS fence key"))
    }
    pub(super) fn key(&self) -> ObjectKey {
        ObjectKey::Fence {
            container: ANCHOR.into(),
            rule: self.label.clone(),
            port: self.port,
        }
    }
    fn line(&self, v6: bool) -> String {
        let (family, ip, suffix) = if v6 {
            ("inet6", "::1", "v6")
        } else {
            ("inet", "127.0.0.1", "v4")
        };
        format!(
            "block return out quick on lo0 {family} proto tcp from any to {ip} port = {} user != 0 label \"{}-{suffix}\"",
            self.port, self.label
        )
    }
}

fn valid_label(label: &str) -> bool {
    label.strip_prefix("etd-").is_some_and(|id| {
        id.len() == 32
            && id
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    })
}

fn parsed(line: &str) -> Option<(Rule, bool)> {
    let (prefix, label) = line.rsplit_once(" label \"")?;
    let (label, family) = label.strip_suffix('"')?.rsplit_once('-')?;
    let port = prefix
        .split_once(" port = ")?
        .1
        .split_whitespace()
        .next()?
        .parse::<u16>()
        .ok()?;
    let rule = Rule {
        label: label.into(),
        port,
    };
    let v6 = family == "v6";
    (port != 0 && valid_label(label) && rule.line(v6) == line).then_some((rule, v6))
}
fn inventory(sweep: bool) -> io::Result<BTreeSet<Rule>> {
    let parents = output(command(PF).args(["-a", "com.apple", "-s", "Anchors"]))?;
    if !parents
        .lines()
        .any(|l| matches!(l.trim(), ANCHOR | "easytier-desk"))
    {
        return Ok(BTreeSet::new());
    }
    let mut anomaly = false;
    for args in [&["-sn"][..], &["-s", "Tables"], &["-s", "Anchors"]] {
        for _ in output(command(PF).args(["-a", ANCHOR]).args(args))?
            .lines()
            .filter(|l| !l.trim().is_empty())
        {
            anomaly = true;
            tracing::warn!(anchor=ANCHOR,query=?args,"unexpected PF object left untouched");
        }
    }
    let mut pairs = std::collections::BTreeMap::<Rule, (usize, usize)>::new();
    let mut unknown = Vec::new();
    let filters = output(command(PF).args(["-a", ANCHOR, "-sr"]))?;
    for (index, line) in filters.lines().enumerate() {
        if let Some((rule, v6)) = parsed(line) {
            let counts = pairs.entry(rule).or_default();
            if v6 {
                counts.1 += 1;
            } else {
                counts.0 += 1;
            }
        } else {
            anomaly = true;
            unknown.push(line);
            tracing::warn!(
                anchor = ANCHOR,
                index,
                "unrecognized PF filter left untouched"
            );
        }
    }
    let mut found = BTreeSet::new();
    for (rule, count) in pairs {
        if count == (1, 1) && !unknown.iter().any(|line| line.contains(&rule.label)) {
            found.insert(rule);
        } else {
            anomaly = true;
            tracing::warn!(anchor=ANCHOR,label=%rule.label,"ambiguous or incomplete PF generation left untouched");
        }
    }
    if anomaly && !sweep {
        return Err(io::Error::other("unexpected objects in product PF anchor"));
    }
    Ok(found)
}
pub(super) fn rules() -> io::Result<BTreeSet<Rule>> {
    inventory(false)
}
pub(super) fn sweep_rules() -> io::Result<BTreeSet<Rule>> {
    inventory(true)
}

// HR keeps the maintenance directory across uninstall. All privileged
// sessions use its stable inode, independent of the generation's state dir.
// Each mutating pfctl inherits the lock if its spawning host dies mid-command.
pub(super) struct Writer(File, std::path::PathBuf);
impl Writer {
    pub(super) fn lock() -> io::Result<Self> {
        if !Uid::effective().is_root() {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let path = NativeHostFilesystem.service_layout()?.maintenance;
        for parent in path.parent().unwrap().ancestors() {
            let m = fs::symlink_metadata(parent)?;
            if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
                return Err(io::Error::other(format!(
                    "untrusted PF maintenance parent {}",
                    parent.display()
                )));
            }
        }
        match fs::DirBuilder::new().mode(0o700).create(&path) {
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            result => result?,
        }
        let dir = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
            .open(&path)?;
        let m = dir.metadata()?;
        if !m.is_dir() || m.uid() != 0 || m.mode() & 0o777 != 0o700 {
            return Err(io::Error::other("untrusted PF maintenance directory"));
        }
        let deadline = std::time::Instant::now() + COMMAND_TIMEOUT;
        loop {
            match dir.try_lock() {
                Ok(()) => break,
                Err(std::fs::TryLockError::WouldBlock) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(25))
                }
                Err(std::fs::TryLockError::WouldBlock) => {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "PF writer is busy"));
                }
                Err(std::fs::TryLockError::Error(e)) => return Err(e),
            }
        }
        Ok(Self(dir, path.join(OWNER)))
    }
    fn pf(&self) -> io::Result<Command> {
        let mut cmd = command(PF);
        // stdin is replaced for rule loads; retain the same flock in an
        // independent fd until pfctl exits. fcntl is async-signal-safe.
        let fd = self.0.as_raw_fd();
        unsafe {
            cmd.pre_exec(move || {
                if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        Ok(cmd)
    }
    fn load(&self, intended: &BTreeSet<Rule>) -> io::Result<()> {
        let mut input = tempfile::tempfile()?;
        for rule in intended {
            writeln!(input, "{}", rule.line(false))?;
            writeln!(input, "{}", rule.line(true))?;
        }
        input.rewind()?;
        output(
            self.pf()?
                .args(["-a", ANCHOR, "-R", "-f", "-"])
                .stdin(input),
        )?;
        if rules()? != *intended {
            return Err(io::Error::other(
                "PF readback differs from intended filters",
            ));
        }
        Ok(())
    }
    pub(super) fn confirm(&self, rule: &Rule) -> io::Result<()> {
        hook()?;
        active()?;
        let own = token(&self.1)?.ok_or_else(|| io::Error::other("missing PF receipt"))?;
        if !reference_live(&own)? || !rules()?.contains(rule) {
            return Err(io::Error::other("generation fence is not active"));
        }
        Ok(())
    }
    fn install(&self) -> io::Result<()> {
        hook()?;
        let current = rules()?;
        if let Some(token) = token(&self.1)?
            && reference_live(&token)?
        {
            return active();
        }
        if !current.is_empty() {
            return Err(io::Error::other(
                "live PF rules without an owned enable reference",
            ));
        }
        // pfctl writes its receipt directly to a protected boot-local file.
        // This also finishes if the host is killed during enable.
        let mut receipt = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&self.1)?;
        writeln!(receipt, "boot {}", boot()?.0)?;
        receipt.sync_all()?;
        let status = status(
            self.pf()?
                .arg("-E")
                .stdout(receipt.try_clone()?)
                .stderr(receipt),
            COMMAND_TIMEOUT,
        )?;
        if !status.success() || token(&self.1)?.is_none() {
            return Err(io::Error::other("PF enable failed"));
        }
        self.load(&current)?;
        active()
    }
}

fn hook() -> io::Result<()> {
    let top = output(command(PF).arg("-sr"))?;
    if !top
        .lines()
        .any(|l| l.trim() == "anchor \"com.apple/*\" all")
    {
        return Err(io::Error::other("PF wildcard filter hook unavailable"));
    }
    Ok(())
}
fn active() -> io::Result<()> {
    if !output(command(PF).args(["-s", "info"]))?
        .lines()
        .any(|l| l.starts_with("Status: Enabled"))
    {
        return Err(io::Error::other("PF is disabled"));
    }
    let interfaces = output(command(PF).args(["-v", "-s", "Interfaces"]))?;
    if !interfaces
        .lines()
        .any(|line| line.split_whitespace().next() == Some("lo0") && !line.contains("skip"))
    {
        return Err(io::Error::other(
            "PF loopback filtering is skipped or unavailable",
        ));
    }
    Ok(())
}

fn token(path: &std::path::Path) -> io::Result<Option<String>> {
    let m = match fs::symlink_metadata(path) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    if !m.is_file() || m.uid() != 0 || m.mode() & 0o077 != 0 {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let contents = fs::read_to_string(path)?;
    let mut lines = contents.lines();
    let Some(header) = lines.next() else {
        return Ok(None);
    };
    let recorded = header
        .strip_prefix("boot ")
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .ok_or_else(|| io::Error::other("invalid PF receipt boot identity"))?;
    if recorded.to_string() != boot()?.0 || lines.all(|l| l.trim().is_empty()) {
        return Ok(None);
    }
    let token = contents
        .lines()
        .filter_map(|s| s.split_once(':'))
        .find_map(|(key, value)| (key.trim() == "Token").then_some(value))
        .map(str::trim)
        .filter(|s| s.parse::<u64>().is_ok())
        .ok_or_else(|| io::Error::other("invalid PF reference receipt"))?;
    Ok(Some(token.into()))
}
fn reference_live(token: &str) -> io::Result<bool> {
    references(&output(command(PF).args(["-s", "References"]))?, token)
}
fn references(list: &str, token: &str) -> io::Result<bool> {
    let mut lines = list.lines().filter(|l| !l.trim().is_empty());
    let Some(header) = lines.next() else {
        return Ok(false);
    };
    let invalid = || io::Error::other("unexpected PF reference table format");
    if header.split_whitespace().collect::<Vec<_>>()
        != ["PID", "Process", "Name", "TOKEN", "TIMESTAMP"]
    {
        return Err(invalid());
    }
    let start = header.find("TOKEN").ok_or_else(invalid)?;
    let end = header.find("TIMESTAMP").ok_or_else(invalid)?;
    let mut found = false;
    for line in lines {
        let value = line.get(start..end).map(str::trim).ok_or_else(invalid)?;
        if value.is_empty()
            || !value.bytes().all(|c| c.is_ascii_digit())
            || value.parse::<u64>().is_err()
        {
            return Err(invalid());
        }
        found |= value == token;
    }
    Ok(found)
}

const SERVICE_RECEIPT: &str = "installed-pf-reference";
pub(crate) fn install_anchor(state: &std::path::Path) -> io::Result<()> {
    let writer = Writer::lock()?;
    let inherited = match token(&writer.1)? {
        Some(t) => reference_live(&t)?,
        None => false,
    };
    if !inherited {
        // Registration's lifecycle journal covers this intent too. Preserve a
        // reference that was already owned by a separate elevated session.
        File::create(state.join(SERVICE_RECEIPT))?.sync_all()?;
    }
    writer.install()
}

pub(crate) fn uninstall_anchor(state: &std::path::Path, rollback: bool) -> io::Result<()> {
    if rollback && !state.join(SERVICE_RECEIPT).try_exists()? {
        return Ok(());
    }
    let writer = Writer::lock()?;
    if !rules()?.is_empty() {
        return Err(io::Error::other("live generation rules remain in PF"));
    }
    if let Some(t) = token(&writer.1)?
        && reference_live(&t)?
    {
        // Do not surface an enable token in diagnostics.
        if !capture(writer.pf()?.args(["-X", &t]))?.status.success() || reference_live(&t)? {
            return Err(io::Error::other("PF reference release failed"));
        }
    }
    match fs::remove_file(&writer.1) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

pub(super) fn change(rule: Rule, install: bool, cores: &CoreIdentity) -> io::Result<bool> {
    let writer = Writer::lock()?;
    if install {
        writer.install()?;
    }
    let mut all = rules()?;
    if install
        && all
            .iter()
            .any(|r| r != &rule && (r.label == rule.label || r.port == rule.port))
    {
        return Err(io::Error::other(
            "PF generation label or management port already in use",
        ));
    }
    let remaining = if !install && all.contains(&rule) {
        let own =
            token(&writer.1)?.ok_or_else(|| io::Error::other("missing product PF reference"))?;
        if !reference_live(&own)? {
            return Err(io::Error::other("unconfirmed product PF reference"));
        }
        cores.before_removal(rule.port)?
    } else {
        vec![]
    };
    let port = rule.port;
    let changed = if install {
        all.insert(rule)
    } else {
        all.remove(&rule)
    };
    if changed {
        writer.load(&all)?;
    }
    for h in remaining {
        tracing::warn!(anchor=ANCHOR,port,pid=h.pid,euid=h.uid,image=%h.image.display(),"reclaimed fence; unrelated listener left running");
    }
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::references;
    #[test]
    fn reference_identity_uses_only_the_token_column() {
        let table = format!(
            "{:<9}{:<29}{:<25}{}\n{:<9}{:<29}{:<25}{}\n",
            "PID",
            "Process Name",
            "TOKEN",
            "TIMESTAMP",
            "42",
            "agent 123",
            "567",
            "2026-11-26 12:34:56"
        );
        assert!(references(&table, "567").unwrap());
        for other in ["42", "123", "2026", "34"] {
            assert!(!references(&table, other).unwrap());
        }
        assert!(references(&table.replace("567", "bad"), "42").is_err());
    }
}
