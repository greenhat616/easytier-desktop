//! The kernel anchor is the source of truth across writer and host restarts.
//! Mutate only its filter rules and read them back before returning.
use super::{command, output};
use etd_sysfx::{FenceSpec, ObjectKey};
use nix::unistd::Uid;
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{self, Seek, Write},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{MetadataExt, OpenOptionsExt},
            process::CommandExt,
        },
    },
    process::Command,
};

pub(super) const ANCHOR: &str = "com.apple/easytier-desk";
const PF: &str = "/sbin/pfctl";
const OWNER: &str = "/private/var/run/easytier-desk.pf-reference";

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

pub(super) fn rules() -> io::Result<BTreeSet<Rule>> {
    let parents = output(command(PF).args(["-a", "com.apple", "-s", "Anchors"]))?;
    if !parents
        .lines()
        .any(|l| matches!(l.trim(), ANCHOR | "easytier-desk"))
    {
        return Ok(BTreeSet::new());
    }
    for args in [&["-sn"][..], &["-s", "Tables"], &["-s", "Anchors"]] {
        if !output(command(PF).args(["-a", ANCHOR]).args(args))?
            .trim()
            .is_empty()
        {
            return Err(io::Error::other(
                "unexpected objects in the product PF anchor",
            ));
        }
    }
    let filter = output(command(PF).args(["-a", ANCHOR, "-sr"]))?;
    let mut v4 = BTreeSet::new();
    let mut v6 = BTreeSet::new();
    for line in filter.lines() {
        let invalid = || io::Error::other("unexpected rule in the product PF anchor");
        let (prefix, label) = line.rsplit_once(" label \"").ok_or_else(invalid)?;
        let (label, family) = label
            .strip_suffix('"')
            .and_then(|s| s.rsplit_once('-'))
            .ok_or_else(invalid)?;
        let port = prefix
            .split_once(" port = ")
            .and_then(|(_, s)| s.split_whitespace().next())
            .and_then(|s| s.parse::<u16>().ok())
            .filter(|p| *p != 0)
            .ok_or_else(invalid)?;
        let rule = Rule {
            label: label.into(),
            port,
        };
        let ipv6 = family == "v6";
        if !valid_label(label)
            || rule.line(ipv6) != line
            || !(if ipv6 { &mut v6 } else { &mut v4 }).insert(rule)
        {
            return Err(invalid());
        }
    }
    if v4 != v6 {
        return Err(io::Error::other("incomplete PF rule pair"));
    }
    Ok(v4)
}

// /private/var/run is a stable root-owned inode shared by service and elevated
// sessions. Lock the directory itself so unlink/reinstall cannot split writers.
// Each mutating pfctl inherits the lock if its spawning host dies mid-command.
struct Writer(File);
impl Writer {
    fn lock() -> io::Result<Self> {
        if !Uid::effective().is_root() {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let dir = File::open("/private/var/run")?;
        let m = dir.metadata()?;
        if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        dir.lock()?;
        Ok(Self(dir))
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
    fn install(&self) -> io::Result<()> {
        let top = output(command(PF).arg("-sr"))?;
        if !top
            .lines()
            .any(|l| l.trim() == "anchor \"com.apple/*\" all")
        {
            return Err(io::Error::other("PF wildcard filter hook unavailable"));
        }
        let current = rules()?;
        if let Some(token) = token()?
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
        let receipt = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(OWNER)?;
        let status = self
            .pf()?
            .arg("-E")
            .stdout(receipt.try_clone()?)
            .stderr(receipt)
            .status()?;
        if !status.success() || token()?.is_none() {
            return Err(io::Error::other("PF enable failed"));
        }
        self.load(&current)?;
        active()
    }
}

fn active() -> io::Result<()> {
    if !output(command(PF).args(["-s", "info"]))?
        .lines()
        .any(|l| l.starts_with("Status: Enabled"))
    {
        return Err(io::Error::other("PF is disabled"));
    }
    Ok(())
}

fn token() -> io::Result<Option<String>> {
    let contents = match fs::read_to_string(OWNER) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let m = fs::symlink_metadata(OWNER)?;
    if !m.is_file() || m.uid() != 0 || m.mode() & 0o077 != 0 {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    if contents.trim().is_empty() {
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
    Ok(output(command(PF).args(["-s", "References"]))?
        .split(|c: char| !c.is_ascii_digit())
        .any(|word| word == token))
}

const SERVICE_RECEIPT: &str = "installed-pf-reference";
pub(crate) fn install_anchor(state: &std::path::Path) -> io::Result<()> {
    let writer = Writer::lock()?;
    let inherited = match token()? {
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
    if let Some(t) = token()?
        && reference_live(&t)?
    {
        // Do not surface an enable token in diagnostics.
        if !writer.pf()?.args(["-X", &t]).output()?.status.success() {
            return Err(io::Error::other("PF reference release failed"));
        }
    }
    match fs::remove_file(OWNER) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

pub(super) fn change(rule: Rule, install: bool) -> io::Result<bool> {
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
    let changed = if install {
        all.insert(rule)
    } else {
        all.remove(&rule)
    };
    if changed {
        writer.load(&all)?;
    }
    Ok(changed)
}
