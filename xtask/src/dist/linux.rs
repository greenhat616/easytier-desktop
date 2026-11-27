//! The Linux packager (PK4, doc#16 v2): nfpm builds a .deb, an .rpm and an
//! Arch package from one rendered `packaging/linux/nfpm.yaml.tmpl`, with the
//! maintainer scripts rendered per format and hook from
//! `packaging/linux/scripts/maintainer.sh`.

use std::{
    collections::BTreeSet,
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, bail, ensure};

use super::{Payload, placeholders};

const TEMPLATE: &str = "packaging/linux/nfpm.yaml.tmpl";
const SCRIPT: &str = "packaging/linux/scripts/maintainer.sh";
const ICONS: &str = "packaging/assets/icons/hicolor";
const ICON_SIZES: [&str; 7] = [
    "16x16", "24x24", "32x32", "48x48", "64x64", "128x128", "256x256",
];
/// The pinned nfpm release; CI installs exactly this version.
pub(crate) const NFPM_VERSION: &str = "2.49.0";
/// Where the payload is installed.
const LIB: &str = "/usr/lib/easytier-desktop";

/// The hooks each format runs; `maintainer.sh` handles every pair.
const HOOKS: [(&str, &[&str]); 3] = [
    ("deb", &["preinstall", "postinstall", "preremove"]),
    ("rpm", &["preinstall", "postinstall", "preremove"]),
    ("arch", &["postinstall", "postupgrade", "preremove"]),
];

/// Runtime libraries of the release etd-ui and etd-host (from `ldd` and the
/// owning packages on Ubuntu; see docs/packaging/README.md), and the tools
/// etd-host runs, per format.
const DEB_DEPENDS: &[&str] = &[
    "libc6",
    "libgcc-s1",
    "libdbus-1-3",
    "libfontconfig1",
    "libfreetype6",
    "libx11-6",
    "libx11-xcb1",
    "libxcb1",
    "libxkbcommon0",
    "libxkbcommon-x11-0",
    "libwayland-client0",
    "libvulkan1",
    "nftables",
    "iproute2",
];
const RPM_DEPENDS: &[&str] = &[
    "glibc",
    "libgcc",
    "dbus-libs",
    "fontconfig",
    "freetype",
    "libX11",
    "libX11-xcb",
    "libxcb",
    "libxkbcommon",
    "libxkbcommon-x11",
    "libwayland-client",
    "vulkan-loader",
    "nftables",
    "iproute",
];
const ARCH_DEPENDS: &[&str] = &[
    "glibc",
    "gcc-libs",
    "dbus",
    "fontconfig",
    "freetype2",
    "libx11",
    "libxcb",
    "libxkbcommon",
    "libxkbcommon-x11",
    "wayland",
    "vulkan-icd-loader",
    "nftables",
    "iproute2",
];

/// nfpm's architecture and each format's file-name architecture.
struct Arch {
    nfpm: &'static str,
    deb: &'static str,
    rpm: &'static str,
}

fn arch(triple: &str) -> Result<Arch> {
    Ok(match triple.split('-').next() {
        Some("x86_64") => Arch {
            nfpm: "amd64",
            deb: "amd64",
            rpm: "x86_64",
        },
        Some("aarch64") => Arch {
            nfpm: "arm64",
            deb: "arm64",
            rpm: "aarch64",
        },
        _ => bail!("no Linux package architecture for {triple}"),
    })
}

/// The packages nfpm writes: (packager, file name).
fn packages(version: &str, arch: &Arch) -> [(&'static str, String); 3] {
    [
        (
            "deb",
            format!("easytier-desktop_{version}-1_{}.deb", arch.deb),
        ),
        (
            "rpm",
            format!("easytier-desktop-{version}-1.{}.rpm", arch.rpm),
        ),
        (
            "archlinux",
            format!("easytier-desktop-{version}-1-{}.pkg.tar.zst", arch.rpm),
        ),
    ]
}

/// A value for a double-quoted YAML scalar.
fn quoted(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// `path` made absolute with `.` and `..` resolved by name, with forward
/// slashes: nfpm's globbing does not accept `..` (xtask's root is
/// `xtask/..`), and the packages it writes do not exist yet.
fn plain(path: &Path) -> Result<String> {
    let mut out = PathBuf::new();
    for part in std::path::absolute(path)?.components() {
        match part {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            other => out.push(other),
        }
    }
    Ok(out
        .to_str()
        .context("path is not UTF-8")?
        .replace('\\', "/"))
}

/// `maintainer.sh` for one format and hook.
fn script(source: &str, format: &str, hook: &str) -> Result<String> {
    ensure!(
        source.matches("@FORMAT@").count() == 1 && source.matches("@HOOK@").count() == 1,
        "{SCRIPT} must hold @FORMAT@ and @HOOK@ once each"
    );
    // A package script must have LF line endings whatever the checkout has.
    let text = source
        .replace("\r\n", "\n")
        .replace("@FORMAT@", format)
        .replace("@HOOK@", hook);
    ensure!(!text.contains("@FORMAT@") && !text.contains("@HOOK@"));
    Ok(text)
}

fn depends(names: &[&str]) -> String {
    names
        .iter()
        .map(|name| format!("      - {name}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Render `nfpm.yaml`: `payload_dir`, `root` and `scripts` are absolute.
fn render(
    template: &str,
    payload: &Payload,
    payload_dir: &str,
    root: &str,
    scripts: &str,
) -> Result<String> {
    let arch = arch(&payload.triple)?;
    let mut cores = String::new();
    for (index, name) in payload.core_files.iter().enumerate() {
        // The kernel executable comes first (cores::verify).
        let mode = if index == 0 { "0755" } else { "0644" };
        let version = &payload.core_version;
        let _ = writeln!(
            cores,
            "  - src: \"{}\"\n    dst: \"{}\"\n    file_info:\n      mode: {mode}",
            quoted(&format!("{payload_dir}/cores/{version}/{name}")),
            quoted(&format!("{LIB}/cores/{version}/{name}")),
        );
    }
    let mut icons = String::new();
    for (size, file) in ICON_SIZES
        .iter()
        .map(|size| (*size, "easytier-desktop.png"))
        .chain([("scalable", "easytier-desktop.svg")])
    {
        let _ = writeln!(
            icons,
            "  - src: \"{}\"\n    dst: \"/usr/share/icons/hicolor/{size}/apps/{file}\"\n    file_info:\n      mode: 0644",
            quoted(&format!("{root}/{ICONS}/{size}/apps/{file}")),
        );
    }
    let values = [
        ("@ARCH@", arch.nfpm.to_owned()),
        ("@VERSION@", payload.version.clone()),
        ("@PAYLOAD@", quoted(payload_dir)),
        ("@ROOT@", quoted(root)),
        ("@SCRIPTS@", quoted(scripts)),
        ("@CORE_CONTENTS@", cores.trim_end().to_owned()),
        ("@ICON_CONTENTS@", icons.trim_end().to_owned()),
        ("@DEB_DEPENDS@", depends(DEB_DEPENDS)),
        ("@RPM_DEPENDS@", depends(RPM_DEPENDS)),
        ("@ARCH_DEPENDS@", depends(ARCH_DEPENDS)),
    ];
    // Check the template's placeholders before filling any in: a value
    // (such as a path) may itself contain an at sign.
    let expected: BTreeSet<&str> = values.iter().map(|(name, _)| *name).collect();
    let found = placeholders(template);
    ensure!(
        found == expected,
        "{TEMPLATE} placeholders {found:?} differ from {expected:?}"
    );
    let mut text = template.to_owned();
    for (placeholder, value) in values {
        text = text.replace(placeholder, &value);
    }
    Ok(text)
}

fn nfpm(args: &[&str]) -> Command {
    let mut command = Command::new("nfpm");
    command.args(args);
    #[cfg(windows)]
    std::os::windows::process::CommandExt::creation_flags(&mut command, 0x0800_0000); // CREATE_NO_WINDOW
    command
}

fn check_nfpm() -> Result<()> {
    let output = nfpm(&["--version"]).output().with_context(|| {
        format!(
            "cannot run nfpm; install nfpm {NFPM_VERSION} (https://nfpm.goreleaser.com/install/)"
        )
    })?;
    let version = String::from_utf8_lossy(&output.stdout);
    ensure!(
        output.status.success()
            && version
                .split(|c: char| !(c.is_ascii_digit() || c == '.'))
                .any(|word| word == NFPM_VERSION),
        "nfpm {} found; this build pins {NFPM_VERSION}",
        version.trim()
    );
    Ok(())
}

/// Render the maintainer scripts and the package definition and, unless
/// `dry_run`, build the three packages.
pub(super) fn package(root: &Path, payload: &Payload, dry_run: bool) -> Result<Vec<PathBuf>> {
    let arch = arch(&payload.triple)?;
    let utf8 = |path: &Path| plain(path);
    let source = fs::read_to_string(root.join(SCRIPT)).context(SCRIPT)?;
    let scripts = payload.out.join("scripts");
    fs::create_dir_all(&scripts)?;
    for (format, hooks) in HOOKS {
        for hook in hooks {
            fs::write(
                scripts.join(format!("{format}-{hook}.sh")),
                script(&source, format, hook)?,
            )?;
        }
    }
    for size in ICON_SIZES {
        let icon = root
            .join(ICONS)
            .join(size)
            .join("apps/easytier-desktop.png");
        ensure!(icon.is_file(), "missing icon {}", icon.display());
    }
    let template = fs::read_to_string(root.join(TEMPLATE))
        .context(TEMPLATE)?
        .replace("\r\n", "\n");
    let config = payload.out.join("nfpm.yaml");
    fs::write(
        &config,
        render(
            &template,
            payload,
            &utf8(&payload.dir)?,
            &utf8(root)?,
            &utf8(&scripts)?,
        )?,
    )?;
    println!("rendered {}", config.display());
    if dry_run {
        return Ok(Vec::new());
    }
    check_nfpm()?;
    let config = utf8(&config)?;
    let mut built = Vec::new();
    for (packager, file) in packages(&payload.version, &arch) {
        let target = payload.out.join(file);
        let status = nfpm(&[
            "package",
            "--config",
            &config,
            "--packager",
            packager,
            "--target",
            &utf8(&target)?,
        ])
        .status()
        .context("cannot run nfpm")?;
        ensure!(status.success(), "nfpm {packager} failed ({status})");
        built.push(target);
    }
    Ok(built)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn template() -> String {
        fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../",
            "packaging/linux/nfpm.yaml.tmpl"
        ))
        .unwrap()
        .replace("\r\n", "\n")
    }

    fn maintainer() -> String {
        fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../",
            "packaging/linux/scripts/maintainer.sh"
        ))
        .unwrap()
        .replace("\r\n", "\n")
    }

    fn payload() -> Payload {
        Payload {
            triple: "x86_64-unknown-linux-gnu".into(),
            version: "0.2.3".into(),
            core_version: "2.7.1".into(),
            core_files: vec!["easytier-core".into()],
            dir: PathBuf::from("unused"),
            out: PathBuf::from("unused"),
            test_build: false,
        }
    }

    #[test]
    fn the_definition_installs_the_payload_links_desktop_entry_and_icons() {
        let text = render(&template(), &payload(), "/b \"q\"/payload", "/r@x", "/s").unwrap();
        assert!(text.contains("arch: amd64\n"), "{text}");
        assert!(text.contains("version: 0.2.3\n"));
        assert!(
            text.contains(r#"src: "/b \"q\"/payload/etd-host""#),
            "{text}"
        );
        assert!(text.contains(
            "src: \"/b \\\"q\\\"/payload/cores/2.7.1/easytier-core\"\n    dst: \"/usr/lib/easytier-desktop/cores/2.7.1/easytier-core\"\n    file_info:\n      mode: 0755"
        ));
        assert!(text.contains("dst: /usr/bin/easytier-desktop\n    type: symlink"));
        assert!(text.contains("dst: /usr/bin/etd-ctl\n    type: symlink"));
        assert!(text.contains("dst: /usr/share/applications/easytier-desktop.desktop"));
        for size in ICON_SIZES {
            assert!(text.contains(&format!(
                "/usr/share/icons/hicolor/{size}/apps/easytier-desktop.png"
            )));
        }
        assert!(text.contains("/usr/share/icons/hicolor/scalable/apps/easytier-desktop.svg"));
        // No unit file: etd-host writes it.
        assert!(!text.contains(".service"));
        for (format, hooks) in HOOKS {
            for hook in hooks {
                assert!(
                    text.contains(&format!("/s/{format}-{hook}.sh")),
                    "{format} {hook}"
                );
            }
        }
        assert!(text.contains("      - nftables"));
        assert!(!text.contains("@ARCH@") && !text.contains("@CORE_CONTENTS@"));
    }

    #[test]
    fn placeholders_are_checked_before_values_are_filled_in() {
        let broken = template().replace("@SCRIPTS@", "@SCRIPT@");
        assert!(render(&broken, &payload(), "/p", "/r", "/s").is_err());
        let mut other = payload();
        other.triple = "riscv64gc-unknown-linux-gnu".into();
        assert!(render(&template(), &other, "/p", "/r", "/s").is_err());
    }

    #[test]
    fn paths_reach_nfpm_without_dot_components() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let plain = plain(&root.join("./packaging/linux")).unwrap();
        assert!(plain.ends_with("/packaging/linux"), "{plain}");
        assert!(
            !plain.contains("/..") && !plain.contains("/./") && !plain.contains('\\'),
            "{plain}"
        );
        assert!(!plain.contains("/xtask/"), "{plain}");
    }

    #[test]
    fn package_names_follow_each_format() {
        let arm = arch("aarch64-unknown-linux-gnu").unwrap();
        let names: Vec<_> = packages("1.2.3", &arm)
            .into_iter()
            .map(|(_, n)| n)
            .collect();
        assert_eq!(
            names,
            [
                "easytier-desktop_1.2.3-1_arm64.deb",
                "easytier-desktop-1.2.3-1.aarch64.rpm",
                "easytier-desktop-1.2.3-1-aarch64.pkg.tar.zst",
            ]
        );
    }

    #[test]
    fn every_format_and_hook_renders_the_maintainer_script() {
        let source = maintainer();
        for (format, hooks) in HOOKS {
            for hook in hooks {
                let text = script(&source, format, hook).unwrap();
                assert!(text.contains(&format!("FORMAT={format}\nHOOK={hook}\n")));
                assert!(text.starts_with("#!/bin/sh\n"));
            }
        }
        assert!(script("FORMAT=@FORMAT@", "deb", "preinstall").is_err());
    }
}

/// Every hook branch of the rendered scripts, run by `sh` against a stub
/// etd-host that logs its arguments (Linux and macOS CI; not on Windows).
#[cfg(all(test, unix))]
mod hook_tests {
    use super::*;
    use std::{os::unix::fs::PermissionsExt, process::Output};

    fn maintainer() -> String {
        fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../",
            "packaging/linux/scripts/maintainer.sh"
        ))
        .unwrap()
        .replace("\r\n", "\n")
    }

    struct Machine {
        dir: tempfile::TempDir,
    }

    impl Machine {
        /// A machine with systemd running, no service, and a stub host
        /// that exits with `status`.
        fn new(status: i32) -> Self {
            let dir = tempfile::tempdir().unwrap();
            fs::create_dir(dir.path().join("systemd")).unwrap();
            let host = dir.path().join("etd-host");
            fs::write(
                &host,
                format!(
                    "#!/bin/sh\necho \"$*\" >> \"{}\"\nexit {status}\n",
                    dir.path().join("log").display()
                ),
            )
            .unwrap();
            fs::set_permissions(&host, fs::Permissions::from_mode(0o755)).unwrap();
            Self { dir }
        }
        fn with_service(self) -> Self {
            fs::write(self.dir.path().join("unit"), "").unwrap();
            self
        }
        fn without_systemd(self) -> Self {
            fs::remove_dir(self.dir.path().join("systemd")).unwrap();
            self
        }
        fn script(&self, format: &str, hook: &str) -> String {
            let path = |name: &str| self.dir.path().join(name).display().to_string();
            let text = script(&maintainer(), format, hook).unwrap();
            let mut out = text.clone();
            for (line, value) in [
                ("HOST=/usr/lib/easytier-desktop/etd-host", path("etd-host")),
                (
                    "UNIT=/etc/systemd/system/easytier-desk-host.service",
                    path("unit"),
                ),
                ("SYSTEMD=/run/systemd/system", path("systemd")),
            ] {
                assert_eq!(text.matches(line).count(), 1, "{line}");
                let name = line.split('=').next().unwrap();
                out = out.replace(line, &format!("{name}='{value}'"));
            }
            out
        }
        /// Run a hook as dpkg or rpm does: the script with arguments.
        fn run(&self, format: &str, hook: &str, args: &[&str]) -> Output {
            let file = self.dir.path().join("hook.sh");
            fs::write(&file, self.script(format, hook)).unwrap();
            Command::new("sh").arg(&file).args(args).output().unwrap()
        }
        /// Run an Arch hook as pacman does: the script is the body of a
        /// function in .INSTALL, called with versions.
        fn run_arch(&self, hook: &str, function: &str, args: &[&str]) -> Output {
            let file = self.dir.path().join("install");
            let body = self.script("arch", hook);
            fs::write(
                &file,
                format!("{function}() {{\n{body}\n}}\n{function} \"$@\"\n"),
            )
            .unwrap();
            Command::new("sh").arg(&file).args(args).output().unwrap()
        }
        fn calls(&self) -> Vec<String> {
            fs::read_to_string(self.dir.path().join("log"))
                .map(|log| log.lines().map(str::to_owned).collect())
                .unwrap_or_default()
        }
    }

    const INSTALL: &str = "install --owner easytier-desktop-package";
    const UPGRADE: &str = "upgrade --only-owner easytier-desktop-package";
    const UNINSTALL: &str = "uninstall --only-owner easytier-desktop-package";

    fn ok(output: &Output) -> String {
        assert!(output.status.success(), "{output:?}");
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    #[test]
    fn deb_hooks_install_upgrade_and_remove_only_their_service() {
        let fresh = Machine::new(0);
        ok(&fresh.run("deb", "preinstall", &["install"]));
        ok(&fresh.run("deb", "postinstall", &["configure", ""]));
        assert_eq!(fresh.calls(), [INSTALL]);

        let refused = Machine::new(0).with_service();
        let output = refused.run("deb", "preinstall", &["install"]);
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("uninstall"),
            "{output:?}"
        );
        assert!(refused.calls().is_empty());

        let upgrade = Machine::new(0).with_service();
        ok(&upgrade.run("deb", "preinstall", &["upgrade", "0.1.0-1"]));
        ok(&upgrade.run("deb", "preremove", &["upgrade", "0.2.0-1"]));
        ok(&upgrade.run("deb", "postinstall", &["configure", "0.1.0-1"]));
        for quiet in ["failed-upgrade", "deconfigure"] {
            ok(&upgrade.run("deb", "preremove", &[quiet, "0.2.0-1"]));
        }
        ok(&upgrade.run("deb", "postinstall", &["abort-upgrade", "0.2.0-1"]));
        assert_eq!(upgrade.calls(), [UPGRADE]);

        let fallback = Machine::new(0);
        let notice = ok(&fallback.run("deb", "postinstall", &["configure", "0.1.0-1"]));
        assert!(
            notice.contains("installing it instead of upgrading"),
            "{notice}"
        );
        assert_eq!(fallback.calls(), [INSTALL]);

        let removal = Machine::new(0).with_service();
        ok(&removal.run("deb", "preremove", &["remove"]));
        assert_eq!(removal.calls(), [UNINSTALL]);
    }

    #[test]
    fn rpm_hooks_follow_the_instance_count() {
        let fresh = Machine::new(0);
        ok(&fresh.run("rpm", "preinstall", &["1"]));
        ok(&fresh.run("rpm", "postinstall", &["1"]));
        assert_eq!(fresh.calls(), [INSTALL]);

        let refused = Machine::new(0).with_service();
        assert!(!refused.run("rpm", "preinstall", &["1"]).status.success());

        let upgrade = Machine::new(0).with_service();
        ok(&upgrade.run("rpm", "preinstall", &["2"]));
        ok(&upgrade.run("rpm", "postinstall", &["2"]));
        // The old package's %preun runs after the new %post, with 1 left.
        ok(&upgrade.run("rpm", "preremove", &["1"]));
        assert_eq!(upgrade.calls(), [UPGRADE]);

        let fallback = Machine::new(0);
        ok(&fallback.run("rpm", "postinstall", &["2"]));
        assert_eq!(fallback.calls(), [INSTALL]);

        let removal = Machine::new(0).with_service();
        ok(&removal.run("rpm", "preremove", &["0"]));
        assert_eq!(removal.calls(), [UNINSTALL]);
    }

    #[test]
    fn arch_hooks_take_versions_and_leave_a_foreign_service_alone() {
        let fresh = Machine::new(0);
        ok(&fresh.run_arch("postinstall", "post_install", &["0.1.0-1"]));
        // The stub installs nothing: the service exists from here on.
        let fresh = fresh.with_service();
        ok(&fresh.run_arch("postupgrade", "post_upgrade", &["0.2.0-1", "0.1.0-1"]));
        // pacman passes the old version to pre_remove: still a removal.
        ok(&fresh.run_arch("preremove", "pre_remove", &["0.2.0-1"]));
        assert_eq!(fresh.calls(), [INSTALL, UPGRADE, UNINSTALL]);

        let foreign = Machine::new(0).with_service();
        let warning = ok(&foreign.run_arch("postinstall", "post_install", &["0.1.0-1"]));
        assert!(warning.contains("leaves it alone"), "{warning}");
        assert!(
            warning.contains("/usr/local/lib/easytier-desk/etd-host uninstall"),
            "{warning}"
        );
        assert!(warning.contains("pacman -S easytier-desktop"), "{warning}");
        assert!(foreign.calls().is_empty());
        // Its removal hook asks etd-host to remove only what the package
        // owns; etd-host leaves the foreign service (uninstall --only-owner).
        ok(&foreign.run_arch("preremove", "pre_remove", &["0.1.0-1"]));
        assert_eq!(foreign.calls(), [UNINSTALL]);
    }

    #[test]
    fn without_systemd_every_hook_only_prints_a_notice() {
        let container = Machine::new(0).with_service().without_systemd();
        assert!(ok(&container.run("deb", "preinstall", &["install"])).is_empty());
        for (format, hook, args) in [
            ("deb", "postinstall", &["configure", ""][..]),
            ("deb", "preremove", &["remove"][..]),
            ("rpm", "postinstall", &["1"][..]),
            ("rpm", "preremove", &["0"][..]),
        ] {
            let notice = ok(&container.run(format, hook, args));
            assert!(
                notice.contains("systemd is not running"),
                "{format} {hook}: {notice}"
            );
        }
        ok(&container.run_arch("postinstall", "post_install", &["0.1.0-1"]));
        assert!(container.calls().is_empty());
    }

    #[test]
    fn a_failing_etd_host_fails_the_hook() {
        let broken = Machine::new(3);
        assert!(
            !broken
                .run("deb", "postinstall", &["configure", ""])
                .status
                .success()
        );
        assert!(!broken.run("rpm", "postinstall", &["1"]).status.success());
        let broken = broken.with_service();
        assert!(!broken.run("deb", "preremove", &["remove"]).status.success());
    }
}
