//! Windows packager: a per-machine MSI built with WiX 7.x (PK3, doc#16).
//!
//! `packaging/windows/Product.wxs.tmpl` is rendered with the package
//! version, the payload folder and one component per kernel bundle file,
//! then `wix build` turns it into `easytier-desktop-<version>-<arch>.msi`.
//! WiX 7 binaries carry the Open Source Maintenance Fee EULA: this project
//! uses them as a non-commercial open source project and accepts it
//! explicitly with `-acceptEula wix7` (msg#1468); without it the build fails
//! with WIX7015.

use super::Payload;
use anyhow::{Context, Result, bail, ensure};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const TEMPLATE: &str = "packaging/windows/Product.wxs.tmpl";
/// The pinned WiX release; CI installs exactly this version.
pub(crate) const WIX_VERSION: &str = "7.0.1";
const WIX_EULA: &str = "wix7";
const UTIL_EXTENSION: &str = "WixToolset.Util.wixext";

/// MSI ProductVersion: <major>.<minor>.<build> with major and minor below
/// 256 and build below 65536. Windows Installer ignores a fourth field when
/// comparing versions, so none is written.
fn msi_version(version: &str) -> Result<String> {
    let [major, minor, patch] = super::check_version(version)?;
    ensure!(
        major < 256 && minor < 256 && patch < 65536,
        "package version {version} does not fit an MSI ProductVersion (255.255.65535)"
    );
    Ok(format!("{major}.{minor}.{patch}"))
}

/// The architecture part of the package file name and `wix build -arch`.
fn arch(triple: &str) -> Result<(&'static str, &'static str)> {
    Ok(match triple.split('-').next() {
        Some("x86_64") => ("x86_64", "x64"),
        Some("aarch64") => ("aarch64", "arm64"),
        _ => bail!("no MSI architecture for {triple}"),
    })
}

fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

/// A WiX identifier for a bundle file: letters, digits, underscores and
/// periods only.
fn identifier(name: &str) -> String {
    let body: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!("Core_{body}")
}

fn render(template: &str, payload: &Payload, payload_dir: &str) -> Result<String> {
    let mut components = String::new();
    let mut ids = BTreeSet::new();
    for name in &payload.core_files {
        let id = identifier(name);
        ensure!(
            ids.insert(id.to_ascii_lowercase()),
            "kernel bundle files {name} and another map to the WiX id {id}"
        );
        let source = format!("{payload_dir}\\cores\\{}\\{name}", payload.core_version);
        let _ = writeln!(
            components,
            "      <Component Id=\"{id}\">\n        <File Id=\"{id}\" Source=\"{}\" KeyPath=\"yes\" />\n      </Component>",
            escape(&source)
        );
    }
    let mut text = template.to_owned();
    for (placeholder, value) in [
        ("@VERSION@", escape(&msi_version(&payload.version)?)),
        ("@PAYLOAD@", escape(payload_dir)),
        ("@CORE_VERSION@", escape(&payload.core_version)),
        ("@CORE_COMPONENTS@", components.trim_end().to_owned()),
    ] {
        ensure!(
            text.contains(placeholder),
            "{TEMPLATE} has no {placeholder}"
        );
        text = text.replace(placeholder, &value);
    }
    ensure!(
        !text.contains('@'),
        "{TEMPLATE} has an unknown @ placeholder"
    );
    Ok(text)
}

fn wix(args: &[&str]) -> Command {
    let mut command = Command::new("wix");
    command.args(args);
    #[cfg(windows)]
    std::os::windows::process::CommandExt::creation_flags(&mut command, 0x0800_0000); // CREATE_NO_WINDOW
    command
}

fn check_wix() -> Result<()> {
    let output = wix(&["--version"]).output().with_context(|| {
        format!(
            "cannot run wix; install it with `dotnet tool install --global wix --version {WIX_VERSION}`, \
             `wix extension add -g {UTIL_EXTENSION}/{WIX_VERSION}`"
        )
    })?;
    let version = String::from_utf8_lossy(&output.stdout);
    ensure!(
        output.status.success() && version.trim().starts_with(WIX_VERSION),
        "wix {} found; this build pins {WIX_VERSION}",
        version.trim()
    );
    Ok(())
}

/// Render the package definition and, unless `dry_run`, build the MSI.
pub(super) fn package(root: &Path, payload: &Payload, dry_run: bool) -> Result<Option<PathBuf>> {
    let (file_arch, wix_arch) = arch(&payload.triple)?;
    let dir = std::path::absolute(&payload.dir)?;
    let dir = dir.to_str().context("payload path is not UTF-8")?;
    let template = fs::read_to_string(root.join(TEMPLATE)).context(TEMPLATE)?;
    let source = payload.out.join("Product.wxs");
    fs::write(&source, render(&template, payload, dir)?)?;
    println!("rendered {}", source.display());
    if dry_run {
        return Ok(None);
    }
    ensure!(
        cfg!(windows),
        "building an MSI needs Windows and wix {WIX_VERSION}; use --dry-run elsewhere"
    );
    check_wix()?;
    let msi = payload.out.join(format!(
        "easytier-desktop-{}-{file_arch}.msi",
        payload.version
    ));
    let source = source.to_str().context("output path is not UTF-8")?;
    let target = msi.to_str().context("output path is not UTF-8")?;
    let status = wix(&[
        "build",
        "-acceptEula",
        WIX_EULA,
        "-arch",
        wix_arch,
        "-ext",
        UTIL_EXTENSION,
        "-o",
        target,
        source,
    ])
    .status()
    .context("cannot run wix build")?;
    ensure!(status.success(), "wix build failed ({status})");
    Ok(Some(msi))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload() -> Payload {
        Payload {
            triple: "x86_64-pc-windows-msvc".into(),
            version: "0.2.3".into(),
            core_version: "2.7.1".into(),
            core_files: vec![
                "easytier-core.exe".into(),
                "Packet.dll".into(),
                "WinDivert64.sys".into(),
                "wintun.dll".into(),
            ],
            dir: PathBuf::from("unused"),
            out: PathBuf::from("unused"),
        }
    }

    fn template() -> String {
        fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../packaging/windows/Product.wxs.tmpl"
        ))
        .unwrap()
    }

    #[test]
    fn the_template_renders_every_kernel_file_and_no_placeholder() {
        let text = render(&template(), &payload(), r"C:\b & c\payload").unwrap();
        assert!(text.contains(r#"Version="0.2.3""#), "{text}");
        assert!(text.contains(r#"Name="2.7.1""#));
        assert!(text.contains(r#"Source="C:\b &amp; c\payload\etd-host.exe""#));
        for name in &payload().core_files {
            let id = identifier(name);
            assert!(
                text.contains(&format!(
                    r#"<File Id="{id}" Source="C:\b &amp; c\payload\cores\2.7.1\{name}""#
                )),
                "{name} missing:\n{text}"
            );
        }
        assert!(!text.contains('@'));
    }

    #[test]
    fn the_custom_actions_follow_doc16() {
        let text = template();
        // Uninstall only on a full removal, never while an upgrade removes
        // the old product: that would purge the ledger and allow list.
        assert!(
            text.contains(r#"Condition="(REMOVE~=&quot;ALL&quot;) AND NOT UPGRADINGPRODUCTCODE""#)
        );
        assert!(text.contains(r#"<Custom Action="UpgradeHostService" Before="InstallFinalize""#));
        assert!(text.contains(r#"<Custom Action="InstallHostService" Before="InstallFinalize""#));
        assert!(text.contains(r#"Execute="rollback" Impersonate="no""#));
        // Every action runs without a console window, as LocalSystem.
        assert_eq!(text.matches(r#"DllEntry="WixQuietExec""#).count(), 4);
        assert_eq!(text.matches(r#"Impersonate="no""#).count(), 4);
        assert!(text.contains(r#"Scope="perMachine""#));
    }

    #[test]
    fn msi_versions_fit_windows_installer() {
        assert_eq!(msi_version("0.1.0").unwrap(), "0.1.0");
        assert_eq!(msi_version("255.255.65535").unwrap(), "255.255.65535");
        assert!(msi_version("256.0.0").is_err());
        assert!(msi_version("0.256.0").is_err());
        assert!(msi_version("0.0.65536").is_err());
    }

    #[test]
    fn colliding_bundle_identifiers_are_refused() {
        let mut payload = payload();
        payload.core_files = vec!["a-b.dll".into(), "a_b.dll".into()];
        assert!(render(&template(), &payload, "C:\\p").is_err());
    }
}
