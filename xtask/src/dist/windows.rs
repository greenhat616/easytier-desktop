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
/// The product icon (Add/Remove Programs), relative to the workspace root.
const ICON: &str = "packaging/assets/icons/app.ico";
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

fn render(template: &str, payload: &Payload, payload_dir: &str, icon: &str) -> Result<String> {
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
    let values = [
        ("@VERSION@", escape(&msi_version(&payload.version)?)),
        ("@PAYLOAD@", escape(payload_dir)),
        ("@CORE_VERSION@", escape(&payload.core_version)),
        ("@CORE_COMPONENTS@", components.trim_end().to_owned()),
        ("@ICON@", escape(icon)),
    ];
    // Check the template's placeholders before filling any in: a value
    // (such as a payload path) may itself contain an at sign.
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

/// Every `@NAME@` token (capital letters and underscores) in `template`.
fn placeholders(template: &str) -> BTreeSet<&str> {
    let mut found = BTreeSet::new();
    let mut rest = template;
    while let Some(start) = rest.find('@') {
        let after = &rest[start + 1..];
        match after.find('@') {
            Some(end)
                if end > 0
                    && after[..end]
                        .bytes()
                        .all(|b| b.is_ascii_uppercase() || b == b'_') =>
            {
                found.insert(&rest[start..start + end + 2]);
                rest = &after[end + 1..];
            }
            _ => rest = after,
        }
    }
    found
}

/// The PE optional header's Subsystem field: 2 is the Windows GUI, 3 the
/// console.
fn pe_subsystem(image: &[u8]) -> Result<u16> {
    let field = |at: usize, len: usize| image.get(at..at + len).context("truncated PE image");
    ensure!(field(0, 2)? == b"MZ", "not a PE image");
    let pe = u32::from_le_bytes(field(0x3c, 4)?.try_into()?) as usize;
    ensure!(field(pe, 4)? == b"PE\0\0", "not a PE image");
    // Signature (4) + file header (20); Subsystem is at 68 in the optional
    // header for both PE32 and PE32+.
    Ok(u16::from_le_bytes(field(pe + 24 + 68, 2)?.try_into()?))
}

const GUI_SUBSYSTEM: u16 = 2;

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
    let ui = fs::read(payload.dir.join("etd-ui.exe"))?;
    ensure!(
        payload.test_build || pe_subsystem(&ui)? == GUI_SUBSYSTEM,
        "etd-ui.exe is not a Windows GUI program (a debug build opens a console); \
         package a release build"
    );
    let icon = std::path::absolute(root.join(ICON))?;
    let bytes = fs::read(&icon).with_context(|| format!("product icon {ICON}"))?;
    ensure!(
        bytes.starts_with(&[0, 0, 1, 0]),
        "{ICON} is not a Windows icon file"
    );
    let icon = icon.to_str().context("icon path is not UTF-8")?;
    let template = fs::read_to_string(root.join(TEMPLATE)).context(TEMPLATE)?;
    let source = payload.out.join("Product.wxs");
    fs::write(&source, render(&template, payload, dir, icon)?)?;
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
            test_build: false,
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
        let text = render(
            &template(),
            &payload(),
            r"C:\b & c\payload",
            r"C:\r\app.ico",
        )
        .unwrap();
        assert!(text.contains(r#"<Icon Id="ProductIcon" SourceFile="C:\r\app.ico" />"#));
        assert!(text.contains(r#"<Property Id="ARPPRODUCTICON" Value="ProductIcon" />"#));
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
        // A failed install's rollback removes only what this product made,
        // and a first install over an existing service is refused up front.
        assert!(text.contains("uninstall --only-owner [ProductCode]"));
        assert!(text.contains("install --owner [ProductCode]"));
        assert!(text.contains(
            r#"Condition="Installed OR WIX_UPGRADE_DETECTED OR NOT ETD_SERVICE_PRESENT""#
        ));
        assert_eq!(text.matches("NOT ETD_SERVICE_PRESENT AND NOT").count(), 2);
        assert!(text.contains("WIX_UPGRADE_DETECTED AND ETD_SERVICE_PRESENT AND"));
        assert!(text.contains(r#"AllowSameVersionUpgrades="yes""#));
        assert!(
            !text.contains("Secure="),
            "ETD_ALLOW_USER is for administrators only"
        );
        assert!(text.contains(r#"Execute="rollback" Impersonate="no""#));
        // Every action runs without a console window, as LocalSystem.
        assert_eq!(text.matches(r#"DllEntry="WixQuietExec""#).count(), 4);
        assert_eq!(text.matches(r#"Impersonate="no""#).count(), 4);
        assert!(text.contains(r#"Scope="perMachine""#));
    }

    #[test]
    fn an_at_sign_in_the_payload_path_is_not_a_placeholder() {
        let text = render(
            &template(),
            &payload(),
            r"C:\Users\me@example\payload",
            "i@c.ico",
        )
        .unwrap();
        assert!(text.contains(r"C:\Users\me@example\payload\etd-host.exe"));
        let broken = template().replace("@CORE_VERSION@", "@CORE_VERSIONS@");
        assert!(render(&broken, &payload(), "C:\\p", "i.ico").is_err());
    }

    #[test]
    fn the_subsystem_is_read_from_the_pe_header() {
        let mut image = vec![0u8; 0x200];
        image[..2].copy_from_slice(b"MZ");
        image[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        image[0x80..0x84].copy_from_slice(b"PE\0\0");
        image[0x80 + 24 + 68..0x80 + 24 + 70].copy_from_slice(&2u16.to_le_bytes());
        assert_eq!(pe_subsystem(&image).unwrap(), GUI_SUBSYSTEM);
        image[0x80 + 24 + 68] = 3;
        assert_eq!(pe_subsystem(&image).unwrap(), 3);
        assert!(pe_subsystem(&image[..0x90]).is_err());
        assert!(pe_subsystem(b"not a program").is_err());
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
        assert!(render(&template(), &payload, "C:\\p", "i.ico").is_err());
    }
}
