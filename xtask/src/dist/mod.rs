//! `cargo xtask dist`: stage a release payload and build its installer.
//!
//! 1. The release binaries and the kernel bundle (`cargo xtask fetch-cores`
//!    output) are copied into a fresh payload directory, laid out as the
//!    package installs it: `etd-ui`, `etd-host` and `etd-ctl` beside
//!    `cores/<version>/`.
//! 2. The staged bundle is checked file by file against
//!    `crates/etd-host/cores.lock`: a missing, extra or different file stops
//!    the build, so only the payload that was checked is packaged.
//! 3. The platform packager renders its package definition from
//!    `packaging/<platform>/` and, unless `--dry-run`, runs its tool.
//! 4. The sign hook runs over the package; v1 ships unsigned (issue #2).
//!
//! A packager is one module (`windows`; `linux` comes with PK4) with a
//! `package(root, &Payload, dry_run)` function.

mod cores;
mod sign;
mod windows;

use crate::fetch_cores::{self, LOCK, PIN};
use anyhow::{Context, Result, bail, ensure};
use std::fs;
use std::path::{Path, PathBuf};

/// The binaries every package installs, without the platform suffix.
pub(crate) const BINARIES: [&str; 3] = ["etd-ui", "etd-host", "etd-ctl"];

#[derive(clap::Args, Debug)]
pub struct Args {
    /// Target triple to package; `host` is this machine's.
    #[arg(long, default_value = "host")]
    target: String,
    /// Directory holding the built etd-ui, etd-host and etd-ctl.
    /// Default: <target dir>/<triple>/release, else <target dir>/release.
    #[arg(long, value_name = "DIR")]
    bin_dir: Option<PathBuf>,
    /// Kernel bundle directory (`cargo xtask fetch-cores` output).
    /// Default: <target dir>/etd-cores/<triple>/<kernel version>.
    #[arg(long, value_name = "DIR")]
    cores: Option<PathBuf>,
    /// Output root; the payload and package go to <OUT>/<triple>/.
    /// Default: <target dir>/dist.
    #[arg(long, value_name = "OUT")]
    out: Option<PathBuf>,
    /// Package version, <major>.<minor>.<patch>. Default: the workspace's.
    #[arg(long, value_name = "VERSION")]
    package_version: Option<String>,
    /// Stage, verify and render the package definition; skip the packaging
    /// tool.
    #[arg(long)]
    dry_run: bool,
    /// Signing step for the built package.
    #[arg(long, value_enum, default_value = "none")]
    sign_hook: sign::SignHook,
}

/// A staged, verified payload, ready for a packager.
pub(crate) struct Payload {
    pub triple: String,
    /// Package version, <major>.<minor>.<patch>.
    pub version: String,
    /// Kernel version naming `cores/<version>`.
    pub core_version: String,
    /// Kernel bundle file names, the executable first.
    pub core_files: Vec<String>,
    /// Payload root: the binaries and `cores/`.
    pub dir: PathBuf,
    /// Where the package definition and the package go.
    pub out: PathBuf,
}

impl Payload {
    pub fn is_windows(&self) -> bool {
        is_windows(&self.triple)
    }
}

fn is_windows(triple: &str) -> bool {
    triple.contains("-windows-")
}

/// A plain release version: three dot-separated decimal numbers without
/// leading zeros. Installers compare versions numerically and cannot order
/// pre-release tags.
fn check_version(version: &str) -> Result<[u32; 3]> {
    let parts: Vec<&str> = version.split('.').collect();
    let valid = parts.len() == 3
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.bytes().all(|b| b.is_ascii_digit())
                && (*part == "0" || !part.starts_with('0'))
        });
    ensure!(
        valid,
        "package version {version:?} must be <major>.<minor>.<patch> (no pre-release tag)"
    );
    let number = |part: &str| {
        part.parse::<u32>()
            .with_context(|| format!("package version {version:?} is out of range"))
    };
    Ok([number(parts[0])?, number(parts[1])?, number(parts[2])?])
}

/// Copy one regular file; links and directories are refused.
fn copy_file(from: &Path, to: &Path) -> Result<()> {
    let meta =
        fs::symlink_metadata(from).with_context(|| format!("cannot read {}", from.display()))?;
    ensure!(
        meta.file_type().is_file(),
        "{} is not a regular file",
        from.display()
    );
    fs::copy(from, to)
        .with_context(|| format!("cannot copy {} to {}", from.display(), to.display()))?;
    Ok(())
}

/// Fill a fresh payload directory with the binaries and the kernel bundle.
fn stage(bins: &Path, bundle: &Path, core_version: &str, windows: bool, dir: &Path) -> Result<()> {
    if fs::symlink_metadata(dir).is_ok() {
        fs::remove_dir_all(dir).with_context(|| format!("cannot clear {}", dir.display()))?;
    }
    let cores = dir.join("cores").join(core_version);
    fs::create_dir_all(&cores).with_context(|| format!("cannot create {}", cores.display()))?;
    let suffix = if windows { ".exe" } else { "" };
    for name in BINARIES {
        let file = format!("{name}{suffix}");
        copy_file(&bins.join(&file), &dir.join(&file))?;
    }
    for entry in fs::read_dir(bundle).with_context(|| {
        format!(
            "no kernel bundle at {}; run `cargo xtask fetch-cores`",
            bundle.display()
        )
    })? {
        let entry = entry?;
        copy_file(&entry.path(), &cores.join(entry.file_name()))?;
    }
    Ok(())
}

pub fn run(root: &Path, args: Args) -> Result<()> {
    let pin = fetch_cores::parse_pin(&fs::read_to_string(root.join(PIN)).context(PIN)?)?;
    let triple = if args.target == "host" {
        fetch_cores::host_triple()?.to_owned()
    } else {
        args.target.clone()
    };
    let target = pin
        .target
        .iter()
        .find(|target| target.triple == triple)
        .with_context(|| format!("{PIN} pins no kernel for {triple}"))?;
    let version = args
        .package_version
        .clone()
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_owned());
    check_version(&version)?;
    let core_version = pin.release.version.clone();

    let target_dir = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("target"));
    let bins = match &args.bin_dir {
        Some(dir) => dir.clone(),
        None => {
            let cross = target_dir.join(&triple).join("release");
            if cross.is_dir() || triple != fetch_cores::host_triple()? {
                cross
            } else {
                target_dir.join("release")
            }
        }
    };
    let bundle = args.cores.clone().unwrap_or_else(|| {
        target_dir
            .join("etd-cores")
            .join(&triple)
            .join(&core_version)
    });
    let out = args
        .out
        .clone()
        .unwrap_or_else(|| target_dir.join("dist"))
        .join(&triple);
    fs::create_dir_all(&out).with_context(|| format!("cannot create {}", out.display()))?;
    let dir = out.join("payload");

    stage(&bins, &bundle, &core_version, is_windows(&triple), &dir)?;
    let lock = fs::read_to_string(root.join(LOCK)).context(LOCK)?;
    let core_files = cores::verify(
        &lock,
        &triple,
        &core_version,
        target.executable(),
        &dir.join("cores").join(&core_version),
    )?;
    println!(
        "staged {} with the {triple} {core_version} kernel bundle matching {LOCK}",
        dir.display()
    );

    let payload = Payload {
        triple,
        version,
        core_version,
        core_files,
        dir,
        out,
    };
    let package = if payload.is_windows() {
        windows::package(root, &payload, args.dry_run)?
    } else {
        bail!(
            "no packager for {} yet (Linux: PK4; macOS: not this release)",
            payload.triple
        );
    };
    match package {
        Some(package) => {
            sign::run(args.sign_hook, &package)?;
            println!("package: {}", package.display());
        }
        None => println!("dry run: package definition rendered; packaging tool skipped"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_versions_are_plain_release_numbers() {
        assert_eq!(check_version("0.1.0").unwrap(), [0, 1, 0]);
        assert_eq!(check_version("10.20.300").unwrap(), [10, 20, 300]);
        for bad in [
            "0.1",
            "0.1.0.0",
            "0.1.0-rc.1",
            "01.1.0",
            "0.1.x",
            "",
            "0..1",
            "99999999999.0.0",
        ] {
            assert!(check_version(bad).is_err(), "{bad} accepted");
        }
    }

    #[test]
    fn staging_copies_the_binaries_and_the_bundle_into_a_fresh_payload() {
        let scratch = tempfile::tempdir().unwrap();
        let bins = scratch.path().join("bin");
        let bundle = scratch.path().join("bundle");
        fs::create_dir_all(&bins).unwrap();
        fs::create_dir_all(&bundle).unwrap();
        for name in BINARIES {
            fs::write(bins.join(format!("{name}.exe")), name).unwrap();
        }
        fs::write(bundle.join("easytier-core.exe"), b"core").unwrap();
        fs::write(bundle.join("wintun.dll"), b"tun").unwrap();
        let dir = scratch.path().join("payload");
        fs::create_dir_all(dir.join("stale")).unwrap();

        stage(&bins, &bundle, "2.7.1", true, &dir).unwrap();
        assert!(!dir.join("stale").exists(), "a previous payload was kept");
        for name in BINARIES {
            assert_eq!(
                fs::read_to_string(dir.join(format!("{name}.exe"))).unwrap(),
                name
            );
        }
        assert_eq!(
            fs::read(dir.join("cores/2.7.1/wintun.dll")).unwrap(),
            b"tun"
        );

        fs::remove_file(bins.join("etd-ctl.exe")).unwrap();
        let error = stage(&bins, &bundle, "2.7.1", true, &dir).unwrap_err();
        assert!(format!("{error:#}").contains("etd-ctl.exe"), "{error:#}");
    }

    #[test]
    fn a_bundle_subdirectory_is_refused() {
        let scratch = tempfile::tempdir().unwrap();
        let bins = scratch.path().join("bin");
        let bundle = scratch.path().join("bundle");
        fs::create_dir_all(bundle.join("nested")).unwrap();
        fs::create_dir_all(&bins).unwrap();
        for name in BINARIES {
            fs::write(bins.join(name), name).unwrap();
        }
        let error = stage(&bins, &bundle, "2.7.1", false, &scratch.path().join("p")).unwrap_err();
        assert!(
            format!("{error:#}").contains("not a regular file"),
            "{error:#}"
        );
    }
}
