#![cfg(target_os = "macos")]

use std::{fs, io, os::unix::fs::MetadataExt, path::Path};

// Inspect the real system directories. The final product-specific components
// may be absent on a machine where HR has not installed the service yet.
fn inspect(socket: &Path) -> io::Result<String> {
    let mut report = String::new();
    for path in socket
        .parent()
        .unwrap()
        .ancestors()
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
    {
        match fs::symlink_metadata(path) {
            Ok(m) => {
                report.push_str(&format!(
                    "{} uid={} mode={:04o}\n",
                    path.display(),
                    m.uid(),
                    m.mode() & 0o7777
                ));
                if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
                    return Err(io::Error::new(io::ErrorKind::PermissionDenied, report));
                }
            }
            Err(e)
                if e.kind() == io::ErrorKind::NotFound
                    && path
                        .components()
                        .any(|part| part.as_os_str() == "easytier-desk") =>
            {
                report.push_str(&format!("{} created by installer\n", path.display()));
            }
            Err(e) => return Err(e),
        }
    }
    Ok(report)
}

#[test]
fn installed_service_has_a_protected_system_directory_chain() {
    let selected = Path::new(etd_ipc::SERVICE_SOCKET_PATH);
    let report = inspect(selected).unwrap_or_else(|e| {
        panic!(
            "service path check failed: {e}; /private/var/run candidate: {:?}",
            inspect(Path::new("/private/var/run/easytier-desk/host.sock"))
        )
    });
    eprint!("{report}");
}
