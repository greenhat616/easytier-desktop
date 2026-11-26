//! Process lifecycle abstractions and the ProcessKit adapter.
//!
//! Frozen interfaces (F0): `engine`, `model`, `restart`. The rest is owned by
//! P1.
mod engine;
mod model;
mod restart;
pub use engine::*;
pub use model::*;
pub use restart::*;

pub mod backoff;
pub mod console_ctrl;
#[cfg(windows)]
mod console_host;
pub mod identity;
pub mod parent_death;
pub mod processkit_engine;

/// The machine's actual Windows directory, from the native OS API rather
/// than the invoking user's SystemRoot/windir environment.
#[cfg(windows)]
pub fn trusted_system_root() -> std::io::Result<std::ffi::OsString> {
    use std::os::windows::ffi::OsStringExt;
    use windows::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;

    let mut buffer = vec![0u16; 32768];
    // SAFETY: the API receives a writable UTF-16 buffer of the given length.
    let n = unsafe { GetSystemWindowsDirectoryW(Some(&mut buffer)) } as usize;
    if n == 0 {
        return Err(std::io::Error::last_os_error());
    }
    if n >= buffer.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Windows system directory exceeds buffer",
        ));
    }
    let root = std::ffi::OsString::from_wide(&buffer[..n]);
    if !std::path::Path::new(&root).is_absolute() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Windows system directory is not absolute",
        ));
    }
    Ok(root)
}
