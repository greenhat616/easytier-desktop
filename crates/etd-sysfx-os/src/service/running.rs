//! The executable this process is running, opened as a file whose identity
//! is bound to the running image, not to a path that a non-elevated process
//! could swap after the elevation prompt verified the payload.
//!
//! `install` and `upgrade` copy the host image from this handle and hash
//! the bytes as they copy them. The checks per platform:
//! - Linux: `/proc/self/exe` opens the executing inode itself; the kernel
//!   refuses writes to an executing file (`ETXTBSY`).
//! - macOS: the path is opened without following a final symlink and its
//!   device and inode must equal those of the vnode mapped for this code.
//! - Windows: the path is opened sharing only reads (no rename, write or
//!   delete while open), must not be a reparse point, and its volume and
//!   file id must equal those of the file mapped for this code.
//! - Unix: the file must not be writable by group or others, and its
//!   change time and size must be the same after the copy as before it.
//!
//! The residual trust is in the payload as the elevating user started it:
//! a payload directory owned by that user is theirs.
use super::*;
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, Write};

pub(super) struct RunningImage {
    file: File,
}

fn mismatch(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message.to_owned())
}

/// SHA-256 of everything `reader` yields, writing the same bytes to `out`.
pub(super) fn copy_hashing(mut reader: impl Read, mut out: impl Write) -> io::Result<[u8; 32]> {
    let mut hash = Sha256::new();
    let mut buffer = vec![0u8; 1 << 16];
    loop {
        let n = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        hash.update(&buffer[..n]);
        out.write_all(&buffer[..n])?;
    }
    Ok(hash.finalize().into())
}

pub(super) fn sha256_file(path: &Path) -> io::Result<[u8; 32]> {
    copy_hashing(File::open(path)?, io::sink())
}

impl RunningImage {
    pub fn open() -> io::Result<Self> {
        let file = open_bound()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let metadata = file.metadata()?;
            if !metadata.is_file() {
                return Err(mismatch("the running image is not a regular file"));
            }
            if metadata.mode() & 0o022 != 0 {
                return Err(mismatch(
                    "the running image is writable by group or others; run it from a directory only its owner can change",
                ));
            }
        }
        Ok(Self { file })
    }

    /// Copy the whole image into `out` once, returning the SHA-256 of
    /// exactly the bytes written.
    pub fn copy_to(&mut self, out: impl Write) -> io::Result<[u8; 32]> {
        let before = stamp(&self.file)?;
        self.file.rewind()?;
        let digest = copy_hashing(&self.file, out)?;
        if stamp(&self.file)? != before {
            return Err(mismatch("the running image changed while it was copied"));
        }
        Ok(digest)
    }

    pub fn sha256(&mut self) -> io::Result<[u8; 32]> {
        self.copy_to(io::sink())
    }
}

/// Whether `path` holds exactly the bytes of the running image.
pub fn running_image_matches(path: &Path) -> io::Result<bool> {
    Ok(RunningImage::open()?.sha256()? == sha256_file(path)?)
}

#[cfg(unix)]
fn stamp(file: &File) -> io::Result<(u64, u64, u64, i64, i64)> {
    use std::os::unix::fs::MetadataExt;
    let m = file.metadata()?;
    Ok((m.dev(), m.ino(), m.size(), m.ctime(), m.ctime_nsec()))
}
#[cfg(windows)]
fn stamp(file: &File) -> io::Result<u64> {
    // The handle denies write and delete sharing; the size is a cheap
    // consistency check only.
    Ok(file.metadata()?.len())
}

#[cfg(target_os = "linux")]
fn open_bound() -> io::Result<File> {
    File::open("/proc/self/exe")
}

#[cfg(target_os = "macos")]
fn open_bound() -> io::Result<File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(current_exe()?)?;
    let metadata = file.metadata()?;
    let (device, inode) = mapped_vnode()?;
    // `st_dev` is a signed 32-bit value on macOS.
    if metadata.dev() as u32 != device || metadata.ino() != inode {
        return Err(mismatch(
            "the payload file is no longer the running image; start the payload again",
        ));
    }
    Ok(file)
}

/// Device and inode of the vnode mapped at this function's code.
#[cfg(target_os = "macos")]
fn mapped_vnode() -> io::Result<(u32, u64)> {
    // `struct proc_regioninfo` and `proc_regionwithpathinfo` from
    // <sys/proc_info.h>; libc does not define them.
    #[repr(C)]
    struct RegionInfo {
        protection: u32,
        max_protection: u32,
        inheritance: u32,
        flags: u32,
        offset: u64,
        behavior: u32,
        user_wired_count: u32,
        user_tag: u32,
        pages_resident: u32,
        pages_shared_now_private: u32,
        pages_swapped_out: u32,
        pages_dirtied: u32,
        ref_count: u32,
        shadow_depth: u32,
        share_mode: u32,
        private_pages_resident: u32,
        shared_pages_resident: u32,
        obj_id: u32,
        depth: u32,
        address: u64,
        size: u64,
    }
    #[repr(C)]
    struct RegionWithPath {
        info: RegionInfo,
        vnode: libc::vnode_info_path,
    }
    const PROC_PIDREGIONPATHINFO: libc::c_int = 8;
    let address = mapped_vnode as fn() -> io::Result<(u32, u64)> as usize as u64;
    let size = std::mem::size_of::<RegionWithPath>();
    let mut region = std::mem::MaybeUninit::<RegionWithPath>::zeroed();
    // SAFETY: `region` is a writable buffer of `size` bytes, and the kernel
    // writes at most `size` bytes into it.
    let written = unsafe {
        libc::proc_pidinfo(
            libc::getpid(),
            PROC_PIDREGIONPATHINFO,
            address,
            region.as_mut_ptr().cast(),
            size as libc::c_int,
        )
    };
    if written <= 0 {
        return Err(io::Error::last_os_error());
    }
    if written as usize != size {
        return Err(io::Error::other("unexpected region information size"));
    }
    // SAFETY: zero-initialised, and every field is an integer or an array
    // of integers, so any bit pattern the kernel wrote is valid.
    let region = unsafe { region.assume_init() };
    if !(region.info.address <= address && address - region.info.address < region.info.size) {
        return Err(io::Error::other(
            "region information is for another mapping",
        ));
    }
    let stat = &region.vnode.vip_vi.vi_stat;
    Ok((stat.vst_dev, stat.vst_ino))
}

#[cfg(windows)]
fn open_bound() -> io::Result<File> {
    use ::windows::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ.0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(current_exe()?)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        return Err(mismatch("the running image is not a regular file"));
    }
    let mapped = OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES.0)
        .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE).0)
        .open(mapped_image_path()?)?;
    if file_id(&file)? != file_id(&mapped)? {
        return Err(mismatch(
            "the payload file is no longer the running image; start the payload again",
        ));
    }
    Ok(file)
}

/// The NT path of the file mapped at this function's code, as a path
/// `CreateFileW` accepts.
#[cfg(windows)]
fn mapped_image_path() -> io::Result<PathBuf> {
    use ::windows::Win32::System::{
        ProcessStatus::K32GetMappedFileNameW, Threading::GetCurrentProcess,
    };
    use std::os::windows::ffi::OsStringExt;
    let mut buffer = vec![0u16; 32768];
    let address =
        mapped_image_path as fn() -> io::Result<PathBuf> as usize as *const core::ffi::c_void;
    // SAFETY: the pseudo handle needs no closing, `address` lies in this
    // process's image, and the call writes at most `buffer.len()` units.
    let n = unsafe { K32GetMappedFileNameW(GetCurrentProcess(), address, &mut buffer) } as usize;
    if n == 0 || n >= buffer.len() {
        return Err(io::Error::last_os_error());
    }
    let device = std::ffi::OsString::from_wide(&buffer[..n]);
    let mut path = std::ffi::OsString::from(r"\\?\GLOBALROOT");
    path.push(device);
    Ok(PathBuf::from(path))
}

#[cfg(windows)]
fn file_id(file: &File) -> io::Result<(u64, [u8; 16])> {
    use ::windows::Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx},
    };
    use std::os::windows::io::AsRawHandle;
    let mut info = FILE_ID_INFO::default();
    // SAFETY: the handle is open for the duration of the call and `info` is
    // a writable FILE_ID_INFO of the size passed.
    unsafe {
        GetFileInformationByHandleEx(
            HANDLE(file.as_raw_handle()),
            FileIdInfo,
            (&raw mut info).cast(),
            std::mem::size_of::<FILE_ID_INFO>() as u32,
        )
    }
    .map_err(|error| io::Error::other(error.to_string()))?;
    Ok((info.VolumeSerialNumber, info.FileId.Identifier))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_hashing_returns_the_digest_of_the_bytes_written() {
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let mut out = Vec::new();
        let digest = copy_hashing(&data[..], &mut out).unwrap();
        assert_eq!(out, data);
        assert_eq!(digest, <[u8; 32]>::from(Sha256::digest(&data)));
    }

    #[test]
    fn the_running_image_is_this_test_binary() {
        // Opens this process's own executable; nothing is started.
        let mut image = RunningImage::open().unwrap();
        let exe = current_exe().unwrap();
        assert_eq!(image.sha256().unwrap(), sha256_file(&exe).unwrap());
        assert!(running_image_matches(&exe).unwrap());
        let other = tempfile::NamedTempFile::new().unwrap();
        fs::write(other.path(), b"not the image").unwrap();
        assert!(!running_image_matches(other.path()).unwrap());
    }
}
