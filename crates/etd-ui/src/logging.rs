//! Log and panic sink of the desktop binary. A release build has no console
//! (Windows GUI subsystem), so tracing output and panics go to a size-rotated
//! file in the per-user local data directory; a debug build also keeps
//! stdout.
//!
//! No network secret reaches these events: the store strips it before
//! anything holds a spec, and the host redacts its own errors. Panic messages
//! are written as they are.

use std::{
    backtrace::Backtrace,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    panic::PanicHookInfo,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, TryLockError},
};

use tracing_subscriber::{
    EnvFilter, fmt::MakeWriter, layer::SubscriberExt, util::SubscriberInitExt,
};

/// Name of the current log file; rotated ones get `.1` (newest) to `.N`.
pub(crate) const FILE_NAME: &str = "etd-ui.log";
/// A file is rotated before a write would take it past this size.
const MAX_BYTES: u64 = 1024 * 1024;
/// Rotated files kept besides the current one.
const KEEP: usize = 4;

/// `logs/` in the per-user local data directory (never roaming):
/// `%LOCALAPPDATA%\EasyTierDesk\data\logs` on Windows,
/// `~/Library/Application Support/EasyTierDesk/logs` on macOS,
/// `$XDG_DATA_HOME/easytierdesk/logs` on Linux. `None` without a home
/// directory.
pub(crate) fn default_dir() -> Option<PathBuf> {
    directories::ProjectDirs::from("", "", "EasyTierDesk")
        .map(|dirs| dirs.data_local_dir().join("logs"))
}

/// Install the subscriber and the panic hook. Without a usable log folder
/// the binary logs to stdout only.
pub(crate) fn init() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let file = default_dir().and_then(|dir| match LogFile::open(&dir, MAX_BYTES, KEEP) {
        Ok(file) => Some(file),
        Err(error) => {
            eprintln!("etd-ui: cannot open the log in {}: {error}", dir.display());
            None
        }
    });
    let stdout = (cfg!(debug_assertions) || file.is_none()).then(tracing_subscriber::fmt::layer);
    let to_file = file.clone().map(|file| {
        tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(file)
    });
    tracing_subscriber::registry()
        .with(filter)
        .with(stdout)
        .with(to_file)
        .init();
    if let Some(file) = file {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            file.write_panic(info);
            previous(info);
        }));
    }
}

/// The current log file and its rotation.
struct Rolling {
    dir: PathBuf,
    file: File,
    len: u64,
    max_bytes: u64,
    keep: usize,
}

impl Rolling {
    fn path(&self, n: usize) -> PathBuf {
        match n {
            0 => self.dir.join(FILE_NAME),
            n => self.dir.join(format!("{FILE_NAME}.{n}")),
        }
    }

    /// `.keep` is dropped, every other file moves up one, the current one
    /// becomes `.1`, and a new current file starts.
    fn rotate(&mut self) -> io::Result<()> {
        for n in (0..self.keep).rev() {
            let from = self.path(n);
            if from.exists() {
                fs::rename(&from, self.path(n + 1))?;
            }
        }
        self.file = append(&self.path(0))?;
        self.len = 0;
        Ok(())
    }

    fn write(&mut self, buf: &[u8]) -> io::Result<()> {
        if self.len > 0 && self.len + buf.len() as u64 > self.max_bytes {
            self.rotate()?;
        }
        self.file.write_all(buf)?;
        self.len += buf.len() as u64;
        Ok(())
    }
}

fn append(path: &Path) -> io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

/// A size-rotated log file shared by the subscriber and the panic hook.
#[derive(Clone)]
pub(crate) struct LogFile(Arc<Mutex<Rolling>>);

impl LogFile {
    fn open(dir: &Path, max_bytes: u64, keep: usize) -> io::Result<Self> {
        fs::create_dir_all(dir)?;
        let file = append(&dir.join(FILE_NAME))?;
        let len = file.metadata()?.len();
        Ok(Self(Arc::new(Mutex::new(Rolling {
            dir: dir.to_owned(),
            file,
            len,
            max_bytes,
            keep,
        }))))
    }

    /// The panic message and a captured backtrace, written synchronously so
    /// they land before the process exits. A panic raised while this very
    /// file is being written (lock held) is left to the default hook.
    fn write_panic(&self, info: &PanicHookInfo<'_>) {
        let record = panic_record(info, &Backtrace::force_capture());
        match self.0.try_lock() {
            Ok(mut rolling) => {
                let _ = rolling.write(record.as_bytes());
            }
            Err(TryLockError::Poisoned(poisoned)) => {
                let _ = poisoned.into_inner().write(record.as_bytes());
            }
            Err(TryLockError::WouldBlock) => {}
        }
    }
}

fn panic_record(info: &impl std::fmt::Display, backtrace: &Backtrace) -> String {
    let thread = std::thread::current();
    let name = thread.name().unwrap_or("<unnamed>");
    format!(
        "{} PANIC thread '{name}': {info}\nbacktrace:\n{backtrace}\n",
        jiff::Timestamp::now()
    )
}

impl Write for LogFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut rolling = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        rolling.write(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut rolling = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        rolling.file.flush()
    }
}

impl<'a> MakeWriter<'a> for LogFile {
    type Writer = LogFile;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn files_rotate_by_size_and_keep_a_bounded_count() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = LogFile::open(dir.path(), 10, 2).unwrap();
        for line in ["aaaaaa\n", "bbbbbb\n", "cccccc\n", "dddddd\n"] {
            log.write_all(line.as_bytes()).unwrap();
        }
        assert_eq!(
            names(dir.path()),
            [FILE_NAME, "etd-ui.log.1", "etd-ui.log.2"]
        );
        let read = |name: &str| fs::read_to_string(dir.path().join(name)).unwrap();
        assert_eq!(read(FILE_NAME), "dddddd\n");
        assert_eq!(read("etd-ui.log.1"), "cccccc\n");
        assert_eq!(read("etd-ui.log.2"), "bbbbbb\n");
    }

    #[test]
    fn an_existing_file_is_appended_to_and_counted() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(FILE_NAME), "old\n").unwrap();
        let mut log = LogFile::open(dir.path(), 8, 1).unwrap();
        log.write_all(b"new\n").unwrap();
        assert_eq!(names(dir.path()), [FILE_NAME]);
        log.write_all(b"next\n").unwrap();
        let read = |name: &str| fs::read_to_string(dir.path().join(name)).unwrap();
        assert_eq!(read("etd-ui.log.1"), "old\nnew\n");
        assert_eq!(read(FILE_NAME), "next\n");
    }

    #[test]
    fn a_line_longer_than_the_limit_is_written_whole() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = LogFile::open(dir.path(), 4, 1).unwrap();
        log.write_all(b"0123456789\n").unwrap();
        assert_eq!(
            fs::read_to_string(dir.path().join(FILE_NAME)).unwrap(),
            "0123456789\n"
        );
    }

    #[test]
    fn a_panic_record_names_the_thread_and_carries_the_backtrace() {
        let record = panic_record(&"boom at main.rs:1:1", &Backtrace::force_capture());
        assert!(record.contains(" PANIC thread '"), "{record}");
        assert!(
            record.contains("boom at main.rs:1:1\nbacktrace:\n"),
            "{record}"
        );
    }

    #[test]
    fn the_folder_is_local_not_roaming() {
        let Some(dir) = default_dir() else { return };
        assert!(dir.ends_with("logs"));
        #[cfg(windows)]
        assert!(
            dir.to_string_lossy()
                .to_lowercase()
                .contains("appdata\\local"),
            "{}",
            dir.display()
        );
    }
}
