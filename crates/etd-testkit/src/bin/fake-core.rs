//! Scriptable stand-in for easytier-core in process tests; never packaged.
//! Owned by P1.
use std::{
    ffi::OsString,
    path::PathBuf,
    process::ExitCode,
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};

static SIGNALS: AtomicUsize = AtomicUsize::new(0);

#[cfg(windows)]
fn install_handlers() -> std::io::Result<()> {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn SetConsoleCtrlHandler(handler: Option<extern "system" fn(u32) -> i32>, add: i32) -> i32;
    }
    extern "system" fn handle(event: u32) -> i32 {
        if event == 0 || event == 1 {
            SIGNALS.fetch_add(1, Ordering::SeqCst);
            1
        } else {
            0
        }
    }
    // SAFETY: static handler only modifies a lock-free atomic counter.
    if unsafe { SetConsoleCtrlHandler(Some(handle), 1) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
#[cfg(unix)]
fn install_handlers() -> std::io::Result<()> {
    unsafe extern "C" {
        fn signal(sig: i32, handler: extern "C" fn(i32)) -> usize;
    }
    extern "C" fn handle(_: i32) {
        SIGNALS.fetch_add(1, Ordering::SeqCst);
    }
    // SAFETY: SIGINT/SIGTERM handler only updates an atomic.
    if unsafe { signal(2, handle) } == usize::MAX || unsafe { signal(15, handle) } == usize::MAX {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<u8, Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let mut mode = String::from("graceful");
    let mut ready = None;
    let mut child_ready = None;
    let mut config = None;
    let mut signal_log = None;
    let mut delay = None;
    let mut exit_file = None;
    let mut code = 0;
    let mut host_probe = None;
    let mut check_windows_env = false;
    while let Some(arg) = args.next() {
        let value = args.next().ok_or("missing argument value")?;
        match arg.to_str().ok_or("invalid argument")? {
            "--console-ctrl" => {
                etd_proc::console_ctrl::send_ctrl_c(value.to_str().ok_or("invalid pid")?.parse()?)?;
                return Ok(0);
            }
            "--mode" => mode = value.into_string().map_err(|_| "invalid mode")?,
            "--ready-file" => ready = Some(PathBuf::from(value)),
            "--spawn-child" => child_ready = Some(PathBuf::from(value)),
            "--signal-log" => signal_log = Some(PathBuf::from(value)),
            "-c" | "--config" => config = Some(value),
            "--exit-after-ms" => {
                delay = Some(Duration::from_millis(
                    value.to_str().ok_or("invalid delay")?.parse()?,
                ))
            }
            "--exit-file" => exit_file = Some(PathBuf::from(value)),
            "--exit-code" => code = value.to_str().ok_or("invalid exit code")?.parse()?,
            "--host-probe" => host_probe = Some(PathBuf::from(value)),
            "--check-windows-env" => check_windows_env = value == "yes",
            _ => return Err(format!("unknown argument: {arg:?}").into()),
        }
    }

    if let Some(path) = host_probe {
        use etd_proc::{Command, ProcessEngine, processkit_engine::ProcessKitEngine};
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            // Safety net for a failed test; macOS deliberately has no
            // parent-death primitive and needs a shorter natural exit.
            let deadline = if cfg!(target_os = "macos") {
                "5000"
            } else {
                "30000"
            };
            let child_args = vec![
                "--mode".into(),
                "ignore".into(),
                "--exit-after-ms".into(),
                deadline.into(),
                "-c".into(),
                path.clone().into_os_string(),
            ];
            let handle = ProcessKitEngine::new()
                .spawn(Command {
                    executable: std::env::current_exe()?,
                    args: child_args,
                    env: vec![],
                    cwd: None,
                })
                .await?;
            let id = handle.identity();
            publish_ready(
                path,
                format!("{}\n{}\n{}", id.pid, id.start_token, id.exe.display()),
            )?;
            let _exit = handle.wait().await;
            Ok::<_, Box<dyn std::error::Error>>(())
        })?;
        return Ok(0);
    }

    if !matches!(mode.as_str(), "graceful" | "ignore") {
        return Err("unknown mode".into());
    }
    if check_windows_env {
        let root = std::env::var_os("SystemRoot").ok_or("missing SystemRoot")?;
        if std::env::var_os("windir").as_ref() != Some(&root) {
            return Err("missing or inconsistent windir".into());
        }
        let _listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    }
    install_handlers()?;
    // Keep the child alive until the host's actual containment kills it.
    let mut child = if let Some(path) = child_ready {
        let mut cmd = std::process::Command::new(std::env::current_exe()?);
        cmd.args([
            OsString::from("--mode"),
            "ignore".into(),
            "--ready-file".into(),
            path.into_os_string(),
            "--exit-after-ms".into(),
            "30000".into(),
        ]);
        if let Some(config) = config {
            cmd.args([OsString::from("-c"), config]);
        }
        Some(cmd.spawn()?)
    } else {
        None
    };
    if let Some(path) = ready {
        publish_ready(path, std::process::id().to_string())?;
    }
    println!("READY {}", std::process::id());
    eprintln!("fake-core ready");
    let start = Instant::now();
    let mut logged = 0;
    loop {
        if let Some(child) = &mut child {
            let _ = child.try_wait()?;
        }
        let count = SIGNALS.load(Ordering::SeqCst);
        if count != logged {
            logged = count;
            if let Some(path) = &signal_log {
                std::fs::write(path, count.to_string())?;
            }
            if mode == "graceful" {
                return Ok(code);
            }
        }
        if delay.is_some_and(|duration| start.elapsed() >= duration)
            || exit_file.as_ref().is_some_and(|path| path.exists())
        {
            return Ok(code);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn publish_ready(path: PathBuf, content: String) -> std::io::Result<()> {
    // Tests treat the ready path as a publication point, not a partially
    // written file. Use a unique sibling and rename into place.
    let tmp = path.with_extension(format!("ready-{}", std::process::id()));
    std::fs::write(&tmp, content)?;
    std::fs::rename(tmp, path)
}
