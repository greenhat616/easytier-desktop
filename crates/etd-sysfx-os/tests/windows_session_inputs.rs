#![cfg(all(windows, feature = "ci-test-fixtures"))]
//! Untrusted per-user inputs under the elevated session (doc#13#untrusted).
//! The CI runner is an elevated administrator that is not SYSTEM, which is
//! the session form: its management workers must not load anything the
//! user's non-elevated processes can plant. Plants a personal module and a
//! poisoned module analysis cache for the runner account, then runs
//! requests through the worker pool. Disposable Windows CI runners only.
use etd_sysfx::SystemClass;
use etd_sysfx_os::{OsConfig, adapters, windows::worker_diagnostics};
use etd_testkit::no_window::NoWindow;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::Command,
};

const POWERSHELL: &str = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";

/// The runner's own PowerShell with module autoloading and no inherited
/// PSModulePath, so PowerShell builds its default search path with the
/// user's Documents module directory first: the control that shows the
/// plants are effective.
fn ps(script: &str) -> String {
    let output = Command::new(POWERSHELL)
        .no_window()
        .env_remove("PSModulePath")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().into()
}

/// Everything planted, removed again on drop (other tests on the runner run
/// PowerShell too).
struct Plants {
    module: PathBuf,
    cache: PathBuf,
    cache_backup: Option<Vec<u8>>,
}
impl Drop for Plants {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.module);
        match &self.cache_backup {
            Some(original) => {
                let _ = std::fs::write(&self.cache, original);
            }
            None => {
                let _ = std::fs::remove_file(&self.cache);
            }
        }
    }
}

fn plant(marker: &Path) -> Plants {
    let documents = PathBuf::from(ps("[Environment]::GetFolderPath('MyDocuments')"));
    let local = PathBuf::from(ps("[Environment]::GetFolderPath('LocalApplicationData')"));
    // A newer "NetSecurity" in the personal module directory: autoloading
    // would pick it for Get-NetFirewallRule.
    let module = documents.join(r"WindowsPowerShell\Modules\NetSecurity");
    std::fs::create_dir_all(&module).unwrap();
    std::fs::write(
        module.join("NetSecurity.psd1"),
        "@{ ModuleVersion = '99.0'; RootModule = 'NetSecurity.psm1'; FunctionsToExport = '*' }\r\n",
    )
    .unwrap();
    std::fs::write(
        module.join("NetSecurity.psm1"),
        format!(
            "[IO.File]::WriteAllText('{}', 'planted module loaded')\r\nfunction Get-NetFirewallRule {{ 'planted' }}\r\n",
            marker.display()
        ),
    )
    .unwrap();
    let cache = local.join(r"Microsoft\Windows\PowerShell\ModuleAnalysisCache");
    let cache_backup = std::fs::read(&cache).ok();
    std::fs::create_dir_all(cache.parent().unwrap()).unwrap();
    std::fs::write(&cache, b"poisoned module analysis cache \x00\xff\x00\xff").unwrap();
    Plants {
        module,
        cache,
        cache_backup,
    }
}

#[tokio::test]
#[ignore = "plants a module and a module analysis cache for the runner account on a disposable Windows CI runner"]
async fn user_inputs_do_not_reach_the_elevated_workers() {
    assert_eq!(std::env::var("CI").as_deref(), Ok("true"));
    assert_ne!(
        ps("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value"),
        "S-1-5-18",
        "the session form needs a host that is not SYSTEM"
    );
    let dir = tempfile::tempdir().unwrap();
    let profile = dir.path().join("profile");
    let state = dir.path().join("state");
    std::fs::create_dir(&profile).unwrap();
    std::fs::create_dir(&state).unwrap();
    let marker = dir.path().join("marker.txt");
    let _plants = plant(&marker);

    // Control: the runner's ordinary PowerShell loads the planted module.
    assert_eq!(
        ps("Get-NetFirewallRule -PolicyStore PersistentStore"),
        "planted"
    );
    assert!(marker.exists(), "the planted module is effective");
    std::fs::remove_file(&marker).unwrap();

    let os = adapters(&OsConfig {
        state_dir: state,
        run_dir: dir.path().join("run"),
        core_store_dir: dir.path().join("core"),
    })
    .unwrap();
    let rules = os
        .observer
        .enumerate(SystemClass::FirewallRules)
        .await
        .unwrap();
    assert!(!rules.is_empty(), "the firewall query returned real rules");
    assert!(!marker.exists(), "a worker loaded the planted module");

    let report = worker_diagnostics().unwrap();
    println!("{report:#}");
    assert!(!marker.exists(), "a worker loaded the planted module");
    assert_eq!(report["autoload"], "None");
    let home = ps("$PSHOME").to_lowercase();
    for module in report["modules"].as_array().unwrap() {
        let path = module["path"].as_str().unwrap().to_lowercase();
        assert!(
            path.starts_with(&format!(r"{home}\modules\")),
            "module from outside $PSHOME: {module}"
        );
    }
    let environment: BTreeMap<String, String> = report["environment"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| {
            (
                v["name"].as_str().unwrap().to_uppercase(),
                v["value"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    let explicit = [
        "APPDATA",
        "COMSPEC",
        "ETD_OS_SERVE",
        "HOMEDRIVE",
        "HOMEPATH",
        "LOCALAPPDATA",
        "PATH",
        "PSMODULEANALYSISCACHEPATH",
        "PSMODULEPATH",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "WINDIR",
    ];
    assert_eq!(
        environment.keys().map(String::as_str).collect::<Vec<_>>(),
        explicit,
        "only the explicit variables"
    );
    for name in ["USERPROFILE", "APPDATA", "LOCALAPPDATA"] {
        assert_eq!(Path::new(&environment[name]), profile, "{name}");
    }
    assert_eq!(
        Path::new(&format!(
            "{}{}",
            environment["HOMEDRIVE"], environment["HOMEPATH"]
        )),
        profile
    );
    assert_eq!(environment["PSMODULEANALYSISCACHEPATH"], "NUL");
    etd_sysfx_os::shutdown_helpers().unwrap();
}
