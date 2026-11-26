#![cfg(target_os = "macos")]

use etd_sysfx::{Credential, ObjectKey, SystemClass};
use etd_sysfx_os::{OsConfig, adapters};
use std::{fs, io::Write, os::unix::fs::MetadataExt, path::Path, process::Command};

#[tokio::test]
#[ignore = "foreign files under /etc/resolver on a disposable macOS runner"]
async fn rejected_magic_dns_preserves_foreign_resolvers() {
    assert_eq!(std::env::var("ETD_O3_CI").as_deref(), Ok("1"));
    let dir = Path::new("/etc/resolver");
    let created = match fs::create_dir(dir) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(e) => panic!("{e}"),
    };
    let temp = tempfile::tempdir().unwrap();
    let adapters = adapters(&OsConfig {
        state_dir: temp.path().into(),
        run_dir: temp.path().join("run"),
        core_store_dir: temp.path().join("cores"),
    })
    .unwrap();
    let mut files = vec![];
    for (prefix, content) in [
        (
            "etd-o3-foreign-marked-",
            "# Added by easytier\nnameserver 192.0.2.18\n",
        ),
        ("etd-o3-foreign-domain-", "nameserver 192.0.2.19\n"),
    ] {
        let mut file = tempfile::Builder::new()
            .prefix(prefix)
            .tempfile_in(dir)
            .unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file.flush().unwrap();
        let m = file.as_file().metadata().unwrap();
        files.push((
            file,
            content,
            Credential::File {
                file_id: m.ino(),
                device: m.dev(),
            },
        ));
    }
    let before = adapters
        .observer
        .enumerate(SystemClass::DnsPolicy)
        .await
        .unwrap();
    // Run E1's actual launch planner refusal while the foreign files exist.
    let planner =
        std::env::var_os("ETD_O3_PLAN_TEST").expect("path to the plan_classify test executable");
    let result = Command::new(planner)
        .args(["--exact", "macos_magic_dns_is_refused_on_a_privileged_host"])
        .output()
        .unwrap();
    assert!(
        result.status.success() && String::from_utf8_lossy(&result.stdout).contains("1 passed")
    );
    adapters.sweeper.find_marked(None, &[]).await.unwrap();
    let after = adapters
        .observer
        .enumerate(SystemClass::DnsPolicy)
        .await
        .unwrap();
    for (f, text, identity) in files {
        let key = ObjectKey::Path {
            path: f.path().into(),
        };
        let previous = before.iter().find(|e| e.key == key).unwrap();
        assert_eq!(previous.identity.as_ref(), Some(&identity));
        assert!(after.contains(previous));
        assert_eq!(fs::read_to_string(f.path()).unwrap(), text);
        println!(
            "Foreign resolver {} preserved content and {identity:?} after Magic DNS refusal",
            f.path().display()
        );
    }
    if created {
        fs::remove_dir(dir).unwrap();
    }
}
