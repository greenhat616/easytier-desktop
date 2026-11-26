//! The TOML profile library: atomic replace, migration, and never losing
//! the original.
use etd_app::profiles_toml::{PROFILE_SCHEMA_VERSION, TomlProfileStore};
use etd_app::{Profile, ProfileError, ProfileStore};
use etd_contract::v1::{NetworkFlags, PortForward, TransportProtocol, network_spec::Ipv4};
use etd_contract::{InstanceId, NetworkSpec};
use proptest::prelude::*;
use std::{fs, path::Path};

fn full_spec() -> NetworkSpec {
    NetworkSpec {
        display_name: "办公室 \"main\"".into(),
        network_name: "office".into(),
        network_secret: None,
        network_secret_set: false,
        hostname: "laptop".into(),
        ipv4: Some(Ipv4::Ipv4Cidr("10.1.2.3/24".into())),
        peers: vec!["tcp://peer.example:11010".into()],
        listeners: vec!["udp://0.0.0.0:11010".into()],
        no_listener: false,
        proxy_cidrs: vec!["192.168.1.0/24".into()],
        exit_nodes: vec!["10.1.2.1".into()],
        enable_exit_node: true,
        mtu: 1380,
        no_tun: true,
        socks5_port: 1080,
        port_forwards: vec![PortForward {
            protocol: TransportProtocol::Udp as i32,
            bind: "127.0.0.1:5353".into(),
            destination: "10.1.2.1:53".into(),
        }],
        magic_dns: true,
        public_ipv6_provider: true,
        flags: Some(NetworkFlags {
            latency_first: true,
            disable_encryption: true,
            enable_kcp_proxy: true,
            enable_quic_proxy: true,
            disable_p2p: true,
            disable_udp_hole_punching: true,
            relay_all_peer_rpc: true,
            multi_thread: Some(false),
            private_mode: true,
            disable_ipv6: true,
            use_smoltcp: true,
            bind_device: None,
            compression: "zstd".into(),
        }),
    }
}

fn profile(id: &str, spec: NetworkSpec) -> Profile {
    Profile {
        instance_id: InstanceId(id.into()),
        spec,
        updated_at: "2026-11-26T01:02:03.5Z".parse().unwrap(),
    }
}

fn store_in(dir: &Path) -> TomlProfileStore {
    TomlProfileStore::new(dir.join("profiles.toml"))
}

fn entries(dir: &Path) -> Vec<String> {
    fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect()
}

#[test]
fn a_missing_file_is_an_empty_library() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(store_in(dir.path()).load().unwrap(), []);
}

#[test]
fn every_field_round_trips_and_no_temporary_file_stays() {
    let dir = tempfile::tempdir().unwrap();
    let nested = dir.path().join("not/yet/there");
    let store = store_in(&nested);
    let mut dhcp = NetworkSpec {
        network_name: "home".into(),
        ipv4: Some(Ipv4::Dhcp(true)),
        ..NetworkSpec::default()
    };
    let saved = vec![profile("a", full_spec()), profile("b", dhcp.clone())];
    store.save(&saved).unwrap();
    assert_eq!(store.load().unwrap(), saved);
    // Replacing keeps exactly the new content.
    dhcp.network_name = "cabin".into();
    let replaced = vec![profile("b", dhcp)];
    store.save(&replaced).unwrap();
    assert_eq!(store.load().unwrap(), replaced);
    assert_eq!(entries(&nested), ["profiles.toml"]);
}

#[test]
fn a_new_configuration_starts_with_no_listener() {
    assert!(NetworkSpec::default().listeners.is_empty());
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    store.save(&[profile("a", NetworkSpec::default())]).unwrap();
    assert!(store.load().unwrap()[0].spec.listeners.is_empty());
}

#[test]
fn the_secret_is_never_written_or_read() {
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    let mut spec = full_spec();
    spec.network_secret = Some("do-not-store".into());
    spec.network_secret_set = true;
    store.save(&[profile("a", spec)]).unwrap();
    let text = fs::read_to_string(store.path()).unwrap();
    assert!(!text.contains("do-not-store"), "{text}");
    assert!(!text.contains("secret"), "{text}");

    // Typed in by hand: ignored, and gone at the next save.
    let edited = text.replace(
        "network_name = \"office\"",
        "network_name = \"office\"\nnetwork_secret = \"typed-by-hand\"",
    );
    assert_ne!(edited, text);
    fs::write(store.path(), edited).unwrap();
    let loaded = store.load().unwrap();
    assert_eq!(loaded[0].spec.network_secret, None);
    store.save(&loaded).unwrap();
    assert!(
        !fs::read_to_string(store.path())
            .unwrap()
            .contains("typed-by-hand")
    );
}

#[test]
fn errors_do_not_quote_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    fs::write(
        store.path(),
        "version = 1\nnetwork_secret = \"quoted-secret\" oops\n",
    )
    .unwrap();
    let error = store.load().unwrap_err().to_string();
    assert!(error.contains("line 2"), "{error}");
    assert!(!error.contains("quoted-secret"), "{error}");
}

const OLD_LAYOUT: &str = r#"
[[network]]
id = "one"
name = "Office"
network_name = "office"
ipv4 = "dhcp"
peers = ["tcp://peer.example:11010"]
network_secret = "legacy-secret"

[[network]]
id = "two"
network_name = "home"
ipv4 = "10.0.0.2/24"
listeners = ["tcp://0.0.0.0:11010"]
"#;

#[test]
fn the_old_layout_migrates() {
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    fs::write(store.path(), OLD_LAYOUT).unwrap();
    let migrated = store.load().unwrap();
    assert_eq!(migrated.len(), 2);
    assert_eq!(migrated[0].instance_id, InstanceId("one".into()));
    assert_eq!(migrated[0].spec.display_name, "Office");
    assert_eq!(migrated[0].spec.ipv4, Some(Ipv4::Dhcp(true)));
    assert_eq!(migrated[0].spec.network_secret, None);
    assert_eq!(
        migrated[1].spec.ipv4,
        Some(Ipv4::Ipv4Cidr("10.0.0.2/24".into()))
    );
    assert_eq!(migrated[1].spec.listeners, ["tcp://0.0.0.0:11010"]);
    // Loading alone does not touch the file.
    assert_eq!(fs::read_to_string(store.path()).unwrap(), OLD_LAYOUT);

    store.save(&migrated).unwrap();
    let rewritten = fs::read_to_string(store.path()).unwrap();
    assert!(rewritten.starts_with(&format!("version = {PROFILE_SCHEMA_VERSION}\n")));
    assert!(!rewritten.contains("legacy-secret"));
    assert_eq!(store.load().unwrap(), migrated);
}

#[test]
fn an_empty_file_is_an_empty_library() {
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    fs::write(store.path(), "").unwrap();
    assert_eq!(store.load().unwrap(), []);
}

/// What this build cannot read completely, it does not overwrite.
#[test]
fn unreadable_files_are_kept_as_they_are() {
    let newer = "version = 2\n[[profile]]\nfuture = true\n";
    let broken = "version = 1\n[[profile\n";
    let unrelated = "[settings]\ntheme = \"dark\"\n";
    let twice = "version = 1\n\
        [[profile]]\ninstance_id = \"a\"\nupdated_at = \"2026-11-26T00:00:00Z\"\n[profile.network]\n\
        [[profile]]\ninstance_id = \"a\"\nupdated_at = \"2026-11-26T00:00:00Z\"\n[profile.network]\n";
    let both = "version = 1\n\
        [[profile]]\ninstance_id = \"a\"\nupdated_at = \"2026-11-26T00:00:00Z\"\n\
        [profile.network]\ndhcp = true\nipv4_cidr = \"10.0.0.1/24\"\n";
    let not_utf8: &[u8] = &[0xff, 0xfe, 0x00];
    for content in [
        newer.as_bytes(),
        broken.as_bytes(),
        unrelated.as_bytes(),
        twice.as_bytes(),
        both.as_bytes(),
        b"version = \"one\"\n",
        not_utf8,
    ] {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(dir.path());
        fs::write(store.path(), content).unwrap();
        let load = store.load().unwrap_err();
        let save = store
            .save(&[profile("new", NetworkSpec::default())])
            .unwrap_err();
        for error in [load, save] {
            if content == newer.as_bytes() {
                assert!(
                    matches!(
                        error,
                        ProfileError::UnsupportedVersion {
                            found: 2,
                            supported: PROFILE_SCHEMA_VERSION
                        }
                    ),
                    "{error}"
                );
            } else {
                assert!(matches!(error, ProfileError::Corrupt(_)), "{error}");
            }
        }
        assert_eq!(fs::read(store.path()).unwrap(), content);
    }
}

#[test]
fn duplicate_ids_are_refused_before_writing() {
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    let kept = vec![profile("a", NetworkSpec::default())];
    store.save(&kept).unwrap();
    let twice = [kept[0].clone(), kept[0].clone()];
    assert!(matches!(store.save(&twice), Err(ProfileError::Corrupt(_))));
    assert_eq!(store.load().unwrap(), kept);
}

/// Makes the replacement fail the way the platform can: Windows refuses to
/// rename over a read-only file, Unix refuses to create a file in a
/// read-only directory.
#[test]
fn a_failed_write_keeps_the_original() {
    let dir = tempfile::tempdir().unwrap();
    let store = store_in(dir.path());
    let original = vec![profile("a", full_spec())];
    store.save(&original).unwrap();
    let bytes = fs::read(store.path()).unwrap();

    let locked: &Path = if cfg!(windows) {
        store.path()
    } else {
        dir.path()
    };
    let writable = fs::metadata(locked).unwrap().permissions();
    let mut read_only = writable.clone();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        read_only.set_mode(0o500);
    }
    #[cfg(windows)]
    read_only.set_readonly(true);
    fs::set_permissions(locked, read_only).unwrap();
    // Root ignores directory permissions; there is nothing to test then.
    let ignored = cfg!(unix) && fs::write(dir.path().join("probe"), b"x").is_ok();

    let result = store.save(&[profile("b", NetworkSpec::default())]);
    fs::set_permissions(locked, writable).unwrap();
    if ignored {
        return;
    }
    assert!(matches!(result, Err(ProfileError::Io(_))), "{result:?}");
    assert_eq!(fs::read(store.path()).unwrap(), bytes);
    assert_eq!(store.load().unwrap(), original);
    assert_eq!(
        entries(dir.path()),
        ["profiles.toml"],
        "temporary file left"
    );
}

proptest! {
    #[test]
    fn any_text_round_trips(
        name in ".*",
        peers in prop::collection::vec(".*", 0..4),
        mtu in any::<u32>(),
        port in any::<u32>(),
        protocol in any::<i32>(),
        multi_thread in any::<Option<bool>>(),
    ) {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(dir.path());
        let spec = NetworkSpec {
            network_name: name.clone(),
            display_name: name,
            peers,
            mtu,
            socks5_port: port,
            port_forwards: vec![PortForward { protocol, ..PortForward::default() }],
            flags: Some(NetworkFlags { multi_thread, ..NetworkFlags::default() }),
            ..NetworkSpec::default()
        };
        let saved = vec![profile("a", spec)];
        store.save(&saved).unwrap();
        prop_assert_eq!(store.load().unwrap(), saved);
    }
}
