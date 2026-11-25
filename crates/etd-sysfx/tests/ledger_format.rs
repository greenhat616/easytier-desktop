//! Persisted model JSON is part of the SQLite schema, not just a wire format.
//! Deliberately fixed fixtures catch changes that require a migration.
use etd_sysfx::*;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

fn snapshot<T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug>(
    value: T,
    expected: Value,
) {
    assert_eq!(serde_json::to_value(&value).unwrap(), expected);
    assert_eq!(serde_json::from_value::<T>(expected).unwrap(), value);
}

#[test]
fn persistence_and_undo_format() {
    let until = "2025-01-01T00:00:00Z".parse().unwrap();
    snapshot(Persistence::WithProcess, json!("with_process"));
    snapshot(Persistence::UntilReboot, json!("until_reboot"));
    snapshot(Persistence::Persistent, json!("persistent"));
    snapshot(
        Persistence::Expiring { until },
        json!({"expiring":{"until":"2025-01-01T00:00:00Z"}}),
    );
    snapshot(
        Persistence::Lease { seconds: 60 },
        json!({"lease":{"seconds":60}}),
    );
    snapshot(Undo::EnsureAbsent, json!({"type":"ensure_absent"}));
    snapshot(
        Undo::RestoreIfOurs {
            ours: SettingValue::MultiString(vec!["a".into(), "b".into()]),
            original: SettingValue::Absent,
        },
        json!({"type":"restore_if_ours","ours":{"type":"multi_string","value":["a","b"]},"original":{"type":"absent"}}),
    );
    snapshot(
        SettingValue::String("value".into()),
        json!({"type":"string","value":"value"}),
    );
    snapshot(SettingValue::U32(7), json!({"type":"u32","value":7}));
    snapshot(SettingValue::U64(8), json!({"type":"u64","value":8}));
    snapshot(
        SettingValue::Bytes(vec![1, 2]),
        json!({"type":"bytes","value":[1,2]}),
    );
}

#[test]
fn object_key_format() {
    snapshot(
        ObjectKey::Process {
            exe: "core".into(),
            cmdline_marker: "run/a/1".into(),
        },
        json!({"type":"process","exe":"core","cmdline_marker":"run/a/1"}),
    );
    snapshot(
        ObjectKey::Path {
            path: "run/a/1".into(),
        },
        json!({"type":"path","path":"run/a/1"}),
    );
    snapshot(
        ObjectKey::Interface {
            name: None,
            guid: Some("guid".into()),
        },
        json!({"type":"interface","name":null,"guid":"guid"}),
    );
    snapshot(
        ObjectKey::RoutesVia {
            interface: Some("tun".into()),
        },
        json!({"type":"routes_via","interface":"tun"}),
    );
    snapshot(
        ObjectKey::Rule {
            name: "rule".into(),
            group: None,
        },
        json!({"type":"rule","name":"rule","group":null}),
    );
    snapshot(
        ObjectKey::Registry {
            key: "key".into(),
            value: None,
        },
        json!({"type":"registry","key":"key","value":null}),
    );
    snapshot(
        ObjectKey::Fence {
            container: "container".into(),
            rule: "rule".into(),
            port: 90,
        },
        json!({"type":"fence","container":"container","rule":"rule","port":90}),
    );
    snapshot(
        ObjectKey::ResolvedLink {
            interface: "tun".into(),
        },
        json!({"type":"resolved_link","interface":"tun"}),
    );
    snapshot(
        ObjectKey::PortMapping {
            protocol: "tcp".into(),
            internal_port: 90,
            external_port: None,
            description: "fixture".into(),
        },
        json!({"type":"port_mapping","protocol":"tcp","internal_port":90,"external_port":null,"description":"fixture"}),
    );
    snapshot(
        ObjectKey::Service { name: "svc".into() },
        json!({"type":"service","name":"svc"}),
    );
}

#[test]
fn observation_and_credential_format() {
    snapshot(
        Credential::WinAdapter {
            luid: 1,
            device_instance_id: "dev".into(),
        },
        json!({"type":"win_adapter","luid":1,"device_instance_id":"dev"}),
    );
    snapshot(
        Credential::UnixInterface {
            index: 2,
            boot: BootId("boot".into()),
        },
        json!({"type":"unix_interface","index":2,"boot":"boot"}),
    );
    snapshot(
        Credential::File {
            file_id: 3,
            device: 4,
        },
        json!({"type":"file","file_id":3,"device":4}),
    );
    snapshot(
        Credential::Process {
            pid: 5,
            start_token: "start".into(),
        },
        json!({"type":"process","pid":5,"start_token":"start"}),
    );
    snapshot(
        Credential::ExclusiveContainer {
            container: "container".into(),
        },
        json!({"type":"exclusive_container","container":"container"}),
    );
    snapshot(
        Credential::Opaque {
            value: "identity".into(),
        },
        json!({"type":"opaque","value":"identity"}),
    );
    snapshot(
        Observation {
            credential: Some(Credential::Process {
                pid: 5,
                start_token: "start".into(),
            }),
            key: Some(ObjectKey::Path {
                path: "run/a/1".into(),
            }),
            observed_at: "2025-01-01T00:00:00Z".parse().unwrap(),
            detail: None,
        },
        json!({
            "credential":{"type":"process","pid":5,"start_token":"start"},
            "key":{"type":"path","path":"run/a/1"},
            "observed_at":"2025-01-01T00:00:00Z","detail":null
        }),
    );
}
