//! Every contract method carries `(etd.v1.required_role)`, and the table
//! matches the architecture's read / control / admin split.
use etd_contract::{REQUIRED_ROLE_OPTION, Role, SERVICE_NAME, method_roles, required_role};

const EXPECTED: &[(&str, Role)] = &[
    ("Handshake", Role::Viewer),
    ("Snapshot", Role::Viewer),
    ("Subscribe", Role::Viewer),
    ("Apply", Role::Control),
    ("SetDesired", Role::Control),
    ("RemoveInstance", Role::Control),
    ("GetReceipt", Role::Viewer),
    ("Query", Role::Viewer),
    ("StreamLogs", Role::Viewer),
    ("GetReclaimReport", Role::Viewer),
    ("RetryReclaim", Role::Control),
    ("RetryStart", Role::Control),
    ("ResolveCandidates", Role::Admin),
    ("ReleaseLease", Role::Control),
    ("GetAllowList", Role::Admin),
    ("SetAllowList", Role::Admin),
    ("ListCores", Role::Viewer),
    ("SelectCore", Role::Admin),
    ("PurgeAllData", Role::Admin),
];

#[test]
fn every_method_declares_a_role() {
    let missing: Vec<_> = method_roles()
        .iter()
        .filter(|method| method.role.is_none())
        .map(|method| method.path.as_str())
        .collect();
    assert!(
        missing.is_empty(),
        "methods without required_role: {missing:?}"
    );
}

#[test]
fn role_table_matches_architecture() {
    let table = method_roles();
    assert_eq!(
        table.len(),
        EXPECTED.len(),
        "method set changed: {table:#?}"
    );
    for (method, role) in EXPECTED {
        let path = format!("/{SERVICE_NAME}/{method}");
        assert_eq!(required_role(&path), Some(*role), "{path}");
    }
}

#[test]
fn unknown_method_has_no_role() {
    assert_eq!(required_role("/etd.v1.HostService/Nope"), None);
    assert_eq!(required_role("Apply"), None);
}

#[test]
fn streaming_shape() {
    let streaming: Vec<_> = method_roles()
        .iter()
        .filter(|method| method.server_streaming)
        .map(|method| method.path.rsplit('/').next().unwrap())
        .collect();
    assert_eq!(streaming, ["Subscribe", "StreamLogs"]);
    assert!(method_roles().iter().all(|method| !method.client_streaming));
}

#[test]
fn option_number_is_stable() {
    assert_eq!(REQUIRED_ROLE_OPTION, 50000);
}
