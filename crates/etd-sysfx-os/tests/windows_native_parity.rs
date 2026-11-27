#![cfg(all(windows, feature = "ci-test-fixtures"))]
//! The ES2N parity gate (doc#17 #parity): every native operation against
//! the retired PowerShell worker (`windows_reference.ps1`), on real system
//! state and on fixtures, with the declared differences only. Elevated,
//! disposable Windows CI runners only; the gate workflow also runs it under
//! HKCU COM plants and Process Monitor.
use etd_sysfx_os::windows::native_rows;
use etd_testkit::no_window::NoWindow;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    process::Command,
};

const POWERSHELL: &str = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";

/// The reference worker's answer to `request`: its rows, or its error.
fn reference(request: &Value) -> Result<Vec<Value>, String> {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), r"\tests\windows_reference.ps1");
    let output = Command::new(POWERSHELL)
        .no_window()
        .env("ETD_OS_REQUEST", request.to_string())
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            script,
        ])
        .output()
        .unwrap();
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }
    let v: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "reference output: {e}: {}",
            String::from_utf8_lossy(&output.stdout)
        )
    });
    Ok(v["result"].as_array().cloned().unwrap_or_default())
}

fn native(request: &Value) -> Result<Vec<Value>, String> {
    native_rows(request).map_err(|e| e.to_string())
}

fn both(request: Value) -> (Vec<Value>, Vec<Value>) {
    let old = reference(&request).unwrap_or_else(|e| panic!("reference {request}: {e}"));
    let new = native(&request).unwrap_or_else(|e| panic!("native {request}: {e}"));
    (old, new)
}

fn ps(script: &str) -> String {
    let output = Command::new(POWERSHELL)
        .no_window()
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{script}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().into()
}

/// A driver image path as one canonical full path: `\??\` dropped,
/// `\SystemRoot\` and a leading `System32\` resolved against the Windows
/// directory, lowercase.
fn driver_path(path: &str) -> String {
    let windows = std::env::var("SystemRoot")
        .expect("SystemRoot")
        .trim_end_matches('\\')
        .to_lowercase();
    let p = path.trim().to_lowercase();
    let p = p.strip_prefix(r"\??\").unwrap_or(&p);
    if let Some(rest) = p.strip_prefix(r"\systemroot\") {
        format!(r"{windows}\{rest}")
    } else if p.starts_with(r"system32\") {
        format!(r"{windows}\{p}")
    } else {
        p.to_owned()
    }
}

/// A string field, with null and "" the same.
fn text(v: &Value, key: &str) -> String {
    v[key].as_str().unwrap_or("").to_owned()
}

fn by<'a>(rows: &'a [Value], key: &str) -> BTreeMap<String, &'a Value> {
    rows.iter().map(|r| (text(r, key), r)).collect()
}

/// A `k=v;k=v` description as a sorted list: the worker's culture-aware
/// name order is a declared difference.
fn items(description: &str) -> Vec<String> {
    let mut v: Vec<String> = description.split(';').map(str::to_lowercase).collect();
    v.sort();
    v
}

fn report(what: &str, missing: &[String]) {
    assert!(
        missing.is_empty(),
        "{what}: {} differences:\n{}",
        missing.len(),
        missing.join("\n")
    );
}

struct Cleanup(Vec<String>);
impl Drop for Cleanup {
    fn drop(&mut self) {
        for script in &self.0 {
            let _ = Command::new(POWERSHELL)
                .no_window()
                .args(["-NoProfile", "-NonInteractive", "-Command", script])
                .output();
        }
    }
}

#[test]
#[ignore = "elevated disposable Windows CI runner only"]
fn firewall_rows_match() {
    let tag = uuid();
    let ids = [
        format!("etd-parity-{tag}-a'q\\b\"c"),
        format!("etd-parity-{tag}-b"),
    ];
    let program = format!(r"C:\etd-parity-{tag}\core.exe");
    let name = format!("EasyTier {program} (Inbound)");
    let _cleanup = Cleanup(vec![format!(
        "Remove-NetFirewallRule -Name '{}','{}' -ErrorAction SilentlyContinue",
        ids[0].replace('\'', "''"),
        ids[1]
    )]);
    for id in &ids {
        ps(&format!(
            "New-NetFirewallRule -Name '{}' -DisplayName '{}' -Group 'etd-parity' -Direction Inbound -Program '{program}' -Action Allow | Out-Null",
            id.replace('\'', "''"),
            name
        ));
    }
    let (old, new) = both(json!({"op":"firewall"}));
    let (old, new) = (by(&old, "id"), by(&new, "id"));
    let mut diff = Vec::new();
    for id in old
        .keys()
        .collect::<BTreeSet<_>>()
        .symmetric_difference(&new.keys().collect())
    {
        diff.push(format!("only one side has rule {id}"));
    }
    for (id, o) in &old {
        let Some(n) = new.get(id) else { continue };
        for key in ["group", "program", "direction", "description"] {
            if text(o, key) != text(n, key) {
                diff.push(format!("{id} {key}: {} vs {}", o[key], n[key]));
            }
        }
        // Declared: indirect names (`@dll,-id`, `@{package?ms-resource}`)
        // stay unresolved; foreign rules only.
        if text(o, "name") != text(n, "name") && !text(n, "name").starts_with('@') {
            diff.push(format!("{id} name: {} vs {}", o["name"], n["name"]));
        }
    }
    report("firewall", &diff);
    for id in &ids {
        assert_eq!(text(new[id.as_str()], "program"), program);
    }
    // The name filter.
    let (old, new) = both(json!({"op":"firewall","name":name.to_uppercase()}));
    assert_eq!(old.len(), 2);
    assert_eq!(new.len(), 2);
}

#[test]
#[ignore = "elevated disposable Windows CI runner only"]
fn firewall_deletion_is_by_id_and_verified() {
    let tag = uuid();
    let a = format!("etd-parity-{tag}-a'q\\b\"c");
    let b = format!("etd-parity-{tag}-b");
    let program = format!(r"C:\etd-parity-{tag}\core.exe");
    let name = format!("EasyTier {program} (Inbound)");
    let quoted = |id: &str| id.replace('\'', "''");
    let _cleanup = Cleanup(vec![format!(
        "Remove-NetFirewallRule -Name '{}','{b}' -ErrorAction SilentlyContinue",
        quoted(&a)
    )]);
    for id in [&a, &b] {
        ps(&format!(
            "New-NetFirewallRule -Name '{}' -DisplayName '{name}' -Group 'etd-parity' -Direction Inbound -Program '{program}' -Action Allow | Out-Null",
            quoted(id)
        ));
    }
    let count = |id: &str, store: &str| -> usize {
        ps(&format!(
            "@(Get-NetFirewallRule -PolicyStore {store} -Name '{}' -ErrorAction SilentlyContinue).Count",
            quoted(id)
        ))
        .parse()
        .unwrap()
    };
    let request = |id: &str, program: &str, direction: &str| json!({"op":"delete_firewall","id":id,"name":name.to_lowercase(),"group":"etd-parity","program":program.to_lowercase(),"direction":direction});
    // Every credential mismatch errors in both, and nothing is deleted.
    for bad in [
        request(&a, r"C:\elsewhere\core.exe", "inbound"),
        request(&a, &program, "outbound"),
        json!({"op":"delete_firewall","id":a,"name":"other","group":"etd-parity"}),
        json!({"op":"delete_firewall","id":a,"name":name,"group":"other"}),
        json!({"op":"delete_firewall","id":format!("{a}-absent"),"name":name}),
    ] {
        assert!(reference(&bad).is_err(), "reference accepted {bad}");
        assert!(native(&bad).is_err(), "native accepted {bad}");
    }
    assert_eq!(
        (count(&a, "PersistentStore"), count(&b, "PersistentStore")),
        (1, 1)
    );
    // The same-name sibling survives; the id is gone from every view.
    assert_eq!(
        native(&request(&a, &program, "inbound")).unwrap(),
        [json!("removed")]
    );
    assert_eq!(count(&a, "PersistentStore"), 0);
    assert_eq!(count(&a, "ActiveStore"), 0);
    assert_eq!(
        (count(&b, "PersistentStore"), count(&b, "ActiveStore")),
        (1, 1)
    );
    // Deleting it again is an error, never "removed".
    assert!(native(&request(&a, &program, "inbound")).is_err());
    // The reference deletes the sibling the same way.
    assert_eq!(
        reference(&request(&b, &program, "inbound")).unwrap(),
        [json!("removed")]
    );
    assert_eq!(count(&b, "PersistentStore"), 0);
}

/// opus msg#2113 minor-1: a foreign rule using a feature newer than 2.27 (a
/// dynamic keyword address) stops neither the listing nor the deletion of
/// ours. Records whether 2.27 reads it fully (listed) or not (skipped) in
/// the gate's artifacts.
#[test]
#[ignore = "elevated disposable Windows CI runner only"]
fn a_foreign_rule_with_a_newer_feature_does_not_stop_cleanup() {
    let tag = uuid();
    let keyword = format!("{{{}}}", uuid());
    let foreign = format!("etd-parity-{tag}-keyword");
    let ours = format!("etd-parity-{tag}-ours");
    let name = format!("EasyTier etd-parity-{tag} - TCP Protocol (Inbound)");
    let _cleanup = Cleanup(vec![
        format!("Remove-NetFirewallRule -Name '{foreign}','{ours}' -ErrorAction SilentlyContinue"),
        format!(
            "Remove-NetFirewallDynamicKeywordAddress -Id '{keyword}' -ErrorAction SilentlyContinue"
        ),
    ]);
    ps(&format!(
        "New-NetFirewallDynamicKeywordAddress -Id '{keyword}' -Keyword 'etd-parity-{tag}' -Addresses '192.0.2.1' | Out-Null"
    ));
    ps(&format!(
        "New-NetFirewallRule -Name '{foreign}' -DisplayName '{foreign}' -Direction Outbound -Action Block -RemoteDynamicKeywordAddresses '{keyword}' | Out-Null"
    ));
    ps(&format!(
        "New-NetFirewallRule -Name '{ours}' -DisplayName '{name}' -Group 'EasyTier' -Direction Inbound -Protocol TCP -Action Allow | Out-Null"
    ));
    let rows = native(&json!({"op":"firewall"})).unwrap();
    let seen = if rows.iter().any(|r| text(r, "id") == foreign) {
        "read fully at 2.27 (status OK): listed"
    } else {
        "not read fully at 2.27: skipped with a warning"
    };
    let note = format!("a foreign rule with a dynamic keyword address is {seen}\n");
    eprint!("{note}");
    if let Some(out) = std::env::var_os("PM_OUT") {
        let _ = std::fs::write(
            std::path::Path::new(&out).join("firewall-newer-feature.txt"),
            note,
        );
    }
    assert!(rows.iter().any(|r| text(r, "id") == ours));
    assert_eq!(
        native(&json!({"op":"delete_firewall","id":ours,"name":name,"group":"EasyTier"})).unwrap(),
        [json!("removed")]
    );
}

const FIXTURE: &str = r"SOFTWARE\etd-parity";

#[test]
#[ignore = "elevated disposable Windows CI runner only"]
fn registry_values_and_restores_match() {
    let key = format!(r"{FIXTURE}\{}", uuid());
    let path = format!(r"HKLM:\{key}");
    let _cleanup = Cleanup(vec![format!(
        "Remove-Item '{path}' -Recurse -Force -ErrorAction SilentlyContinue"
    )]);
    ps(&format!(
        "$k = New-Item '{path}' -Force; \
         Set-ItemProperty '{path}' sz 'a' -Type String; \
         Set-ItemProperty '{path}' nul ([string][char]0 + 'x') -Type String; \
         Set-ItemProperty '{path}' expand '%SystemRoot%\\x;%USERPROFILE%' -Type ExpandString; \
         Set-ItemProperty '{path}' multi ([string[]]@('a','','b')) -Type MultiString; \
         Set-ItemProperty '{path}' dword 4294967295 -Type DWord; \
         Set-ItemProperty '{path}' qword 18446744073709551615 -Type QWord; \
         Set-ItemProperty '{path}' binary ([byte[]]@(1,255)) -Type Binary"
    ));
    let hklm = format!(r"HKLM\{key}");
    for value in [
        "sz", "nul", "expand", "multi", "dword", "qword", "binary", "absent",
    ] {
        let request = json!({"op":"registry","key":hklm,"value":value});
        match (reference(&request), native(&request)) {
            (Ok(o), Ok(n)) => assert_eq!(o, n, "{value}"),
            (Err(_), Err(_)) => {}
            (o, n) => panic!("{value}: {o:?} vs {n:?}"),
        }
    }
    let request = json!({"op":"registry","key":r"HKCU\Software","value":"x"});
    assert!(reference(&request).is_err() && native(&request).is_err());
    // restore_registry: absent / modified / restored, both ways.
    let restore = |ours: Value, original: Value| json!({"op":"restore_registry","key":hklm,"value":"dword","ours":ours,"original":original});
    let u32v = |n: u32| json!({"type":"u32","value":n});
    for run in [reference, native] {
        ps(&format!("Set-ItemProperty '{path}' dword 7 -Type DWord"));
        assert_eq!(run(&restore(u32v(1), u32v(7))).unwrap(), [json!("absent")]);
        assert_eq!(
            run(&restore(u32v(1), u32v(2))).unwrap(),
            [json!("modified")]
        );
        assert_eq!(
            run(&restore(u32v(7), u32v(2))).unwrap(),
            [json!("restored")]
        );
        assert_eq!(ps(&format!("(Get-ItemProperty '{path}').dword")), "2");
        assert_eq!(
            run(&restore(u32v(2), json!({"type":"absent"}))).unwrap(),
            [json!("restored")]
        );
        assert_eq!(
            ps(&format!(
                "@((Get-Item '{path}').GetValueNames() | Where-Object {{ $_ -eq 'dword' }}).Count"
            )),
            "0"
        );
    }
    // The expansion uses the machine's values only, never the process's.
    // SAFETY: this test's own process; no other thread reads it.
    unsafe { std::env::set_var("SystemRoot", r"C:\attacker") };
    let rows = native(&json!({"op":"registry_rows","sweep":false})).unwrap();
    assert!(
        !rows
            .iter()
            .any(|r| text(r, "description").contains("attacker"))
    );
}

#[test]
#[ignore = "elevated disposable Windows CI runner only"]
fn nrpt_profile_and_interface_rows_match() {
    let tag = uuid().to_uppercase();
    let nrpt = format!(
        r"HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig\{{{tag}}}"
    );
    let profile = format!(
        r"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{{{tag}}}"
    );
    let _cleanup = Cleanup(vec![
        format!("Remove-Item '{nrpt}' -Recurse -Force -ErrorAction SilentlyContinue"),
        format!("Remove-Item '{profile}' -Recurse -Force -ErrorAction SilentlyContinue"),
    ]);
    ps(&format!(
        "New-Item '{nrpt}' -Force | Out-Null; Set-ItemProperty '{nrpt}' Comment 'etd-parity'; Set-ItemProperty '{nrpt}' Zeta 1 -Type DWord; Set-ItemProperty '{nrpt}' alpha ([string[]]@('x','y')) -Type MultiString; \
         New-Item '{profile}' -Force | Out-Null; Set-ItemProperty '{profile}' ProfileName 'etd-parity'"
    ));
    for op in ["nrpt", "profiles"] {
        let (old, new) = both(json!({"op":op}));
        let (old, new) = (by(&old, "id"), by(&new, "id"));
        let mut diff = Vec::new();
        assert_eq!(
            old.keys().collect::<Vec<_>>(),
            new.keys().collect::<Vec<_>>(),
            "{op} ids"
        );
        for (id, o) in &old {
            let n = new[id];
            for key in ["name", "group"] {
                if text(o, key) != text(n, key) {
                    diff.push(format!("{op} {id} {key}: {} vs {}", o[key], n[key]));
                }
            }
            if items(&text(o, "description")) != items(&text(n, "description")) {
                diff.push(format!(
                    "{op} {id}: {} vs {}",
                    o["description"], n["description"]
                ));
            }
        }
        report(op, &diff);
    }
    let (old, new) = both(json!({"op":"registry_rows"}));
    let set = |rows: &[Value]| -> BTreeSet<String> { rows.iter().map(Value::to_string).collect() };
    let (old, new) = (set(&old), set(&new));
    let diff: Vec<String> = old.symmetric_difference(&new).cloned().collect();
    report("registry_rows", &diff);
    let (old, new) = both(json!({"op":"magic"}));
    assert_eq!(old, new);
}

#[test]
#[ignore = "elevated disposable Windows CI runner only"]
fn nrpt_and_profile_deletion_match() {
    for run in [reference, native] {
        let tag = uuid().to_uppercase();
        let guid = format!("{{{tag}}}");
        let nrpt = format!(
            r"HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig\{guid}"
        );
        let profile = format!(
            r"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{guid}"
        );
        let signatures =
            r"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged";
        let mine = format!(r"{signatures}\etd-parity-{tag}-mine");
        let other = format!(r"{signatures}\etd-parity-{tag}-other");
        let _cleanup = Cleanup(
            [&nrpt, &profile, &mine, &other]
                .iter()
                .map(|p| format!("Remove-Item '{p}' -Recurse -Force -ErrorAction SilentlyContinue"))
                .collect(),
        );
        ps(&format!(
            "New-Item '{nrpt}' -Force | Out-Null; Set-ItemProperty '{nrpt}' Comment 'etd-parity'; \
             New-Item '{profile}' -Force | Out-Null; Set-ItemProperty '{profile}' ProfileName 'etd-parity'; \
             New-Item '{mine}' -Force | Out-Null; Set-ItemProperty '{mine}' ProfileGuid '{}'; \
             New-Item '{other}' -Force | Out-Null; Set-ItemProperty '{other}' ProfileGuid '{{{}}}'",
            guid.to_lowercase(),
            uuid()
        ));
        let exists = |p: &str| ps(&format!("Test-Path '{p}'")) == "True";
        assert!(run(&json!({"op":"delete_nrpt","id":guid,"name":guid,"group":"other"})).is_err());
        assert!(run(&json!({"op":"delete_nrpt","id":guid,"name":"x"})).is_err());
        assert!(exists(&nrpt));
        assert_eq!(
            run(&json!({"op":"delete_nrpt","id":guid,"name":guid,"group":"ETD-PARITY"})).unwrap(),
            [json!("removed")]
        );
        assert!(!exists(&nrpt));
        assert_eq!(
            run(&json!({"op":"delete_nrpt","id":guid,"name":guid})).unwrap(),
            [json!("absent")]
        );
        assert!(run(&json!({"op":"delete_profile","id":guid,"name":"other"})).is_err());
        assert!(run(&json!({"op":"delete_profile","id":tag,"name":"etd-parity"})).is_err());
        assert!(exists(&profile) && exists(&mine));
        assert_eq!(
            run(&json!({"op":"delete_profile","id":guid,"name":"ETD-parity"})).unwrap(),
            [json!("removed")]
        );
        assert!(!exists(&profile) && !exists(&mine) && exists(&other));
        assert_eq!(
            run(&json!({"op":"delete_profile","id":guid,"name":"etd-parity"})).unwrap(),
            [json!("absent")]
        );
    }
}

#[test]
#[ignore = "elevated disposable Windows CI runner only"]
fn network_rows_match() {
    // Listeners of this process that stay open across both queries.
    let v4 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let v6 = std::net::TcpListener::bind("[::]:0").unwrap();
    let pid = std::process::id();
    let set = |rows: &[Value]| -> BTreeSet<String> { rows.iter().map(Value::to_string).collect() };
    for op in ["ip_addresses", "routes"] {
        let (old, new) = both(json!({"op":op}));
        let diff: Vec<String> = set(&old)
            .symmetric_difference(&set(&new))
            .cloned()
            .collect();
        report(op, &diff);
    }
    let (old, new) = both(json!({"op":"listeners"}));
    for rows in [&old, &new] {
        for port in [
            v4.local_addr().unwrap().port(),
            v6.local_addr().unwrap().port(),
        ] {
            assert!(
                rows.iter().any(|r| r["port"] == port && r["pid"] == pid),
                "listener {port} missing: {rows:?}"
            );
        }
    }
    // Other processes' sockets can come and go between the two queries.
    // Declared: Get-NetTCPConnection hides the System process's (pid 4)
    // IPv4 wildcard listeners (SMB, HTTP.sys); the native table has them.
    let new: Vec<Value> = new
        .into_iter()
        .filter(|r| !(r["pid"] == 4 && r["address"] == "0.0.0.0"))
        .collect();
    let (old, new) = (set(&old), set(&new));
    let common = old.intersection(&new).count();
    assert!(
        common * 10 >= old.len().max(new.len()) * 9,
        "{old:?}\nvs\n{new:?}"
    );
}

#[test]
#[ignore = "elevated disposable Windows CI runner only"]
fn service_driver_and_process_rows_match() {
    for op in ["services", "drivers"] {
        let (old, new) = both(json!({"op":op}));
        let (old, new) = (by(&old, "name"), by(&new, "name"));
        assert_eq!(
            old.keys().collect::<Vec<_>>(),
            new.keys().collect::<Vec<_>>(),
            "{op} names"
        );
        let mut diff = Vec::new();
        for (name, o) in &old {
            let (o, n) = (text(o, "description"), text(new[name], "description"));
            let (o, n): (Vec<&str>, Vec<&str>) = (o.split('|').collect(), n.split('|').collect());
            // Declared: WMI expands driver paths (\SystemRoot\..., System32\...,
            // \??\); both sides are compared as full paths after the same
            // expansion (opus msg#2113 nit-2).
            let path_same = if op == "drivers" {
                driver_path(o[0]) == driver_path(n[0])
            } else {
                o[0] == n[0]
            };
            if !path_same || o[1..] != n[1..] {
                diff.push(format!("{op} {name}: {o:?} vs {n:?}"));
            }
        }
        // A service can change state between the two queries.
        assert!(diff.len() <= 3, "{op}: {}", diff.join("\n"));
    }
    let (old, new) = both(json!({"op":"processes"}));
    let key = |r: &&Value| (r["pid"].as_u64().unwrap(), text(r, "name").to_lowercase());
    let old: BTreeMap<_, _> = old.iter().map(|r| (key(&r), r)).collect();
    let mut diff = Vec::new();
    let mut common = 0;
    for n in &new {
        let Some(o) = old.get(&key(&n)) else { continue };
        common += 1;
        if text(o, "start") != text(n, "start") && !text(o, "start").is_empty() {
            diff.push(format!("start {n}: {}", o["start"]));
        }
        if !o["path"].is_null()
            && !n["path"].is_null()
            && !text(o, "path").eq_ignore_ascii_case(&text(n, "path"))
        {
            diff.push(format!("path {n}: {}", o["path"]));
        }
    }
    assert!(common * 10 >= old.len() * 9, "{common} of {}", old.len());
    report("processes", &diff);
}

#[test]
#[ignore = "elevated disposable Windows CI runner only"]
fn unknown_requests_fail_in_both() {
    for request in [
        json!({"op":"nonsense"}),
        json!({"op":"delete_profile","id":"x","name":"y"}),
    ] {
        assert!(reference(&request).is_err());
        assert!(native(&request).is_err());
    }
    assert_eq!(
        etd_sysfx_os::windows::firewall_cleanup_supported().unwrap(),
        "listed"
    );
}

fn uuid() -> String {
    uuid::Uuid::new_v4().hyphenated().to_string()
}

/// The native operations alone, under the gate's HKCU COM plants (which
/// break the PowerShell reference, so it is not run here). The workflow
/// made the rule `ETD_GATE_RULE` (display name `ETD_GATE_NAME`, program
/// `ETD_GATE_PROGRAM`, inbound) before planting.
#[test]
#[ignore = "elevated disposable Windows CI runner, gate step only"]
fn native_under_plants() {
    let id = std::env::var("ETD_GATE_RULE").expect("ETD_GATE_RULE");
    let name = std::env::var("ETD_GATE_NAME").expect("ETD_GATE_NAME");
    let program = std::env::var("ETD_GATE_PROGRAM").expect("ETD_GATE_PROGRAM");
    for op in [
        "nrpt",
        "profiles",
        "registry_rows",
        "magic",
        "ip_addresses",
        "routes",
        "listeners",
        "services",
        "drivers",
        "processes",
    ] {
        native(&json!({"op":op})).unwrap_or_else(|e| panic!("{op}: {e}"));
    }
    let present = || {
        native(&json!({"op":"firewall","name":name}))
            .unwrap()
            .iter()
            .any(|r| r["id"] == id.as_str())
    };
    assert!(present());
    let delete = |program: &str| {
        native(
            &json!({"op":"delete_firewall","id":id,"name":name,"program":program,"direction":"inbound"}),
        )
    };
    // Failure paths: a changed credential, then (after the deletion) an
    // absent rule.
    assert!(delete(r"C:\elsewhere.exe").is_err());
    assert!(present());
    assert_eq!(delete(&program).unwrap(), [json!("removed")]);
    assert!(!present());
    assert!(delete(&program).is_err());
    let request = json!({"op":"registry","key":r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion","value":"CurrentBuildNumber"});
    assert_eq!(native(&request).unwrap()[0]["type"], "string");
}
