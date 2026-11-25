//! Interface name and Windows adapter GUID.
//!
//! The GUID vectors were computed outside Rust (Python `uuid.uuid5`) from
//! the formula in upstream c97f36b `easytier/src/arch/windows/tun_name.rs`
//! `tun_device_guid`: UUIDv5(NAMESPACE_URL, "https://easytier.rs/wintun/" +
//! lower-case name).
#[path = "plan_fixtures.rs"]
mod fixtures;

use etd_core_api::CoreError;
use etd_core_easytier::plan::{Platform, effects, plan_for};
use etd_sysfx::{EffectKind, ObjectKey, naming};
use fixtures::*;

const VECTORS: &[(&str, &str)] = &[
    ("etd-3f9a1c2e", "5bc25188-8866-52c1-a851-1705f7958f22"),
    ("ETD-3F9A1C2E", "5bc25188-8866-52c1-a851-1705f7958f22"),
    ("etd-00000000", "00a93962-1574-5c80-b744-2aa658173242"),
    ("etd-ffffffff", "d49caf3d-a366-5161-8bf6-632c5a36a88a"),
];

#[test]
fn guid_matches_upstream_vectors() {
    for (name, guid) in VECTORS {
        assert_eq!(naming::wintun_guid(name).to_string(), *guid, "{name}");
        assert_eq!(
            effects::adapter_guid(name),
            format!("{{{}}}", guid.to_ascii_uppercase()),
            "{name}"
        );
    }
}

#[test]
fn interface_name_shape() {
    let name = interface_name();
    assert_eq!(name.len(), 12);
    assert!(name.starts_with("etd-"));
    assert!(
        name[4..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
}

#[test]
fn plan_uses_the_derived_name_and_guid() {
    let name = interface_name();
    let guid = effects::adapter_guid(&name);
    let plan = plan_for(&ctx(basic()), Platform::Windows).unwrap();
    let toml = String::from_utf8(plan.files[0].contents.clone()).unwrap();
    assert!(toml.contains(&format!("dev_name = \"{name}\"")));
    let adapter = plan
        .effects
        .iter()
        .find(|e| e.kind == EffectKind::WinTunAdapter)
        .unwrap();
    assert_eq!(
        adapter.key,
        ObjectKey::Interface {
            name: Some(name.clone()),
            guid: Some(guid.clone()),
        }
    );
    // Every registry value lives under that GUID.
    for effect in plan
        .effects
        .iter()
        .filter(|e| e.kind == EffectKind::WinRegistryValue)
    {
        let ObjectKey::Registry { key, .. } = &effect.key else {
            panic!("registry record without registry key");
        };
        assert!(key.ends_with(&guid), "{key}");
    }
    // Linux uses the same name, macOS none.
    let linux = plan_for(&ctx(basic()), Platform::Linux).unwrap();
    assert!(linux.effects.iter().any(|e| e.kind == EffectKind::LinuxTun
        && e.key
            == ObjectKey::Interface {
                name: Some(name.clone()),
                guid: None
            }));
    let mac = plan_for(&ctx(basic()), Platform::MacOs).unwrap();
    assert!(mac.effects.iter().any(|e| e.kind == EffectKind::MacUtun
        && e.key
            == ObjectKey::Interface {
                name: None,
                guid: None
            }));
}

#[test]
fn only_derived_names_are_planned() {
    for bad in [
        "et_1",
        "etd-3F9A1C2E",
        "etd-3f9a1c2",
        "etd-3f9a1c2e0",
        "wintun",
        "",
    ] {
        let mut ctx = ctx(basic());
        ctx.inputs.interface_name = bad.into();
        assert!(
            matches!(
                plan_for(&ctx, Platform::Windows),
                Err(CoreError::InvalidSpec(_))
            ),
            "{bad:?}"
        );
    }
}
