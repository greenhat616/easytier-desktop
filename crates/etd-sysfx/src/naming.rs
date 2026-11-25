//! Frozen name derivation (F0 signatures; body reviewed by R1). The host
//! derives the interface name and passes it to `CoreDriver::plan_launch`
//! through `LaunchContext::interface_name`; E1, R1 and O1 all use these two
//! functions instead of re-deriving.
use crate::InstallKey;
use etd_contract::InstanceId;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

/// Prefix of every interface name the product derives.
pub const INTERFACE_PREFIX: &str = "etd-";

/// `etd-` + the first 8 lower-case hex digits of
/// HMAC-SHA256(install key, instance id). Only someone holding the install
/// key can predict it, so a prefix match alone never proves ownership.
pub fn interface_name(key: &InstallKey, instance: &InstanceId) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(&key.0).expect("HMAC accepts any key length");
    mac.update(instance.as_str().as_bytes());
    let digest = mac.finalize().into_bytes();
    let mut name = String::from(INTERFACE_PREFIX);
    for byte in &digest[..4] {
        name.push_str(&format!("{byte:02x}"));
    }
    name
}

/// Windows adapter GUID upstream derives for a wintun name:
/// UUIDv5(NAMESPACE_URL, "https://easytier.rs/wintun/" + lower-case name)
/// (EasyTier c97f36b `easytier/src/arch/windows/tun_name.rs`).
pub fn wintun_guid(name: &str) -> uuid::Uuid {
    uuid::Uuid::new_v5(
        &uuid::Uuid::NAMESPACE_URL,
        format!("https://easytier.rs/wintun/{}", name.to_lowercase()).as_bytes(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_name_shape() {
        let name = interface_name(&InstallKey([7; 32]), &InstanceId::from("3f9a1c2e"));
        assert_eq!(name.len(), 12);
        assert!(name.starts_with(INTERFACE_PREFIX));
        assert!(
            name[4..]
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
        assert_ne!(
            name,
            interface_name(&InstallKey([8; 32]), &InstanceId::from("3f9a1c2e"))
        );
    }

    #[test]
    fn wintun_guid_ignores_case() {
        assert_eq!(wintun_guid("ETD-3F9A1C2E"), wintun_guid("etd-3f9a1c2e"));
        assert_eq!(wintun_guid("etd-3f9a1c2e").get_version_num(), 5);
    }
}
