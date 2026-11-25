//! Linux adapters: netlink interfaces and routes, uid-matched fence in the product nftables table, systemd-resolved restore over D-Bus, /proc/sys/kernel/random/boot_id, marker sweep. Owned by O2.
//! Note: refer to the `windows` crate as `::windows` inside this crate.

pub(crate) fn adapters(_config: &crate::OsConfig) -> Result<crate::OsAdapters, crate::OsError> {
    Err(crate::OsError::Unsupported(
        "Linux adapters not implemented".into(),
    ))
}
