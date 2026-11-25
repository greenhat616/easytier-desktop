//! Windows adapters: wintun adapter, 8 interface + 2 program firewall rules, Tcpip/Tcpip6/NetBT registry values, NRPT Magic DNS restore, WFP fence and dropped-privilege probe, LUID-based enumeration, boot id. Owned by O1.
//! Note: refer to the `windows` crate as `::windows` inside this crate.

pub(crate) fn adapters(_config: &crate::OsConfig) -> Result<crate::OsAdapters, crate::OsError> {
    Err(crate::OsError::Unsupported(
        "Windows adapters not implemented".into(),
    ))
}
