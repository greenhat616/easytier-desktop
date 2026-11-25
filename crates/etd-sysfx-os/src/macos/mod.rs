//! macOS adapters: utun enumeration (name read back), PF anchor fence, kern.bootsessionuuid; never writes /etc/resolver. Owned by O3.
//! Note: refer to the `windows` crate as `::windows` inside this crate.

pub(crate) fn adapters(_config: &crate::OsConfig) -> Result<crate::OsAdapters, crate::OsError> {
    Err(crate::OsError::Unsupported(
        "macOS adapters not implemented".into(),
    ))
}
