//! Linux parent-death signal, armed from a dedicated long-lived thread.
//! Owned by P1.

/// Spawn a dedicated OS thread running the single-thread runtime which
/// owns the child for its entire lifetime. On Linux the parent-death signal
/// applies to the specific thread that forks, not just the host process.
pub(crate) fn worker<F>(work: F) -> std::io::Result<()>
where
    F: FnOnce() + Send + 'static,
{
    std::thread::Builder::new()
        .name("etd-process".into())
        .spawn(work)?;
    Ok(())
}
