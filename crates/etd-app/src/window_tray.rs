//! Window and tray state table (shown / hidden-to-tray / no tray), driven by
//! [`crate::TrayBackend`] events; converges under reordered events. Owned
//! by A1.
