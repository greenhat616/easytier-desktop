//! Reclaimers for the host's own records, which need the process engine and
//! so cannot live in etd-sysfx-os: `EffectKind::Process` (verified kill via
//! `ProcessEngine::kill_verified`, never by pid alone; `Uncertain` is never
//! absent) and `EffectKind::RuntimeDir` (exclusive container under the run
//! directory). Owned by H1.
