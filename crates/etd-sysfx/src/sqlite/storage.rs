//! SQLite persistence and migrations. A worker owns the sole connection.
use super::{codec::*, state::LedgerState};
use crate::*;
use etd_contract::{Desired, InstanceId, RequestId};
use rusqlite::{Connection, Error, ErrorCode, Transaction, params};
use serde::{Serialize, de::DeserializeOwned};
use std::path::Path;

pub(super) const VERSION: u32 = 1;
const BASELINE: &str = include_str!("../../migrations/000_baseline.sql");
const SETTINGS: &str = include_str!("../../migrations/001_settings.sql");

pub(super) fn storage_error(error: Error) -> LedgerError {
    match error.sqlite_error_code() {
        Some(ErrorCode::DiskFull) => LedgerError::Unavailable(StorageFault::DiskFull),
        Some(ErrorCode::ReadOnly) | Some(ErrorCode::PermissionDenied) => {
            LedgerError::Unavailable(StorageFault::ReadOnly)
        }
        Some(ErrorCode::DatabaseBusy) | Some(ErrorCode::DatabaseLocked) => {
            LedgerError::Unavailable(StorageFault::Locked)
        }
        Some(ErrorCode::DatabaseCorrupt) | Some(ErrorCode::NotADatabase) => {
            LedgerError::Unavailable(StorageFault::Corrupt("SQLite database is corrupt".into()))
        }
        Some(ErrorCode::SystemIoFailure) | Some(ErrorCode::CannotOpen) => {
            LedgerError::Unavailable(StorageFault::Io("SQLite I/O failure".into()))
        }
        _ => match error {
            Error::QueryReturnedNoRows
            | Error::InvalidColumnType(..)
            | Error::FromSqlConversionFailure(..) => {
                LedgerError::Unreadable("unsupported or unreadable SQLite record".into())
            }
            _ => LedgerError::Unavailable(StorageFault::Io("SQLite operation failed".into())),
        },
    }
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, LedgerError> {
    serde_json::to_vec(value).map_err(|_| {
        LedgerError::Unavailable(StorageFault::Io("could not encode ledger row".into()))
    })
}
fn decode<T: DeserializeOwned>(data: &[u8]) -> Result<T, LedgerError> {
    serde_json::from_slice(data)
        .map_err(|_| LedgerError::Unreadable("could not decode ledger row".into()))
}
fn number(s: String) -> Result<u64, LedgerError> {
    s.parse()
        .map_err(|_| LedgerError::Unreadable("invalid counter".into()))
}
fn unreadable() -> LedgerError {
    LedgerError::Unreadable("inconsistent ledger rows".into())
}

pub(super) fn open(
    path: &Path,
    options: &super::OpenOptions,
) -> Result<(Connection, LedgerState), LedgerError> {
    use rusqlite::OpenFlags;
    let flags = if options.read_only {
        OpenFlags::SQLITE_OPEN_READ_ONLY
    } else {
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
    };
    let mut conn = Connection::open_with_flags(path, flags).map_err(storage_error)?;
    conn.busy_timeout(std::time::Duration::from_secs(2))
        .map_err(storage_error)?;
    let version: u32 = conn
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .map_err(storage_error)?;
    if version > VERSION {
        return Err(LedgerError::SchemaTooNew {
            found: version,
            supported: VERSION,
        });
    }
    let empty = validate_schema(&conn, version)?;
    // Interpret all existing data before configuring WAL or migrating. If
    // anything is unknown, leave the database untouched for diagnose-only.
    if !empty {
        let _ = load(&conn, version)?;
    }
    if options.read_only {
        if empty || version != VERSION {
            return Err(LedgerError::Unavailable(StorageFault::ReadOnly));
        }
        let state = load(&conn, VERSION)?;
        return Ok((conn, state));
    }
    let mode: String = conn
        .query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))
        .map_err(storage_error)?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(LedgerError::Unavailable(StorageFault::Io(
            "WAL unavailable".into(),
        )));
    }
    conn.pragma_update(None, "synchronous", "FULL")
        .map_err(storage_error)?;
    conn.pragma_update(None, "secure_delete", "ON")
        .map_err(storage_error)?;
    #[cfg(target_os = "macos")]
    conn.pragma_update(None, "fullfsync", true)
        .map_err(storage_error)?;
    if version == 0 {
        let tx = conn.transaction().map_err(storage_error)?;
        if empty {
            tx.execute_batch(BASELINE).map_err(storage_error)?;
        }
        tx.execute_batch(SETTINGS).map_err(storage_error)?;
        tx.commit().map_err(storage_error)?;
    }
    if let Some(max) = options.max_page_count {
        conn.pragma_update(None, "max_page_count", max)
            .map_err(storage_error)?;
    }
    let state = load(&conn, VERSION)?;
    Ok((conn, state))
}

fn validate_schema(conn: &Connection, version: u32) -> Result<bool, LedgerError> {
    let mut stmt = conn
        .prepare(
            "SELECT type, name FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY name",
        )
        .map_err(storage_error)?;
    let objects = stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
        .map_err(storage_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(storage_error)?;
    if version == 0 && objects.is_empty() {
        return Ok(true);
    }
    let expected = [
        ("effects", &["id", "payload"][..]),
        ("generations", &["instance", "epoch", "payload"][..]),
        ("high_water", &["id", "epoch"][..]),
        ("instances", &["id", "payload"][..]),
        ("meta", &["singleton", "revision", "next_effect"][..]),
        ("requests", &["id", "payload"][..]),
        ("settings", &["singleton", "payload"][..]),
        ("removal_pending", &["id"][..]),
    ];
    let mut expected = expected[..if version == 0 { 6 } else { 8 }].to_vec();
    expected.sort_by_key(|(name, _)| *name);
    if objects.len() != expected.len() {
        return Err(unreadable());
    }
    for ((kind, name), (table, columns)) in objects.iter().zip(expected) {
        if kind != "table" || name != table {
            return Err(unreadable());
        }
        let mut stmt = conn
            .prepare(&format!("PRAGMA table_info({table})"))
            .map_err(storage_error)?;
        let actual = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(storage_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage_error)?;
        if actual != *columns {
            return Err(unreadable());
        }
    }
    Ok(false)
}

fn payload_rows(conn: &Connection, table: &str) -> Result<Vec<(String, Vec<u8>)>, LedgerError> {
    // Table names are internal constants, never data.
    let mut stmt = conn
        .prepare(&format!("SELECT id, payload FROM {table}"))
        .map_err(storage_error)?;
    let rows = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .map_err(storage_error)?;
    rows.collect::<Result<_, _>>().map_err(storage_error)
}

fn load(conn: &Connection, version: u32) -> Result<LedgerState, LedgerError> {
    let (revision, next_effect): (String, String) = conn
        .query_row(
            "SELECT revision, next_effect FROM meta WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(storage_error)?;
    let mut state = LedgerState {
        revision: number(revision)?,
        next_effect: number(next_effect)?,
        ..Default::default()
    };
    if version >= 1 {
        let raw: Vec<u8> = conn
            .query_row("SELECT payload FROM settings WHERE singleton=1", [], |r| {
                r.get(0)
            })
            .map_err(storage_error)?;
        state.settings = decode::<Settings>(&raw)?.into();
    }
    for (id, raw) in payload_rows(conn, "instances")? {
        let (row, claims): (Instance, Vec<String>) = decode(&raw)?;
        if id != row.instance_id || Desired::try_from(row.desired).is_err() {
            return Err(unreadable());
        }
        state.instances.insert(InstanceId(id), (row.into(), claims));
    }
    for (id, raw) in payload_rows(conn, "requests")? {
        let request = RequestId(id);
        let pair = decode::<StoredRequest>(&raw)?.into_pair(request.clone())?;
        if pair.1.receipt.request_id != request.0 || pair.1.receipt.revision > state.revision {
            return Err(unreadable());
        }
        state.requests.insert(request, pair);
    }
    {
        let mut stmt = conn
            .prepare("SELECT id, epoch FROM high_water")
            .map_err(storage_error)?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .map_err(storage_error)?;
        for row in rows {
            let (i, e) = row.map_err(storage_error)?;
            state.high_water.insert(InstanceId(i), Epoch(number(e)?));
        }
    }
    {
        let mut stmt = conn
            .prepare("SELECT instance, epoch, payload FROM generations")
            .map_err(storage_error)?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                ))
            })
            .map_err(storage_error)?;
        for row in rows {
            let (i, e, raw) = row.map_err(storage_error)?;
            let id = InstanceId(i);
            let epoch = Epoch(number(e)?);
            if state.high_water.get(&id).is_none_or(|h| epoch > *h) {
                return Err(unreadable());
            }
            state
                .generations
                .insert((id, epoch), decode::<StoredGenerationEntry>(&raw)?.into());
        }
    }
    for (id, raw) in payload_rows(conn, "effects")? {
        if number(id.clone())? > state.next_effect {
            return Err(unreadable());
        }
        let id = EffectId(id);
        let effect = decode::<StoredEffect>(&raw)?.into_effect(id.clone())?;
        if let Some((instance, epoch)) = effect.scope.generation()
            && !state.generations.contains_key(&(instance.clone(), epoch))
        {
            return Err(unreadable());
        }
        state.effects.insert(id, effect);
    }
    for entry in state.generations.values() {
        if entry.shared.iter().any(|id| {
            state
                .effects
                .get(id)
                .is_none_or(|e| e.scope.generation().is_some())
        }) {
            return Err(unreadable());
        }
    }
    if version >= 1 {
        let mut stmt = conn
            .prepare("SELECT id FROM removal_pending")
            .map_err(storage_error)?;
        let ids = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(storage_error)?;
        for id in ids {
            let id = InstanceId(id.map_err(storage_error)?);
            if state
                .instances
                .get(&id)
                .is_none_or(|(i, _)| i.desired() != Desired::Stopped)
                || !state.effects.values().any(|e| {
                    !e.state.is_closed() && e.scope.generation().is_some_and(|(i, _)| i == &id)
                })
            {
                return Err(unreadable());
            }
            state.removal_pending.insert(id);
        }
    }
    Ok(state)
}

// Writes are incremental: rows unrelated to this mutation are not rewritten.
// Every table update, including high-water and ticket, belongs to this tx.
fn upsert_payload(
    tx: &Transaction<'_>,
    table: &str,
    id: &str,
    payload: &[u8],
) -> Result<(), LedgerError> {
    tx.execute(&format!("INSERT INTO {table}(id,payload) VALUES (?1,?2) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload WHERE payload != excluded.payload"), params![id,payload]).map_err(storage_error)?;
    Ok(())
}
fn delete_payload(tx: &Transaction<'_>, table: &str, id: &str) -> Result<(), LedgerError> {
    tx.execute(&format!("DELETE FROM {table} WHERE id=?1"), [id])
        .map_err(storage_error)?;
    Ok(())
}

pub(super) fn persist(
    conn: &mut Connection,
    old: &LedgerState,
    new: &LedgerState,
    observer: &impl Fn(super::CommitStage),
) -> Result<(), LedgerError> {
    use super::CommitStage::*;
    let tx = conn.transaction().map_err(storage_error)?;
    observer(Begin);
    for id in old
        .requests
        .keys()
        .filter(|id| !new.requests.contains_key(*id))
    {
        delete_payload(&tx, "requests", &id.0)?;
    }
    for (id, (request, ticket)) in &new.requests {
        if old.requests.get(id) != Some(&(request.clone(), ticket.clone())) {
            upsert_payload(
                &tx,
                "requests",
                &id.0,
                &encode(&StoredRequest::from_pair(request.clone(), ticket.clone()))?,
            )?;
        }
    }
    observer(Requests);
    for id in old
        .instances
        .keys()
        .filter(|id| !new.instances.contains_key(*id))
    {
        delete_payload(&tx, "instances", &id.0)?;
    }
    for (id, (instance, claims)) in &new.instances {
        if old.instances.get(id) != Some(&(instance.clone(), claims.clone())) {
            upsert_payload(
                &tx,
                "instances",
                &id.0,
                &encode(&(Instance::from(instance.clone()), claims))?,
            )?;
        }
    }
    for id in old.removal_pending.difference(&new.removal_pending) {
        tx.execute("DELETE FROM removal_pending WHERE id=?1", [&id.0])
            .map_err(storage_error)?;
    }
    for id in new.removal_pending.difference(&old.removal_pending) {
        tx.execute("INSERT INTO removal_pending VALUES (?1)", [&id.0])
            .map_err(storage_error)?;
    }
    if old.settings != new.settings {
        tx.execute(
            "UPDATE settings SET payload=?1 WHERE singleton=1",
            [encode(&Settings::from(new.settings.clone()))?],
        )
        .map_err(storage_error)?;
    }
    tx.execute(
        "UPDATE meta SET revision=?1,next_effect=?2 WHERE singleton=1",
        params![new.revision.to_string(), new.next_effect.to_string()],
    )
    .map_err(storage_error)?;
    observer(Desired);
    for (id, epoch) in &new.high_water {
        if old.high_water.get(id) != Some(epoch) {
            tx.execute("INSERT INTO high_water VALUES (?1,?2) ON CONFLICT(id) DO UPDATE SET epoch=excluded.epoch", params![id.0,epoch.0.to_string()]).map_err(storage_error)?;
        }
    }
    for (id, epoch) in old
        .generations
        .keys()
        .filter(|key| !new.generations.contains_key(*key))
    {
        tx.execute(
            "DELETE FROM generations WHERE instance=?1 AND epoch=?2",
            params![id.0, epoch.0.to_string()],
        )
        .map_err(storage_error)?;
    }
    for ((id, epoch), entry) in &new.generations {
        if old
            .generations
            .get(&(id.clone(), *epoch))
            .is_none_or(|old| {
                old.inputs != entry.inputs
                    || old.claims != entry.claims
                    || old.shared != entry.shared
            })
        {
            tx.execute("INSERT INTO generations VALUES (?1,?2,?3) ON CONFLICT(instance,epoch) DO UPDATE SET payload=excluded.payload", params![id.0,epoch.0.to_string(),encode(&StoredGenerationEntry::from(entry.clone()))?]).map_err(storage_error)?;
        }
    }
    observer(Generations);
    for id in old
        .effects
        .keys()
        .filter(|id| !new.effects.contains_key(*id))
    {
        delete_payload(&tx, "effects", &id.0)?;
    }
    for (id, effect) in &new.effects {
        if old.effects.get(id) != Some(effect) {
            upsert_payload(
                &tx,
                "effects",
                &id.0,
                &encode(&StoredEffect::from(effect.clone()))?,
            )?;
        }
    }
    observer(Effects);
    tx.commit().map_err(storage_error)?;
    observer(Committed);
    Ok(())
}

pub(super) fn pragmas(conn: &Connection) -> Result<super::LedgerPragmas, LedgerError> {
    Ok(super::LedgerPragmas {
        journal_mode: conn
            .pragma_query_value(None, "journal_mode", |r| r.get(0))
            .map_err(storage_error)?,
        synchronous: conn
            .pragma_query_value(None, "synchronous", |r| r.get(0))
            .map_err(storage_error)?,
        fullfsync: conn
            .pragma_query_value(None, "fullfsync", |r| r.get(0))
            .map_err(storage_error)?,
        secure_delete: conn
            .pragma_query_value(None, "secure_delete", |r| r.get(0))
            .map_err(storage_error)?,
    })
}

pub(super) fn checkpoint_truncate(conn: &Connection) -> Result<(), LedgerError> {
    let (busy, _, _): (i64, i64, i64) = conn
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .map_err(storage_error)?;
    if busy != 0 {
        return Err(LedgerError::Unavailable(StorageFault::Locked));
    }
    Ok(())
}

pub(super) fn reload(conn: &Connection) -> Result<LedgerState, LedgerError> {
    load(conn, VERSION)
}
