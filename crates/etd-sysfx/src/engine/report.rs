//! Reclaim reports, candidate and conflict ids, key matching.
use super::record::INDETERMINATE;
use crate::*;
use etd_contract::{DesiredInstance, InstanceId};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const RECORD_PREFIX: &str = "rec:";
const CONFLICT_PREFIX: &str = "conflict:";
const SWEPT_PREFIX: &str = "swept:";
/// `Observation::detail` prefix of a held record: the credential the probe
/// found, as JSON. A held record never stores a found credential in
/// `Observation::credential`, so nothing it saw can later authorise a
/// delete.
const FOUND_PREFIX: &str = "found credential: ";

/// What a candidate or conflict id refers to.
pub(super) enum CandidateRef {
    /// A candidate ledger record, with the identity version it was reported
    /// with (`rec:<effect>@<version>`).
    Candidate(EffectId, String),
    /// A conflict ledger record (KEEP only).
    Conflict(EffectId),
    /// An object found by the sweep (looked up by the full id, which
    /// carries its identity version).
    Swept,
}

impl CandidateRef {
    /// The record a candidate or conflict reference names (`None` for
    /// swept objects).
    pub(super) fn effect(&self) -> Option<&EffectId> {
        match self {
            CandidateRef::Candidate(id, _) | CandidateRef::Conflict(id) => Some(id),
            CandidateRef::Swept => None,
        }
    }
}

pub(super) fn parse_id(id: &str) -> Option<CandidateRef> {
    if let Some(rest) = id.strip_prefix(RECORD_PREFIX) {
        let (effect, version) = rest.rsplit_once('@')?;
        Some(CandidateRef::Candidate(
            EffectId(effect.to_owned()),
            version.to_owned(),
        ))
    } else if let Some(rest) = id.strip_prefix(CONFLICT_PREFIX) {
        Some(CandidateRef::Conflict(EffectId(rest.to_owned())))
    } else {
        id.starts_with(SWEPT_PREFIX).then_some(CandidateRef::Swept)
    }
}

/// Version of an observed object identity: kind, concrete key and
/// credential. An approval given for one version never applies to another
/// (a refreshed candidate gets a new id).
pub(super) fn identity_version(
    kind: EffectKind,
    key: &ObjectKey,
    credential: Option<&Credential>,
) -> String {
    let mut h = Sha256::new();
    h.update(kind.as_str().as_bytes());
    h.update([0]);
    h.update(serde_json::to_vec(key).unwrap_or_default());
    h.update([0]);
    h.update(serde_json::to_vec(&credential).unwrap_or_default());
    hex(&h.finalize()[..12])
}

/// Identity version of a candidate record as reported.
pub(super) fn candidate_version(e: &Effect) -> String {
    identity_version(e.kind, lookup_key(e), found_credential(e).as_ref())
}

pub(super) fn candidate_id(e: &Effect) -> String {
    format!("{RECORD_PREFIX}{}@{}", e.id.0, candidate_version(e))
}

pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Id of a swept object: its identity version (kind, key, credential).
pub(super) fn swept_id(object: &FoundObject) -> String {
    format!(
        "{SWEPT_PREFIX}{}",
        identity_version(
            object.kind,
            &object.key,
            object.observation.credential.as_ref()
        )
    )
}

/// The key a record's object is found under: the concrete key observed
/// after the action, else the planned key.
pub(super) fn lookup_key(e: &Effect) -> &ObjectKey {
    e.observation
        .as_ref()
        .and_then(|o| o.key.as_ref())
        .unwrap_or(&e.key)
}

fn same_key(a: &ObjectKey, b: &ObjectKey) -> bool {
    match (a, b) {
        (ObjectKey::Interface { name, guid }, ObjectKey::Interface { name: bn, guid: bg }) => {
            let eq = |x: &Option<String>, y: &Option<String>| matches!((x, y), (Some(x), Some(y)) if x.eq_ignore_ascii_case(y));
            eq(name, bn) || eq(guid, bg)
        }
        // Windows service names are case-insensitive: the service control
        // manager may report a registered name in another case than the
        // planned key (`windivert` for `WinDivert`).
        (ObjectKey::Service { name }, ObjectKey::Service { name: bn }) if cfg!(windows) => {
            name.eq_ignore_ascii_case(bn)
        }
        _ => a == b,
    }
}

/// Whether a swept object is the one an open record describes.
pub(super) fn locates_record(e: &Effect, kind: EffectKind, key: &ObjectKey) -> bool {
    e.kind == kind && (same_key(&e.key, key) || same_key(lookup_key(e), key))
}

/// A record-shaped view of a swept object, for its reclaimer.
pub(super) fn synthetic_effect(object: &FoundObject) -> Effect {
    Effect {
        id: EffectId(swept_id(object)),
        scope: EffectScope::Product,
        kind: object.kind,
        key: object.key.clone(),
        undo: Undo::EnsureAbsent,
        persistence: Persistence::Persistent,
        state: EffectState::Applied,
        boot: BootId(String::new()),
        observation: Some(object.observation.clone()),
        failures: 0,
        last_error: None,
        recorded_at: object.observation.observed_at,
    }
}

/// Observation stored on a candidate or conflict record: the concrete key
/// found, `expected` (the recorded credential, conflicts only) as the
/// credential, the found credential in the detail.
pub(super) fn held_observation(found: &Observation, expected: Option<Credential>) -> Observation {
    let found_json = serde_json::to_string(&found.credential).unwrap_or_default();
    let detail = match &found.detail {
        Some(d) => format!("{FOUND_PREFIX}{found_json}\n{d}"),
        None => format!("{FOUND_PREFIX}{found_json}"),
    };
    Observation {
        credential: expected,
        key: found.key.clone(),
        observed_at: found.observed_at,
        detail: Some(detail),
    }
}

pub(super) fn found_credential(e: &Effect) -> Option<Credential> {
    let detail = e.observation.as_ref()?.detail.as_ref()?;
    let json = detail.strip_prefix(FOUND_PREFIX)?.lines().next()?;
    serde_json::from_str(json).ok().flatten()
}

pub(super) fn desired_id(d: &DesiredInstance) -> Option<InstanceId> {
    (!d.instance_id.is_empty()).then(|| InstanceId::from(d.instance_id.as_str()))
}

/// SHA-256 of a core-binary-scope record.
pub(super) fn core_scope_of(e: &Effect) -> Option<&str> {
    match &e.scope {
        EffectScope::CoreBinary { sha256 } => Some(sha256),
        _ => None,
    }
}

fn residue(e: &Effect) -> Residue {
    let reason = match &e.last_error {
        Some(err) if err.starts_with(INDETERMINATE) => {
            ResidueReason::Indeterminate(err[INDETERMINATE.len()..].to_owned())
        }
        Some(err) => ResidueReason::Failing {
            failures: e.failures,
            last_error: err.clone(),
        },
        None => ResidueReason::Pending,
    };
    Residue {
        effect: e.id.clone(),
        kind: e.kind,
        key: lookup_key(e).clone(),
        reason,
    }
}

fn is_held(e: &Effect) -> bool {
    matches!(e.state, EffectState::Candidate | EffectState::Conflict)
}

/// Report on one generation from its open records.
pub(super) fn generation(instance: &InstanceId, epoch: Epoch, open: &[Effect]) -> GenerationReport {
    let quarantined = open
        .iter()
        .filter(|e| e.state == EffectState::Quarantined)
        .count();
    let candidates = open
        .iter()
        .filter(|e| e.state == EffectState::Candidate)
        .count();
    let conflicts = open
        .iter()
        .filter(|e| e.state == EffectState::Conflict)
        .count();
    let outcome = if open.is_empty() {
        GenerationOutcome::Closed
    } else if quarantined + candidates + conflicts > 0 {
        let mut why = Vec::new();
        if quarantined > 0 {
            why.push(format!("{quarantined} record(s) quarantined"));
        }
        if candidates > 0 {
            why.push(format!("{candidates} candidate(s) await confirmation"));
        }
        if conflicts > 0 {
            why.push(format!("{conflicts} conflict(s)"));
        }
        GenerationOutcome::Quarantined(why.join(", "))
    } else {
        GenerationOutcome::Pending
    };
    GenerationReport {
        instance: instance.clone(),
        epoch,
        outcome,
        residues: open.iter().filter(|e| !is_held(e)).map(residue).collect(),
    }
}

/// Note for a product or core-binary record still open.
pub(super) fn pending_note(e: &Effect) -> String {
    let scope = match &e.scope {
        EffectScope::CoreBinary { sha256 } => format!("core binary {sha256}"),
        _ => "product".to_owned(),
    };
    format!(
        "{scope} record {} ({} {:?}) still open: {:?}",
        e.id.0,
        e.kind,
        lookup_key(e),
        e.state
    )
}

/// Full report. `generations`: the ones a run just handled (closed ones
/// included); `None`: every open generation, from `open`.
pub(super) fn build(
    open: &[Effect],
    generations: Option<Vec<GenerationReport>>,
    swept: &BTreeMap<String, FoundObject>,
    mut notes: Vec<String>,
) -> ReclaimReport {
    let mut by_generation: BTreeMap<(InstanceId, Epoch), Vec<Effect>> = BTreeMap::new();
    for e in open {
        if let Some((i, n)) = e.scope.generation() {
            by_generation
                .entry((i.clone(), n))
                .or_default()
                .push(e.clone());
        } else if !is_held(e) {
            notes.push(pending_note(e));
        }
    }
    let generations = match generations {
        Some(mut handled) => {
            // Open generations the run did not touch are still reported.
            for ((i, n), records) in &by_generation {
                if !handled.iter().any(|g| g.instance == *i && g.epoch == *n) {
                    handled.push(generation(i, *n, records));
                }
            }
            handled
        }
        None => by_generation
            .iter()
            .map(|((i, n), records)| generation(i, *n, records))
            .collect(),
    };
    let mut candidates: Vec<Candidate> = open
        .iter()
        .filter(|e| e.state == EffectState::Candidate)
        .map(|e| Candidate {
            id: candidate_id(e),
            kind: e.kind,
            key: lookup_key(e).clone(),
            scope: Some(e.scope.clone()),
            observation: e.observation.clone(),
            source: CandidateSource::PlannedRecord {
                effect: e.id.clone(),
            },
        })
        .collect();
    candidates.extend(swept.iter().map(|(id, o)| Candidate {
        id: id.clone(),
        kind: o.kind,
        key: o.key.clone(),
        scope: None,
        observation: Some(o.observation.clone()),
        source: CandidateSource::Swept(o.origin.clone()),
    }));
    let conflicts = open
        .iter()
        .filter(|e| e.state == EffectState::Conflict)
        .map(|e| Conflict {
            id: format!("{CONFLICT_PREFIX}{}", e.id.0),
            effect: e.id.clone(),
            kind: e.kind,
            key: lookup_key(e).clone(),
            expected: e.observation.as_ref().and_then(|o| o.credential.clone()),
            found: found_credential(e),
        })
        .collect();
    ReclaimReport {
        generated_at: jiff::Timestamp::now(),
        generations,
        candidates,
        conflicts,
        notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service(name: &str) -> ObjectKey {
        ObjectKey::Service { name: name.into() }
    }

    fn driver_record(name: &str) -> Effect {
        Effect {
            id: EffectId("driver".into()),
            scope: EffectScope::Product,
            kind: EffectKind::Driver,
            key: service(name),
            undo: Undo::EnsureAbsent,
            persistence: Persistence::Persistent,
            state: EffectState::Applied,
            boot: BootId(String::new()),
            observation: None,
            failures: 0,
            last_error: None,
            recorded_at: jiff::Timestamp::UNIX_EPOCH,
        }
    }

    #[test]
    fn service_keys_match_case_insensitively_only_on_windows() {
        let record = driver_record("WinDivert");
        assert!(locates_record(
            &record,
            EffectKind::Driver,
            &service("WinDivert")
        ));
        assert_eq!(
            locates_record(&record, EffectKind::Driver, &service("windivert")),
            cfg!(windows)
        );
        assert!(!locates_record(
            &record,
            EffectKind::Driver,
            &service("wintun")
        ));
        assert!(!locates_record(
            &record,
            EffectKind::ServiceRegistration,
            &service("windivert")
        ));
    }

    #[test]
    fn other_keys_stay_exact() {
        let rule = |name: &str| ObjectKey::Rule {
            name: name.into(),
            group: Some("EasyTier".into()),
        };
        let mut record = driver_record("unused");
        record.kind = EffectKind::WinFirewallRule;
        record.key = rule("EasyTier etd-1 (in)");
        assert!(!locates_record(
            &record,
            EffectKind::WinFirewallRule,
            &rule("easytier ETD-1 (in)")
        ));
    }
}
