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
    /// A candidate or conflict ledger record.
    Record(EffectId),
    /// An object found by the sweep (looked up by the full id).
    Swept,
}

pub(super) fn parse_id(id: &str) -> Option<CandidateRef> {
    if let Some(rest) = id.strip_prefix(RECORD_PREFIX) {
        Some(CandidateRef::Record(EffectId(rest.to_owned())))
    } else if let Some(rest) = id.strip_prefix(CONFLICT_PREFIX) {
        Some(CandidateRef::Record(EffectId(rest.to_owned())))
    } else {
        id.starts_with(SWEPT_PREFIX).then_some(CandidateRef::Swept)
    }
}

pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Stable id of a swept object: kind and key.
pub(super) fn swept_id(kind: EffectKind, key: &ObjectKey) -> String {
    let mut h = Sha256::new();
    h.update(kind.as_str().as_bytes());
    h.update([0]);
    h.update(serde_json::to_vec(key).unwrap_or_default());
    format!("{SWEPT_PREFIX}{}", hex(&h.finalize()[..12]))
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
        id: EffectId(swept_id(object.kind, &object.key)),
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

fn found_credential(e: &Effect) -> Option<Credential> {
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
            id: format!("{RECORD_PREFIX}{}", e.id.0),
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
