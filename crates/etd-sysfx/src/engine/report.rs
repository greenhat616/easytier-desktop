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
        // Registry key paths and value names are case-insensitive: the plan
        // spells the adapter GUID in upper case, the sweep reports it as
        // enumerated. Firewall / NRPT rule names and groups, and network
        // profile names, are matched case-insensitively by the Windows
        // observer too. Ordinal (ASCII) comparison, as Windows does for
        // these names.
        (ObjectKey::Registry { key, value }, ObjectKey::Registry { key: bk, value: bv })
            if cfg!(windows) =>
        {
            key.eq_ignore_ascii_case(bk) && same_name(value, bv)
        }
        (
            ObjectKey::Rule { name, group },
            ObjectKey::Rule {
                name: bn,
                group: bg,
            },
        ) if cfg!(windows) => name.eq_ignore_ascii_case(bn) && same_name(group, bg),
        (
            ObjectKey::NetworkProfile { profile_name },
            ObjectKey::NetworkProfile { profile_name: bn },
        ) if cfg!(windows) => profile_name.eq_ignore_ascii_case(bn),
        _ => a == b,
    }
}

/// Both absent, or both present and equal ignoring ASCII case.
fn same_name(a: &Option<String>, b: &Option<String>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
        (None, None) => true,
        _ => false,
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

    fn record(kind: EffectKind, key: ObjectKey) -> Effect {
        Effect {
            kind,
            key,
            ..driver_record("unused")
        }
    }

    /// Registry path of a per-adapter value, with the GUID as the plan
    /// spells it (`adapter_guid`: braced, upper case) or as a sweep may
    /// report it.
    fn tcpip6(guid: &str, value: &str) -> ObjectKey {
        ObjectKey::Registry {
            key: format!(
                r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\{guid}"
            ),
            value: Some(value.into()),
        }
    }

    const PLANNED: &str = "{8D2E9F3A-1B4C-5D6E-8F70-A1B2C3D4E5F6}";
    const SWEPT: &str = "{8d2e9f3a-1b4c-5d6e-8f70-a1b2c3d4e5f6}";

    #[test]
    fn registry_keys_match_case_insensitively_only_on_windows() {
        let planned = record(
            EffectKind::WinRegistryValue,
            tcpip6(PLANNED, "MaxNumberOfAddressesToRegister"),
        );
        let swept = tcpip6(SWEPT, "maxnumberofaddressestoregister");
        assert!(locates_record(
            &planned,
            EffectKind::WinRegistryValue,
            &tcpip6(PLANNED, "MaxNumberOfAddressesToRegister")
        ));
        assert_eq!(
            locates_record(&planned, EffectKind::WinRegistryValue, &swept),
            cfg!(windows)
        );
        // Another GUID, another value, or a value against the key itself:
        // never the same object.
        let other = "{8D2E9F3A-1B4C-5D6E-8F70-A1B2C3D4E5F7}";
        for different in [
            tcpip6(other, "MaxNumberOfAddressesToRegister"),
            tcpip6(SWEPT, "RegistrationEnabled"),
            ObjectKey::Registry {
                key: format!(
                    r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\{SWEPT}"
                ),
                value: None,
            },
        ] {
            assert!(
                !locates_record(&planned, EffectKind::WinRegistryValue, &different),
                "{different:?}"
            );
        }
    }

    #[test]
    fn rule_and_profile_names_match_case_insensitively_only_on_windows() {
        let rule = |name: &str, group: Option<&str>| ObjectKey::Rule {
            name: name.into(),
            group: group.map(str::to_owned),
        };
        let firewall = record(
            EffectKind::WinFirewallRule,
            rule("EasyTier etd-1 (in)", Some("EasyTier")),
        );
        assert_eq!(
            locates_record(
                &firewall,
                EffectKind::WinFirewallRule,
                &rule("easytier ETD-1 (IN)", Some("easytier"))
            ),
            cfg!(windows)
        );
        assert!(!locates_record(
            &firewall,
            EffectKind::WinFirewallRule,
            &rule("EasyTier etd-1 (in)", None)
        ));
        let nrpt = record(EffectKind::WinNrptRule, rule(PLANNED, None));
        assert_eq!(
            locates_record(&nrpt, EffectKind::WinNrptRule, &rule(SWEPT, None)),
            cfg!(windows)
        );
        let profile = |name: &str| ObjectKey::NetworkProfile {
            profile_name: name.into(),
        };
        let planned = record(EffectKind::WinNetworkProfile, profile("etd-1a2b3c4d"));
        assert_eq!(
            locates_record(
                &planned,
                EffectKind::WinNetworkProfile,
                &profile("ETD-1A2B3C4D")
            ),
            cfg!(windows)
        );
    }

    #[test]
    fn paths_and_fences_stay_exact() {
        let path = |p: &str| ObjectKey::Path { path: p.into() };
        let dir = record(EffectKind::RuntimeDir, path("run/a/1"));
        assert!(!locates_record(
            &dir,
            EffectKind::RuntimeDir,
            &path("RUN/A/1")
        ));
        let fence = |rule: &str| ObjectKey::Fence {
            container: "etd-fence".into(),
            rule: rule.into(),
            port: 15888,
        };
        let planned = record(EffectKind::WinFenceFilter, fence("8d2e9f3a"));
        assert!(!locates_record(
            &planned,
            EffectKind::WinFenceFilter,
            &fence("8D2E9F3A")
        ));
    }
}
