//! Frozen side-effect model (F0).
//!
//! Every system object the kernel or the host creates is recorded *before*
//! the action that creates it ("record first, act second"), so the ledger can
//! only ever hold more than the system, never less. A record carries its
//! scope (instance + epoch, or product), a natural key, how to undo it, how
//! long it survives, and, once observed, the creation credential that
//! authorises deletion. Names locate objects; only credentials (or an
//! exclusive container) authorise deleting them.
use etd_contract::InstanceId;
use serde::{Deserialize, Serialize};
use std::{fmt, path::PathBuf, str::FromStr};

/// Ledger-assigned record id (opaque, unique, sortable by creation).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EffectId(pub String);

/// Generation of an instance. Every start of an instance uses a new epoch;
/// a new epoch may not start while an older one has open records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Epoch(pub u64);

/// Opaque boot identifier (Linux boot_id, macOS kern.bootsessionuuid,
/// Windows boot-time derived). Changes on every reboot.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BootId(pub String);

/// Secret per-installation key from which interface names are derived.
/// Kept out of logs.
#[derive(Clone, PartialEq, Eq)]
pub struct InstallKey(pub [u8; 32]);

impl fmt::Debug for InstallKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InstallKey(..)")
    }
}

/// Owner of a record.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EffectScope {
    /// Belongs to one generation of one instance; reclaimed when that
    /// generation ends.
    Instance { instance: InstanceId, epoch: Epoch },
    /// Belongs to the product (driver, service registration); only
    /// `uninstall` / `reclaim --all --purge` remove it.
    Product,
    /// Tied to one kernel-store binary (SHA-256, lower-case hex), shared by
    /// every instance launched from it: the two Windows program firewall
    /// rules (ruling msg#276). Reclaimed when that kernel is removed from the
    /// store (`ReclaimEngine::reclaim_core`, only while no open generation
    /// uses it), with `uninstall` / `reclaim --all --purge` as backstop.
    CoreBinary { sha256: String },
}

impl EffectScope {
    /// Instance generation this record belongs to, if any.
    pub fn generation(&self) -> Option<(&InstanceId, Epoch)> {
        match self {
            EffectScope::Instance { instance, epoch } => Some((instance, *epoch)),
            EffectScope::Product | EffectScope::CoreBinary { .. } => None,
        }
    }
}

/// Concrete object type. One [`crate::Reclaimer`] handles one kind. The
/// string form ([`EffectKind::as_str`]) is what the ledger stores and the
/// reclaim report shows; it never changes for an existing kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum EffectKind {
    /// The kernel process itself (closed last, after it is verified dead).
    Process,
    /// `run/<instance>/<epoch>/`, holding the generated configuration.
    RuntimeDir,
    /// Routes pointing at the instance's interface (verify none remain).
    Route,
    /// UPnP / NAT-PMP mapping on the router: recorded, expires on its own.
    UpnpMapping,
    /// Management-port fence: WFP filter in the product sublayer.
    WinFenceFilter,
    /// Management-port fence: rule in the product nftables table.
    LinuxFenceRule,
    /// Management-port fence: rule in the product PF anchor.
    MacFenceRule,
    /// wintun adapter (name derived from the install key, GUID = UUIDv5).
    WinTunAdapter,
    /// One of the eight per-interface firewall rules.
    WinFirewallRule,
    /// One of the two per-program firewall rules (core-binary scope).
    WinProgramFirewallRule,
    /// Tcpip / Tcpip6 / NetBT interface values under the adapter GUID.
    WinRegistryValue,
    /// NRPT rule written by Magic DNS (shared with other EasyTier installs).
    WinNrptRule,
    /// Linux TUN interface.
    LinuxTun,
    /// systemd-resolved per-link DNS configuration.
    LinuxResolvedLink,
    /// macOS utun interface (name assigned by the system, read back).
    MacUtun,
    /// wintun / WinDivert driver (product scope).
    Driver,
    /// Host service registration (product scope).
    ServiceRegistration,
    /// Windows Magic DNS as a whole: upstream's ownership record under
    /// `HKLM\SOFTWARE\EasyTier\MagicDNS` (NRPT rule ids, saved search
    /// lists), which covers zones learned at run time. Undone by
    /// [`Undo::ReplayUpstreamRecovery`], only while no other EasyTier process
    /// runs (shared with other installs).
    WinMagicDnsRecovery,
    /// Windows network-list profile created for the instance's adapter
    /// (upstream sets its `Category`). Located by profile name, deleted only
    /// by the profile GUID read back as credential.
    WinNetworkProfile,
}

impl EffectKind {
    pub const ALL: &'static [EffectKind] = &[
        EffectKind::Process,
        EffectKind::RuntimeDir,
        EffectKind::Route,
        EffectKind::UpnpMapping,
        EffectKind::WinFenceFilter,
        EffectKind::LinuxFenceRule,
        EffectKind::MacFenceRule,
        EffectKind::WinTunAdapter,
        EffectKind::WinFirewallRule,
        EffectKind::WinProgramFirewallRule,
        EffectKind::WinRegistryValue,
        EffectKind::WinNrptRule,
        EffectKind::LinuxTun,
        EffectKind::LinuxResolvedLink,
        EffectKind::MacUtun,
        EffectKind::Driver,
        EffectKind::ServiceRegistration,
        EffectKind::WinMagicDnsRecovery,
        EffectKind::WinNetworkProfile,
    ];

    /// Stable storage / report name.
    pub fn as_str(self) -> &'static str {
        match self {
            EffectKind::Process => "process",
            EffectKind::RuntimeDir => "run_dir",
            EffectKind::Route => "route",
            EffectKind::UpnpMapping => "upnp_mapping",
            EffectKind::WinFenceFilter => "win.fence_filter",
            EffectKind::LinuxFenceRule => "linux.fence_rule",
            EffectKind::MacFenceRule => "macos.fence_rule",
            EffectKind::WinTunAdapter => "win.tun",
            EffectKind::WinFirewallRule => "win.firewall_rule",
            EffectKind::WinProgramFirewallRule => "win.program_firewall_rule",
            EffectKind::WinRegistryValue => "win.registry_value",
            EffectKind::WinNrptRule => "win.nrpt_rule",
            EffectKind::LinuxTun => "linux.tun",
            EffectKind::LinuxResolvedLink => "linux.resolved_link",
            EffectKind::MacUtun => "macos.utun",
            EffectKind::Driver => "driver",
            EffectKind::ServiceRegistration => "service_registration",
            EffectKind::WinMagicDnsRecovery => "win.magic_dns_recovery",
            EffectKind::WinNetworkProfile => "win.network_profile",
        }
    }

    /// Default reclaim rank (see [`crate::rank`]).
    pub fn default_rank(self) -> u8 {
        use crate::rank;
        match self {
            EffectKind::WinFirewallRule
            | EffectKind::WinProgramFirewallRule
            | EffectKind::WinNrptRule
            | EffectKind::LinuxResolvedLink
            | EffectKind::UpnpMapping
            | EffectKind::WinMagicDnsRecovery => rank::DNS_AND_FIREWALL,
            EffectKind::WinRegistryValue | EffectKind::WinNetworkProfile => rank::REGISTRY,
            EffectKind::WinTunAdapter | EffectKind::LinuxTun | EffectKind::MacUtun => {
                rank::INTERFACE
            }
            EffectKind::Route => rank::ROUTES,
            EffectKind::RuntimeDir => rank::RUNTIME_DIR,
            EffectKind::Process => rank::PROCESS,
            EffectKind::WinFenceFilter | EffectKind::LinuxFenceRule | EffectKind::MacFenceRule => {
                rank::FENCE
            }
            EffectKind::Driver | EffectKind::ServiceRegistration => rank::PRODUCT,
        }
    }
}

impl fmt::Display for EffectKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Unknown kind name (e.g. a ledger written by a newer version).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown effect kind {0:?}")]
pub struct UnknownEffectKind(pub String);

impl FromStr for EffectKind {
    type Err = UnknownEffectKind;
    fn from_str(name: &str) -> Result<Self, Self::Err> {
        EffectKind::ALL
            .iter()
            .copied()
            .find(|kind| kind.as_str() == name)
            .ok_or_else(|| UnknownEffectKind(name.to_owned()))
    }
}

/// Natural key: enough to find the object with no in-memory state. Names are
/// visible to others and only locate; see [`Credential`] for deletion.
///
/// A key holds only what is known *before* the action (it is written while
/// the record is `Planned`). Facts that exist only afterwards (pid and start
/// token, a system-assigned interface name, a router-assigned port) are
/// recorded later as an [`Observation`]: its `credential` and its concrete
/// `key`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum ObjectKey {
    /// Kernel process, by its image and the epoch directory its command line
    /// references. pid and start token are observed after spawn
    /// ([`Credential::Process`]).
    Process {
        exe: PathBuf,
        cmdline_marker: PathBuf,
    },
    /// File or directory.
    Path { path: PathBuf },
    /// Network interface. `name` is `None` until known (macOS utun);
    /// `guid` is the Windows adapter GUID derived from the name.
    Interface {
        name: Option<String>,
        guid: Option<String>,
    },
    /// Routes whose next hop is the named interface.
    /// `None` while the interface name is not known yet (macOS utun). When
    /// the host reads the name back it transitions this record too, writing
    /// `RoutesVia { interface: Some(name) }` as its observed key, so the
    /// route reclaimer needs no other record.
    RoutesVia { interface: Option<String> },
    /// Named rule (firewall, NRPT): exact rule name, optional group.
    Rule { name: String, group: Option<String> },
    /// Registry value or key (`value: None` = the key itself).
    Registry { key: String, value: Option<String> },
    /// Rule inside a product-exclusive container (WFP sublayer, nftables
    /// table, PF anchor) guarding one loopback port.
    Fence {
        container: String,
        rule: String,
        port: u16,
    },
    /// systemd-resolved link configuration.
    ResolvedLink { interface: String },
    /// Router port mapping.
    /// Planned with `external_port: None`; the router-assigned port is
    /// recorded later as the observed key (`Some(port)`).
    PortMapping {
        protocol: String,
        internal_port: u16,
        external_port: Option<u16>,
        description: String,
    },
    /// Driver or service, by its registered name.
    Service { name: String },
    /// Windows network-list profile, by its `ProfileName` (the interface
    /// name). The profile GUID is observed later as an opaque credential.
    NetworkProfile { profile_name: String },
}

/// Creation credential, read back from the system once the object exists.
/// A reclaimer deletes only when the object it finds matches the recorded
/// credential, or when the object sits in an exclusive container.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Credential {
    /// Windows adapter LUID and device instance id.
    WinAdapter {
        luid: u64,
        device_instance_id: String,
    },
    /// Unix interface index, valid only within `boot`.
    UnixInterface { index: u32, boot: BootId },
    /// File identity (inode / file index plus device / volume).
    File { file_id: u64, device: u64 },
    /// Process identity (pid + start token).
    Process { pid: u32, start_token: String },
    /// Lives in a container only the host can write; deletable by key.
    ExclusiveContainer { container: String },
    /// Opaque platform-specific identity (e.g. firewall rule GUID).
    Opaque { value: String },
}

/// What was seen when looking at the system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    pub credential: Option<Credential>,
    /// Concrete key as found (e.g. the utun name once assigned).
    pub key: Option<ObjectKey>,
    pub observed_at: jiff::Timestamp,
    /// Human-readable detail for reports.
    pub detail: Option<String>,
}

/// A setting value, for "restore if still ours".
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
#[non_exhaustive]
pub enum SettingValue {
    Absent,
    String(String),
    MultiString(Vec<String>),
    U32(u32),
    U64(u64),
    Bytes(Vec<u8>),
}

/// How to undo. Every form is idempotent.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Undo {
    /// Objects we (or the kernel on our behalf) created: make sure it no
    /// longer exists.
    EnsureAbsent,
    /// Settings we changed: if the current value is still `ours`, put back
    /// `original`; if someone else changed it since, leave it.
    RestoreIfOurs {
        ours: SettingValue,
        original: SettingValue,
    },
    /// Replay the creator's own recovery record named by the key (Windows
    /// Magic DNS: delete every NRPT rule listed in `NRPTRuleIDs`, restore the
    /// saved search lists, then delete the record), gated on no other
    /// process of that creator running.
    ReplayUpstreamRecovery,
}

/// How long the object survives on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Persistence {
    /// Expected to vanish with the process; still probed after a crash.
    /// Whether the wintun adapter belongs here depends on spike S2: if S2
    /// shows it survives a kill, E1 classifies it as `Persistent`.
    WithProcess,
    /// Vanishes on reboot: closed without probing when the boot id changed.
    UntilReboot,
    /// Stays until removed.
    Persistent,
    /// Expires by itself (router lease) at the given time.
    Expiring { until: jiff::Timestamp },
    /// Expires by itself (router lease) `seconds` after the generation's
    /// process is gone. Planned form of a lease whose absolute end is unknown
    /// at plan time; the reclaimer closes the record once the process record
    /// is closed and `seconds` have passed since then. Never reclaimed actively.
    Lease { seconds: u32 },
}

impl Persistence {
    /// Records closed without probing when the boot id differs from the one
    /// they were written under (doc#2 v7: volatile records are closed
    /// directly after a reboot).
    pub fn closes_on_reboot(self) -> bool {
        matches!(self, Persistence::WithProcess | Persistence::UntilReboot)
    }
}

/// Ledger record state. See the record state machine in doc#2 v7.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EffectState {
    /// Committed before the action; the object may or may not exist.
    Planned,
    /// Observed, credential recorded.
    Applied,
    /// Probe, delete, verify in progress.
    Reclaiming,
    /// Verified gone (or restored). Closed; removed at compaction.
    Reclaimed,
    /// Five consecutive reclaim failures. Open.
    Quarantined,
    /// Object present without a matching credential and outside an
    /// exclusive container: never deleted automatically. Open until an
    /// administrator decides.
    Candidate,
    /// The key now names an object with a different identity: ours is gone,
    /// the name is taken by someone else. Never deleted. Open (the
    /// generation stays quarantined, so the next generation cannot clash on
    /// the same derived name) until an administrator releases it.
    Conflict,
}

impl EffectState {
    /// Closed records no longer hold their epoch open.
    pub fn is_closed(self) -> bool {
        matches!(self, EffectState::Reclaimed)
    }
}

/// What a planner wants recorded before acting. The ledger turns it into an
/// [`Effect`] (id, state `Planned`, boot id, timestamp).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectIntent {
    pub scope: EffectScope,
    pub kind: EffectKind,
    pub key: ObjectKey,
    pub undo: Undo,
    pub persistence: Persistence,
}

/// A ledger record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Effect {
    pub id: EffectId,
    pub scope: EffectScope,
    pub kind: EffectKind,
    pub key: ObjectKey,
    pub undo: Undo,
    pub persistence: Persistence,
    pub state: EffectState,
    /// Boot id when the record was written.
    pub boot: BootId,
    /// Latest observation; carries the creation credential once applied.
    pub observation: Option<Observation>,
    /// Consecutive reclaim failures (quarantine at
    /// [`crate::QUARANTINE_AFTER`]). Reset to 0 when the record closes and
    /// when a retry (RetryReclaim ticket) moves it out of `Quarantined`.
    pub failures: u32,
    pub last_error: Option<String>,
    pub recorded_at: jiff::Timestamp,
}

/// Selects open records. Empty vectors mean "any".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScopeFilter {
    pub instance: Option<InstanceId>,
    pub epoch: Option<Epoch>,
    /// Include product-scope records.
    pub product: bool,
    /// Include core-binary-scope records.
    pub core_binary: bool,
    pub kinds: Vec<EffectKind>,
    pub states: Vec<EffectState>,
}

impl ScopeFilter {
    /// Every open record, instance and product scope.
    pub fn all() -> Self {
        Self {
            product: true,
            core_binary: true,
            ..Self::default()
        }
    }
    /// Open records of one instance, every epoch.
    pub fn instance(instance: InstanceId) -> Self {
        Self {
            instance: Some(instance),
            ..Self::default()
        }
    }
    /// Open records of one generation.
    pub fn epoch(instance: InstanceId, epoch: Epoch) -> Self {
        Self {
            instance: Some(instance),
            epoch: Some(epoch),
            ..Self::default()
        }
    }
}

/// An object found by a [`crate::Sweeper`] outside the ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundObject {
    pub kind: EffectKind,
    pub key: ObjectKey,
    pub observation: Observation,
    pub origin: FoundBy,
}

/// How a swept object was found; decides what may happen to it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FoundBy {
    /// Inside a product-exclusive container: may be removed.
    ExclusiveContainer,
    /// Name re-derived for a known instance from the repair index: candidate.
    DerivedName { instance: InstanceId },
    /// Product prefix only: candidate, report only.
    PrefixOnly,
}

/// Result of probing for a recorded object. Deliberately exhaustive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Probe {
    Present(Observation),
    Absent,
    /// Could not tell (access error, API failure); never treated as absent.
    Indeterminate(String),
}

/// Successful reclaim outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Reclaimed {
    Removed,
    AlreadyAbsent,
    /// Setting restored to its original value.
    Restored,
    /// Setting changed by someone else since; left alone.
    LeftModified,
}

/// Why a record holds its epoch open in a report.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResidueReason {
    /// Still being retried.
    Pending,
    Failing {
        failures: u32,
        last_error: String,
    },
    Indeterminate(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Residue {
    pub effect: EffectId,
    pub kind: EffectKind,
    pub key: ObjectKey,
    pub reason: ResidueReason,
}

/// Where a candidate came from.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CandidateSource {
    /// Planned record, object present, no credential read back.
    PlannedRecord { effect: EffectId },
    /// Swept object (repair index or prefix).
    Swept(FoundBy),
}

/// Never deleted automatically; an administrator decides item by item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// Stable id for the decision round trip.
    pub id: String,
    pub kind: EffectKind,
    pub key: ObjectKey,
    pub scope: Option<EffectScope>,
    pub observation: Option<Observation>,
    pub source: CandidateSource,
}

/// Same key as our record, different identity: not ours any more; never
/// deleted, reported. The record is in [`EffectState::Conflict`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conflict {
    /// Stable id for the decision round trip (KEEP only).
    pub id: String,
    pub effect: EffectId,
    pub kind: EffectKind,
    pub key: ObjectKey,
    pub expected: Option<Credential>,
    pub found: Option<Credential>,
}

/// Per-generation outcome of a reclaim run.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum GenerationOutcome {
    /// Every record closed: the next epoch may start.
    Closed,
    /// Some records remain and will be retried.
    Pending,
    /// Quarantined: five failures, uncertain liveness, open candidates or
    /// open conflicts.
    Quarantined(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerationReport {
    pub instance: InstanceId,
    pub epoch: Epoch,
    pub outcome: GenerationOutcome,
    pub residues: Vec<Residue>,
}

/// Output of a reclaim run (instance stop/crash, self-check, retry).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReclaimReport {
    pub generated_at: jiff::Timestamp,
    pub generations: Vec<GenerationReport>,
    pub candidates: Vec<Candidate>,
    pub conflicts: Vec<Conflict>,
    /// Free-text notes, e.g. shared Magic DNS left in place.
    pub notes: Vec<String>,
}
