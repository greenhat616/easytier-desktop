//! Versioned on-disk representations. Kept separate from the frozen public
//! interfaces and protobuf messages; exhaustive conversions catch model drift.
use super::state::GenerationEntry;
use crate::*;
use etd_contract::{
    AllowEntry, CandidateDecision, Desired, DesiredInstance, InstanceId, NetworkSpec, OsPrincipal,
    Receipt, RequestId, v1,
};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, path::PathBuf};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Spec {
    display_name: String,
    network_name: String,
    network_secret: Option<String>,
    network_secret_set: bool,
    hostname: String,
    peers: Vec<String>,
    listeners: Vec<String>,
    no_listener: bool,
    proxy_cidrs: Vec<String>,
    exit_nodes: Vec<String>,
    enable_exit_node: bool,
    mtu: u32,
    no_tun: bool,
    socks5_port: u32,
    port_forwards: Vec<Forward>,
    magic_dns: bool,
    public_ipv6_provider: bool,
    flags: Option<Flags>,
    ipv4: Option<Ipv4>,
}
impl From<NetworkSpec> for Spec {
    fn from(value: NetworkSpec) -> Self {
        let NetworkSpec {
            display_name,
            network_name,
            network_secret,
            network_secret_set,
            hostname,
            peers,
            listeners,
            no_listener,
            proxy_cidrs,
            exit_nodes,
            enable_exit_node,
            mtu,
            no_tun,
            socks5_port,
            port_forwards,
            magic_dns,
            public_ipv6_provider,
            flags,
            ipv4,
        } = value;
        Self {
            display_name,
            network_name,
            network_secret,
            network_secret_set,
            hostname,
            peers,
            listeners,
            no_listener,
            proxy_cidrs,
            exit_nodes,
            enable_exit_node,
            mtu,
            no_tun,
            socks5_port,
            port_forwards: port_forwards.into_iter().map(Into::into).collect(),
            magic_dns,
            public_ipv6_provider,
            flags: flags.map(Into::into),
            ipv4: ipv4.map(Into::into),
        }
    }
}
impl From<Spec> for NetworkSpec {
    fn from(value: Spec) -> Self {
        let Spec {
            display_name,
            network_name,
            network_secret,
            network_secret_set,
            hostname,
            peers,
            listeners,
            no_listener,
            proxy_cidrs,
            exit_nodes,
            enable_exit_node,
            mtu,
            no_tun,
            socks5_port,
            port_forwards,
            magic_dns,
            public_ipv6_provider,
            flags,
            ipv4,
        } = value;
        Self {
            display_name,
            network_name,
            network_secret,
            network_secret_set,
            hostname,
            peers,
            listeners,
            no_listener,
            proxy_cidrs,
            exit_nodes,
            enable_exit_node,
            mtu,
            no_tun,
            socks5_port,
            port_forwards: port_forwards.into_iter().map(Into::into).collect(),
            magic_dns,
            public_ipv6_provider,
            flags: flags.map(Into::into),
            ipv4: ipv4.map(Into::into),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Flags {
    latency_first: bool,
    disable_encryption: bool,
    enable_kcp_proxy: bool,
    enable_quic_proxy: bool,
    disable_p2p: bool,
    disable_udp_hole_punching: bool,
    relay_all_peer_rpc: bool,
    multi_thread: bool,
    private_mode: bool,
    disable_ipv6: bool,
    use_smoltcp: bool,
    bind_device: bool,
    compression: String,
}
impl From<v1::NetworkFlags> for Flags {
    fn from(value: v1::NetworkFlags) -> Self {
        let v1::NetworkFlags {
            latency_first,
            disable_encryption,
            enable_kcp_proxy,
            enable_quic_proxy,
            disable_p2p,
            disable_udp_hole_punching,
            relay_all_peer_rpc,
            multi_thread,
            private_mode,
            disable_ipv6,
            use_smoltcp,
            bind_device,
            compression,
        } = value;
        Self {
            latency_first,
            disable_encryption,
            enable_kcp_proxy,
            enable_quic_proxy,
            disable_p2p,
            disable_udp_hole_punching,
            relay_all_peer_rpc,
            multi_thread,
            private_mode,
            disable_ipv6,
            use_smoltcp,
            bind_device,
            compression,
        }
    }
}
impl From<Flags> for v1::NetworkFlags {
    fn from(value: Flags) -> Self {
        let Flags {
            latency_first,
            disable_encryption,
            enable_kcp_proxy,
            enable_quic_proxy,
            disable_p2p,
            disable_udp_hole_punching,
            relay_all_peer_rpc,
            multi_thread,
            private_mode,
            disable_ipv6,
            use_smoltcp,
            bind_device,
            compression,
        } = value;
        Self {
            latency_first,
            disable_encryption,
            enable_kcp_proxy,
            enable_quic_proxy,
            disable_p2p,
            disable_udp_hole_punching,
            relay_all_peer_rpc,
            multi_thread,
            private_mode,
            disable_ipv6,
            use_smoltcp,
            bind_device,
            compression,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Forward {
    protocol: i32,
    bind: String,
    destination: String,
}
impl From<v1::PortForward> for Forward {
    fn from(value: v1::PortForward) -> Self {
        let v1::PortForward {
            protocol,
            bind,
            destination,
        } = value;
        Self {
            protocol,
            bind,
            destination,
        }
    }
}
impl From<Forward> for v1::PortForward {
    fn from(value: Forward) -> Self {
        let Forward {
            protocol,
            bind,
            destination,
        } = value;
        Self {
            protocol,
            bind,
            destination,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Instance {
    pub(super) instance_id: String,
    spec: Option<Spec>,
    pub(super) desired: i32,
}
impl From<DesiredInstance> for Instance {
    fn from(value: DesiredInstance) -> Self {
        let DesiredInstance {
            instance_id,
            spec,
            desired,
        } = value;
        Self {
            instance_id,
            spec: spec.map(Into::into),
            desired,
        }
    }
}
impl From<Instance> for DesiredInstance {
    fn from(value: Instance) -> Self {
        let Instance {
            instance_id,
            spec,
            desired,
        } = value;
        Self {
            instance_id,
            spec: spec.map(Into::into),
            desired,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StoredReceipt {
    request_id: String,
    revision: u64,
    ticket: String,
    accepted_unix_ms: i64,
}
impl From<Receipt> for StoredReceipt {
    fn from(value: Receipt) -> Self {
        let Receipt {
            request_id,
            revision,
            ticket,
            accepted_unix_ms,
        } = value;
        Self {
            request_id,
            revision,
            ticket,
            accepted_unix_ms,
        }
    }
}
impl From<StoredReceipt> for Receipt {
    fn from(value: StoredReceipt) -> Self {
        let StoredReceipt {
            request_id,
            revision,
            ticket,
            accepted_unix_ms,
        } = value;
        Self {
            request_id,
            revision,
            ticket,
            accepted_unix_ms,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Decision {
    candidate_id: String,
    action: i32,
}
impl From<CandidateDecision> for Decision {
    fn from(value: CandidateDecision) -> Self {
        let CandidateDecision {
            candidate_id,
            action,
        } = value;
        Self {
            candidate_id,
            action,
        }
    }
}
impl From<Decision> for CandidateDecision {
    fn from(value: Decision) -> Self {
        let Decision {
            candidate_id,
            action,
        } = value;
        Self {
            candidate_id,
            action,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Principal {
    id: Option<PrincipalId>,
}
impl From<OsPrincipal> for Principal {
    fn from(value: OsPrincipal) -> Self {
        let OsPrincipal { id } = value;
        Self {
            id: id.map(Into::into),
        }
    }
}
impl From<Principal> for OsPrincipal {
    fn from(value: Principal) -> Self {
        let Principal { id } = value;
        Self {
            id: id.map(Into::into),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Allow {
    principal: Option<Principal>,
    role: i32,
    display_name: String,
}
impl From<AllowEntry> for Allow {
    fn from(value: AllowEntry) -> Self {
        let AllowEntry {
            principal,
            role,
            display_name,
        } = value;
        Self {
            principal: principal.map(Into::into),
            role,
            display_name,
        }
    }
}
impl From<Allow> for AllowEntry {
    fn from(value: Allow) -> Self {
        let Allow {
            principal,
            role,
            display_name,
        } = value;
        Self {
            principal: principal.map(Into::into),
            role,
            display_name,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Settings {
    allow_list: Vec<Allow>,
    selected_core: Option<String>,
}
impl From<HostSettings> for Settings {
    fn from(value: HostSettings) -> Self {
        let HostSettings {
            allow_list,
            selected_core,
        } = value;
        Self {
            allow_list: allow_list.into_iter().map(Into::into).collect(),
            selected_core,
        }
    }
}
impl From<Settings> for HostSettings {
    fn from(value: Settings) -> Self {
        let Settings {
            allow_list,
            selected_core,
        } = value;
        Self {
            allow_list: allow_list.into_iter().map(Into::into).collect(),
            selected_core,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Core {
    version: String,
    proto_revision: String,
    sha256: [u8; 32],
    binary: PathBuf,
    profile: Option<String>,
}
impl From<CoreRef> for Core {
    fn from(value: CoreRef) -> Self {
        let CoreRef {
            version,
            proto_revision,
            sha256,
            binary,
            profile,
        } = value;
        Self {
            version,
            proto_revision,
            sha256,
            binary,
            profile,
        }
    }
}
impl From<Core> for CoreRef {
    fn from(value: Core) -> Self {
        let Core {
            version,
            proto_revision,
            sha256,
            binary,
            profile,
        } = value;
        Self {
            version,
            proto_revision,
            sha256,
            binary,
            profile,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Inputs {
    spec: Spec,
    spec_revision: u64,
    runtime_dir: PathBuf,
    interface_name: String,
    management: SocketAddr,
    privilege: StoredPrivilege,
    guard: Guard,
    core: Core,
}
impl From<LaunchInputs> for Inputs {
    fn from(value: LaunchInputs) -> Self {
        let LaunchInputs {
            spec,
            spec_revision,
            runtime_dir,
            interface_name,
            management,
            privilege,
            guard,
            core,
        } = value;
        Self {
            spec: spec.into(),
            spec_revision,
            runtime_dir,
            interface_name,
            management,
            privilege: privilege.into(),
            guard: guard.into(),
            core: core.into(),
        }
    }
}
impl From<Inputs> for LaunchInputs {
    fn from(value: Inputs) -> Self {
        let Inputs {
            spec,
            spec_revision,
            runtime_dir,
            interface_name,
            management,
            privilege,
            guard,
            core,
        } = value;
        Self {
            spec: spec.into(),
            spec_revision,
            runtime_dir,
            interface_name,
            management,
            privilege: privilege.into(),
            guard: guard.into(),
            core: core.into(),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Ipv4 {
    Ipv4Cidr(String),
    Dhcp(bool),
}
impl From<v1::network_spec::Ipv4> for Ipv4 {
    fn from(value: v1::network_spec::Ipv4) -> Self {
        match value {
            v1::network_spec::Ipv4::Ipv4Cidr(v) => Self::Ipv4Cidr(v),
            v1::network_spec::Ipv4::Dhcp(v) => Self::Dhcp(v),
        }
    }
}
impl From<Ipv4> for v1::network_spec::Ipv4 {
    fn from(value: Ipv4) -> Self {
        match value {
            Ipv4::Ipv4Cidr(v) => Self::Ipv4Cidr(v),
            Ipv4::Dhcp(v) => Self::Dhcp(v),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PrincipalId {
    WindowsUserSid(String),
    WindowsGroupSid(String),
    UnixUid(u32),
    UnixGid(u32),
}
impl From<v1::os_principal::Id> for PrincipalId {
    fn from(value: v1::os_principal::Id) -> Self {
        match value {
            v1::os_principal::Id::WindowsUserSid(v) => Self::WindowsUserSid(v),
            v1::os_principal::Id::WindowsGroupSid(v) => Self::WindowsGroupSid(v),
            v1::os_principal::Id::UnixUid(v) => Self::UnixUid(v),
            v1::os_principal::Id::UnixGid(v) => Self::UnixGid(v),
        }
    }
}
impl From<PrincipalId> for v1::os_principal::Id {
    fn from(value: PrincipalId) -> Self {
        match value {
            PrincipalId::WindowsUserSid(v) => Self::WindowsUserSid(v),
            PrincipalId::WindowsGroupSid(v) => Self::WindowsGroupSid(v),
            PrincipalId::UnixUid(v) => Self::UnixUid(v),
            PrincipalId::UnixGid(v) => Self::UnixGid(v),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StoredPrivilege {
    System,
    User,
}
impl From<Privilege> for StoredPrivilege {
    fn from(value: Privilege) -> Self {
        match value {
            Privilege::System => Self::System,
            Privilege::User => Self::User,
        }
    }
}
impl From<StoredPrivilege> for Privilege {
    fn from(value: StoredPrivilege) -> Self {
        match value {
            StoredPrivilege::System => Self::System,
            StoredPrivilege::User => Self::User,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Guard {
    Fence,
    DenyAll,
    Unguarded,
    LifecycleOnly,
}
impl From<ManagementGuard> for Guard {
    fn from(value: ManagementGuard) -> Self {
        match value {
            ManagementGuard::Fence => Self::Fence,
            ManagementGuard::DenyAll => Self::DenyAll,
            ManagementGuard::Unguarded => Self::Unguarded,
            ManagementGuard::LifecycleOnly => Self::LifecycleOnly,
        }
    }
}
impl From<Guard> for ManagementGuard {
    fn from(value: Guard) -> Self {
        match value {
            Guard::Fence => Self::Fence,
            Guard::DenyAll => Self::DenyAll,
            Guard::Unguarded => Self::Unguarded,
            Guard::LifecycleOnly => Self::LifecycleOnly,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum State {
    Planned,
    Applied,
    Reclaiming,
    Reclaimed,
    Quarantined,
    Candidate,
    Conflict,
}
impl From<EffectState> for State {
    fn from(value: EffectState) -> Self {
        match value {
            EffectState::Planned => Self::Planned,
            EffectState::Applied => Self::Applied,
            EffectState::Reclaiming => Self::Reclaiming,
            EffectState::Reclaimed => Self::Reclaimed,
            EffectState::Quarantined => Self::Quarantined,
            EffectState::Candidate => Self::Candidate,
            EffectState::Conflict => Self::Conflict,
        }
    }
}
impl From<State> for EffectState {
    fn from(value: State) -> Self {
        match value {
            State::Planned => Self::Planned,
            State::Applied => Self::Applied,
            State::Reclaiming => Self::Reclaiming,
            State::Reclaimed => Self::Reclaimed,
            State::Quarantined => Self::Quarantined,
            State::Candidate => Self::Candidate,
            State::Conflict => Self::Conflict,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum Scope {
    Instance { instance: String, epoch: Epoch },
    Product,
    CoreBinary { sha256: String },
}

impl From<EffectScope> for Scope {
    fn from(value: EffectScope) -> Self {
        match value {
            EffectScope::Instance { instance, epoch } => Self::Instance {
                instance: instance.0,
                epoch,
            },
            EffectScope::Product => Self::Product,
            EffectScope::CoreBinary { sha256 } => Self::CoreBinary { sha256 },
        }
    }
}
impl From<Scope> for EffectScope {
    fn from(value: Scope) -> Self {
        match value {
            Scope::Instance { instance, epoch } => Self::Instance {
                instance: instance.into(),
                epoch,
            },
            Scope::Product => Self::Product,
            Scope::CoreBinary { sha256 } => Self::CoreBinary { sha256 },
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StoredEffect {
    scope: Scope,
    kind: String,
    key: ObjectKey,
    undo: Undo,
    persistence: Persistence,
    state: State,
    boot: BootId,
    observation: Option<Observation>,
    failures: u32,
    last_error: Option<String>,
    recorded_at: jiff::Timestamp,
}
impl From<Effect> for StoredEffect {
    fn from(value: Effect) -> Self {
        let Effect {
            id: _,
            scope,
            kind,
            key,
            undo,
            persistence,
            state,
            boot,
            observation,
            failures,
            last_error,
            recorded_at,
        } = value;
        Self {
            scope: scope.into(),
            kind: kind.as_str().into(),
            key,
            undo,
            persistence,
            state: state.into(),
            boot,
            observation,
            failures,
            last_error,
            recorded_at,
        }
    }
}
impl StoredEffect {
    pub(super) fn into_effect(self, id: EffectId) -> Result<Effect, LedgerError> {
        let Self {
            scope,
            kind,
            key,
            undo,
            persistence,
            state,
            boot,
            observation,
            failures,
            last_error,
            recorded_at,
        } = self;
        let kind = kind
            .parse()
            .map_err(|_| LedgerError::Unreadable("unknown effect kind".into()))?;
        Ok(Effect {
            id,
            scope: scope.into(),
            kind,
            key,
            undo,
            persistence,
            state: state.into(),
            boot,
            observation,
            failures,
            last_error,
            recorded_at,
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum StoredChange {
    PutInstance {
        instance: Box<Instance>,
        claims: Vec<String>,
    },
    SetDesired {
        instance: String,
        desired: i32,
    },
    RemoveInstance(String),
    RetryReclaim(String),
    RetryStart(String),
    ResolveCandidates(Vec<Decision>),
    SetAllowList(Vec<Allow>),
    SelectCore(Option<String>),
    PurgeAll,
}
impl From<Change> for StoredChange {
    fn from(value: Change) -> Self {
        match value {
            Change::PutInstance { instance, claims } => Self::PutInstance {
                instance: Box::new((*instance).into()),
                claims,
            },
            Change::SetDesired { instance, desired } => Self::SetDesired {
                instance: instance.0,
                desired: desired as i32,
            },
            Change::RemoveInstance(i) => Self::RemoveInstance(i.0),
            Change::RetryReclaim(i) => Self::RetryReclaim(i.0),
            Change::RetryStart(i) => Self::RetryStart(i.0),
            Change::ResolveCandidates(d) => {
                Self::ResolveCandidates(d.into_iter().map(Into::into).collect())
            }
            Change::SetAllowList(a) => Self::SetAllowList(a.into_iter().map(Into::into).collect()),
            Change::SelectCore(c) => Self::SelectCore(c),
            Change::PurgeAll => Self::PurgeAll,
        }
    }
}
impl TryFrom<StoredChange> for Change {
    type Error = LedgerError;
    fn try_from(value: StoredChange) -> Result<Self, Self::Error> {
        Ok(match value {
            StoredChange::PutInstance { instance, claims } => Self::PutInstance {
                instance: Box::new((*instance).into()),
                claims,
            },
            StoredChange::SetDesired { instance, desired } => Self::SetDesired {
                instance: instance.into(),
                desired: Desired::try_from(desired)
                    .map_err(|_| LedgerError::Unreadable("invalid desired state".into()))?,
            },
            StoredChange::RemoveInstance(i) => Self::RemoveInstance(i.into()),
            StoredChange::RetryReclaim(i) => Self::RetryReclaim(i.into()),
            StoredChange::RetryStart(i) => Self::RetryStart(i.into()),
            StoredChange::ResolveCandidates(d) => {
                Self::ResolveCandidates(d.into_iter().map(Into::into).collect())
            }
            StoredChange::SetAllowList(a) => {
                Self::SetAllowList(a.into_iter().map(Into::into).collect())
            }
            StoredChange::SelectCore(c) => Self::SelectCore(c),
            StoredChange::PurgeAll => Self::PurgeAll,
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StoredRequest {
    caller: String,
    digest: [u8; 32],
    receipt: StoredReceipt,
    changes: Vec<StoredChange>,
    generations: Vec<(String, Epoch)>,
    done: bool,
}
impl StoredRequest {
    pub(super) fn from_pair(request: RequestRecord, ticket: Ticket) -> Self {
        Self {
            caller: request.caller,
            digest: request.digest.0,
            receipt: ticket.receipt.into(),
            changes: ticket.changes.into_iter().map(Into::into).collect(),
            generations: ticket
                .generations
                .into_iter()
                .map(|(i, e)| (i.0, e))
                .collect(),
            done: ticket.done,
        }
    }
    pub(super) fn into_pair(
        self,
        request_id: RequestId,
    ) -> Result<(RequestRecord, Ticket), LedgerError> {
        Ok((
            RequestRecord {
                request_id,
                caller: self.caller,
                digest: RequestDigest(self.digest),
            },
            Ticket {
                receipt: self.receipt.into(),
                changes: self
                    .changes
                    .into_iter()
                    .map(TryInto::try_into)
                    .collect::<Result<_, _>>()?,
                generations: self
                    .generations
                    .into_iter()
                    .map(|(i, e)| (InstanceId(i), e))
                    .collect(),
                done: self.done,
            },
        ))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StoredGenerationEntry {
    inputs: Inputs,
    claims: Vec<String>,
    shared: Vec<String>,
}
impl From<GenerationEntry> for StoredGenerationEntry {
    fn from(value: GenerationEntry) -> Self {
        Self {
            inputs: value.inputs.into(),
            claims: value.claims,
            shared: value.shared.into_iter().map(|id| id.0).collect(),
        }
    }
}
impl From<StoredGenerationEntry> for GenerationEntry {
    fn from(value: StoredGenerationEntry) -> Self {
        Self {
            inputs: value.inputs.into(),
            claims: value.claims,
            shared: value.shared.into_iter().map(EffectId).collect(),
        }
    }
}
