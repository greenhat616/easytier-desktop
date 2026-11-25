//! Old and new peers read each other's messages: every message decodes from
//! empty input (a newer reader of an older writer that sent nothing new) and
//! skips fields it does not know (an older reader of a newer writer).
use etd_contract::FILE_DESCRIPTOR_SET;
use etd_contract::v1::*;
use prost::Message;
use std::collections::BTreeSet;

/// Bytes a future minor version could append: an unknown varint field and an
/// unknown length-delimited field.
fn future_fields() -> Vec<u8> {
    let mut bytes = Vec::new();
    prost::encoding::uint64::encode(19_999, &7, &mut bytes);
    prost::encoding::string::encode(19_998, &"from-the-future".to_owned(), &mut bytes);
    bytes
}

fn check<T: Message + Default + PartialEq + std::fmt::Debug>(sample: T) {
    // Newer reader, older writer: absent fields take their defaults.
    assert_eq!(T::decode(&[][..]).unwrap(), T::default());
    // Round trip of a populated message.
    let bytes = sample.encode_to_vec();
    assert_eq!(T::decode(bytes.as_slice()).unwrap(), sample);
    // Older reader, newer writer: unknown fields are skipped.
    let mut newer = bytes.clone();
    newer.extend(future_fields());
    assert_eq!(T::decode(newer.as_slice()).unwrap(), sample);
}

macro_rules! all_messages {
    ($($name:ident => $sample:expr),* $(,)?) => {
        const MESSAGES: &[&str] = &[$(stringify!($name)),*];
        #[test]
        fn every_message_reads_old_and_new() {
            $(check::<$name>($sample);)*
        }
    };
}

fn header() -> Option<MutationHeader> {
    Some(MutationHeader {
        request_id: "req-1".into(),
        expected_revision: 12,
    })
}
fn receipt() -> Option<Receipt> {
    Some(Receipt {
        request_id: "req-1".into(),
        revision: 13,
        ticket: "t-1".into(),
        accepted_unix_ms: 1_764_000_000_000,
    })
}
fn spec() -> NetworkSpec {
    NetworkSpec {
        display_name: "home".into(),
        network_name: "net".into(),
        network_secret: Some("secret".into()),
        network_secret_set: true,
        hostname: "pc".into(),
        ipv4: Some(network_spec::Ipv4::Ipv4Cidr("10.0.0.2/24".into())),
        peers: vec!["tcp://203.0.113.1:11010".into()],
        listeners: vec!["udp://0.0.0.0:11010".into()],
        no_listener: false,
        proxy_cidrs: vec!["192.168.1.0/24".into()],
        exit_nodes: vec!["10.0.0.1".into()],
        enable_exit_node: true,
        mtu: 1380,
        no_tun: false,
        socks5_port: 1080,
        port_forwards: vec![PortForward {
            protocol: TransportProtocol::Tcp as i32,
            bind: "127.0.0.1:8080".into(),
            destination: "10.0.0.3:80".into(),
        }],
        magic_dns: true,
        public_ipv6_provider: false,
        flags: Some(NetworkFlags {
            latency_first: true,
            compression: "zstd".into(),
            ..Default::default()
        }),
    }
}
fn desired_instance() -> DesiredInstance {
    DesiredInstance {
        instance_id: "3f9a1c2e".into(),
        spec: Some(spec()),
        desired: Desired::Running as i32,
    }
}
fn exit() -> ExitInfo {
    ExitInfo {
        code: Some(1),
        signal: None,
        abnormal: true,
        at_unix_ms: 5,
    }
}
fn status() -> InstanceStatus {
    InstanceStatus {
        instance_id: "3f9a1c2e".into(),
        state: InstanceState::Backoff as i32,
        epoch: 7,
        management: ManagementAccess::Available as i32,
        restart_attempt: 1,
        next_restart_unix_ms: 9,
        last_exit: Some(exit()),
        message: "crashed, restarting in 1s".into(),
        interface_name: "etd-3f9a1c2e".into(),
        addresses: vec!["10.0.0.2/24".into()],
        core_version: "2.7.1".into(),
        state_since_unix_ms: 3,
        open_residues: 2,
    }
}
fn cursor() -> EventCursor {
    EventCursor {
        stream_id: "run-1".into(),
        seq: 42,
    }
}
fn report() -> ReclaimReport {
    ReclaimReport {
        generated_unix_ms: 1,
        instances: vec![InstanceReclaim {
            instance_id: "3f9a1c2e".into(),
            epoch: 7,
            status: ReclaimStatus::Quarantined as i32,
            residues: vec![Residue {
                effect_id: "e-1".into(),
                kind: "win.firewall_rule".into(),
                identity: "EasyTier etd-3f9a1c2e - TCP Protocol (Inbound)".into(),
                failures: 5,
                last_error: "access denied".into(),
                state: ResidueState::Failing as i32,
            }],
            reason: "reclaim failed 5 times".into(),
        }],
        candidates: vec![Candidate {
            candidate_id: "c-1".into(),
            kind: "win.tun".into(),
            identity: "etd-3f9a1c2e".into(),
            origin: CandidateOrigin::NoCredential as i32,
            instance_id: "3f9a1c2e".into(),
            epoch: 7,
            detail: "planned record without read-back".into(),
        }],
        conflicts: vec![Conflict {
            kind: "win.tun".into(),
            identity: "etd-3f9a1c2e".into(),
            expected: "luid=1".into(),
            found: "luid=2".into(),
            effect_id: "e-2".into(),
        }],
        notes: vec![notice()],
    }
}
fn notice() -> Notice {
    Notice {
        level: NoticeLevel::Warning as i32,
        code: "magic_dns.shared".into(),
        message: "left in place".into(),
        instance_id: String::new(),
    }
}
fn principal() -> Option<OsPrincipal> {
    Some(OsPrincipal {
        id: Some(os_principal::Id::WindowsUserSid(
            "S-1-5-21-1-2-3-1001".into(),
        )),
    })
}

all_messages! {
    Hello => Hello { major: 1, minor: 0, build: "0.4.2".into(), client_kind: ClientKind::Desktop as i32 },
    Welcome => Welcome {
        major: 1, minor: 5, capabilities: vec!["instances".into()], role: Role::Control as i32,
        host_build: "0.4.2".into(), host_mode: HostMode::Service as i32,
        phase: HostPhase::Serving as i32, stream_id: "run-1".into(),
    },
    MutationHeader => header().unwrap(),
    Receipt => receipt().unwrap(),
    PortForward => spec().port_forwards[0].clone(),
    NetworkFlags => spec().flags.unwrap(),
    NetworkSpec => spec(),
    DesiredInstance => desired_instance(),
    ExitInfo => exit(),
    InstanceStatus => status(),
    InstanceView => InstanceView { desired: Some(desired_instance()), status: Some(status()) },
    EventCursor => cursor(),
    SnapshotRequest => SnapshotRequest {},
    HostSnapshot => HostSnapshot {
        revision: 13,
        instances: vec![InstanceView { desired: Some(desired_instance()), status: Some(status()) }],
        cursor: Some(cursor()), phase: HostPhase::Serving as i32, reclaim: Some(report()),
        default_core_version: "2.7.1".into(),
    },
    SubscribeRequest => SubscribeRequest { after: Some(cursor()) },
    DesiredChanged => DesiredChanged {
        revision: 13, instance: Some(desired_instance()), request_id: "req-1".into(), ticket: "t-1".into(),
    },
    InstanceRemoved => InstanceRemoved { instance_id: "3f9a1c2e".into(), revision: 14 },
    InstanceExited => InstanceExited {
        instance_id: "3f9a1c2e".into(), epoch: 7, exit: Some(exit()), attempt: 1,
        restart_at_unix_ms: 10, gave_up: false,
    },
    HostPhaseChanged => HostPhaseChanged { phase: HostPhase::ShuttingDown as i32 },
    ResyncRequired => ResyncRequired { reason: "cursor expired".into() },
    Notice => notice(),
    Event => Event {
        cursor: Some(cursor()), at_unix_ms: 11,
        payload: Some(event::Payload::InstanceStatus(status())),
    },
    ApplyRequest => ApplyRequest {
        header: header(), instance_id: "3f9a1c2e".into(), spec: Some(spec()),
        desired: Desired::Running as i32,
    },
    ApplyResponse => ApplyResponse { receipt: receipt() },
    SetDesiredRequest => SetDesiredRequest {
        header: header(), instance_id: "3f9a1c2e".into(), desired: Desired::Stopped as i32,
    },
    SetDesiredResponse => SetDesiredResponse { receipt: receipt() },
    RemoveInstanceRequest => RemoveInstanceRequest { header: header(), instance_id: "3f9a1c2e".into() },
    RemoveInstanceResponse => RemoveInstanceResponse { receipt: receipt() },
    GetReceiptRequest => GetReceiptRequest { request_id: "req-1".into() },
    GetReceiptResponse => GetReceiptResponse { receipt: receipt() },
    QueryRequest => QueryRequest { instance_id: "3f9a1c2e".into(), kind: QueryKind::Nodes as i32 },
    Node => Node {
        peer_id: 1, hostname: "pc".into(), ipv4_cidr: "10.0.0.2/24".into(), version: "2.7.1".into(),
        latency_us: 900, loss_rate: 0.01, nat_type: "full-cone".into(), tunnels: vec!["udp".into()],
        cost: 1, is_self: true, rx_bytes: 2, tx_bytes: 3, ipv6_cidr: String::new(),
    },
    NodeList => NodeList { nodes: vec![Node { peer_id: 2, ..Default::default() }] },
    Route => Route {
        peer_id: 2, hostname: "peer".into(), ipv4_cidr: "10.0.0.3/24".into(),
        proxy_cidrs: vec!["192.168.2.0/24".into()], next_hop_peer_id: 2, cost: 1, path_latency_us: 5,
    },
    RouteList => RouteList { routes: vec![Route { peer_id: 3, ..Default::default() }] },
    PeerTraffic => PeerTraffic { peer_id: 2, rx_bytes: 1, tx_bytes: 2 },
    TrafficStats => TrafficStats {
        rx_bytes: 1, tx_bytes: 2, rx_packets: 3, tx_packets: 4,
        peers: vec![PeerTraffic { peer_id: 2, rx_bytes: 1, tx_bytes: 2 }],
    },
    QueryResponse => QueryResponse {
        result: Some(query_response::Result::Traffic(TrafficStats { rx_bytes: 1, ..Default::default() })),
        at_unix_ms: 12,
    },
    StreamLogsRequest => StreamLogsRequest { instance_id: "3f9a1c2e".into(), tail_lines: 100, follow: true },
    LogLine => LogLine {
        at_unix_ms: 1, source: LogSource::CoreStderr as i32, text: "hello".into(),
        instance_id: "3f9a1c2e".into(), epoch: 7,
    },
    Residue => report().instances[0].residues[0].clone(),
    InstanceReclaim => report().instances[0].clone(),
    Candidate => report().candidates[0].clone(),
    Conflict => report().conflicts[0].clone(),
    GetReclaimReportRequest => GetReclaimReportRequest {},
    ReclaimReport => report(),
    RetryReclaimRequest => RetryReclaimRequest { header: header(), instance_id: "3f9a1c2e".into() },
    RetryReclaimResponse => RetryReclaimResponse { receipt: receipt() },
    CandidateDecision => CandidateDecision { candidate_id: "c-1".into(), action: CandidateAction::Delete as i32 },
    ResolveCandidatesRequest => ResolveCandidatesRequest {
        header: header(),
        decisions: vec![CandidateDecision { candidate_id: "c-1".into(), action: CandidateAction::Keep as i32 }],
    },
    ResolveCandidatesResponse => ResolveCandidatesResponse { receipt: receipt() },
    ReleaseLeaseRequest => ReleaseLeaseRequest { instances: LeaseRelease::StopInstances as i32 },
    ReleaseLeaseResponse => ReleaseLeaseResponse { host_exiting: true },
    OsPrincipal => principal().unwrap(),
    AllowEntry => AllowEntry { principal: principal(), role: Role::Admin as i32, display_name: "me".into() },
    GetAllowListRequest => GetAllowListRequest {},
    GetAllowListResponse => GetAllowListResponse {
        entries: vec![AllowEntry { principal: principal(), role: Role::Viewer as i32, display_name: String::new() }],
        revision: 3,
    },
    SetAllowListRequest => SetAllowListRequest {
        header: header(),
        entries: vec![AllowEntry { principal: principal(), role: Role::Control as i32, display_name: String::new() }],
    },
    SetAllowListResponse => SetAllowListResponse { receipt: receipt() },
    CoreEntry => CoreEntry {
        version: "2.7.1".into(), proto_revision: "c97f36b".into(), sha256: "ab".repeat(32),
        support: CoreSupport::Profiled as i32,
    },
    ListCoresRequest => ListCoresRequest {},
    ListCoresResponse => ListCoresResponse {
        cores: vec![CoreEntry { version: "2.7.1".into(), ..Default::default() }],
        default_version: "2.7.1".into(),
    },
    SelectCoreRequest => SelectCoreRequest { header: header(), version: "2.7.1".into() },
    SelectCoreResponse => SelectCoreResponse { receipt: receipt() },
    PurgeAllDataRequest => PurgeAllDataRequest { header: header(), confirm: true },
    PurgeAllDataResponse => PurgeAllDataResponse { receipt: receipt() },
    ErrorDetail => ErrorDetail {
        code: ErrorCode::RevisionConflict as i32, message: "stale".into(), current_revision: 14,
        features: vec!["magic_dns".into()], instance_id: "3f9a1c2e".into(), host_major: 1, host_minor: 0,
    },
}

#[test]
fn every_contract_message_is_covered() {
    let set = prost_types::FileDescriptorSet::decode(FILE_DESCRIPTOR_SET).unwrap();
    let declared: BTreeSet<String> = set
        .file
        .iter()
        .filter(|file| file.package() == "etd.v1")
        .flat_map(|file| file.message_type.iter())
        .map(|message| message.name().to_owned())
        .collect();
    let covered: BTreeSet<String> = MESSAGES.iter().map(|name| (*name).to_owned()).collect();
    assert_eq!(declared, covered, "add new messages to all_messages!");
}

#[test]
fn unknown_enum_values_survive() {
    // An older reader keeps an enum value it does not know as a raw number
    // and reports it as UNSPECIFIED through the typed accessor.
    let mut bytes = Vec::new();
    prost::encoding::int32::encode(2, &999, &mut bytes);
    let status = InstanceStatus::decode(bytes.as_slice()).unwrap();
    assert_eq!(status.state, 999);
    assert_eq!(status.state(), InstanceState::Unspecified);
}
