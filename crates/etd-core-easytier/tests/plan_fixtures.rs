//! Shared fixtures for the `plan_*` tests (included with `#[path]`; as its
//! own test target it holds no tests).
#![allow(dead_code)]

use etd_contract::{
    InstanceId, NetworkSpec,
    v1::{NetworkFlags, PortForward, TransportProtocol, network_spec::Ipv4},
};
use etd_core_api::{CoreRef, LaunchContext, LaunchInputs, ManagementGuard, Privilege};
use etd_sysfx::{Epoch, InstallKey, naming};
use std::path::PathBuf;

pub const INSTANCE: &str = "3f9a1c2e-5b7d-4e21-9c4a-7d2f8e1b6a90";
pub const SECRET: &str = "s3cr3t-\"quoted\"-p@ss";
pub const SHA256: [u8; 32] = [0xab; 32];
pub const EPOCH: u64 = 7;

pub fn instance() -> InstanceId {
    InstanceId::from(INSTANCE)
}

/// Interface name derived exactly as the host derives it.
pub fn interface_name() -> String {
    naming::interface_name(&InstallKey([7; 32]), &instance())
}

/// Absolute on the host running the test.
pub fn runtime_dir() -> PathBuf {
    let root = if cfg!(windows) {
        PathBuf::from(r"C:\ProgramData\easytier-desktop\run")
    } else {
        PathBuf::from("/var/lib/easytier-desktop/run")
    };
    root.join(INSTANCE).join(EPOCH.to_string())
}

pub fn binary() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r"C:\Program Files\EasyTier Desktop\cores\2.7.1-c97f36b\easytier-core.exe")
    } else {
        PathBuf::from("/opt/easytier-desktop/cores/2.7.1-c97f36b/easytier-core")
    }
}

pub fn core(profile: Option<&str>) -> CoreRef {
    CoreRef {
        version: "2.7.1".into(),
        proto_revision: "c97f36b8".into(),
        sha256: SHA256,
        binary: binary(),
        profile: profile.map(str::to_owned),
    }
}

pub fn ctx_with(
    spec: NetworkSpec,
    privilege: Privilege,
    guard: ManagementGuard,
    profile: Option<&str>,
) -> LaunchContext {
    LaunchContext {
        instance: instance(),
        epoch: Epoch(EPOCH),
        inputs: LaunchInputs {
            spec,
            spec_revision: 42,
            runtime_dir: runtime_dir(),
            interface_name: interface_name(),
            management: "127.0.0.1:15999".parse().unwrap(),
            privilege,
            guard,
            core: core(profile),
        },
    }
}

/// Privileged host, fenced, first profile.
pub fn ctx(spec: NetworkSpec) -> LaunchContext {
    ctx_with(
        spec,
        Privilege::System,
        ManagementGuard::Fence,
        Some("2.7.1-c97f36b"),
    )
}

/// User host, unguarded, first profile.
pub fn user_ctx(spec: NetworkSpec) -> LaunchContext {
    ctx_with(
        spec,
        Privilege::User,
        ManagementGuard::Unguarded,
        Some("2.7.1-c97f36b"),
    )
}

/// Minimal TUN instance with a static address and a secret.
pub fn basic() -> NetworkSpec {
    NetworkSpec {
        display_name: "Office".into(),
        network_name: "office-net".into(),
        network_secret: Some(SECRET.into()),
        hostname: "laptop".into(),
        ipv4: Some(Ipv4::Ipv4Cidr("10.144.144.2/24".into())),
        peers: vec!["tcp://public.example.org:11010".into()],
        ..Default::default()
    }
}

pub fn dhcp() -> NetworkSpec {
    NetworkSpec {
        ipv4: Some(Ipv4::Dhcp(true)),
        listeners: vec!["udp://0.0.0.0:11010".into(), "tcp://[::]:11010".into()],
        ..basic()
    }
}

/// Everything the spec can set.
pub fn full() -> NetworkSpec {
    NetworkSpec {
        display_name: "Everything".into(),
        network_name: "lab".into(),
        network_secret: Some(SECRET.into()),
        hostname: "bench-01".into(),
        ipv4: Some(Ipv4::Ipv4Cidr("10.126.126.1/24".into())),
        peers: vec![
            "udp://198.51.100.7:11010".into(),
            "wss://relay.example.org:443/et".into(),
            "txt://et.example.org".into(),
        ],
        listeners: vec!["tcp://0.0.0.0:21010".into(), "quic://0.0.0.0:21012".into()],
        no_listener: false,
        proxy_cidrs: vec!["192.168.10.0/24".into(), "172.16.0.0/12".into()],
        exit_nodes: vec!["10.126.126.9".into()],
        enable_exit_node: true,
        mtu: 1300,
        no_tun: false,
        socks5_port: 1080,
        port_forwards: vec![
            PortForward {
                protocol: TransportProtocol::Tcp as i32,
                bind: "0.0.0.0:8080".into(),
                destination: "10.126.126.5:80".into(),
            },
            PortForward {
                protocol: TransportProtocol::Udp as i32,
                bind: "127.0.0.1:5353".into(),
                destination: "10.126.126.5:53".into(),
            },
        ],
        magic_dns: false,
        public_ipv6_provider: false,
        flags: Some(NetworkFlags {
            latency_first: true,
            disable_encryption: false,
            enable_kcp_proxy: true,
            enable_quic_proxy: true,
            disable_p2p: false,
            disable_udp_hole_punching: true,
            relay_all_peer_rpc: true,
            multi_thread: Some(true),
            private_mode: true,
            disable_ipv6: true,
            use_smoltcp: true,
            bind_device: Some(true),
            compression: "zstd".into(),
        }),
        ..Default::default()
    }
}

/// No TUN: socks5 and port forwarding only (what a user host runs).
pub fn no_tun() -> NetworkSpec {
    NetworkSpec {
        ipv4: None,
        no_tun: true,
        socks5_port: 1080,
        no_listener: true,
        ..basic()
    }
}

pub fn magic_dns() -> NetworkSpec {
    NetworkSpec {
        magic_dns: true,
        ..basic()
    }
}

pub fn public_ipv6() -> NetworkSpec {
    NetworkSpec {
        public_ipv6_provider: true,
        ..basic()
    }
}

/// Without a secret (credential-style network name only).
pub fn no_secret() -> NetworkSpec {
    NetworkSpec {
        network_secret: None,
        ..basic()
    }
}

/// Replaces host-specific paths and the secret so snapshots are stable and
/// never contain it.
pub fn scrub(text: &str) -> String {
    let run = runtime_dir().to_string_lossy().into_owned();
    let bin = binary().to_string_lossy().into_owned();
    text.replace(&run, "<RUN>")
        .replace(&run.replace('\\', "\\\\"), "<RUN>")
        .replace(&bin, "<CORE>")
        .replace(&bin.replace('\\', "\\\\"), "<CORE>")
        .replace("<RUN>\\", "<RUN>/")
        .replace(SECRET, "<SECRET>")
        .replace(&SECRET.replace('"', "\\\""), "<SECRET>")
}
