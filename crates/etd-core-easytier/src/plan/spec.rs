//! `NetworkSpec` → validated settings → kernel TOML.
//!
//! The TOML schema is upstream's `Config` in
//! `easytier-core/src/config/toml.rs` (c97f36b) with flags from
//! `easytier-proto/proto/common.proto` `Flags` (snake_case keys, enums by
//! name). Everything the kernel reads comes from this file: the command line
//! carries only the file, the management portal and logging, so no CLI
//! `NetworkOptions` merge happens (`easytier/src/core.rs` `can_merge`).
use etd_contract::{
    InstanceId, NetworkSpec,
    v1::{NetworkFlags, PortForward, TransportProtocol, network_spec::Ipv4},
};
use etd_core_api::CoreError;
use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Listener port upstream's CLI expands by default (tcp/udp 11010, then
/// +1..+3 per scheme). Not applied here: an empty listener list means no
/// listeners, so the instance only dials out and hole-punches, because the
/// default set collides between instances and with an official install.
/// The UI offers that set as a suggestion (ruling msg#477).
pub const SUGGESTED_LISTENER_PORT: u16 = 11010;

/// Schemes the kernel can listen on or dial directly (`IpScheme`).
const IP_SCHEMES: &[&str] = &["tcp", "udp", "wg", "quic", "ws", "wss", "faketcp"];
/// Peer-only schemes resolved at run time to one of [`IP_SCHEMES`]
/// (`TunnelScheme`: http/https/txt/srv discovery).
const DISCOVERY_SCHEMES: &[&str] = &["http", "https", "txt", "srv"];

/// A URI with any userinfo (`user:pass@`) replaced by `***@`, for logs,
/// errors and `Debug`. The generated file keeps the URI as given.
pub fn redact_uri(uri: &str) -> String {
    let (prefix, rest) = match uri.find("://") {
        Some(i) => uri.split_at(i + 3),
        None => ("", uri),
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    match authority.rfind('@') {
        Some(at) => format!("{prefix}***{}{tail}", &authority[at..]),
        None => uri.to_owned(),
    }
}

/// A validated listener or peer URI. `Debug` redacts userinfo.
#[derive(Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub uri: String,
    pub scheme: String,
    /// `ip:port` when the authority is a literal address.
    pub socket: Option<SocketAddr>,
}

impl Endpoint {
    fn parse(field: &str, uri: &str, listener: bool) -> Result<Self, CoreError> {
        let invalid =
            |why: &str| CoreError::InvalidSpec(format!("{field}: {:?} {why}", redact_uri(uri)));
        let (scheme, rest) = uri
            .split_once("://")
            .ok_or_else(|| invalid("is not a scheme://host:port URI"))?;
        let scheme = scheme.to_ascii_lowercase();
        let known = IP_SCHEMES.contains(&scheme.as_str())
            || (!listener && DISCOVERY_SCHEMES.contains(&scheme.as_str()));
        if !known {
            return Err(invalid("has an unsupported scheme"));
        }
        if rest.is_empty() || rest.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(invalid("has no usable authority"));
        }
        let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
        let socket = authority.parse::<SocketAddr>().ok();
        if listener && socket.is_none() {
            return Err(invalid("must listen on ip:port"));
        }
        Ok(Self {
            uri: uri.to_owned(),
            scheme,
            socket,
        })
    }
}

impl std::fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Endpoint")
            .field("uri", &redact_uri(&self.uri))
            .field("scheme", &self.scheme)
            .field("socket", &self.socket)
            .finish()
    }
}

/// Port forward, validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Forward {
    pub proto: &'static str,
    pub bind: SocketAddr,
    pub destination: SocketAddr,
}

/// IPv4 network `a.b.c.d/len` with no host bits (what `cidr::Ipv4Cidr`
/// accepts).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Ipv4Net {
    pub addr: Ipv4Addr,
    pub len: u8,
}

impl std::fmt::Display for Ipv4Net {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.len)
    }
}

fn parse_ipv4_inet(field: &str, text: &str) -> Result<(Ipv4Addr, u8), CoreError> {
    let invalid = || CoreError::InvalidSpec(format!("{field}: {text:?} is not a.b.c.d/len"));
    let (addr, len) = text.split_once('/').ok_or_else(invalid)?;
    let addr: Ipv4Addr = addr.parse().map_err(|_| invalid())?;
    let len: u8 = len.parse().map_err(|_| invalid())?;
    if len > 32 {
        return Err(invalid());
    }
    Ok((addr, len))
}

fn parse_ipv4_net(field: &str, text: &str) -> Result<Ipv4Net, CoreError> {
    let (addr, len) = parse_ipv4_inet(field, text)?;
    let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
    if u32::from(addr) & !mask != 0 {
        return Err(CoreError::InvalidSpec(format!(
            "{field}: {text:?} has host bits set"
        )));
    }
    Ok(Ipv4Net { addr, len })
}

/// How the virtual IPv4 address is obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv4Mode {
    /// Neither address nor DHCP: no IPv4 on the interface until configured.
    None,
    Static {
        addr: Ipv4Addr,
        len: u8,
    },
    Dhcp,
}

/// Everything the adapter takes from a spec, validated and normalised.
/// `Debug` redacts the secret.
#[derive(Clone, PartialEq, Eq)]
pub struct Settings {
    pub network_name: String,
    /// Empty and absent both mean "no secret" (credential mode upstream).
    pub network_secret: Option<String>,
    pub hostname: Option<String>,
    pub ipv4: Ipv4Mode,
    pub peers: Vec<Endpoint>,
    /// Listeners; empty means none.
    pub listeners: Vec<Endpoint>,
    pub proxy_cidrs: Vec<Ipv4Net>,
    pub exit_nodes: Vec<IpAddr>,
    pub enable_exit_node: bool,
    pub mtu: Option<u32>,
    pub no_tun: bool,
    pub socks5_port: Option<u16>,
    pub port_forwards: Vec<Forward>,
    pub magic_dns: bool,
    pub public_ipv6_provider: bool,
    pub flags: NetworkFlags,
    /// Upstream `CompressionAlgoPb` name.
    pub compression: Option<&'static str>,
}

impl Settings {
    pub fn from_spec(spec: &NetworkSpec) -> Result<Self, CoreError> {
        let invalid = |message: String| CoreError::InvalidSpec(message);
        if spec.network_name.trim().is_empty() {
            return Err(invalid("network_name is empty".into()));
        }
        let ipv4 = match &spec.ipv4 {
            None | Some(Ipv4::Dhcp(false)) => Ipv4Mode::None,
            Some(Ipv4::Dhcp(true)) => Ipv4Mode::Dhcp,
            Some(Ipv4::Ipv4Cidr(text)) => {
                let (addr, len) = parse_ipv4_inet("ipv4_cidr", text)?;
                Ipv4Mode::Static { addr, len }
            }
        };
        let peers = spec
            .peers
            .iter()
            .map(|uri| Endpoint::parse("peers", uri, false))
            .collect::<Result<Vec<_>, _>>()?;
        if spec.no_listener && !spec.listeners.is_empty() {
            return Err(invalid("listeners given with no_listener set".into()));
        }
        let listeners = spec
            .listeners
            .iter()
            .map(|uri| Endpoint::parse("listeners", uri, true))
            .collect::<Result<Vec<_>, _>>()?;
        let proxy_cidrs = spec
            .proxy_cidrs
            .iter()
            .map(|text| parse_ipv4_net("proxy_cidrs", text))
            .collect::<Result<Vec<_>, _>>()?;
        let exit_nodes = spec
            .exit_nodes
            .iter()
            .map(|text| {
                text.parse::<IpAddr>()
                    .map_err(|_| invalid(format!("exit_nodes: {text:?} is not an IP address")))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let socks5_port = match spec.socks5_port {
            0 => None,
            port => Some(
                u16::try_from(port)
                    .map_err(|_| invalid(format!("socks5_port: {port} is not a port")))?,
            ),
        };
        let port_forwards = spec
            .port_forwards
            .iter()
            .map(forward)
            .collect::<Result<Vec<_>, _>>()?;
        let flags = spec.flags.clone().unwrap_or_default();
        let compression = match flags.compression.to_ascii_lowercase().as_str() {
            "" => None,
            "none" => Some("None"),
            "zstd" => Some("Zstd"),
            "lzo" => Some("Lzo"),
            other => {
                return Err(invalid(format!(
                    "flags.compression: unknown algorithm {other:?}"
                )));
            }
        };
        let mtu = match spec.mtu {
            0 => None,
            mtu if (576..=65535).contains(&mtu) => Some(mtu),
            mtu => return Err(invalid(format!("mtu: {mtu} is out of range"))),
        };
        let hostname = Some(spec.hostname.clone()).filter(|name| !name.is_empty());
        Ok(Self {
            network_name: spec.network_name.clone(),
            network_secret: spec.network_secret.clone().filter(|s| !s.is_empty()),
            hostname,
            ipv4,
            peers,
            listeners,
            proxy_cidrs,
            exit_nodes,
            enable_exit_node: spec.enable_exit_node,
            mtu,
            no_tun: spec.no_tun,
            socks5_port,
            port_forwards,
            magic_dns: spec.magic_dns,
            public_ipv6_provider: spec.public_ipv6_provider,
            flags,
            compression,
        })
    }

    /// Listener and peer schemes in use.
    pub fn uses_scheme(&self, scheme: &str) -> bool {
        self.listeners
            .iter()
            .chain(&self.peers)
            .any(|endpoint| endpoint.scheme == scheme)
    }
}

impl std::fmt::Debug for Settings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Settings")
            .field("network_name", &self.network_name)
            .field(
                "network_secret",
                &self.network_secret.as_ref().map(|_| "<redacted>"),
            )
            .field("hostname", &self.hostname)
            .field("ipv4", &self.ipv4)
            .field("peers", &self.peers)
            .field("listeners", &self.listeners)
            .field("proxy_cidrs", &self.proxy_cidrs)
            .field("exit_nodes", &self.exit_nodes)
            .field("enable_exit_node", &self.enable_exit_node)
            .field("mtu", &self.mtu)
            .field("no_tun", &self.no_tun)
            .field("socks5_port", &self.socks5_port)
            .field("port_forwards", &self.port_forwards)
            .field("magic_dns", &self.magic_dns)
            .field("public_ipv6_provider", &self.public_ipv6_provider)
            .field("flags", &self.flags)
            .field("compression", &self.compression)
            .finish()
    }
}

fn forward(pf: &PortForward) -> Result<Forward, CoreError> {
    let invalid = |why: String| CoreError::InvalidSpec(format!("port_forwards: {why}"));
    let proto = match TransportProtocol::try_from(pf.protocol) {
        Ok(TransportProtocol::Tcp) => "tcp",
        Ok(TransportProtocol::Udp) => "udp",
        _ => {
            return Err(invalid(format!(
                "protocol {} is not tcp or udp",
                pf.protocol
            )));
        }
    };
    let bind = pf
        .bind
        .parse::<SocketAddr>()
        .map_err(|_| invalid(format!("bind {:?} is not ip:port", pf.bind)))?;
    let destination = pf
        .destination
        .parse::<SocketAddr>()
        .map_err(|_| invalid(format!("destination {:?} is not ip:port", pf.destination)))?;
    Ok(Forward {
        proto,
        bind,
        destination,
    })
}

/// Kernel-side instance id: the contract id when it is a UUID (client ids
/// are), else a UUIDv5 of it, so the same instance always has the same
/// kernel id and E2 can address it over RPC.
pub fn kernel_instance_id(instance: &InstanceId) -> uuid::Uuid {
    uuid::Uuid::parse_str(instance.as_str()).unwrap_or_else(|_| {
        uuid::Uuid::new_v5(
            &uuid::Uuid::NAMESPACE_URL,
            format!("https://easytier-desktop.invalid/instance/{instance}").as_bytes(),
        )
    })
}

// ---------------------------------------------------------------- TOML

#[derive(Serialize)]
struct Toml<'a> {
    instance_name: String,
    instance_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    hostname: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ipv4: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dhcp: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ipv6_public_addr_provider: Option<bool>,
    listeners: Vec<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    exit_nodes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    socks5_proxy: Option<String>,
    network_identity: Identity<'a>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    peer: Vec<Peer<'a>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    proxy_network: Vec<ProxyNetwork>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    port_forward: Vec<PortForwardToml>,
    flags: Flags<'a>,
}

#[derive(Serialize)]
struct Identity<'a> {
    network_name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    network_secret: Option<&'a str>,
}

#[derive(Serialize)]
struct Peer<'a> {
    uri: &'a str,
}

#[derive(Serialize)]
struct ProxyNetwork {
    cidr: String,
}

#[derive(Serialize)]
struct PortForwardToml {
    bind_addr: String,
    dst_addr: String,
    proto: &'static str,
}

/// `[flags]`: every flag the spec controls is written explicitly, so the
/// plan does not depend on upstream defaults; the rest keep them.
#[derive(Serialize)]
struct Flags<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    dev_name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mtu: Option<u32>,
    no_tun: bool,
    latency_first: bool,
    enable_encryption: bool,
    enable_ipv6: bool,
    enable_exit_node: bool,
    use_smoltcp: bool,
    disable_p2p: bool,
    relay_all_peer_rpc: bool,
    disable_udp_hole_punching: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    multi_thread: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bind_device: Option<bool>,
    enable_kcp_proxy: bool,
    enable_quic_proxy: bool,
    accept_dns: bool,
    private_mode: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_compress_algo: Option<&'static str>,
}

/// The kernel configuration for one generation.
pub fn render_toml(
    settings: &Settings,
    instance: &InstanceId,
    platform: super::Platform,
    interface_name: &str,
) -> Result<String, CoreError> {
    let flags = &settings.flags;
    let doc = Toml {
        instance_name: format!("etd-{instance}"),
        instance_id: kernel_instance_id(instance).to_string(),
        hostname: settings.hostname.as_deref(),
        ipv4: match settings.ipv4 {
            Ipv4Mode::Static { addr, len } => Some(format!("{addr}/{len}")),
            _ => None,
        },
        dhcp: (settings.ipv4 == Ipv4Mode::Dhcp).then_some(true),
        ipv6_public_addr_provider: settings.public_ipv6_provider.then_some(true),
        listeners: settings.listeners.iter().map(|l| l.uri.as_str()).collect(),
        exit_nodes: settings
            .exit_nodes
            .iter()
            .map(ToString::to_string)
            .collect(),
        socks5_proxy: settings
            .socks5_port
            .map(|port| format!("socks5://0.0.0.0:{port}")),
        network_identity: Identity {
            network_name: &settings.network_name,
            network_secret: settings.network_secret.as_deref(),
        },
        peer: settings
            .peers
            .iter()
            .map(|p| Peer { uri: &p.uri })
            .collect(),
        proxy_network: settings
            .proxy_cidrs
            .iter()
            .map(|net| ProxyNetwork {
                cidr: net.to_string(),
            })
            .collect(),
        port_forward: settings
            .port_forwards
            .iter()
            .map(|pf| PortForwardToml {
                bind_addr: pf.bind.to_string(),
                dst_addr: pf.destination.to_string(),
                proto: pf.proto,
            })
            .collect(),
        flags: Flags {
            // macOS never applies a name (`virtual_nic.rs` sets `tun_name`
            // on Linux and Windows only); the system assigns utunN.
            dev_name: (platform != super::Platform::MacOs).then_some(interface_name),
            mtu: settings.mtu,
            no_tun: settings.no_tun,
            latency_first: flags.latency_first,
            enable_encryption: !flags.disable_encryption,
            enable_ipv6: !flags.disable_ipv6,
            enable_exit_node: settings.enable_exit_node,
            use_smoltcp: flags.use_smoltcp,
            disable_p2p: flags.disable_p2p,
            relay_all_peer_rpc: flags.relay_all_peer_rpc,
            disable_udp_hole_punching: flags.disable_udp_hole_punching,
            multi_thread: flags.multi_thread,
            bind_device: flags.bind_device,
            enable_kcp_proxy: flags.enable_kcp_proxy,
            enable_quic_proxy: flags.enable_quic_proxy,
            accept_dns: settings.magic_dns,
            private_mode: flags.private_mode,
            data_compress_algo: settings.compression,
        },
    };
    toml::to_string(&doc).map_err(|error| CoreError::InvalidSpec(format!("toml: {error}")))
}
