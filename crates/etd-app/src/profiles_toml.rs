//! TOML-backed [`crate::ProfileStore`]: atomic replace, migration of older
//! layouts, original kept on write failure. Owned by A1.
//!
//! The file never contains a network secret: the stored layout has no field
//! for it, so one typed into the file by hand is ignored and disappears at
//! the next save. Error messages never quote file content for the same
//! reason.
//!
//! Layouts: version 1 is current. A file without a `version` key is the
//! pre-versioning layout (version 0); it is migrated in memory on load and
//! rewritten by the next save. A file from a newer version, or one that does
//! not parse, is never overwritten.
use crate::{Profile, ProfileError, ProfileStore};
use etd_contract::v1::{NetworkFlags, PortForward, network_spec::Ipv4};
use etd_contract::{InstanceId, NetworkSpec};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

pub const PROFILE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone)]
pub struct TomlProfileStore {
    path: PathBuf,
}

impl TomlProfileStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// `profiles.toml` in the user's configuration directory; `None` when the
    /// system reports no home directory.
    pub fn default_path() -> Option<PathBuf> {
        directories::ProjectDirs::from("", "", "EasyTierDesk")
            .map(|dirs| dirs.config_dir().join("profiles.toml"))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn read(&self) -> Result<Option<Vec<Profile>>, ProfileError> {
        match fs::read_to_string(&self.path) {
            Ok(text) => parse(&text).map(Some),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                Err(ProfileError::Corrupt("not UTF-8 text".into()))
            }
            Err(error) => Err(io_error("read", &error)),
        }
    }
}

impl ProfileStore for TomlProfileStore {
    fn load(&self) -> Result<Vec<Profile>, ProfileError> {
        Ok(self.read()?.unwrap_or_default())
    }

    fn save(&self, profiles: &[Profile]) -> Result<(), ProfileError> {
        // Refuses to replace a file this build cannot read completely.
        self.read()?;
        check_unique(profiles)?;
        let document = Document {
            version: PROFILE_SCHEMA_VERSION,
            profile: profiles.iter().map(StoredProfile::from).collect(),
        };
        let text = toml::to_string_pretty(&document)
            .map_err(|error| ProfileError::Io(format!("cannot encode profiles: {error}")))?;
        write_atomically(&self.path, text.as_bytes()).map_err(|error| io_error("write", &error))
    }
}

fn io_error(action: &str, error: &io::Error) -> ProfileError {
    ProfileError::Io(format!("cannot {action} the profile library: {error}"))
}

fn write_atomically(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let directory = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    fs::create_dir_all(directory)?;
    // Same directory, so the final rename stays on one file system. The
    // temporary file is private to the user and removed if anything fails.
    let mut file = tempfile::NamedTempFile::new_in(directory)?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    file.persist(path).map_err(|error| error.error)?;
    #[cfg(unix)]
    fs::File::open(directory)?.sync_all()?;
    Ok(())
}

fn check_unique(profiles: &[Profile]) -> Result<(), ProfileError> {
    let mut seen = HashSet::new();
    for profile in profiles {
        if profile.instance_id.0.is_empty() {
            return Err(ProfileError::Corrupt("a profile has no instance id".into()));
        }
        if !seen.insert(&profile.instance_id) {
            return Err(ProfileError::Corrupt(format!(
                "instance id {} appears twice",
                profile.instance_id
            )));
        }
    }
    Ok(())
}

/// The parser's message and line, without the source snippet it would print.
fn corrupt(text: &str, error: &toml::de::Error) -> ProfileError {
    let line = error.span().map(|span| {
        text.as_bytes()
            .iter()
            .take(span.start)
            .filter(|byte| **byte == b'\n')
            .count()
            + 1
    });
    ProfileError::Corrupt(match line {
        Some(line) => format!("line {line}: the file is not a valid profile library"),
        None => "the file is not a valid profile library".into(),
    })
}

fn parse(text: &str) -> Result<Vec<Profile>, ProfileError> {
    let table: toml::Table = toml::from_str(text).map_err(|error| corrupt(text, &error))?;
    let version = match table.get("version") {
        None => 0,
        Some(value) => value
            .as_integer()
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| ProfileError::Corrupt("`version` is not a version number".into()))?,
    };
    let profiles = match version {
        0 => {
            let document: DocumentV0 =
                toml::from_str(text).map_err(|error| corrupt(text, &error))?;
            document
                .network
                .into_iter()
                .map(Profile::from)
                .collect::<Vec<_>>()
        }
        PROFILE_SCHEMA_VERSION => {
            let document: Document = toml::from_str(text).map_err(|error| corrupt(text, &error))?;
            document
                .profile
                .into_iter()
                .map(Profile::try_from)
                .collect::<Result<_, _>>()?
        }
        found => {
            return Err(ProfileError::UnsupportedVersion {
                found,
                supported: PROFILE_SCHEMA_VERSION,
            });
        }
    };
    check_unique(&profiles)?;
    Ok(profiles)
}

// ------------------------------------------------------------ version 0

/// An empty file is an empty version 0 library. Any other unversioned file
/// must have `[[network]]` tables only, so that an unrelated or damaged file
/// is not mistaken for an empty library.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DocumentV0 {
    #[serde(default)]
    network: Vec<NetworkV0>,
}

#[derive(Deserialize)]
struct NetworkV0 {
    id: String,
    #[serde(default)]
    name: String,
    network_name: String,
    /// "dhcp", "a.b.c.d/len", or absent.
    #[serde(default)]
    ipv4: Option<String>,
    #[serde(default)]
    peers: Vec<String>,
    #[serde(default)]
    listeners: Vec<String>,
}

impl From<NetworkV0> for Profile {
    fn from(old: NetworkV0) -> Self {
        Self {
            instance_id: InstanceId(old.id),
            spec: NetworkSpec {
                display_name: old.name,
                network_name: old.network_name,
                ipv4: old.ipv4.map(|value| {
                    if value == "dhcp" {
                        Ipv4::Dhcp(true)
                    } else {
                        Ipv4::Ipv4Cidr(value)
                    }
                }),
                peers: old.peers,
                listeners: old.listeners,
                ..NetworkSpec::default()
            },
            updated_at: jiff::Timestamp::UNIX_EPOCH,
        }
    }
}

// ------------------------------------------------------------ version 1

#[derive(Serialize, Deserialize)]
struct Document {
    version: u32,
    #[serde(default)]
    profile: Vec<StoredProfile>,
}

#[derive(Serialize, Deserialize)]
struct StoredProfile {
    instance_id: String,
    updated_at: String,
    network: StoredNetwork,
}

#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
struct StoredNetwork {
    display_name: String,
    network_name: String,
    hostname: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ipv4_cidr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dhcp: Option<bool>,
    peers: Vec<String>,
    listeners: Vec<String>,
    no_listener: bool,
    proxy_cidrs: Vec<String>,
    exit_nodes: Vec<String>,
    enable_exit_node: bool,
    mtu: u32,
    no_tun: bool,
    socks5_port: u32,
    magic_dns: bool,
    public_ipv6_provider: bool,
    // Tables go last: TOML needs plain values first.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    port_forwards: Vec<StoredPortForward>,
    #[serde(skip_serializing_if = "Option::is_none")]
    flags: Option<StoredFlags>,
}

#[derive(Serialize, Deserialize)]
struct StoredPortForward {
    /// The wire value, so that a protocol added later survives a rewrite.
    protocol: i32,
    bind: String,
    destination: String,
}

#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
struct StoredFlags {
    latency_first: bool,
    disable_encryption: bool,
    enable_kcp_proxy: bool,
    enable_quic_proxy: bool,
    disable_p2p: bool,
    disable_udp_hole_punching: bool,
    relay_all_peer_rpc: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    multi_thread: Option<bool>,
    private_mode: bool,
    disable_ipv6: bool,
    use_smoltcp: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    bind_device: Option<bool>,
    compression: String,
}

// The conversions below name every contract field, without `..`, so that a
// field added to the contract cannot be silently dropped from profiles.

impl From<&Profile> for StoredProfile {
    fn from(profile: &Profile) -> Self {
        let NetworkSpec {
            display_name,
            network_name,
            network_secret: _,
            network_secret_set: _,
            hostname,
            ipv4,
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
        } = profile.spec.clone();
        let (ipv4_cidr, dhcp) = match ipv4 {
            Some(Ipv4::Ipv4Cidr(cidr)) => (Some(cidr), None),
            Some(Ipv4::Dhcp(dhcp)) => (None, Some(dhcp)),
            None => (None, None),
        };
        Self {
            instance_id: profile.instance_id.0.clone(),
            updated_at: profile.updated_at.to_string(),
            network: StoredNetwork {
                display_name,
                network_name,
                hostname,
                ipv4_cidr,
                dhcp,
                peers,
                listeners,
                no_listener,
                proxy_cidrs,
                exit_nodes,
                enable_exit_node,
                mtu,
                no_tun,
                socks5_port,
                magic_dns,
                public_ipv6_provider,
                port_forwards: port_forwards.into_iter().map(Into::into).collect(),
                flags: flags.map(Into::into),
            },
        }
    }
}

impl TryFrom<StoredProfile> for Profile {
    type Error = ProfileError;

    fn try_from(stored: StoredProfile) -> Result<Self, Self::Error> {
        let updated_at = stored.updated_at.parse().map_err(|_| {
            ProfileError::Corrupt(format!(
                "profile {} has an invalid `updated_at`",
                stored.instance_id
            ))
        })?;
        let n = stored.network;
        let ipv4 = match (n.ipv4_cidr, n.dhcp) {
            (Some(_), Some(_)) => {
                return Err(ProfileError::Corrupt(format!(
                    "profile {} sets both `ipv4_cidr` and `dhcp`",
                    stored.instance_id
                )));
            }
            (Some(cidr), None) => Some(Ipv4::Ipv4Cidr(cidr)),
            (None, Some(dhcp)) => Some(Ipv4::Dhcp(dhcp)),
            (None, None) => None,
        };
        Ok(Self {
            instance_id: InstanceId(stored.instance_id),
            spec: NetworkSpec {
                display_name: n.display_name,
                network_name: n.network_name,
                network_secret: None,
                network_secret_set: false,
                hostname: n.hostname,
                ipv4,
                peers: n.peers,
                listeners: n.listeners,
                no_listener: n.no_listener,
                proxy_cidrs: n.proxy_cidrs,
                exit_nodes: n.exit_nodes,
                enable_exit_node: n.enable_exit_node,
                mtu: n.mtu,
                no_tun: n.no_tun,
                socks5_port: n.socks5_port,
                port_forwards: n.port_forwards.into_iter().map(Into::into).collect(),
                magic_dns: n.magic_dns,
                public_ipv6_provider: n.public_ipv6_provider,
                flags: n.flags.map(Into::into),
            },
            updated_at,
        })
    }
}

impl From<PortForward> for StoredPortForward {
    fn from(forward: PortForward) -> Self {
        let PortForward {
            protocol,
            bind,
            destination,
        } = forward;
        Self {
            protocol,
            bind,
            destination,
        }
    }
}

impl From<StoredPortForward> for PortForward {
    fn from(stored: StoredPortForward) -> Self {
        Self {
            protocol: stored.protocol,
            bind: stored.bind,
            destination: stored.destination,
        }
    }
}

macro_rules! convert_flags {
    ($from:ident => $to:ident) => {
        impl From<$from> for $to {
            fn from(flags: $from) -> Self {
                let $from {
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
                } = flags;
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
    };
}
convert_flags!(NetworkFlags => StoredFlags);
convert_flags!(StoredFlags => NetworkFlags);
