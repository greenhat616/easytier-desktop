//! `plan_launch`: TOML and command line from typed parameters (interface
//! name and loopback RPC port forced, no `rpc_portal` in TOML, `-c` only
//! to the epoch directory), side-effect prediction per adapter profile,
//! feature classification. Owned by E1.
//!
//! Pure: the result depends on the [`LaunchContext`] and the target
//! platform only (no clock, no file system, no environment), so the host can
//! replay a committed generation and get the same effects.
pub mod classify;
pub mod command;
pub mod effects;
pub mod spec;

use crate::profiles::{self, Profile};
use etd_core_api::{
    CoreEndpoint, CoreError, LaunchContext, LaunchPlan, ManagementGuard, PlannedFile, Privilege,
    Readiness, ReadinessCondition,
};
use etd_sysfx::naming;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

/// How long the kernel must stay alive before basic readiness.
pub const MINIMUM_UPTIME: Duration = Duration::from_secs(2);

/// Platform the plan is made for. `plan_launch` uses the build target;
/// tests plan for every platform from any host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Platform {
    Windows,
    Linux,
    MacOs,
}

impl Platform {
    /// The platform this crate is compiled for (Linux for any other Unix).
    pub const fn current() -> Self {
        if cfg!(windows) {
            Platform::Windows
        } else if cfg!(target_os = "macos") {
            Platform::MacOs
        } else {
            Platform::Linux
        }
    }
}

pub fn plan_launch(ctx: &LaunchContext) -> Result<LaunchPlan, CoreError> {
    plan_for(ctx, Platform::current())
}

/// [`plan_launch`] for an explicit platform.
pub fn plan_for(ctx: &LaunchContext, platform: Platform) -> Result<LaunchPlan, CoreError> {
    let inputs = &ctx.inputs;
    let profile = resolve_profile(ctx)?;
    check_guard(
        inputs.privilege,
        inputs.guard,
        profile,
        &inputs.core.version,
    )?;
    check_management(inputs.management)?;
    check_interface_name(&inputs.interface_name)?;
    if !inputs.runtime_dir.is_absolute() {
        return Err(CoreError::InvalidSpec(
            "runtime directory must be absolute".into(),
        ));
    }

    let settings = spec::Settings::from_spec(&inputs.spec)?;
    let features = classify::classify(&settings, platform, inputs.privilege);
    classify::enforce(&features)?;
    if !settings.no_tun && settings.ipv4 == spec::Ipv4Mode::None {
        // Upstream creates the TUN only once it has an address
        // (`runtime_host/tun_desktop.rs` `start_static_ip`, or a DHCP lease):
        // such an instance would never become ready.
        return Err(CoreError::InvalidSpec(
            "a TUN instance needs ipv4_cidr or dhcp; set no_tun otherwise".into(),
        ));
    }

    let toml = spec::render_toml(&settings, &ctx.instance, platform, &inputs.interface_name)?;
    let command = command::command(
        &inputs.core.binary,
        &inputs.runtime_dir,
        inputs.management,
        inputs.guard,
    );
    let config = PlannedFile {
        path: inputs.runtime_dir.join(command::CONFIG_FILE),
        contents: toml.into_bytes(),
    };
    let effects = match inputs.privilege {
        Privilege::System => effects::predict(ctx, &settings, platform),
        // A user host's kernel runs without the rights to change the
        // system; only what it does off the machine remains.
        _ => effects::predict_unprivileged(ctx, &settings),
    };
    let exclusive = classify::exclusive(&features);

    Ok(LaunchPlan {
        command,
        files: vec![config],
        readiness: readiness(
            &settings,
            platform,
            &inputs.interface_name,
            inputs.management,
        ),
        effects,
        management: inputs.guard,
        endpoint: CoreEndpoint(inputs.management),
        exclusive,
        features,
    })
}

/// The profile named by the committed inputs, checked against the kernel.
fn resolve_profile(ctx: &LaunchContext) -> Result<Option<&'static Profile>, CoreError> {
    let core = &ctx.inputs.core;
    let no_profile = || CoreError::NoProfile {
        version: core.version.clone(),
    };
    match &core.profile {
        None => Ok(None),
        Some(id) => {
            let profile = profiles::by_id(id).ok_or_else(no_profile)?;
            let descriptor = etd_core_api::CoreDescriptor {
                version: core.version.clone(),
                proto_revision: core.proto_revision.clone(),
            };
            if !profile.matches(&descriptor) {
                return Err(no_profile());
            }
            Ok(Some(profile))
        }
    }
}

/// Which guards each host can plan (v7: privileged hosts fence, or fall
/// back to a verified deny-all; user hosts run unguarded, or lifecycle-only
/// without a profile).
fn check_guard(
    privilege: Privilege,
    guard: ManagementGuard,
    profile: Option<&Profile>,
    version: &str,
) -> Result<(), CoreError> {
    let unavailable = || Err(CoreError::GuardUnavailable(guard));
    match (privilege, profile) {
        (Privilege::System, None) => Err(CoreError::NoProfile {
            version: version.to_owned(),
        }),
        (Privilege::System, Some(profile)) => match guard {
            ManagementGuard::Fence => Ok(()),
            ManagementGuard::DenyAll if profile.deny_all_verified => Ok(()),
            _ => unavailable(),
        },
        (_, None) => match guard {
            ManagementGuard::LifecycleOnly => Ok(()),
            _ => unavailable(),
        },
        (_, Some(_)) => match guard {
            ManagementGuard::Unguarded | ManagementGuard::LifecycleOnly => Ok(()),
            _ => unavailable(),
        },
    }
}

/// The portal must be a loopback address with a fixed port: a bare or zero
/// port makes upstream pick 0.0.0.0 or a free port (`select_proper_rpc_port`).
fn check_management(addr: SocketAddr) -> Result<(), CoreError> {
    if !addr.ip().is_loopback() || addr.port() == 0 {
        return Err(CoreError::InvalidSpec(format!(
            "management address {addr} must be loopback with a fixed port"
        )));
    }
    Ok(())
}

/// Only names derived by `naming::interface_name` are accepted.
fn check_interface_name(name: &str) -> Result<(), CoreError> {
    let suffix = name.strip_prefix(naming::INTERFACE_PREFIX);
    let valid = suffix.is_some_and(|s| {
        s.len() == 8
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    });
    if !valid {
        return Err(CoreError::InvalidSpec(format!(
            "interface name {name:?} is not a derived name"
        )));
    }
    Ok(())
}

fn readiness(
    settings: &spec::Settings,
    platform: Platform,
    interface_name: &str,
    management: SocketAddr,
) -> Readiness {
    let condition = if settings.no_tun {
        ReadinessCondition::Listener(readiness_listener(settings).unwrap_or(management))
    } else if platform == Platform::MacOs {
        ReadinessCondition::OwnedInterfaceAddress
    } else {
        ReadinessCondition::InterfaceAddress(effects::interface_key(platform, interface_name))
    };
    Readiness {
        minimum_uptime: MINIMUM_UPTIME,
        condition,
    }
}

/// A TCP socket the kernel binds once its network instance runs: the first
/// tcp listener, else the SOCKS5 portal, else nothing (the caller falls
/// back to the management portal).
fn readiness_listener(settings: &spec::Settings) -> Option<SocketAddr> {
    settings
        .listeners
        .iter()
        .find(|l| l.scheme == "tcp")
        .and_then(|l| l.socket)
        .or_else(|| {
            settings
                .socks5_port
                .map(|port| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port))
        })
}
