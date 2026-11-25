//! Feature classification by side effects (doc#2 v7 "adapter profile").
//!
//! Rulings for the first release: Windows Magic DNS is single-writer;
//! macOS Magic DNS system writes are disabled; the Linux public IPv6
//! provider is refused under a privileged host; a user host runs no TUN.
use super::{Platform, spec::Settings};
use etd_core_api::{CoreError, FeatureClass, FeatureVerdict, Privilege};

/// Single-writer resource: the machine-wide Windows Magic DNS (NRPT rules
/// and `HKLM\SOFTWARE\EasyTier\MagicDNS`, cleaned by whichever EasyTier
/// process next wins the 127.0.0.1:49813 election).
pub const WINDOWS_MAGIC_DNS: &str = "windows.magic_dns";

/// Magic DNS writes system state only with a TUN and an IPv4 source
/// (`runtime_host/tun_desktop.rs`: `MagicDnsRuntime::start` needs ipv4).
pub fn magic_dns_active(settings: &Settings) -> bool {
    settings.magic_dns && !settings.no_tun
}

pub fn classify(
    settings: &Settings,
    platform: Platform,
    privilege: Privilege,
) -> Vec<FeatureVerdict> {
    let privileged = privilege == Privilege::System;
    let mut verdicts = Vec::new();
    let mut push = |feature: &str, class: FeatureClass| {
        verdicts.push(FeatureVerdict {
            feature: feature.to_owned(),
            class,
        })
    };

    if !settings.no_tun {
        push(
            "no_tun",
            if privileged {
                FeatureClass::Supported
            } else {
                FeatureClass::Disabled {
                    reason: "a TUN interface needs the system service; set no_tun on a user host"
                        .into(),
                }
            },
        );
    }

    if settings.magic_dns {
        let class = if !privileged || !magic_dns_active(settings) {
            // Without rights or without a TUN nothing is written.
            FeatureClass::Supported
        } else {
            match platform {
                Platform::Windows => FeatureClass::SingleWriter {
                    resource: WINDOWS_MAGIC_DNS.into(),
                },
                Platform::MacOs => FeatureClass::Disabled {
                    reason: "macOS Magic DNS deletes every /etc/resolver file carrying the \
                             EasyTier marker and takes over unmarked files of its domain"
                        .into(),
                },
                Platform::Linux => FeatureClass::Supported,
            }
        };
        push("magic_dns", class);
    }

    if settings.public_ipv6_provider {
        let class = if privileged && platform == Platform::Linux {
            FeatureClass::Rejected {
                reason: "the public IPv6 provider sets forwarding/proxy_ndp sysctls and NDP \
                         proxy entries on a WAN interface chosen at run time"
                    .into(),
            }
        } else {
            // The provider exists on Linux only; elsewhere, or without
            // rights, it changes nothing.
            FeatureClass::Supported
        };
        push("public_ipv6_provider", class);
    }

    for (feature, set) in [
        ("peers", !settings.peers.is_empty()),
        ("listeners", !settings.listeners.is_empty()),
        ("proxy_cidrs", !settings.proxy_cidrs.is_empty()),
        ("exit_nodes", !settings.exit_nodes.is_empty()),
        ("enable_exit_node", settings.enable_exit_node),
        ("socks5_port", settings.socks5_port.is_some()),
        ("port_forwards", !settings.port_forwards.is_empty()),
    ] {
        // Sockets, routes on the instance's own interface, or user-space
        // NAT only (no sysctl, nftables or WFP changes upstream).
        if set {
            push(feature, FeatureClass::Supported);
        }
    }
    verdicts
}

/// Disabled features fail first (`FeatureRejected`), then features with an
/// unmodelled write set (`UnmodelledEffects`).
pub fn enforce(verdicts: &[FeatureVerdict]) -> Result<(), CoreError> {
    if let Some((feature, reason)) = verdicts.iter().find_map(|v| match &v.class {
        FeatureClass::Disabled { reason } => Some((&v.feature, reason)),
        _ => None,
    }) {
        return Err(CoreError::FeatureRejected {
            feature: feature.clone(),
            reason: reason.clone(),
        });
    }
    let unmodelled: Vec<String> = verdicts
        .iter()
        .filter(|v| matches!(v.class, FeatureClass::Rejected { .. }))
        .map(|v| v.feature.clone())
        .collect();
    if !unmodelled.is_empty() {
        return Err(CoreError::UnmodelledEffects {
            features: unmodelled,
        });
    }
    Ok(())
}

/// Single-writer resources the launch claims.
pub fn exclusive(verdicts: &[FeatureVerdict]) -> Vec<String> {
    verdicts
        .iter()
        .filter_map(|v| match &v.class {
            FeatureClass::SingleWriter { resource } => Some(resource.clone()),
            _ => None,
        })
        .collect()
}
