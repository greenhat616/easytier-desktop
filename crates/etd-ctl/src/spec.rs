//! The `apply` configuration file: a JSON object whose keys are the field
//! names of the contract's `NetworkSpec`.
//!
//! Unknown keys are refused so that a typo cannot silently drop a setting.
//! Error messages name keys only and never quote a value, so that the network
//! secret cannot leak through them.
use etd_contract::{
    NetworkSpec,
    v1::{NetworkFlags, PortForward, TransportProtocol, network_spec::Ipv4},
};
use serde_json::{Map, Value};

type Parsed<T> = Result<T, String>;

/// A JSON object whose keys are consumed one by one.
struct Object {
    path: &'static str,
    entries: Map<String, Value>,
}

impl Object {
    fn new(path: &'static str, value: Value) -> Parsed<Self> {
        match value {
            Value::Object(entries) => Ok(Self { path, entries }),
            _ => Err(format!("{path} must be a JSON object")),
        }
    }

    fn take<T>(
        &mut self,
        key: &str,
        expected: &str,
        read: impl FnOnce(Value) -> Option<T>,
    ) -> Parsed<Option<T>> {
        match self.entries.remove(key) {
            None | Some(Value::Null) => Ok(None),
            Some(value) => read(value)
                .map(Some)
                .ok_or_else(|| format!("{}.{key} must be {expected}", self.path)),
        }
    }

    fn flag(&mut self, key: &str) -> Parsed<Option<bool>> {
        self.take(key, "true or false", |value| value.as_bool())
    }

    fn text(&mut self, key: &str) -> Parsed<Option<String>> {
        self.take(key, "a string", |value| match value {
            Value::String(text) => Some(text),
            _ => None,
        })
    }

    fn number(&mut self, key: &str, max: u32) -> Parsed<u32> {
        let expected = format!("an integer from 0 to {max}");
        let value = self.take(key, &expected, |value| {
            value
                .as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .filter(|n| *n <= max)
        })?;
        Ok(value.unwrap_or_default())
    }

    fn texts(&mut self, key: &str) -> Parsed<Vec<String>> {
        let value = self.take(key, "an array of strings", |value| match value {
            Value::Array(items) => items
                .into_iter()
                .map(|item| match item {
                    Value::String(text) => Some(text),
                    _ => None,
                })
                .collect(),
            _ => None,
        })?;
        Ok(value.unwrap_or_default())
    }

    fn finish(self) -> Parsed<()> {
        match self.entries.keys().next() {
            None => Ok(()),
            Some(key) => Err(format!("{} has an unknown key {key:?}", self.path)),
        }
    }
}

/// Parses the file. The second value is the secret it carries, if any, for
/// scrubbing later messages.
pub fn parse(text: &str) -> Parsed<NetworkSpec> {
    // A serde_json syntax error reports a position, not the content.
    let value: Value =
        serde_json::from_str(text).map_err(|error| format!("not valid JSON: {error}"))?;
    let mut object = Object::new("spec", value)?;
    if object.entries.contains_key("network_secret_set") {
        return Err("spec.network_secret_set is output only; remove it".to_owned());
    }
    let ipv4_cidr = object.text("ipv4_cidr")?;
    let dhcp = object.flag("dhcp")?;
    let ipv4 = match (ipv4_cidr, dhcp) {
        (Some(_), Some(_)) => return Err("give spec.ipv4_cidr or spec.dhcp, not both".to_owned()),
        (Some(cidr), None) => Some(Ipv4::Ipv4Cidr(cidr)),
        (None, Some(dhcp)) => Some(Ipv4::Dhcp(dhcp)),
        (None, None) => None,
    };
    let port_forwards = object
        .take("port_forwards", "an array", |value| match value {
            Value::Array(items) => Some(items),
            _ => None,
        })?
        .unwrap_or_default()
        .into_iter()
        .map(port_forward)
        .collect::<Parsed<Vec<_>>>()?;
    let flags = object.take("flags", "a JSON object", Some)?;
    let spec = NetworkSpec {
        display_name: object.text("display_name")?.unwrap_or_default(),
        network_name: object.text("network_name")?.unwrap_or_default(),
        // Absent keeps the stored secret, "" clears it.
        network_secret: object.text("network_secret")?,
        network_secret_set: false,
        hostname: object.text("hostname")?.unwrap_or_default(),
        ipv4,
        peers: object.texts("peers")?,
        listeners: object.texts("listeners")?,
        no_listener: object.flag("no_listener")?.unwrap_or_default(),
        proxy_cidrs: object.texts("proxy_cidrs")?,
        exit_nodes: object.texts("exit_nodes")?,
        enable_exit_node: object.flag("enable_exit_node")?.unwrap_or_default(),
        mtu: object.number("mtu", u32::MAX)?,
        no_tun: object.flag("no_tun")?.unwrap_or_default(),
        socks5_port: object.number("socks5_port", u16::MAX.into())?,
        port_forwards,
        magic_dns: object.flag("magic_dns")?.unwrap_or_default(),
        public_ipv6_provider: object.flag("public_ipv6_provider")?.unwrap_or_default(),
        flags: flags.map(network_flags).transpose()?,
    };
    object.finish()?;
    Ok(spec)
}

fn port_forward(value: Value) -> Parsed<PortForward> {
    let mut object = Object::new("spec.port_forwards[]", value)?;
    let protocol = match object.text("protocol")?.as_deref() {
        Some("tcp") => TransportProtocol::Tcp,
        Some("udp") => TransportProtocol::Udp,
        _ => return Err("spec.port_forwards[].protocol must be \"tcp\" or \"udp\"".to_owned()),
    };
    let forward = PortForward {
        protocol: protocol as i32,
        bind: object.text("bind")?.unwrap_or_default(),
        destination: object.text("destination")?.unwrap_or_default(),
    };
    object.finish()?;
    Ok(forward)
}

fn network_flags(value: Value) -> Parsed<NetworkFlags> {
    let mut object = Object::new("spec.flags", value)?;
    let mut off = |key: &str| object.flag(key).map(Option::unwrap_or_default);
    let flags = NetworkFlags {
        latency_first: off("latency_first")?,
        disable_encryption: off("disable_encryption")?,
        enable_kcp_proxy: off("enable_kcp_proxy")?,
        enable_quic_proxy: off("enable_quic_proxy")?,
        disable_p2p: off("disable_p2p")?,
        disable_udp_hole_punching: off("disable_udp_hole_punching")?,
        relay_all_peer_rpc: off("relay_all_peer_rpc")?,
        private_mode: off("private_mode")?,
        disable_ipv6: off("disable_ipv6")?,
        use_smoltcp: off("use_smoltcp")?,
        // Absent preserves the upstream default.
        multi_thread: object.flag("multi_thread")?,
        bind_device: object.flag("bind_device")?,
        compression: object.text("compression")?.unwrap_or_default(),
    };
    object.finish()?;
    Ok(flags)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_field_is_read() {
        let spec = parse(
            r#"{"display_name":"d","network_name":"n","network_secret":"","hostname":"h",
                "ipv4_cidr":"10.0.0.1/24","peers":["tcp://p:1"],"listeners":["udp://0.0.0.0:2"],
                "no_listener":true,"proxy_cidrs":["10.1.0.0/16"],"exit_nodes":["10.0.0.2"],
                "enable_exit_node":true,"mtu":1380,"no_tun":true,"socks5_port":1080,
                "port_forwards":[{"protocol":"udp","bind":"a:1","destination":"b:2"}],
                "magic_dns":true,"public_ipv6_provider":true,
                "flags":{"latency_first":true,"disable_encryption":true,"enable_kcp_proxy":true,
                  "enable_quic_proxy":true,"disable_p2p":true,"disable_udp_hole_punching":true,
                  "relay_all_peer_rpc":true,"multi_thread":false,"private_mode":true,
                  "disable_ipv6":true,"use_smoltcp":true,"bind_device":false,
                  "compression":"zstd"}}"#,
        )
        .unwrap();
        let flags = NetworkFlags {
            latency_first: true,
            disable_encryption: true,
            enable_kcp_proxy: true,
            enable_quic_proxy: true,
            disable_p2p: true,
            disable_udp_hole_punching: true,
            relay_all_peer_rpc: true,
            multi_thread: Some(false),
            private_mode: true,
            disable_ipv6: true,
            use_smoltcp: true,
            bind_device: Some(false),
            compression: "zstd".into(),
        };
        let expected = NetworkSpec {
            display_name: "d".into(),
            network_name: "n".into(),
            network_secret: Some(String::new()),
            network_secret_set: false,
            hostname: "h".into(),
            ipv4: Some(Ipv4::Ipv4Cidr("10.0.0.1/24".into())),
            peers: vec!["tcp://p:1".into()],
            listeners: vec!["udp://0.0.0.0:2".into()],
            no_listener: true,
            proxy_cidrs: vec!["10.1.0.0/16".into()],
            exit_nodes: vec!["10.0.0.2".into()],
            enable_exit_node: true,
            mtu: 1380,
            no_tun: true,
            socks5_port: 1080,
            port_forwards: vec![PortForward {
                protocol: TransportProtocol::Udp as i32,
                bind: "a:1".into(),
                destination: "b:2".into(),
            }],
            magic_dns: true,
            public_ipv6_provider: true,
            flags: Some(flags),
        };
        assert_eq!(spec, expected);
    }

    #[test]
    fn an_absent_secret_stays_absent() {
        assert_eq!(parse("{}").unwrap().network_secret, None);
    }

    #[test]
    fn mistakes_are_refused_without_quoting_values() {
        for text in [
            r#"{"network_secret":["hunter2"]}"#,
            r#"{"network_secret":"hunter2","netwrok_name":"x"}"#,
            r#"{"network_secret":"hunter2","flags":{"latency_frist":true}}"#,
            r#"{"network_secret":"hunter2","dhcp":true,"ipv4_cidr":"x"}"#,
            r#"{"network_secret":"hunter2","socks5_port":70000}"#,
            r#"{"network_secret":"hunter2","port_forwards":[{"protocol":"hunter2"}]}"#,
            r#"{"network_secret":"hunter2","network_secret_set":true}"#,
            r#"{"network_secret":"hunter2" "#,
            r#"["hunter2"]"#,
            r#""hunter2""#,
        ] {
            let error = parse(text).unwrap_err();
            assert!(!error.contains("hunter2"), "{error}");
        }
    }
}
