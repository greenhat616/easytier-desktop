//! Network configuration editor state and rendering.
//!
//! Security invariant: network secrets are **never** stored in `UiModel`,
//! `StateStore`, or `ProfileStore`. Every create/edit starts with an empty
//! masked secret input and scrubs the field immediately after submit or cancel.
//!
//! Each form section is built in a separate `#[inline(never)]` helper returning
//! [`AnyElement`] so debug stack frames remain small on Windows' 1 MiB main stack.

use etd_app::{
    ApplyDraft, SUGGESTED_LISTENERS, Secret, SecretFreeSpec, SecretInput, new_instance_id,
};
use etd_contract::{
    Desired, InstanceId, NetworkSpec, capability,
    v1::{NetworkFlags, network_spec::Ipv4},
};
use gpui_kit::{
    AnyElement, App, AppContext as _, Context, Entity, InteractiveElement as _, IntoElement,
    ParentElement as _, Role, SharedString, StatefulInteractiveElement as _, Styled as _,
    TestSupportExt as _, Window,
    component::{ActiveTheme as _, Size, StyledExt as _, button::ButtonVariant, input::InputState},
    div,
};

use crate::views::{
    MainView,
    ui::{BtnStyle, action_button, password_input, switch_control, text_field},
};

/// How the user chooses to handle the network secret on create or edit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretMode {
    /// Keep the secret already held by the host (valid only when editing).
    Keep,
    /// Send the newly entered secret to the host.
    Set,
    /// Explicitly clear / omit the network secret.
    Clear,
}

/// Holds GPUI [`InputState`] entities and toggles for the Network Config Editor.
pub struct NetworkEditorState {
    pub editing_instance: Option<InstanceId>,
    pub host_has_secret: bool,
    pub secret_mode: SecretMode,
    pub display_name: Entity<InputState>,
    pub network_name: Entity<InputState>,
    pub network_secret: Entity<InputState>,
    pub hostname: Entity<InputState>,
    pub dhcp: bool,
    pub ipv4_cidr: Entity<InputState>,
    pub peers: Entity<InputState>,
    pub listeners: Entity<InputState>,
    pub no_listener: bool,
    pub proxy_cidrs: Entity<InputState>,
    pub exit_nodes: Entity<InputState>,
    pub enable_exit_node: bool,
    pub no_tun: bool,
    pub mtu: Entity<InputState>,
    pub socks5_port: Entity<InputState>,
    pub magic_dns: bool,
    pub public_ipv6_provider: bool,
    pub latency_first: bool,
    pub disable_encryption: bool,
    pub enable_kcp_proxy: bool,
    pub enable_quic_proxy: bool,
    pub disable_p2p: bool,
    pub disable_udp_hole_punching: bool,
    pub relay_all_peer_rpc: bool,
    pub private_mode: bool,
    pub disable_ipv6: bool,
    pub use_smoltcp: bool,
    pub validation_error: Option<String>,
}

impl NetworkEditorState {
    pub fn new(window: &mut Window, cx: &mut App) -> Self {
        Self {
            editing_instance: None,
            host_has_secret: false,
            secret_mode: SecretMode::Set,
            display_name: cx.new(|cx| InputState::new(window, cx).placeholder("e.g. Office Mesh")),
            network_name: cx
                .new(|cx| InputState::new(window, cx).placeholder("Required network name")),
            network_secret: cx.new(|cx| {
                InputState::new(window, cx)
                    .placeholder("Never stored locally — enter secret")
                    .masked(true)
            }),
            hostname: cx.new(|cx| InputState::new(window, cx).placeholder("Optional hostname")),
            dhcp: true,
            ipv4_cidr: cx.new(|cx| InputState::new(window, cx).placeholder("10.144.144.1/24")),
            peers: cx.new(|cx| {
                InputState::new(window, cx)
                    .placeholder("Comma-separated peer URIs, e.g. tcp://public.easytier.top:11010")
            }),
            listeners: cx.new(|cx| {
                InputState::new(window, cx)
                    .placeholder("Empty = dial-out only; or click Suggested Listeners below")
            }),
            no_listener: false,
            proxy_cidrs: cx
                .new(|cx| InputState::new(window, cx).placeholder("Optional, e.g. 192.168.1.0/24")),
            exit_nodes: cx
                .new(|cx| InputState::new(window, cx).placeholder("Optional exit node IPs")),
            enable_exit_node: false,
            no_tun: false,
            mtu: cx.new(|cx| InputState::new(window, cx).placeholder("0 (kernel default)")),
            socks5_port: cx.new(|cx| InputState::new(window, cx).placeholder("0 (disabled)")),
            magic_dns: false,
            public_ipv6_provider: false,
            latency_first: false,
            disable_encryption: false,
            enable_kcp_proxy: false,
            enable_quic_proxy: false,
            disable_p2p: false,
            disable_udp_hole_punching: false,
            relay_all_peer_rpc: false,
            private_mode: false,
            disable_ipv6: false,
            use_smoltcp: false,
            validation_error: None,
        }
    }

    /// Resets the form for creating a brand-new network configuration.
    /// Starts with no listeners (dial-out only) and an empty secret input.
    pub fn load_new(&mut self, tun_available: bool, window: &mut Window, cx: &mut App) {
        self.editing_instance = None;
        self.host_has_secret = false;
        self.secret_mode = SecretMode::Set;
        self.validation_error = None;
        set_input(&self.display_name, "", window, cx);
        set_input(&self.network_name, "", window, cx);
        self.clear_secret(window, cx);
        set_input(&self.hostname, "", window, cx);
        self.dhcp = true;
        set_input(&self.ipv4_cidr, "", window, cx);
        set_input(&self.peers, "", window, cx);
        set_input(&self.listeners, "", window, cx);
        self.no_listener = false;
        set_input(&self.proxy_cidrs, "", window, cx);
        set_input(&self.exit_nodes, "", window, cx);
        self.enable_exit_node = false;
        self.no_tun = !tun_available;
        set_input(&self.mtu, "", window, cx);
        set_input(&self.socks5_port, "", window, cx);
        self.magic_dns = false;
        self.public_ipv6_provider = false;
        self.latency_first = false;
        self.disable_encryption = false;
        self.enable_kcp_proxy = false;
        self.enable_quic_proxy = false;
        self.disable_p2p = false;
        self.disable_udp_hole_punching = false;
        self.relay_all_peer_rpc = false;
        self.private_mode = false;
        self.disable_ipv6 = false;
        self.use_smoltcp = false;
    }

    /// Populates the editor from an existing instance or profile spec.
    /// Always clears the secret input and defaults secret handling to [`SecretMode::Keep`].
    pub fn load_existing(
        &mut self,
        instance_id: InstanceId,
        spec: &NetworkSpec,
        window: &mut Window,
        cx: &mut App,
    ) {
        self.editing_instance = Some(instance_id);
        self.host_has_secret = spec.network_secret_set;
        self.secret_mode = SecretMode::Keep;
        self.validation_error = None;

        set_input(&self.display_name, &spec.display_name, window, cx);
        set_input(&self.network_name, &spec.network_name, window, cx);
        // Never pre-fill a network secret.
        self.clear_secret(window, cx);
        set_input(&self.hostname, &spec.hostname, window, cx);

        match &spec.ipv4 {
            Some(Ipv4::Ipv4Cidr(cidr)) => {
                self.dhcp = false;
                set_input(&self.ipv4_cidr, cidr, window, cx);
            }
            Some(Ipv4::Dhcp(enabled)) => {
                self.dhcp = *enabled;
                set_input(&self.ipv4_cidr, "", window, cx);
            }
            None => {
                self.dhcp = false;
                set_input(&self.ipv4_cidr, "", window, cx);
            }
        }

        set_input(&self.peers, &spec.peers.join(", "), window, cx);
        set_input(&self.listeners, &spec.listeners.join(", "), window, cx);
        self.no_listener = spec.no_listener;
        set_input(&self.proxy_cidrs, &spec.proxy_cidrs.join(", "), window, cx);
        set_input(&self.exit_nodes, &spec.exit_nodes.join(", "), window, cx);
        self.enable_exit_node = spec.enable_exit_node;
        self.no_tun = spec.no_tun;
        let mtu = if spec.mtu == 0 {
            String::new()
        } else {
            spec.mtu.to_string()
        };
        set_input(&self.mtu, &mtu, window, cx);
        let socks = if spec.socks5_port == 0 {
            String::new()
        } else {
            spec.socks5_port.to_string()
        };
        set_input(&self.socks5_port, &socks, window, cx);
        self.magic_dns = spec.magic_dns;
        self.public_ipv6_provider = spec.public_ipv6_provider;

        let flags = spec.flags.as_ref();
        self.latency_first = flags.is_some_and(|f| f.latency_first);
        self.disable_encryption = flags.is_some_and(|f| f.disable_encryption);
        self.enable_kcp_proxy = flags.is_some_and(|f| f.enable_kcp_proxy);
        self.enable_quic_proxy = flags.is_some_and(|f| f.enable_quic_proxy);
        self.disable_p2p = flags.is_some_and(|f| f.disable_p2p);
        self.disable_udp_hole_punching = flags.is_some_and(|f| f.disable_udp_hole_punching);
        self.relay_all_peer_rpc = flags.is_some_and(|f| f.relay_all_peer_rpc);
        self.private_mode = flags.is_some_and(|f| f.private_mode);
        self.disable_ipv6 = flags.is_some_and(|f| f.disable_ipv6);
        self.use_smoltcp = flags.is_some_and(|f| f.use_smoltcp);
    }

    /// Scrubs the secret input field immediately.
    pub fn clear_secret(&mut self, window: &mut Window, cx: &mut App) {
        set_input(&self.network_secret, "", window, cx);
    }

    /// Fills the listeners field with the upstream 11010 suggested listener set
    /// (excluding `faketcp`).
    pub fn apply_suggested_listeners(&mut self, window: &mut Window, cx: &mut App) {
        self.no_listener = false;
        let joined = SUGGESTED_LISTENERS.join(", ");
        set_input(&self.listeners, &joined, window, cx);
    }

    /// Appends a single suggested listener URI if not already listed.
    pub fn add_suggested_listener(&mut self, listener: &str, window: &mut Window, cx: &mut App) {
        self.no_listener = false;
        let mut current = parse_list(self.listeners.read(cx).value().as_ref());
        if !current.iter().any(|item| item == listener) {
            current.push(listener.to_owned());
        }
        set_input(&self.listeners, &current.join(", "), window, cx);
    }

    /// Validates all fields, constructs an [`ApplyDraft`], and scrubs the secret
    /// input field immediately upon success.
    pub fn build_draft(
        &mut self,
        desired: Desired,
        window: &mut Window,
        cx: &mut App,
    ) -> Result<ApplyDraft, String> {
        let network_name = self.network_name.read(cx).value().trim().to_owned();
        if network_name.is_empty() {
            return Err("Network name is required.".into());
        }

        let mtu = parse_optional_u32(self.mtu.read(cx).value().as_ref(), "MTU")?;
        let socks5_port =
            parse_optional_u32(self.socks5_port.read(cx).value().as_ref(), "SOCKS5 port")?;
        if socks5_port > u16::MAX as u32 {
            return Err("SOCKS5 port must be between 0 and 65535.".into());
        }

        let raw_secret = self.network_secret.read(cx).value().to_string();
        let secret = match self.secret_mode {
            SecretMode::Keep if self.editing_instance.is_some() => SecretInput::Keep,
            SecretMode::Keep => {
                if raw_secret.is_empty() {
                    SecretInput::Clear
                } else {
                    SecretInput::Set(Secret::new(raw_secret))
                }
            }
            SecretMode::Clear => SecretInput::Clear,
            SecretMode::Set => {
                if self.editing_instance.is_some() && raw_secret.is_empty() {
                    return Err(
                        "Enter a new network secret, or choose Keep Existing / Clear Secret."
                            .into(),
                    );
                }
                if raw_secret.is_empty() {
                    SecretInput::Clear
                } else {
                    SecretInput::Set(Secret::new(raw_secret))
                }
            }
        };

        let ipv4_text = self.ipv4_cidr.read(cx).value().trim().to_owned();
        let ipv4 = if self.dhcp {
            Some(Ipv4::Dhcp(true))
        } else if !ipv4_text.is_empty() {
            Some(Ipv4::Ipv4Cidr(ipv4_text))
        } else {
            None
        };

        let listeners = if self.no_listener {
            Vec::new()
        } else {
            parse_list(self.listeners.read(cx).value().as_ref())
        };

        let spec = NetworkSpec {
            display_name: self.display_name.read(cx).value().trim().to_owned(),
            network_name,
            network_secret: None,
            network_secret_set: false,
            hostname: self.hostname.read(cx).value().trim().to_owned(),
            ipv4,
            peers: parse_list(self.peers.read(cx).value().as_ref()),
            listeners,
            no_listener: self.no_listener,
            proxy_cidrs: parse_list(self.proxy_cidrs.read(cx).value().as_ref()),
            exit_nodes: parse_list(self.exit_nodes.read(cx).value().as_ref()),
            enable_exit_node: self.enable_exit_node,
            mtu,
            no_tun: self.no_tun,
            socks5_port,
            port_forwards: Vec::new(),
            magic_dns: self.magic_dns,
            public_ipv6_provider: self.public_ipv6_provider,
            flags: Some(NetworkFlags {
                latency_first: self.latency_first,
                disable_encryption: self.disable_encryption,
                enable_kcp_proxy: self.enable_kcp_proxy,
                enable_quic_proxy: self.enable_quic_proxy,
                disable_p2p: self.disable_p2p,
                disable_udp_hole_punching: self.disable_udp_hole_punching,
                relay_all_peer_rpc: self.relay_all_peer_rpc,
                multi_thread: None,
                private_mode: self.private_mode,
                disable_ipv6: self.disable_ipv6,
                use_smoltcp: self.use_smoltcp,
                bind_device: None,
                compression: String::new(),
            }),
        };

        let instance_id = self
            .editing_instance
            .clone()
            .unwrap_or_else(new_instance_id);

        // Immediately wipe the secret field once packaged for dispatch.
        self.clear_secret(window, cx);
        self.validation_error = None;

        Ok(ApplyDraft {
            instance_id,
            spec: SecretFreeSpec::new(spec),
            secret,
            desired,
        })
    }
}

fn set_input(entity: &Entity<InputState>, value: &str, window: &mut Window, cx: &mut App) {
    entity.update(cx, |state, cx| {
        state.set_value(value.to_owned(), window, cx);
    });
}

/// Splits comma- or newline-separated URIs / CIDRs, trimming blanks.
pub fn parse_list(raw: &str) -> Vec<String> {
    raw.split([',', '\n'])
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_owned)
        .collect()
}

fn parse_optional_u32(raw: &str, label: &str) -> Result<u32, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(0);
    }
    trimmed
        .parse::<u32>()
        .map_err(|_| format!("{label} must be a non-negative integer."))
}

/// Renders the Network Config Editor inside [`MainView`].
#[inline(never)]
pub fn render_editor(view: &MainView, cx: &mut Context<MainView>) -> AnyElement {
    let tun_available = view
        .controller
        .model
        .read(cx)
        .store
        .has_capability(capability::TUN);
    let is_edit = view.editor.editing_instance.is_some();
    let title = if is_edit {
        "Edit Network Configuration"
    } else {
        "New Network Configuration"
    };

    let header = render_editor_header(title, is_edit, cx);
    let mut sections: Vec<AnyElement> = Vec::new();

    if let Some(error) = &view.editor.validation_error {
        sections.push(render_validation_error(error, cx));
    }
    sections.push(render_identity_section(&view.editor, is_edit, cx));
    sections.push(render_addressing_section(&view.editor, cx));
    sections.push(render_listeners_section(&view.editor, cx));
    sections.push(render_options_section(&view.editor, tun_available, cx));

    let form = div()
        .id("network-editor-scroll")
        .test_support()
        .flex_1()
        .overflow_y_scroll()
        .flex()
        .flex_col()
        .gap_4()
        .p_5()
        .children(sections);

    div()
        .id("network-editor-view")
        .test_support()
        .aria_label(SharedString::from(title))
        .flex()
        .flex_col()
        .size_full()
        .overflow_hidden()
        .child(header)
        .child(form)
        .into_any_element()
}

#[inline(never)]
fn render_editor_header(
    title: &'static str,
    is_edit: bool,
    cx: &mut Context<MainView>,
) -> AnyElement {
    let border = cx.theme().border;
    let fg = cx.theme().foreground;
    let save_desired = if is_edit {
        Desired::Unspecified
    } else {
        Desired::Stopped
    };

    let cancel_btn = action_button(
        "editor-cancel",
        "Cancel",
        BtnStyle::new(ButtonVariant::Ghost, Size::Small),
        cx.listener(|this, _, window, cx| {
            this.cancel_editor(window, cx);
        }),
    );
    let save_btn = action_button(
        "editor-submit-save",
        "Save",
        BtnStyle::new(ButtonVariant::Secondary, Size::Small),
        cx.listener(move |this, _, window, cx| {
            this.submit_editor(save_desired, window, cx);
        }),
    );
    let start_btn = action_button(
        "editor-submit-start",
        "Save & Start",
        BtnStyle::new(ButtonVariant::Primary, Size::Small),
        cx.listener(|this, _, window, cx| {
            this.submit_editor(Desired::Running, window, cx);
        }),
    );

    div()
        .flex()
        .flex_row()
        .items_center()
        .justify_between()
        .px_5()
        .py_3()
        .border_b_1()
        .border_color(border)
        .child(div().text_lg().font_semibold().text_color(fg).child(title))
        .child(
            div()
                .flex()
                .flex_row()
                .items_center()
                .gap_2()
                .child(cancel_btn)
                .child(save_btn)
                .child(start_btn),
        )
        .into_any_element()
}

#[inline(never)]
fn render_validation_error(error: &str, cx: &Context<MainView>) -> AnyElement {
    let danger = cx.theme().danger;
    div()
        .id("editor-validation-error")
        .role(Role::Alert)
        .test_support()
        .aria_label(SharedString::from(error.to_owned()))
        .px_3()
        .py_2()
        .rounded_md()
        .border_1()
        .border_color(danger)
        .bg(danger.opacity(0.12))
        .text_color(danger)
        .text_sm()
        .child(error.to_owned())
        .into_any_element()
}

#[inline(never)]
fn render_identity_section(
    editor: &NetworkEditorState,
    is_edit: bool,
    cx: &mut Context<MainView>,
) -> AnyElement {
    let border = crate::theme::card_stroke(cx);
    let card = crate::theme::card_fill(cx);

    let display = text_field(
        "Display Name",
        "editor-display-name",
        "Display Name",
        &editor.display_name,
        false,
        cx,
    );
    let net_name = text_field(
        "Network Name *",
        "editor-network-name",
        "Network Name",
        &editor.network_name,
        false,
        cx,
    );
    let secret = render_secret_block(editor, is_edit, cx);
    let hostname = text_field(
        "Hostname",
        "editor-hostname",
        "Hostname",
        &editor.hostname,
        false,
        cx,
    );

    div()
        .flex()
        .flex_col()
        .gap_3()
        .p_4()
        .rounded_md()
        .border_1()
        .border_color(border)
        .bg(card)
        .child(display)
        .child(net_name)
        .child(secret)
        .child(hostname)
        .into_any_element()
}

#[inline(never)]
fn render_secret_block(
    editor: &NetworkEditorState,
    is_edit: bool,
    cx: &mut Context<MainView>,
) -> AnyElement {
    let fg = cx.theme().foreground;
    let muted = cx.theme().muted_foreground;
    let secret_hint = if is_edit {
        if editor.host_has_secret {
            "Network secrets are never stored in the UI. The host currently holds a secret; choose Keep, Replace, or Clear."
        } else {
            "Network secrets are never stored in the UI. The host currently has no secret stored."
        }
    } else {
        "Network secrets are never stored locally and are asked on each create or edit."
    };

    let mut mode_btns = Vec::new();
    if is_edit {
        mode_btns.push(action_button(
            "secret-mode-keep",
            "Keep Existing",
            BtnStyle::new(
                if editor.secret_mode == SecretMode::Keep {
                    ButtonVariant::Primary
                } else {
                    ButtonVariant::Secondary
                },
                Size::Small,
            )
            .outline(),
            cx.listener(|this, _, window, cx| {
                this.editor.secret_mode = SecretMode::Keep;
                this.editor.clear_secret(window, cx);
                cx.notify();
            }),
        ));
    }
    mode_btns.push(action_button(
        "secret-mode-set",
        if is_edit {
            "Replace Secret"
        } else {
            "Set Secret"
        },
        BtnStyle::new(
            if editor.secret_mode == SecretMode::Set {
                ButtonVariant::Primary
            } else {
                ButtonVariant::Secondary
            },
            Size::Small,
        )
        .outline(),
        cx.listener(|this, _, _, cx| {
            this.editor.secret_mode = SecretMode::Set;
            cx.notify();
        }),
    ));
    mode_btns.push(action_button(
        "secret-mode-clear",
        if is_edit { "Clear Secret" } else { "No Secret" },
        BtnStyle::new(
            if editor.secret_mode == SecretMode::Clear {
                ButtonVariant::Primary
            } else {
                ButtonVariant::Secondary
            },
            Size::Small,
        )
        .outline(),
        cx.listener(|this, _, window, cx| {
            this.editor.secret_mode = SecretMode::Clear;
            this.editor.clear_secret(window, cx);
            cx.notify();
        }),
    ));

    let secret_input = password_input(
        "editor-network-secret",
        "Network Secret",
        &editor.network_secret,
        editor.secret_mode != SecretMode::Set,
    );

    div()
        .flex()
        .flex_col()
        .gap_2()
        .child(
            div()
                .text_sm()
                .font_medium()
                .text_color(fg)
                .child("Network Secret (never saved locally)"),
        )
        .child(
            div()
                .id("editor-secret-hint")
                .test_support()
                .aria_label(SharedString::from(secret_hint))
                .text_xs()
                .text_color(muted)
                .child(secret_hint),
        )
        .child(div().flex().flex_row().gap_2().children(mode_btns))
        .child(secret_input)
        .into_any_element()
}

#[inline(never)]
fn render_addressing_section(
    editor: &NetworkEditorState,
    cx: &mut Context<MainView>,
) -> AnyElement {
    let border = crate::theme::card_stroke(cx);
    let card = crate::theme::card_fill(cx);

    let dhcp_sw = switch_control(
        "editor-dhcp",
        "Assign virtual IPv4 automatically (DHCP)",
        editor.dhcp,
        cx.listener(|this, checked, _, cx| {
            this.editor.dhcp = *checked;
            cx.notify();
        }),
    );
    let cidr = text_field(
        "Static IPv4 CIDR",
        "editor-ipv4-cidr",
        "Static IPv4 CIDR",
        &editor.ipv4_cidr,
        editor.dhcp,
        cx,
    );
    let peers = text_field("Peers", "editor-peers", "Peers", &editor.peers, false, cx);

    div()
        .flex()
        .flex_col()
        .gap_3()
        .p_4()
        .rounded_md()
        .border_1()
        .border_color(border)
        .bg(card)
        .child(dhcp_sw)
        .child(cidr)
        .child(peers)
        .into_any_element()
}

#[inline(never)]
fn render_listeners_section(editor: &NetworkEditorState, cx: &mut Context<MainView>) -> AnyElement {
    let border = crate::theme::card_stroke(cx);
    let card = crate::theme::card_fill(cx);
    let muted = cx.theme().muted_foreground;

    let listeners_input = text_field(
        "Listeners",
        "editor-listeners",
        "Listeners",
        &editor.listeners,
        editor.no_listener,
        cx,
    );
    let apply_all_btn = action_button(
        "btn-suggested-listeners",
        "Use Suggested 11010 Set",
        BtnStyle::new(ButtonVariant::Default, Size::XSmall).outline(),
        cx.listener(|this, _, window, cx| {
            this.editor.apply_suggested_listeners(window, cx);
            cx.notify();
        }),
    );

    let mut chips = Vec::with_capacity(SUGGESTED_LISTENERS.len());
    for (idx, uri) in SUGGESTED_LISTENERS.iter().enumerate() {
        let uri_owned = (*uri).to_owned();
        chips.push(action_button(
            SharedString::from(format!("btn-suggested-listener-{idx}")),
            *uri,
            BtnStyle::new(ButtonVariant::Secondary, Size::XSmall),
            cx.listener(move |this, _, window, cx| {
                this.editor.add_suggested_listener(&uri_owned, window, cx);
                cx.notify();
            }),
        ));
    }

    let no_listener_sw = switch_control(
        "editor-no-listener",
        "Disable all listeners (no_listener)",
        editor.no_listener,
        cx.listener(|this, checked, _, cx| {
            this.editor.no_listener = *checked;
            cx.notify();
        }),
    );

    div()
        .flex()
        .flex_col()
        .gap_3()
        .p_4()
        .rounded_md()
        .border_1()
        .border_color(border)
        .bg(card)
        .child(listeners_input)
        .child(
            div()
                .flex()
                .flex_row()
                .items_center()
                .justify_between()
                .gap_2()
                .child(
                    div()
                        .text_xs()
                        .text_color(muted)
                        .child("Suggested listeners (upstream 11010 set; faketcp excluded):"),
                )
                .child(apply_all_btn),
        )
        .child(div().flex().flex_row().flex_wrap().gap_2().children(chips))
        .child(no_listener_sw)
        .into_any_element()
}

#[inline(never)]
fn render_options_section(
    editor: &NetworkEditorState,
    tun_available: bool,
    cx: &mut Context<MainView>,
) -> AnyElement {
    let border = crate::theme::card_stroke(cx);
    let card = crate::theme::card_fill(cx);

    let no_tun_label = if tun_available {
        "No TUN interface (SOCKS5 / port forwarding only)"
    } else {
        "No TUN interface (required by current user-mode host)"
    };

    let proxy = text_field(
        "Proxy CIDRs",
        "editor-proxy-cidrs",
        "Proxy CIDRs",
        &editor.proxy_cidrs,
        false,
        cx,
    );
    let exits = text_field(
        "Exit Nodes",
        "editor-exit-nodes",
        "Exit Nodes",
        &editor.exit_nodes,
        false,
        cx,
    );
    let mtu = text_field("MTU", "editor-mtu", "MTU", &editor.mtu, false, cx);
    let socks = text_field(
        "SOCKS5 Port",
        "editor-socks5-port",
        "SOCKS5 Port",
        &editor.socks5_port,
        false,
        cx,
    );

    let switches = vec![
        switch_control(
            "editor-no-tun",
            no_tun_label,
            editor.no_tun,
            cx.listener(|this, checked, _, cx| {
                this.editor.no_tun = *checked;
                cx.notify();
            }),
        ),
        switch_control(
            "editor-enable-exit-node",
            "Act as exit node",
            editor.enable_exit_node,
            cx.listener(|this, checked, _, cx| {
                this.editor.enable_exit_node = *checked;
                cx.notify();
            }),
        ),
        switch_control(
            "editor-magic-dns",
            "Enable Magic DNS",
            editor.magic_dns,
            cx.listener(|this, checked, _, cx| {
                this.editor.magic_dns = *checked;
                cx.notify();
            }),
        ),
        switch_control(
            "editor-latency-first",
            "Latency-first routing",
            editor.latency_first,
            cx.listener(|this, checked, _, cx| {
                this.editor.latency_first = *checked;
                cx.notify();
            }),
        ),
        switch_control(
            "editor-private-mode",
            "Private mode",
            editor.private_mode,
            cx.listener(|this, checked, _, cx| {
                this.editor.private_mode = *checked;
                cx.notify();
            }),
        ),
        switch_control(
            "editor-disable-p2p",
            "Disable P2P (relay only)",
            editor.disable_p2p,
            cx.listener(|this, checked, _, cx| {
                this.editor.disable_p2p = *checked;
                cx.notify();
            }),
        ),
    ];

    div()
        .flex()
        .flex_col()
        .gap_3()
        .p_4()
        .rounded_md()
        .border_1()
        .border_color(border)
        .bg(card)
        .child(proxy)
        .child(exits)
        .child(
            div()
                .flex()
                .flex_row()
                .gap_3()
                .child(div().flex_1().child(mtu))
                .child(div().flex_1().child(socks)),
        )
        .children(switches)
        .into_any_element()
}
