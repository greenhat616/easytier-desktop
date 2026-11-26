//! Network configuration editor state and rendering.
//!
//! Security invariant: network secrets are **never** stored in `UiModel`,
//! `StateStore`, or `ProfileStore`. Every create/edit starts with an empty
//! masked secret input and scrubs the field immediately after submit or cancel.

use etd_app::{
    ApplyDraft, SUGGESTED_LISTENERS, Secret, SecretFreeSpec, SecretInput, new_instance_id,
};
use etd_contract::{
    Desired, InstanceId, NetworkSpec, capability,
    v1::{NetworkFlags, network_spec::Ipv4},
};
use gpui_kit::{
    App, AppContext as _, Context, Entity, InteractiveElement as _, IntoElement,
    ParentElement as _, Role, SharedString, StatefulInteractiveElement as _, Styled as _,
    TestSupportExt as _, Window,
    component::{
        ActiveTheme as _, Sizable as _, StyledExt as _,
        button::{Button, ButtonVariants as _},
        input::{Input, InputContentType, InputState},
        switch::Switch,
    },
    div,
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

/// Renders the Network Config Editor inside [`crate::views::MainView`].
pub fn render_editor(
    view: &crate::views::MainView,
    cx: &mut Context<crate::views::MainView>,
) -> impl IntoElement {
    let theme = cx.theme();
    let model = view.controller.model.read(cx);
    let tun_available = model.store.has_capability(capability::TUN);
    let editor = &view.editor;
    let is_edit = editor.editing_instance.is_some();

    let title = if is_edit {
        "Edit Network Configuration"
    } else {
        "New Network Configuration"
    };

    let secret_hint = if is_edit {
        if editor.host_has_secret {
            "Network secrets are never stored in the UI. The host currently holds a secret; choose Keep, Replace, or Clear."
        } else {
            "Network secrets are never stored in the UI. The host currently has no secret stored."
        }
    } else {
        "Network secrets are never stored locally and are asked on each create or edit."
    };

    let secret_input_disabled = editor.secret_mode != SecretMode::Set;

    let save_desired = if is_edit {
        Desired::Unspecified
    } else {
        Desired::Stopped
    };

    let header = div()
        .flex()
        .flex_row()
        .items_center()
        .justify_between()
        .px_5()
        .py_3()
        .border_b_1()
        .border_color(theme.border)
        .bg(theme.background)
        .child(
            div()
                .text_lg()
                .font_semibold()
                .text_color(theme.foreground)
                .child(title),
        )
        .child(
            div()
                .flex()
                .flex_row()
                .items_center()
                .gap_2()
                .child(
                    Button::new("editor-cancel")
                        .ghost()
                        .small()
                        .label("Cancel")
                        .on_click(cx.listener(|this, _, window, cx| {
                            this.cancel_editor(window, cx);
                        })),
                )
                .child(
                    Button::new("editor-submit-save")
                        .secondary()
                        .small()
                        .label("Save")
                        .on_click(cx.listener(move |this, _, window, cx| {
                            this.submit_editor(save_desired, window, cx);
                        })),
                )
                .child(
                    Button::new("editor-submit-start")
                        .primary()
                        .small()
                        .label("Save & Start")
                        .on_click(cx.listener(|this, _, window, cx| {
                            this.submit_editor(Desired::Running, window, cx);
                        })),
                ),
        );

    let mut form = div()
        .id("network-editor-scroll")
        .flex_1()
        .overflow_y_scroll()
        .flex()
        .flex_col()
        .gap_4()
        .p_5();

    if let Some(error) = &editor.validation_error {
        form = form.child(
            div()
                .id("editor-validation-error")
                .role(Role::Alert)
                .test_support()
                .aria_label(SharedString::from(error.clone()))
                .px_3()
                .py_2()
                .rounded_md()
                .border_1()
                .border_color(theme.danger)
                .bg(theme.danger.opacity(0.12))
                .text_color(theme.danger)
                .text_sm()
                .child(error.clone()),
        );
    }

    // Core identity fields
    form = form.child(
        div()
            .flex()
            .flex_col()
            .gap_3()
            .p_4()
            .rounded_md()
            .border_1()
            .border_color(theme.border)
            .bg(theme.secondary.opacity(0.25))
            .child(field_row(
                "Display Name",
                Input::new(&editor.display_name)
                    .id("editor-display-name")
                    .aria_label("Display Name"),
                cx,
            ))
            .child(field_row(
                "Network Name *",
                Input::new(&editor.network_name)
                    .id("editor-network-name")
                    .aria_label("Network Name"),
                cx,
            ))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child(
                        div()
                            .text_sm()
                            .font_medium()
                            .text_color(theme.foreground)
                            .child("Network Secret (never saved locally)"),
                    )
                    .child(
                        div()
                            .id("editor-secret-hint")
                            .test_support()
                            .aria_label(SharedString::from(secret_hint))
                            .text_xs()
                            .text_color(theme.muted_foreground)
                            .child(secret_hint),
                    )
                    .child({
                        let mut mode_row = div().flex().flex_row().gap_2();
                        if is_edit {
                            mode_row = mode_row.child(
                                Button::new("secret-mode-keep")
                                    .small()
                                    .outline()
                                    .label("Keep Existing")
                                    .with_variant(if editor.secret_mode == SecretMode::Keep {
                                        gpui_kit::component::button::ButtonVariant::Primary
                                    } else {
                                        gpui_kit::component::button::ButtonVariant::Secondary
                                    })
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        this.editor.secret_mode = SecretMode::Keep;
                                        this.editor.clear_secret(window, cx);
                                        cx.notify();
                                    })),
                            );
                        }
                        mode_row
                            .child(
                                Button::new("secret-mode-set")
                                    .small()
                                    .outline()
                                    .label(if is_edit {
                                        "Replace Secret"
                                    } else {
                                        "Set Secret"
                                    })
                                    .with_variant(if editor.secret_mode == SecretMode::Set {
                                        gpui_kit::component::button::ButtonVariant::Primary
                                    } else {
                                        gpui_kit::component::button::ButtonVariant::Secondary
                                    })
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.editor.secret_mode = SecretMode::Set;
                                        cx.notify();
                                    })),
                            )
                            .child(
                                Button::new("secret-mode-clear")
                                    .small()
                                    .outline()
                                    .label(if is_edit { "Clear Secret" } else { "No Secret" })
                                    .with_variant(if editor.secret_mode == SecretMode::Clear {
                                        gpui_kit::component::button::ButtonVariant::Primary
                                    } else {
                                        gpui_kit::component::button::ButtonVariant::Secondary
                                    })
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        this.editor.secret_mode = SecretMode::Clear;
                                        this.editor.clear_secret(window, cx);
                                        cx.notify();
                                    })),
                            )
                    })
                    .child(
                        Input::new(&editor.network_secret)
                            .id("editor-network-secret")
                            .aria_label("Network Secret")
                            .content_type(InputContentType::Password)
                            .mask_toggle()
                            .disabled(secret_input_disabled),
                    ),
            )
            .child(field_row(
                "Hostname",
                Input::new(&editor.hostname)
                    .id("editor-hostname")
                    .aria_label("Hostname"),
                cx,
            )),
    );

    // Addressing & Peers
    form = form.child(
        div()
            .flex()
            .flex_col()
            .gap_3()
            .p_4()
            .rounded_md()
            .border_1()
            .border_color(theme.border)
            .bg(theme.secondary.opacity(0.25))
            .child(
                Switch::new("editor-dhcp")
                    .checked(editor.dhcp)
                    .label("Assign virtual IPv4 automatically (DHCP)")
                    .on_change(cx.listener(|this, checked, _, cx| {
                        this.editor.dhcp = *checked;
                        cx.notify();
                    })),
            )
            .child(field_row(
                "Static IPv4 CIDR",
                Input::new(&editor.ipv4_cidr)
                    .id("editor-ipv4-cidr")
                    .aria_label("Static IPv4 CIDR")
                    .disabled(editor.dhcp),
                cx,
            ))
            .child(field_row(
                "Peers",
                Input::new(&editor.peers)
                    .id("editor-peers")
                    .aria_label("Peers"),
                cx,
            )),
    );

    // Listeners & Suggested 11010 set (without faketcp)
    let mut suggested_chips = div().flex().flex_row().flex_wrap().gap_2();
    for (idx, uri) in SUGGESTED_LISTENERS.iter().enumerate() {
        let uri_owned = (*uri).to_owned();
        suggested_chips = suggested_chips.child(
            Button::new(SharedString::from(format!("btn-suggested-listener-{idx}")))
                .xsmall()
                .secondary()
                .label(*uri)
                .on_click(cx.listener(move |this, _, window, cx| {
                    this.editor.add_suggested_listener(&uri_owned, window, cx);
                    cx.notify();
                })),
        );
    }

    form = form.child(
        div()
            .flex()
            .flex_col()
            .gap_3()
            .p_4()
            .rounded_md()
            .border_1()
            .border_color(theme.border)
            .bg(theme.secondary.opacity(0.25))
            .child(field_row(
                "Listeners",
                Input::new(&editor.listeners)
                    .id("editor-listeners")
                    .aria_label("Listeners")
                    .disabled(editor.no_listener),
                cx,
            ))
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
                            .text_color(theme.muted_foreground)
                            .child("Suggested listeners (upstream 11010 set; faketcp excluded):"),
                    )
                    .child(
                        Button::new("btn-suggested-listeners")
                            .xsmall()
                            .outline()
                            .label("Use Suggested 11010 Set")
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.editor.apply_suggested_listeners(window, cx);
                                cx.notify();
                            })),
                    ),
            )
            .child(suggested_chips)
            .child(
                Switch::new("editor-no-listener")
                    .checked(editor.no_listener)
                    .label("Disable all listeners (no_listener)")
                    .on_change(cx.listener(|this, checked, _, cx| {
                        this.editor.no_listener = *checked;
                        cx.notify();
                    })),
            ),
    );

    // Routing, TUN, and advanced toggles
    let no_tun_label = if tun_available {
        "No TUN interface (SOCKS5 / port forwarding only)"
    } else {
        "No TUN interface (required by current user-mode host)"
    };

    form = form.child(
        div()
            .flex()
            .flex_col()
            .gap_3()
            .p_4()
            .rounded_md()
            .border_1()
            .border_color(theme.border)
            .bg(theme.secondary.opacity(0.25))
            .child(field_row(
                "Proxy CIDRs",
                Input::new(&editor.proxy_cidrs)
                    .id("editor-proxy-cidrs")
                    .aria_label("Proxy CIDRs"),
                cx,
            ))
            .child(field_row(
                "Exit Nodes",
                Input::new(&editor.exit_nodes)
                    .id("editor-exit-nodes")
                    .aria_label("Exit Nodes"),
                cx,
            ))
            .child(
                div()
                    .flex()
                    .flex_row()
                    .gap_3()
                    .child(div().flex_1().child(field_row(
                        "MTU",
                        Input::new(&editor.mtu).id("editor-mtu").aria_label("MTU"),
                        cx,
                    )))
                    .child(
                        div().flex_1().child(field_row(
                            "SOCKS5 Port",
                            Input::new(&editor.socks5_port)
                                .id("editor-socks5-port")
                                .aria_label("SOCKS5 Port"),
                            cx,
                        )),
                    ),
            )
            .child(
                Switch::new("editor-no-tun")
                    .checked(editor.no_tun)
                    .label(no_tun_label)
                    .on_change(cx.listener(|this, checked, _, cx| {
                        this.editor.no_tun = *checked;
                        cx.notify();
                    })),
            )
            .child(
                Switch::new("editor-enable-exit-node")
                    .checked(editor.enable_exit_node)
                    .label("Act as exit node")
                    .on_change(cx.listener(|this, checked, _, cx| {
                        this.editor.enable_exit_node = *checked;
                        cx.notify();
                    })),
            )
            .child(
                Switch::new("editor-magic-dns")
                    .checked(editor.magic_dns)
                    .label("Enable Magic DNS")
                    .on_change(cx.listener(|this, checked, _, cx| {
                        this.editor.magic_dns = *checked;
                        cx.notify();
                    })),
            )
            .child(
                Switch::new("editor-latency-first")
                    .checked(editor.latency_first)
                    .label("Latency-first routing")
                    .on_change(cx.listener(|this, checked, _, cx| {
                        this.editor.latency_first = *checked;
                        cx.notify();
                    })),
            )
            .child(
                Switch::new("editor-private-mode")
                    .checked(editor.private_mode)
                    .label("Private mode")
                    .on_change(cx.listener(|this, checked, _, cx| {
                        this.editor.private_mode = *checked;
                        cx.notify();
                    })),
            )
            .child(
                Switch::new("editor-disable-p2p")
                    .checked(editor.disable_p2p)
                    .label("Disable P2P (relay only)")
                    .on_change(cx.listener(|this, checked, _, cx| {
                        this.editor.disable_p2p = *checked;
                        cx.notify();
                    })),
            ),
    );

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
}

fn field_row(label: &str, control: impl IntoElement, cx: &App) -> impl IntoElement {
    let theme = cx.theme();
    div()
        .flex()
        .flex_col()
        .gap_1()
        .child(
            div()
                .text_sm()
                .font_medium()
                .text_color(theme.foreground)
                .child(label.to_owned()),
        )
        .child(control)
}
