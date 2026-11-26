mod exit_gate;
mod grpc_backend;
mod tray;

use std::{
    cell::RefCell,
    io::Write as _,
    net::SocketAddr,
    path::PathBuf,
    rc::Rc,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Result, bail};
use gpui_kit::{
    AnyWindowHandle, App, AppContext as _, AsyncApp, Bounds, Context, Entity, InteractiveElement,
    IntoElement, ParentElement, QuitMode, Render, StatefulInteractiveElement, Styled,
    TitlebarOptions, Window, WindowBounds, WindowOptions, component::label::Label, div, px, rgb,
    size,
};

use crate::{
    exit_gate::{ExitGate, ExitPhase, ExitTrace},
    grpc_backend::{BridgeEvent, TokioBridge},
    tray::{TrayAction, TrayAdapter},
};

#[derive(Debug, Clone)]
struct CliArgs {
    cycles: usize,
    cycle_delay_ms: u64,
    hold_ms: u64,
    interactive: bool,
    expect_compositor: Option<String>,
    require_tray: bool,
    ready_file: Option<PathBuf>,
}

impl Default for CliArgs {
    fn default() -> Self {
        Self {
            cycles: 50,
            cycle_delay_ms: 15,
            hold_ms: 0,
            interactive: false,
            expect_compositor: None,
            require_tray: false,
            ready_file: None,
        }
    }
}

fn parse_args() -> Result<CliArgs> {
    let mut cfg = CliArgs::default();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--cycles" => {
                let val = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--cycles requires a number"))?;
                cfg.cycles = val.parse()?;
            }
            "--cycle-delay-ms" => {
                let val = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--cycle-delay-ms requires a number"))?;
                cfg.cycle_delay_ms = val.parse()?;
            }
            "--hold-ms" => {
                let val = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--hold-ms requires a number"))?;
                cfg.hold_ms = val.parse()?;
            }
            "--interactive" => {
                cfg.interactive = true;
            }
            "--expect-compositor" => {
                let val = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--expect-compositor requires a value"))?;
                cfg.expect_compositor = Some(val);
            }
            "--require-tray" => {
                cfg.require_tray = true;
            }
            "--ready-file" => {
                let val = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--ready-file requires a path"))?;
                cfg.ready_file = Some(PathBuf::from(val));
            }
            "--help" | "-h" => {
                println!(
                    "Usage: ui-runtime-spike [--cycles N] [--cycle-delay-ms MS] [--hold-ms MS] [--interactive] [--expect-compositor NAME] [--require-tray] [--ready-file PATH]"
                );
                std::process::exit(0);
            }
            other => bail!("unknown argument: {other}"),
        }
    }
    Ok(cfg)
}

#[derive(Debug, Default)]
struct RunMetrics {
    compositor_name: String,
    display_count: usize,
    server_addr: Option<SocketAddr>,
    tray_id: String,
    tray_created: bool,
    tray_shell_registered: bool,
    ns_status_item_exists: Option<bool>,
    tray_rect_raw: Option<(f64, f64, u32, u32)>,
    tray_rect: Option<String>,
    cycles_completed: usize,
    events_while_visible: u64,
    events_while_hidden: u64,
    pongs_received: u64,
    last_event_seq: u64,
    last_pong_rtt_ms: Option<f64>,
    errors: Vec<String>,
}

struct SpikeModel {
    connected_addr: Option<SocketAddr>,
    window_visible: bool,
    current_cycle: usize,
    total_cycles: usize,
    event_seq: u64,
    events_while_hidden: u64,
    pongs: u64,
    last_rtt_ms: Option<f64>,
    last_state: String,
    tray_rect_label: String,
}

#[derive(Clone)]
struct Controller {
    model: Entity<SpikeModel>,
    window: Rc<RefCell<Option<AnyWindowHandle>>>,
    bridge: Rc<RefCell<Option<TokioBridge>>>,
    tray: Rc<RefCell<Option<TrayAdapter>>>,
    metrics: Arc<Mutex<RunMetrics>>,
    exit_gate: ExitGate,
    ping_seq: Rc<RefCell<u64>>,
}

impl Controller {
    fn open_or_focus_window(&self, cx: &mut App) -> Result<()> {
        if let Some(handle) = *self.window.borrow() {
            if handle
                .update(cx, |_, window, _| {
                    window.activate_window();
                })
                .is_ok()
            {
                self.set_visible_flag(true, cx);
                return Ok(());
            }
            *self.window.borrow_mut() = None;
        }

        let controller = self.clone();
        let options = WindowOptions {
            window_bounds: Some(WindowBounds::Windowed(Bounds::centered(
                None,
                size(px(540.), px(340.)),
                cx,
            ))),
            titlebar: Some(TitlebarOptions {
                title: Some("EasyTier S3 — UI Runtime Coexistence Spike".into()),
                ..Default::default()
            }),
            focus: true,
            show: true,
            ..Default::default()
        };

        let (handle, _view) = gpui_kit::open_window(options, cx, |window, cx| {
            let on_close_ctrl = controller.clone();
            window.on_window_should_close(cx, move |_window, cx| {
                // Close button hides to tray; QuitMode::Explicit keeps the app & tray alive.
                *on_close_ctrl.window.borrow_mut() = None;
                on_close_ctrl.set_visible_flag(false, cx);
                true
            });
            cx.new(|cx| {
                cx.observe(&controller.model, |_, _, cx| cx.notify())
                    .detach();
                SpikeView { controller }
            })
        })?;

        *self.window.borrow_mut() = Some(handle);
        self.set_visible_flag(true, cx);
        let _ = handle.update(cx, |_, window, _| {
            window.activate_window();
        });
        Ok(())
    }

    fn hide_to_tray(&self, cx: &mut App) {
        if let Some(handle) = self.window.borrow_mut().take() {
            let _ = handle.update(cx, |_, window, _| {
                window.remove_window();
            });
        }
        self.set_visible_flag(false, cx);
    }

    fn toggle_window(&self, cx: &mut App) {
        if self.window.borrow().is_some() {
            self.hide_to_tray(cx);
        } else if let Err(err) = self.open_or_focus_window(cx) {
            eprintln!("[ui] failed to restore window from tray: {err:#}");
        }
    }

    fn send_ping(&self) {
        let mut seq = self.ping_seq.borrow_mut();
        *seq += 1;
        let next = *seq;
        if let Some(bridge) = self.bridge.borrow().as_ref()
            && let Err(err) = bridge.try_send_ping(next)
        {
            eprintln!("[ui] send_ping failed: {err:#}");
        }
    }

    fn request_exit(&self, cx: &mut App) {
        let ctrl = self.clone();
        cx.spawn(async move |cx| {
            ctrl.run_exit(cx).await;
        })
        .detach();
    }

    async fn run_exit(&self, cx: &mut AsyncApp) {
        // Close any visible window first so UI teardown is deterministic.
        cx.update(|cx| {
            self.hide_to_tray(cx);
        });
        let bridge = self.bridge.borrow_mut().take();
        let tray = self.tray.borrow_mut().take();
        self.exit_gate.run(bridge, tray, cx).await;
    }

    fn set_visible_flag(&self, visible: bool, cx: &mut App) {
        self.model.update(cx, |m, cx| {
            m.window_visible = visible;
            cx.notify();
        });
    }
}

struct SpikeView {
    controller: Controller,
}

impl Render for SpikeView {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let model = self.controller.model.read(cx);
        let addr_text = model
            .connected_addr
            .map(|a| a.to_string())
            .unwrap_or_else(|| "connecting...".to_owned());
        let rtt_text = model
            .last_rtt_ms
            .map(|ms| format!("{ms:.2} ms"))
            .unwrap_or_else(|| "—".to_owned());
        let status_line = format!(
            "Cycle {}/{}  |  Tonic ticks: {} (hidden: {})  |  Pongs: {} ({})",
            model.current_cycle,
            model.total_cycles,
            model.event_seq,
            model.events_while_hidden,
            model.pongs,
            rtt_text,
        );
        let tray_line = format!("Tray icon: {}", model.tray_rect_label);
        let server_line = format!("Fake tonic server: {addr_text}  |  {}", model.last_state);

        let hide_ctrl = self.controller.clone();
        let ping_ctrl = self.controller.clone();
        let quit_ctrl = self.controller.clone();

        div()
            .flex()
            .flex_col()
            .size_full()
            .p_5()
            .gap_3()
            .bg(rgb(0x111827))
            .text_color(rgb(0xf3f4f6))
            .child(
                div()
                    .text_lg()
                    .child(Label::new("EasyTier Desktop — S3 UI Runtime Coexistence")),
            )
            .child(
                div()
                    .p_3()
                    .rounded_md()
                    .bg(rgb(0x1f2937))
                    .flex()
                    .flex_col()
                    .gap_1()
                    .child(Label::new(server_line))
                    .child(Label::new(status_line))
                    .child(Label::new(tray_line)),
            )
            .child(
                div()
                    .flex()
                    .flex_row()
                    .gap_2()
                    .mt_2()
                    .child(
                        div()
                            .id("btn-hide")
                            .px_3()
                            .py_2()
                            .rounded_md()
                            .bg(rgb(0x0f766e))
                            .cursor_pointer()
                            .child("Hide to Tray")
                            .on_click(move |_, _, cx| {
                                hide_ctrl.hide_to_tray(cx);
                            }),
                    )
                    .child(
                        div()
                            .id("btn-ping")
                            .px_3()
                            .py_2()
                            .rounded_md()
                            .bg(rgb(0x2563eb))
                            .cursor_pointer()
                            .child("Ping Server")
                            .on_click(move |_, _, _| {
                                ping_ctrl.send_ping();
                            }),
                    )
                    .child(
                        div()
                            .id("btn-quit")
                            .px_3()
                            .py_2()
                            .rounded_md()
                            .bg(rgb(0xb91c1c))
                            .cursor_pointer()
                            .child("Quit (Ordered)")
                            .on_click(move |_, _, cx| {
                                quit_ctrl.request_exit(cx);
                            }),
                    ),
            )
    }
}

fn finalize_and_verify(
    run_started: Instant,
    cfg: &CliArgs,
    metrics: &Arc<Mutex<RunMetrics>>,
    exit_trace: &Arc<Mutex<ExitTrace>>,
) -> Result<()> {
    let total_elapsed = run_started.elapsed();
    let m = metrics.lock().expect("metrics lock");
    let trace = exit_trace.lock().expect("exit trace lock");
    let exit_elapsed = trace
        .started_at
        .map(|s| s.elapsed())
        .unwrap_or(Duration::ZERO);
    let phase_order: Vec<ExitPhase> = trace.phases.iter().map(|(p, _)| *p).collect();

    println!("=== S3 UI Runtime Coexistence Summary ===");
    println!("os                   : {}", std::env::consts::OS);
    println!("compositor_name      : {}", m.compositor_name);
    println!("display_count        : {}", m.display_count);
    println!("total_elapsed        : {total_elapsed:?}");
    println!("exit_elapsed         : {exit_elapsed:?} (limit: 5s)");
    println!("fake_tonic_server    : {:?}", m.server_addr);
    println!("tray_id              : {}", m.tray_id);
    println!("tray_created         : {}", m.tray_created);
    println!("tray_shell_registered: {}", m.tray_shell_registered);
    println!("ns_status_item_exists: {:?}", m.ns_status_item_exists);
    println!(
        "tray_rect            : {}",
        m.tray_rect.as_deref().unwrap_or("none")
    );
    println!(
        "cycles_completed     : {}/{}",
        m.cycles_completed, cfg.cycles
    );
    println!("events_visible       : {}", m.events_while_visible);
    println!("events_hidden        : {}", m.events_while_hidden);
    println!("last_event_seq       : {}", m.last_event_seq);
    println!("pongs_received       : {}", m.pongs_received);
    println!(
        "exit_phases          : {:?}",
        trace
            .phases
            .iter()
            .map(|(p, d)| format!("{} (+{d:?})", p.as_str()))
            .collect::<Vec<_>>()
    );

    if let Some(expected) = cfg.expect_compositor.as_deref()
        && m.compositor_name != expected
    {
        bail!(
            "unexpected compositor: got {:?}, expected {:?}",
            m.compositor_name,
            expected
        );
    }

    if cfg.require_tray && !m.tray_shell_registered {
        bail!(
            "tray icon was not registered with the platform shell/host (detail: {})",
            m.tray_rect.as_deref().unwrap_or("none")
        );
    }

    if !m.errors.is_empty() || !trace.errors.is_empty() {
        bail!(
            "runtime errors recorded: metrics={:?}, exit={:?}",
            m.errors,
            trace.errors
        );
    }

    let expected_order = vec![
        ExitPhase::StopSubscription,
        ExitPhase::StopTokio,
        ExitPhase::QuitGpui,
    ];
    if phase_order != expected_order {
        bail!("unexpected exit order: got {phase_order:?}, expected {expected_order:?}");
    }
    if exit_elapsed >= Duration::from_secs(5) {
        bail!("exit exceeded 5s budget: {exit_elapsed:?}");
    }
    if !cfg.interactive && cfg.cycles > 0 {
        if m.cycles_completed != cfg.cycles {
            bail!(
                "expected {} cycles, completed {}",
                cfg.cycles,
                m.cycles_completed
            );
        }
        if m.events_while_hidden == 0 {
            bail!("received 0 tonic stream events while window was hidden in tray");
        }
        if m.pongs_received == 0 {
            bail!("received 0 tonic Ping/Pong responses");
        }
    }

    println!("VERDICT: PASS");
    let _ = std::io::stdout().flush();
    Ok(())
}

fn write_ready_file(path: &std::path::Path, metrics: &RunMetrics) -> Result<()> {
    let mut body = String::new();
    body.push_str(&format!("pid={}\n", std::process::id()));
    body.push_str(&format!("os={}\n", std::env::consts::OS));
    body.push_str(&format!("compositor={}\n", metrics.compositor_name));
    body.push_str(&format!("display_count={}\n", metrics.display_count));
    body.push_str(&format!("tray_id={}\n", metrics.tray_id));
    body.push_str(&format!(
        "tray_shell_registered={}\n",
        metrics.tray_shell_registered
    ));
    if let Some(exists) = metrics.ns_status_item_exists {
        body.push_str(&format!("ns_status_item_exists={exists}\n"));
    }
    if let Some((x, y, w, h)) = metrics.tray_rect_raw {
        body.push_str(&format!("tray_rect_raw={x:.1},{y:.1},{w},{h}\n"));
    }
    if let Some(label) = metrics.tray_rect.as_deref() {
        body.push_str(&format!("tray_rect={label}\n"));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, body)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn main() -> Result<()> {
    let cfg = parse_args()?;
    let run_started = Instant::now();
    let metrics = Arc::new(Mutex::new(RunMetrics::default()));
    let exit_gate = ExitGate::new();
    let exit_trace = exit_gate.trace();
    let verified = Arc::new(AtomicBool::new(false));

    let metrics_app = metrics.clone();
    let cfg_app = cfg.clone();
    let trace_quit = exit_trace.clone();
    let verified_quit = verified.clone();

    gpui_kit::application()
        .with_quit_mode(QuitMode::Explicit)
        .run(move |cx| {
            gpui_kit::init(cx);

            let compositor_name = cx.compositor_name().to_owned();
            let display_count = cx.displays().len();
            eprintln!(
                "[platform] os={} compositor={compositor_name:?} displays={display_count}",
                std::env::consts::OS
            );

            // On macOS, `[NSApplication terminate:]` invokes `applicationWillTerminate:` and
            // exits the process without returning from `application().run(...)`. Run summary
            // printing and invariant verification inside `on_app_quit` so macOS produces the
            // exact same verified verdict (and non-zero exit code on failure) as Windows/Linux.
            let quit_metrics = metrics_app.clone();
            let quit_cfg = cfg_app.clone();
            let quit_trace = trace_quit.clone();
            let quit_verified = verified_quit.clone();
            cx.on_app_quit(move |_| {
                let metrics = quit_metrics.clone();
                let cfg = quit_cfg.clone();
                let trace = quit_trace.clone();
                let verified = quit_verified.clone();
                async move {
                    if !verified.swap(true, Ordering::SeqCst)
                        && let Err(err) = finalize_and_verify(run_started, &cfg, &metrics, &trace)
                    {
                        eprintln!("VERDICT: FAIL: {err:#}");
                        let _ = std::io::stderr().flush();
                        std::process::exit(1);
                    }
                }
            })
            .detach();

            let bridge = TokioBridge::start().expect("start background tokio + fake tonic server");
            let evt_rx = bridge.events();

            let initial_tooltip = "EasyTier S3 UI Runtime Spike";
            let tray = TrayAdapter::new(initial_tooltip).expect("create system tray icon");
            let tray_rx = tray.actions();
            let tray_id = tray.tray_id().to_owned();
            let ns_status_item_exists = tray.has_ns_status_item();
            let (tray_shell_registered, tray_rect_label) =
                tray.describe_registration(initial_tooltip);
            let tray_rect_raw = tray
                .rect()
                .map(|r| (r.position.x, r.position.y, r.size.width, r.size.height));
            eprintln!(
                "[tray] pid={} id={tray_id} shell_registered={tray_shell_registered} ns_status_item={ns_status_item_exists:?} | {tray_rect_label}",
                std::process::id()
            );
            {
                let mut m = metrics_app.lock().expect("metrics lock");
                m.compositor_name = compositor_name;
                m.display_count = display_count;
                m.tray_id = tray_id;
                m.tray_created = true;
                m.tray_shell_registered = tray_shell_registered;
                m.ns_status_item_exists = ns_status_item_exists;
                m.tray_rect_raw = tray_rect_raw;
                m.tray_rect = Some(tray_rect_label.clone());
            }

            let model = cx.new(|_| SpikeModel {
                connected_addr: None,
                window_visible: false,
                current_cycle: 0,
                total_cycles: if cfg_app.interactive { 0 } else { cfg_app.cycles },
                event_seq: 0,
                events_while_hidden: 0,
                pongs: 0,
                last_rtt_ms: None,
                last_state: "starting".to_owned(),
                tray_rect_label,
            });

            let controller = Controller {
                model: model.clone(),
                window: Rc::new(RefCell::new(None)),
                bridge: Rc::new(RefCell::new(Some(bridge))),
                tray: Rc::new(RefCell::new(Some(tray))),
                metrics: metrics_app.clone(),
                exit_gate: exit_gate.clone(),
                ping_seq: Rc::new(RefCell::new(0)),
            };

            controller
                .open_or_focus_window(cx)
                .expect("open initial GPUI window");

            // Task 1: Bridge event pump (Tokio/tonic -> async-channel -> GPUI foreground).
            let evt_ctrl = controller.clone();
            cx.spawn(async move |cx| {
                while let Ok(event) = evt_rx.recv().await {
                    cx.update(|cx| {
                        let visible = evt_ctrl.window.borrow().is_some();
                        match event {
                            BridgeEvent::Connected { addr } => {
                                evt_ctrl.metrics.lock().expect("metrics lock").server_addr =
                                    Some(addr);
                                evt_ctrl.model.update(cx, |m, cx| {
                                    m.connected_addr = Some(addr);
                                    m.last_state = "connected".to_owned();
                                    cx.notify();
                                });
                            }
                            BridgeEvent::StatusTick { seq, state } => {
                                {
                                    let mut m = evt_ctrl.metrics.lock().expect("metrics lock");
                                    m.last_event_seq = seq;
                                    if visible {
                                        m.events_while_visible += 1;
                                    } else {
                                        m.events_while_hidden += 1;
                                    }
                                }
                                evt_ctrl.model.update(cx, |m, cx| {
                                    m.event_seq = seq;
                                    if !visible {
                                        m.events_while_hidden += 1;
                                    }
                                    m.last_state = state;
                                    cx.notify();
                                });
                            }
                            BridgeEvent::Pong {
                                seq,
                                server_tick,
                                rtt,
                            } => {
                                let rtt_ms = rtt.as_secs_f64() * 1000.0;
                                {
                                    let mut m = evt_ctrl.metrics.lock().expect("metrics lock");
                                    m.pongs_received += 1;
                                    m.last_pong_rtt_ms = Some(rtt_ms);
                                }
                                evt_ctrl.model.update(cx, |m, cx| {
                                    m.pongs += 1;
                                    m.last_rtt_ms = Some(rtt_ms);
                                    m.last_state =
                                        format!("pong(seq={seq}, tick={server_tick})");
                                    cx.notify();
                                });
                            }
                            BridgeEvent::SubscriptionStopped { last_seq } => {
                                evt_ctrl.model.update(cx, |m, cx| {
                                    m.last_state = format!("subscription stopped at {last_seq}");
                                    cx.notify();
                                });
                            }
                            BridgeEvent::Error(err) => {
                                eprintln!("[bridge] error: {err}");
                                evt_ctrl
                                    .metrics
                                    .lock()
                                    .expect("metrics lock")
                                    .errors
                                    .push(err);
                            }
                        }
                    });
                }
            })
            .detach();

            // Task 2: Tray event pump (tray-icon + muda -> async-channel -> GPUI foreground).
            let tray_ctrl = controller.clone();
            cx.spawn(async move |cx| {
                while let Ok(action) = tray_rx.recv().await {
                    cx.update(|cx| match action {
                        TrayAction::ToggleWindow => tray_ctrl.toggle_window(cx),
                        TrayAction::ShowWindow => {
                            let _ = tray_ctrl.open_or_focus_window(cx);
                        }
                        TrayAction::HideWindow => tray_ctrl.hide_to_tray(cx),
                        TrayAction::PingServer => tray_ctrl.send_ping(),
                        TrayAction::Quit => tray_ctrl.request_exit(cx),
                    });
                }
            })
            .detach();

            // Task 3: Automated hide-to-tray / restore stress driver (unless --interactive).
            if !cfg_app.interactive {
                let driver_ctrl = controller.clone();
                let cycles = cfg_app.cycles;
                let step_delay = Duration::from_millis(cfg_app.cycle_delay_ms);
                let hold_duration = Duration::from_millis(cfg_app.hold_ms);
                let ready_file = cfg_app.ready_file.clone();

                cx.spawn(async move |cx| {
                    // Initial ping + wait briefly for tonic stream, AppKit menu bar layout,
                    // and D-Bus SNI watcher registration to settle.
                    cx.update(|_| driver_ctrl.send_ping());
                    cx.background_executor()
                        .timer(Duration::from_millis(200))
                        .await;

                    let mut registered_now = tray_shell_registered;
                    cx.update(|cx| {
                        if let Some(tray) = driver_ctrl.tray.borrow().as_ref() {
                            let (reg, label) = tray.describe_registration(initial_tooltip);
                            let raw = tray.rect().map(|r| {
                                (r.position.x, r.position.y, r.size.width, r.size.height)
                            });
                            let ns_exists = tray.has_ns_status_item();
                            registered_now = reg;
                            eprintln!(
                                "[tray] settled shell_registered={reg} ns_status_item={ns_exists:?} | {label}"
                            );
                            {
                                let mut m = driver_ctrl.metrics.lock().expect("metrics lock");
                                m.tray_shell_registered = reg;
                                m.ns_status_item_exists = ns_exists;
                                m.tray_rect_raw = raw;
                                m.tray_rect = Some(label.clone());
                            }
                            driver_ctrl.model.update(cx, |m, cx| {
                                m.tray_rect_label = label;
                                cx.notify();
                            });
                        }
                        if let Some(ref ready_path) = ready_file {
                            let m = driver_ctrl.metrics.lock().expect("metrics lock");
                            if let Err(err) = write_ready_file(ready_path, &m) {
                                eprintln!("[driver] failed to write ready file: {err:#}");
                            }
                        }
                    });

                    if !hold_duration.is_zero() {
                        eprintln!(
                            "[driver] holding visible window + tray for {hold_duration:?}..."
                        );
                        cx.background_executor().timer(hold_duration).await;
                    }

                    for cycle in 1..=cycles {
                        // Hide to tray (0 open GPUI windows; tray + tokio + tonic stay live).
                        cx.update(|cx| {
                            driver_ctrl.model.update(cx, |m, cx| {
                                m.current_cycle = cycle;
                                cx.notify();
                            });
                            driver_ctrl.hide_to_tray(cx);
                        });
                        cx.background_executor().timer(step_delay).await;

                        // Exercise tonic unary RPC while window is hidden in tray on every 10th cycle.
                        if cycle % 10 == 0 || cycle == 1 {
                            cx.update(|cx| {
                                if !cx.windows().is_empty() {
                                    driver_ctrl
                                        .metrics
                                        .lock()
                                        .expect("metrics lock")
                                        .errors
                                        .push(format!(
                                            "cycle {cycle}: expected 0 open windows while hidden, found {}",
                                            cx.windows().len()
                                        ));
                                }
                                driver_ctrl.send_ping();
                            });
                        }

                        // Restore from tray (re-open GPUI window attached to live SpikeModel).
                        cx.update(|cx| {
                            if let Err(err) = driver_ctrl.open_or_focus_window(cx) {
                                eprintln!("[driver] restore failed on cycle {cycle}: {err:#}");
                                driver_ctrl
                                    .metrics
                                    .lock()
                                    .expect("metrics lock")
                                    .errors
                                    .push(format!("cycle {cycle} restore: {err:#}"));
                            }
                            if registered_now
                                && let Some(tray) = driver_ctrl.tray.borrow().as_ref()
                            {
                                let _ = tray.set_tooltip(&format!(
                                    "EasyTier S3 Spike — cycle {cycle}/{cycles}"
                                ));
                            }
                            driver_ctrl
                                .metrics
                                .lock()
                                .expect("metrics lock")
                                .cycles_completed = cycle;
                        });
                        cx.background_executor().timer(step_delay).await;
                    }

                    // Final ping after all cycles to verify tonic client is still healthy.
                    cx.update(|_| driver_ctrl.send_ping());
                    cx.background_executor()
                        .timer(Duration::from_millis(60))
                        .await;

                    eprintln!(
                        "[driver] completed {cycles} hide/restore cycles; starting ordered exit..."
                    );
                    driver_ctrl.run_exit(cx).await;
                })
                .detach();
            }
        });

    // GPUI application().run(...) returned cleanly (Windows/Linux; macOS exits inside
    // `[NSApplication terminate:]` after `on_app_quit`).
    if !verified.swap(true, Ordering::SeqCst) {
        finalize_and_verify(run_started, &cfg, &metrics, &exit_trace)?;
    } else {
        let trace = exit_trace.lock().expect("exit trace lock");
        let post_run_exit_elapsed = trace
            .started_at
            .map(|s| s.elapsed())
            .unwrap_or(Duration::ZERO);
        if post_run_exit_elapsed >= Duration::from_secs(5) {
            bail!("post-run exit exceeded 5s budget: {post_run_exit_elapsed:?}");
        }
        eprintln!("[exit] gpui run() returned cleanly ({post_run_exit_elapsed:?})");
    }
    Ok(())
}
