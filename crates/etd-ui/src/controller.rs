//! Main-thread UI controller coordinating `AppBridge`, `WindowTray`, `TrayDriver`,
//! `ExitGate`, window generation tracking, and service installation.

use std::{cell::RefCell, rc::Rc, sync::Arc};

use anyhow::Result;
use etd_app::{
    AppBridge, AppRuntime, ExitDeadlines, ExitGate, ExitSteps, TrayBackend, UserCommand,
    window_tray::{
        APP_TITLE, ExitReason, TrayDriver, WindowAction, WindowInput, WindowTray, tray_menu,
        tray_summary,
    },
};
use etd_contract::{HostMode, InstanceId, v1::LeaseRelease};
use gpui_kit::{
    AnyWindowHandle, App, AppContext as _, AsyncApp, Bounds, Entity, TitlebarOptions, WindowBounds,
    WindowOptions, px, size,
};

use crate::{
    composition::ServiceInstaller,
    model::{DetailTab, InstallStatus, Section, UiModel},
    views::MainView,
};

/// Optional test/runtime hook invoked when the UI finishes the exit sequence
/// (defaults to `cx.quit()`).
pub type ExitHook = Rc<dyn Fn(&mut App)>;

struct BoxedTray(Box<dyn TrayBackend>);

impl TrayBackend for BoxedTray {
    fn install(
        &mut self,
        tooltip: &str,
        menu: &etd_app::TrayMenu,
    ) -> std::result::Result<(), etd_app::TrayError> {
        self.0.install(tooltip, menu)
    }

    fn set_indicator(
        &mut self,
        indicator: etd_app::TrayIndicator,
        tooltip: &str,
    ) -> std::result::Result<(), etd_app::TrayError> {
        self.0.set_indicator(indicator, tooltip)
    }

    fn set_menu(
        &mut self,
        menu: &etd_app::TrayMenu,
    ) -> std::result::Result<(), etd_app::TrayError> {
        self.0.set_menu(menu)
    }

    fn try_next_event(&mut self) -> Option<etd_app::TrayEvent> {
        self.0.try_next_event()
    }

    fn remove(&mut self) {
        self.0.remove();
    }
}

/// Owns the main-thread UI coordination state. Cheaply cloneable (`Rc<RefCell<...>>`).
#[derive(Clone)]
pub struct UiController {
    pub model: Entity<UiModel>,
    bridge: AppBridge,
    installer: Arc<dyn ServiceInstaller>,
    runtime: Rc<RefCell<Option<AppRuntime>>>,
    window_tray: Rc<RefCell<WindowTray>>,
    tray_driver: Rc<RefCell<TrayDriver<BoxedTray>>>,
    active_window: Rc<RefCell<Option<(u64, AnyWindowHandle)>>>,
    exit_gate: ExitGate,
    exit_hook: ExitHook,
}

impl UiController {
    /// Creates a controller and opens the initial window according to [`WindowTray::new`].
    pub fn start(
        bridge: AppBridge,
        runtime: Option<AppRuntime>,
        tray_backend: Box<dyn TrayBackend>,
        tray_wake: Option<async_channel::Receiver<()>>,
        installer: Arc<dyn ServiceInstaller>,
        is_elevated: bool,
        cx: &mut App,
    ) -> Result<Self> {
        Self::start_with_exit_hook(
            bridge,
            runtime,
            tray_backend,
            tray_wake,
            installer,
            is_elevated,
            Rc::new(|cx| cx.quit()),
            cx,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn start_with_exit_hook(
        bridge: AppBridge,
        runtime: Option<AppRuntime>,
        tray_backend: Box<dyn TrayBackend>,
        tray_wake: Option<async_channel::Receiver<()>>,
        installer: Arc<dyn ServiceInstaller>,
        is_elevated: bool,
        exit_hook: ExitHook,
        cx: &mut App,
    ) -> Result<Self> {
        let preview = installer.command_preview();
        let model = cx.new(|_| UiModel::new(is_elevated, preview));

        let (window_tray, initial_action) = WindowTray::new();
        let mut tray_driver = TrayDriver::new(BoxedTray(tray_backend));
        let availability = tray_driver.install(&tray_menu("Open EasyTier Desktop", "Exit"));
        let tray_available = matches!(availability, WindowInput::TrayAvailability(true));

        model.update(cx, |m, cx| {
            m.tray_available = tray_available;
            cx.notify();
        });

        let controller = Self {
            model,
            bridge: bridge.clone(),
            installer,
            runtime: Rc::new(RefCell::new(runtime)),
            window_tray: Rc::new(RefCell::new(window_tray)),
            tray_driver: Rc::new(RefCell::new(tray_driver)),
            active_window: Rc::new(RefCell::new(None)),
            exit_gate: ExitGate::new(ExitDeadlines::default()),
            exit_hook,
        };

        // Feed initial tray availability before opening the first window.
        controller.handle_window_input(availability, cx);
        controller.perform_window_action(initial_action, cx)?;

        // Pump StateStore snapshots from the background Tokio bridge into GPUI.
        let state_ctrl = controller.clone();
        let states_rx = bridge.states.clone();
        cx.spawn(async move |cx| {
            while let Ok(store) = states_rx.recv().await {
                cx.update(|cx| {
                    state_ctrl.apply_store(store, cx);
                });
            }
        })
        .detach();

        // Pump tray events reactively when the global tray handler signals activity.
        if let Some(wake_rx) = tray_wake {
            let tray_ctrl = controller.clone();
            cx.spawn(async move |cx| {
                while wake_rx.recv().await.is_ok() {
                    cx.update(|cx| {
                        tray_ctrl.poll_tray(cx);
                    });
                }
            })
            .detach();
        }

        // Kick off auto-connect probe against installed service or running user host.
        controller.send_command(UserCommand::AutoConnect);

        Ok(controller)
    }

    /// Creates a lightweight controller bound to a single test window without
    /// spawning background OS tray loops.
    pub fn new_for_window(
        bridge: AppBridge,
        runtime: Option<AppRuntime>,
        tray_backend: Box<dyn TrayBackend>,
        installer: Arc<dyn ServiceInstaller>,
        is_elevated: bool,
        exit_hook: ExitHook,
        cx: &mut App,
    ) -> Self {
        let preview = installer.command_preview();
        let model = cx.new(|_| UiModel::new(is_elevated, preview));
        let (mut window_tray, _first) = WindowTray::new();
        let mut tray_driver = TrayDriver::new(BoxedTray(tray_backend));
        let availability = tray_driver.install(&tray_menu("Open EasyTier Desktop", "Exit"));
        let tray_available = matches!(availability, WindowInput::TrayAvailability(true));
        let _ = window_tray.handle(availability);
        model.update(cx, |m, cx| {
            m.tray_available = tray_available;
            cx.notify();
        });
        Self {
            model,
            bridge,
            installer,
            runtime: Rc::new(RefCell::new(runtime)),
            window_tray: Rc::new(RefCell::new(window_tray)),
            tray_driver: Rc::new(RefCell::new(tray_driver)),
            active_window: Rc::new(RefCell::new(None)),
            exit_gate: ExitGate::new(ExitDeadlines::default()),
            exit_hook,
        }
    }

    pub fn send_command(&self, command: UserCommand) {
        if let Err(error) = self.bridge.commands.try_send(command) {
            tracing::warn!(%error, "failed to send command to background runtime");
        }
    }

    /// Updates [`UiModel`] and refreshes the tray indicator/tooltip when connected.
    pub fn apply_store(&self, store: etd_app::StateStore, cx: &mut App) {
        let previous_selected = self.model.read(cx).selected_instance.clone();
        let maybe_summary = tray_summary(&store);

        self.model.update(cx, |m, cx| {
            m.apply_store(store);
            cx.notify();
        });

        let new_selected = self.model.read(cx).selected_instance.clone();
        if new_selected != previous_selected {
            self.send_command(UserCommand::Watch(new_selected));
        }

        if let Some(summary) = maybe_summary {
            let lost = self.tray_driver.borrow_mut().show(&summary);
            if let Some(input) = lost {
                self.handle_window_input(input, cx);
            }
        }
    }

    /// Drains any pending tray events from [`TrayDriver`] into [`WindowTray`].
    pub fn poll_tray(&self, cx: &mut App) {
        let inputs = self.tray_driver.borrow_mut().poll();
        for input in inputs {
            self.handle_window_input(input, cx);
        }
    }

    pub fn select_section(&self, section: Section, cx: &mut App) {
        self.model.update(cx, |m, cx| {
            m.active_section = section;
            cx.notify();
        });
    }

    pub fn select_instance(&self, instance: Option<InstanceId>, cx: &mut App) {
        self.model.update(cx, |m, cx| {
            m.selected_instance = instance.clone();
            m.active_section = Section::Instances;
            cx.notify();
        });
        self.send_command(UserCommand::Watch(instance));
    }

    pub fn select_detail_tab(&self, tab: DetailTab, cx: &mut App) {
        self.model.update(cx, |m, cx| {
            if let Some(cap) = tab.required_capability()
                && !m.store.has_capability(cap)
            {
                return;
            }
            m.detail_tab = tab;
            cx.notify();
        });
    }

    pub fn dismiss_keep_window_notice(&self, cx: &mut App) {
        self.model.update(cx, |m, cx| {
            m.keep_window_notice = false;
            cx.notify();
        });
    }

    /// Invokes [`ServiceInstaller::install`] off the UI thread; on success connects
    /// to [`HostMode::Service`].
    pub fn request_service_install(&self, cx: &mut App) {
        if matches!(
            self.model.read(cx).install_status,
            Some(InstallStatus::InProgress)
        ) {
            return;
        }
        self.model.update(cx, |m, cx| {
            m.install_status = Some(InstallStatus::InProgress);
            cx.notify();
        });

        let installer = self.installer.clone();
        let ctrl = self.clone();
        cx.spawn(async move |cx| {
            let result = cx
                .background_executor()
                .spawn(async move { installer.install() })
                .await;
            cx.update(|cx| match result {
                Ok(()) => {
                    ctrl.model.update(cx, |m, cx| {
                        m.install_status = Some(InstallStatus::Succeeded);
                        cx.notify();
                    });
                    ctrl.send_command(UserCommand::Connect(HostMode::Service));
                }
                Err(message) => {
                    ctrl.model.update(cx, |m, cx| {
                        m.install_status = Some(InstallStatus::Failed(message));
                        cx.notify();
                    });
                }
            });
        })
        .detach();
    }

    /// Requests an ordered exit through [`WindowTray`] and [`ExitGate`].
    pub fn request_exit(&self, reason: ExitReason, cx: &mut App) {
        self.handle_window_input(WindowInput::ExitRequested(reason), cx);
    }

    /// Feeds a [`WindowInput`] into the [`WindowTray`] state table and performs the
    /// resulting [`WindowAction`], returning the action taken.
    pub fn handle_window_input(&self, input: WindowInput, cx: &mut App) -> Option<WindowAction> {
        if let WindowInput::TrayAvailability(available) = input {
            self.model.update(cx, |m, cx| {
                m.tray_available = available;
                if available {
                    m.keep_window_notice = false;
                }
                cx.notify();
            });
        }
        let action = self.window_tray.borrow_mut().handle(input);
        if let Some(action) = action
            && let Err(error) = self.perform_window_action(action, cx)
        {
            tracing::warn!(?action, %error, "window action failed");
        }
        action
    }

    pub fn window_tray_snapshot(&self) -> WindowTray {
        self.window_tray.borrow().clone()
    }

    pub fn is_exiting(&self) -> bool {
        self.exit_gate.is_triggered()
    }

    fn perform_window_action(&self, action: WindowAction, cx: &mut App) -> Result<()> {
        match action {
            WindowAction::OpenWindow { generation } => self.open_window(generation, cx),
            WindowAction::FocusWindow { .. } => {
                let handle = self.active_window.borrow().map(|(_, h)| h);
                if let Some(handle) = handle {
                    let _ = handle.update(cx, |_, window, _| {
                        window.activate_window();
                    });
                }
                Ok(())
            }
            WindowAction::CloseWindow { generation } => {
                let handle = {
                    let mut slot = self.active_window.borrow_mut();
                    if slot.is_some_and(|(active_gen, _)| active_gen == generation) {
                        slot.take().map(|(_, h)| h)
                    } else {
                        None
                    }
                };
                if let Some(handle) = handle {
                    let _ = handle.update(cx, |_, window, _| {
                        window.remove_window();
                    });
                }
                Ok(())
            }
            WindowAction::KeepWindow => {
                self.model.update(cx, |m, cx| {
                    m.keep_window_notice = true;
                    cx.notify();
                });
                Ok(())
            }
            WindowAction::BeginExit(_reason) => {
                let ctrl = self.clone();
                cx.spawn(async move |cx| {
                    ctrl.run_exit_gate(cx).await;
                })
                .detach();
                Ok(())
            }
        }
    }

    fn open_window(&self, generation: u64, cx: &mut App) -> Result<()> {
        let existing = self.active_window.borrow().map(|(_, h)| h);
        if let Some(handle) = existing {
            if handle
                .update(cx, |_, window, _| {
                    window.activate_window();
                })
                .is_ok()
            {
                return Ok(());
            }
            *self.active_window.borrow_mut() = None;
        }

        let ctrl = self.clone();
        let options = WindowOptions {
            window_bounds: Some(WindowBounds::Windowed(Bounds::centered(
                None,
                size(px(1080.), px(720.)),
                cx,
            ))),
            titlebar: Some(TitlebarOptions {
                title: Some(APP_TITLE.into()),
                ..Default::default()
            }),
            focus: true,
            show: true,
            window_background: crate::theme::window_background(cx),
            ..Default::default()
        };

        let (handle, _view) = gpui_kit::open_window(options, cx, |window, cx| {
            let close_ctrl = ctrl.clone();
            window.on_window_should_close(cx, move |_window, cx| {
                // Do not call `handle.update(.. window.remove_window())` re-entrantly
                // while inside `on_window_should_close`: returning `true` lets GPUI
                // close the native window cleanly under `QuitMode::Explicit`.
                let action = close_ctrl
                    .window_tray
                    .borrow_mut()
                    .handle(WindowInput::CloseRequested);
                match action {
                    Some(WindowAction::KeepWindow) => {
                        close_ctrl.model.update(cx, |m, cx| {
                            m.keep_window_notice = true;
                            cx.notify();
                        });
                        false
                    }
                    Some(WindowAction::CloseWindow {
                        generation: closed_gen,
                    }) => {
                        let is_this = close_ctrl
                            .active_window
                            .borrow()
                            .is_some_and(|(active_gen, _)| active_gen == closed_gen);
                        if is_this {
                            *close_ctrl.active_window.borrow_mut() = None;
                        }
                        true
                    }
                    _ => true,
                }
            });

            let gone_ctrl = ctrl.clone();
            cx.on_window_closed(move |cx, closed_id| {
                let matches =
                    gone_ctrl
                        .active_window
                        .borrow()
                        .is_some_and(|(active_gen, handle)| {
                            active_gen == generation && handle.window_id() == closed_id
                        });
                if matches {
                    *gone_ctrl.active_window.borrow_mut() = None;
                    gone_ctrl.handle_window_input(WindowInput::WindowGone { generation }, cx);
                }
            })
            .detach();

            cx.new(|cx| MainView::new(ctrl.clone(), window, cx))
        })?;

        *self.active_window.borrow_mut() = Some((generation, handle));
        let _ = handle.update(cx, |_, window, cx| {
            crate::theme::bind_window(window, cx);
            window.activate_window();
        });
        Ok(())
    }

    /// Runs [`ExitGate`] before quitting GPUI (`settle_instances` -> `stop_subscriptions`
    /// -> `stop_runtime` -> remove tray -> `cx.quit()`).
    pub async fn run_exit_gate(&self, cx: &mut AsyncApp) {
        // Close any visible window first so native teardown is deterministic.
        cx.update(|cx| {
            let handle = self.active_window.borrow_mut().take().map(|(_, h)| h);
            if let Some(handle) = handle {
                let _ = handle.update(cx, |_, window, _| {
                    window.remove_window();
                });
            }
        });

        let runtime = self.runtime.borrow_mut().take();
        let tray_driver = self.tray_driver.clone();
        let exit_hook = self.exit_hook.clone();

        let mut steps = OptionalRuntime(runtime);
        let _report = self
            .exit_gate
            .run(&mut steps, LeaseRelease::StopInstances, || {
                cx.update(|cx| {
                    tray_driver.borrow_mut().remove();
                    (exit_hook)(cx);
                });
            })
            .await;
    }
}

struct OptionalRuntime(Option<AppRuntime>);

impl ExitSteps for OptionalRuntime {
    async fn settle_instances(&mut self, release: LeaseRelease) -> std::result::Result<(), String> {
        match self.0.as_mut() {
            Some(runtime) => runtime.settle_instances(release).await,
            None => Ok(()),
        }
    }

    async fn stop_subscriptions(&mut self) -> std::result::Result<(), String> {
        match self.0.as_mut() {
            Some(runtime) => runtime.stop_subscriptions().await,
            None => Ok(()),
        }
    }

    async fn stop_runtime(&mut self) -> std::result::Result<(), String> {
        match self.0.as_mut() {
            Some(runtime) => runtime.stop_runtime().await,
            None => Ok(()),
        }
    }
}
