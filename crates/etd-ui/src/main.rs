//! `etd-ui` desktop binary entry point.
//!
//! Starts the background Tokio runtime via [`etd_app::AppRuntime::start`] with
//! `GrpcHostClient` + `LocalConnector`, elevation-aware `LocalHostLauncher`,
//! and `TomlProfileStore`, then runs GPUI with [`QuitMode::Explicit`],
//! [`gpui_kit::assets::Assets`], and [`etd_ui::NativeTrayBackend`]. Every exit
//! funnels through [`etd_app::ExitGate`] before `cx.quit()`.

use std::{cell::RefCell, rc::Rc, sync::Arc};

use etd_app::{AppRuntime, BridgeConfig, window_tray::WindowInput};
use etd_ui::{NativeTrayBackend, PlatformServiceInstaller, UiController, build_local_services};
use gpui_kit::QuitMode;
use tracing_subscriber::EnvFilter;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let (services, is_elevated) =
        build_local_services().expect("failed to initialize desktop application services");
    let (bridge, runtime) =
        AppRuntime::start(services, BridgeConfig::default()).expect("failed to start app runtime");
    let installer = Arc::new(PlatformServiceInstaller::detect());

    let app = gpui_kit::application()
        .with_assets(gpui_kit::assets::Assets)
        .with_quit_mode(QuitMode::Explicit);
    let controller_slot: Rc<RefCell<Option<UiController>>> = Rc::new(RefCell::new(None));
    let reopen_slot = controller_slot.clone();
    app.on_reopen(move |cx| {
        if let Some(controller) = reopen_slot.borrow().as_ref() {
            controller.handle_window_input(WindowInput::ShowRequested, cx);
        }
    });

    app.run(move |cx| {
        gpui_kit::init(cx);
        let tray = NativeTrayBackend::new();
        let wake = tray.wake_receiver();
        let controller = UiController::start(
            bridge,
            Some(runtime),
            Box::new(tray),
            Some(wake),
            installer,
            is_elevated,
            cx,
        )
        .expect("failed to start EasyTier Desktop UI");
        *controller_slot.borrow_mut() = Some(controller);
    });
}
