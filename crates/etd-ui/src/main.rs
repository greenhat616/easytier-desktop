//! `etd-ui` desktop binary entry point.
//!
//! Starts the background Tokio runtime via [`etd_app::AppRuntime::start`] with
//! `GrpcHostClient` + `LocalConnector`, elevation-aware `LocalHostLauncher`,
//! and `TomlProfileStore`, then runs GPUI with [`QuitMode::Explicit`],
//! [`etd_ui::assets::FluentAssets`], and [`etd_ui::NativeTrayBackend`]. Every exit
//! funnels through [`etd_app::ExitGate`] before `cx.quit()`. Logs and panics
//! go to a rotated file first ([`logging`]).
//!
//! Release builds use the Windows GUI subsystem, so launching the app opens
//! no console window.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod logging;

use std::{cell::RefCell, rc::Rc, sync::Arc};

use etd_app::launcher_session::HostChoiceFile;
use etd_app::{AppRuntime, BridgeConfig, window_tray::WindowInput};
use etd_ui::{
    NativeTrayBackend, PlatformServiceInstaller, PlatformSessionCleaner, UiController,
    build_local_services, ui_elevation,
};
use gpui_kit::QuitMode;

fn main() {
    logging::init();

    let (services, is_elevated) =
        build_local_services().expect("failed to initialize desktop application services");
    let (bridge, runtime) =
        AppRuntime::start(services, BridgeConfig::default()).expect("failed to start app runtime");
    let installer = Arc::new(PlatformServiceInstaller::detect());

    let app = gpui_kit::application()
        .with_assets(etd_ui::assets::FluentAssets)
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
        etd_ui::theme::init(cx);
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
        .expect("failed to start EasyTier Desktop UI")
        .with_session_support(
            Arc::new(PlatformSessionCleaner::detect()),
            HostChoiceFile::default_path().map(HostChoiceFile::new),
            ui_elevation(),
            cx,
        );
        *controller_slot.borrow_mut() = Some(controller);
    });
}
