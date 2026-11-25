// Tray adapter is not wired until the tray lifecycle prototype.
use gpui_kit::{AppContext, Context, IntoElement, Render, Window, WindowOptions, div};
use muda as _;
use tray_icon as _;

struct EmptyView {
    _state: etd_app::StateStore,
}

impl Render for EmptyView {
    fn render(&mut self, _: &mut Window, _: &mut Context<Self>) -> impl IntoElement {
        div()
    }
}

fn main() {
    gpui_kit::application().run(|cx| {
        gpui_kit::init(cx);
        gpui_kit::open_window(WindowOptions::default(), cx, |_, cx| {
            cx.new(|_| EmptyView {
                _state: etd_app::StateStore::default(),
            })
        })
        .expect("failed to open window");
        cx.activate(true);
    });
}
