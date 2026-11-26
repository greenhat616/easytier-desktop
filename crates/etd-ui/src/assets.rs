//! Embedded Fluent System Icons (MIT), composed with GPUI Kit's default assets.
//!
//! The original upstream files and license/attribution are in `assets/fluent`.
//! All other Kit assets retain their original lookup behavior.

use std::borrow::Cow;

use gpui_kit::{AssetSource, Result, SharedString};

#[derive(Clone, Copy, Default)]
pub struct FluentAssets;

const FLUENT: &[(&str, &[u8])] = &[
    ("add.svg", include_bytes!("../assets/fluent/add.svg")),
    (
        "arrow-clockwise.svg",
        include_bytes!("../assets/fluent/arrow-clockwise.svg"),
    ),
    (
        "arrow-counterclockwise.svg",
        include_bytes!("../assets/fluent/arrow-counterclockwise.svg"),
    ),
    (
        "arrow-download.svg",
        include_bytes!("../assets/fluent/arrow-download.svg"),
    ),
    (
        "arrow-left.svg",
        include_bytes!("../assets/fluent/arrow-left.svg"),
    ),
    (
        "arrow-right.svg",
        include_bytes!("../assets/fluent/arrow-right.svg"),
    ),
    (
        "arrow-sync.svg",
        include_bytes!("../assets/fluent/arrow-sync.svg"),
    ),
    (
        "arrow-upload.svg",
        include_bytes!("../assets/fluent/arrow-upload.svg"),
    ),
    (
        "checkmark-circle.svg",
        include_bytes!("../assets/fluent/checkmark-circle.svg"),
    ),
    (
        "checkmark.svg",
        include_bytes!("../assets/fluent/checkmark.svg"),
    ),
    (
        "chevron-down.svg",
        include_bytes!("../assets/fluent/chevron-down.svg"),
    ),
    (
        "chevron-left.svg",
        include_bytes!("../assets/fluent/chevron-left.svg"),
    ),
    (
        "chevron-right.svg",
        include_bytes!("../assets/fluent/chevron-right.svg"),
    ),
    (
        "chevron-up.svg",
        include_bytes!("../assets/fluent/chevron-up.svg"),
    ),
    ("copy.svg", include_bytes!("../assets/fluent/copy.svg")),
    ("delete.svg", include_bytes!("../assets/fluent/delete.svg")),
    (
        "dismiss.svg",
        include_bytes!("../assets/fluent/dismiss.svg"),
    ),
    (
        "document.svg",
        include_bytes!("../assets/fluent/document.svg"),
    ),
    ("edit.svg", include_bytes!("../assets/fluent/edit.svg")),
    (
        "error-circle.svg",
        include_bytes!("../assets/fluent/error-circle.svg"),
    ),
    (
        "eye-off.svg",
        include_bytes!("../assets/fluent/eye-off.svg"),
    ),
    ("eye.svg", include_bytes!("../assets/fluent/eye.svg")),
    ("folder.svg", include_bytes!("../assets/fluent/folder.svg")),
    (
        "error-circle-filled.svg",
        include_bytes!("../assets/fluent/error-circle-filled.svg"),
    ),
    (
        "warning-filled.svg",
        include_bytes!("../assets/fluent/warning-filled.svg"),
    ),
    (
        "checkmark-circle-filled.svg",
        include_bytes!("../assets/fluent/checkmark-circle-filled.svg"),
    ),
    (
        "info-filled.svg",
        include_bytes!("../assets/fluent/info-filled.svg"),
    ),
    ("globe.svg", include_bytes!("../assets/fluent/globe.svg")),
    (
        "globe-filled.svg",
        include_bytes!("../assets/fluent/globe-filled.svg"),
    ),
    ("info.svg", include_bytes!("../assets/fluent/info.svg")),
    (
        "link-dismiss.svg",
        include_bytes!("../assets/fluent/link-dismiss.svg"),
    ),
    ("link.svg", include_bytes!("../assets/fluent/link.svg")),
    (
        "more-horizontal.svg",
        include_bytes!("../assets/fluent/more-horizontal.svg"),
    ),
    (
        "network-check.svg",
        include_bytes!("../assets/fluent/network-check.svg"),
    ),
    ("person.svg", include_bytes!("../assets/fluent/person.svg")),
    ("play.svg", include_bytes!("../assets/fluent/play.svg")),
    ("search.svg", include_bytes!("../assets/fluent/search.svg")),
    ("server.svg", include_bytes!("../assets/fluent/server.svg")),
    (
        "settings.svg",
        include_bytes!("../assets/fluent/settings.svg"),
    ),
    ("shield.svg", include_bytes!("../assets/fluent/shield.svg")),
    (
        "shield-filled.svg",
        include_bytes!("../assets/fluent/shield-filled.svg"),
    ),
    (
        "sign-out.svg",
        include_bytes!("../assets/fluent/sign-out.svg"),
    ),
    ("stop.svg", include_bytes!("../assets/fluent/stop.svg")),
    (
        "subtract.svg",
        include_bytes!("../assets/fluent/subtract.svg"),
    ),
    (
        "warning.svg",
        include_bytes!("../assets/fluent/warning.svg"),
    ),
    (
        "LICENSE.txt",
        include_bytes!("../assets/fluent/LICENSE.txt"),
    ),
];

fn fluent_name(path: &str) -> Option<&str> {
    if let Some(name) = path.strip_prefix("fluent/") {
        return Some(name);
    }
    // Override the matching Kit icons, including Input's mask toggle.
    let name = path.strip_prefix("icons/")?;
    Some(match name {
        "check.svg" => "checkmark.svg",
        "x.svg" => "dismiss.svg",
        "plus.svg" => "add.svg",
        "minus.svg" => "subtract.svg",
        "refresh-cw.svg" => "arrow-clockwise.svg",
        "refresh-ccw.svg" => "arrow-counterclockwise.svg",
        "download.svg" => "arrow-download.svg",
        "upload.svg" => "arrow-upload.svg",
        "ellipsis.svg" => "more-horizontal.svg",
        "circle-check.svg" => "checkmark-circle.svg",
        "circle-alert.svg" | "circle-x.svg" => "error-circle.svg",
        "alert-triangle.svg" => "warning.svg",
        "unlink.svg" => "link-dismiss.svg",
        "user.svg" => "person.svg",
        "log-out.svg" => "sign-out.svg",
        "trash.svg" | "trash-2.svg" => "delete.svg",
        "pencil.svg" => "edit.svg",
        "file.svg" => "document.svg",
        _ => name,
    })
}

impl AssetSource for FluentAssets {
    fn load(&self, path: &str) -> Result<Option<Cow<'static, [u8]>>> {
        if let Some(name) = fluent_name(path)
            && let Some((_, bytes)) = FLUENT.iter().find(|(candidate, _)| *candidate == name)
        {
            return Ok(Some(Cow::Borrowed(bytes)));
        }
        gpui_kit::assets::Assets.load(path)
    }

    fn list(&self, path: &str) -> Result<Vec<SharedString>> {
        let mut paths = gpui_kit::assets::Assets.list(path)?;
        paths.extend(FLUENT.iter().filter_map(|(name, _)| {
            let name = format!("fluent/{name}");
            name.starts_with(path).then(|| name.into())
        }));
        paths.sort_unstable();
        paths.dedup();
        Ok(paths)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn composed_assets_override_kit_icons_and_keep_fallbacks() {
        let assets = FluentAssets;
        let fluent = assets.load("fluent/eye.svg").unwrap().unwrap();
        assert_eq!(assets.load("icons/eye.svg").unwrap().unwrap(), fluent);
        assert_eq!(
            assets.load("icons/plus.svg").unwrap(),
            assets.load("fluent/add.svg").unwrap()
        );
        let original = gpui_kit::assets::Assets
            .load("icons/eye.svg")
            .unwrap()
            .unwrap();
        assert_ne!(fluent, original);
        // Exercise an actual fallback path from Kit rather than assuming a
        // particular optional Lucide glyph is in the default bundle.
        let fallback = gpui_kit::assets::Assets
            .list("icons/")
            .unwrap()
            .into_iter()
            .find(|p| fluent_name(p).is_none_or(|n| !FLUENT.iter().any(|(f, _)| *f == n)))
            .expect("Kit contains icons outside the Fluent subset");
        assert_eq!(
            assets.load(&fallback).unwrap(),
            gpui_kit::assets::Assets.load(&fallback).unwrap()
        );
        assert!(
            assets
                .list("fluent/")
                .unwrap()
                .iter()
                .any(|p| p.as_ref() == "fluent/LICENSE.txt")
        );
    }
}
