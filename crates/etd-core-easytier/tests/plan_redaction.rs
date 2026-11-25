//! The network secret reaches only the generated file: never the command
//! line, the environment, `Debug` output, errors, logs or snapshots.
#[path = "plan_fixtures.rs"]
mod fixtures;

use etd_core_api::CoreError;
use etd_core_easytier::plan::{Platform, plan_for};
use fixtures::*;
use std::sync::{Arc, Mutex};
use tracing::{
    Event, Metadata, Subscriber,
    field::{Field, Visit},
    span::{Attributes, Id, Record},
};

/// Records every field of every event and span at every level.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<String>>);

impl Visit for Capture {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let mut out = self.0.lock().unwrap();
        out.push_str(&format!("{}={:?}\n", field.name(), value));
    }
}

impl Subscriber for Capture {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, span: &Attributes<'_>) -> Id {
        span.record(&mut self.clone());
        Id::from_u64(1)
    }
    fn record(&self, _: &Id, values: &Record<'_>) {
        values.record(&mut self.clone());
    }
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn event(&self, event: &Event<'_>) {
        event.record(&mut self.clone());
    }
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}
}

#[test]
fn secret_only_in_the_file() {
    for platform in [Platform::Windows, Platform::Linux, Platform::MacOs] {
        let capture = Capture::default();
        let plan = tracing::subscriber::with_default(capture.clone(), || {
            plan_for(&ctx(full()), platform).unwrap()
        });
        let logs = capture.0.lock().unwrap().clone();
        assert!(!logs.contains(SECRET), "secret in logs");
        assert!(!format!("{plan:?}").contains(SECRET), "secret in Debug");
        assert!(!format!("{plan:#?}").contains(SECRET), "secret in Debug");
        for arg in &plan.command.args {
            assert!(
                !arg.to_string_lossy().contains(SECRET),
                "secret on the command line"
            );
        }
        assert!(plan.command.env.is_empty());
        let file = String::from_utf8(plan.files[0].contents.clone()).unwrap();
        // The file carries it, quoted so that TOML reads it back verbatim.
        let doc: toml::Table = toml::from_str(&file).unwrap();
        assert_eq!(
            doc["network_identity"]["network_secret"].as_str(),
            Some(SECRET)
        );
    }
}

#[test]
fn settings_debug_is_redacted() {
    let settings = etd_core_easytier::plan::spec::Settings::from_spec(&full()).unwrap();
    assert_eq!(settings.network_secret.as_deref(), Some(SECRET));
    let debug = format!("{settings:?}{settings:#?}");
    assert!(!debug.contains(SECRET));
    assert!(debug.contains("<redacted>"));
}

#[test]
fn errors_do_not_carry_the_secret() {
    let mut spec = full();
    spec.peers.push("bogus".into());
    let err = plan_for(&ctx(spec), Platform::Linux).unwrap_err();
    assert!(matches!(err, CoreError::InvalidSpec(_)));
    assert!(!err.to_string().contains(SECRET));
    assert!(!format!("{err:?}").contains(SECRET));
}

#[test]
fn snapshots_are_redacted() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/snapshots");
    let mut seen = 0;
    for entry in std::fs::read_dir(&dir).expect("snapshots exist") {
        let path = entry.unwrap().path();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            !text.contains(SECRET),
            "{} holds the secret",
            path.display()
        );
        assert!(
            !text.contains("s3cr3t"),
            "{} holds the secret",
            path.display()
        );
        if text.contains("network_secret") {
            assert!(text.contains("<SECRET>"), "{}", path.display());
            seen += 1;
        }
    }
    assert!(seen > 0, "no snapshot carries a redacted secret");
}
