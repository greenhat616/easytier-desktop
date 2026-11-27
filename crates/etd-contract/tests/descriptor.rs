//! The compiled descriptor matches the frozen baseline in
//! `tests/baseline/etd.v1.txt`: one line per message field, enum value and
//! method, so any renumbering, retyping, rename or removal shows up as a
//! diff. CI's `contract` job runs `buf breaking` against the `freeze-v1` tag
//! and against the start of each change.
//!
//! Additive changes (new fields, values, methods) are allowed by the
//! contract's minor-version rules; accept them by regenerating the baseline
//! with `ETD_UPDATE_BASELINE=1 cargo nextest run -p etd-contract`.
use etd_contract::{FILE_DESCRIPTOR_SET, method_roles};
use prost::Message;
use prost_types::{DescriptorProto, FileDescriptorSet, field_descriptor_proto::Label};
use std::collections::BTreeSet;

const BASELINE: &str = "tests/baseline/etd.v1.txt";

fn message_lines(prefix: &str, message: &DescriptorProto, out: &mut BTreeSet<String>) {
    let name = format!("{prefix}.{}", message.name());
    out.insert(format!("message {name}"));
    for field in &message.field {
        let label = match field.label() {
            Label::Repeated => "repeated",
            _ if field.proto3_optional() => "optional",
            _ => "single",
        };
        let oneof = field
            .oneof_index
            .filter(|_| !field.proto3_optional())
            .map(|index| format!(" oneof={}", message.oneof_decl[index as usize].name()))
            .unwrap_or_default();
        out.insert(format!(
            "field {name}.{} = {} {label} {:?}{}{oneof}",
            field.name(),
            field.number(),
            field.r#type(),
            if field.type_name().is_empty() {
                String::new()
            } else {
                format!(" {}", field.type_name())
            },
        ));
    }
    for nested in &message.nested_type {
        message_lines(&name, nested, out);
    }
    for enumeration in &message.enum_type {
        for value in &enumeration.value {
            out.insert(format!(
                "enum {name}.{}.{} = {}",
                enumeration.name(),
                value.name(),
                value.number()
            ));
        }
    }
}

fn current() -> BTreeSet<String> {
    let set = FileDescriptorSet::decode(FILE_DESCRIPTOR_SET).unwrap();
    let mut out = BTreeSet::new();
    for file in set.file.iter().filter(|file| file.package() == "etd.v1") {
        let prefix = format!(".{}", file.package());
        out.insert(format!("file {}", file.name()));
        for message in &file.message_type {
            message_lines(&prefix, message, &mut out);
        }
        for enumeration in &file.enum_type {
            for value in &enumeration.value {
                out.insert(format!(
                    "enum {prefix}.{}.{} = {}",
                    enumeration.name(),
                    value.name(),
                    value.number()
                ));
            }
        }
        for extension in &file.extension {
            out.insert(format!(
                "extend {} {} = {} {}",
                extension.extendee(),
                extension.name(),
                extension.number(),
                extension.type_name()
            ));
        }
        for service in &file.service {
            for method in &service.method {
                out.insert(format!(
                    "rpc {prefix}.{}.{}({}{}) returns ({}{})",
                    service.name(),
                    method.name(),
                    if method.client_streaming() {
                        "stream "
                    } else {
                        ""
                    },
                    method.input_type(),
                    if method.server_streaming() {
                        "stream "
                    } else {
                        ""
                    },
                    method.output_type(),
                ));
            }
        }
    }
    for method in method_roles() {
        out.insert(format!("role {} = {:?}", method.path, method.role));
    }
    out
}

#[test]
fn descriptor_matches_baseline() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(BASELINE);
    let current = current();
    if std::env::var_os("ETD_UPDATE_BASELINE").is_some() {
        let mut text = current.iter().cloned().collect::<Vec<_>>().join("\n");
        text.push('\n');
        std::fs::write(&path, text).unwrap();
        return;
    }
    let baseline: BTreeSet<String> = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
        .lines()
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect();
    let removed: Vec<_> = baseline.difference(&current).collect();
    let added: Vec<_> = current.difference(&baseline).collect();
    assert!(
        removed.is_empty(),
        "BREAKING: baseline entries changed or removed (needs a major version): {removed:#?}\nnew entries: {added:#?}"
    );
    assert!(
        added.is_empty(),
        "additive contract change; review and regenerate the baseline with ETD_UPDATE_BASELINE=1: {added:#?}"
    );
}
