//! The system operations of the retired PowerShell worker, in-process and
//! without COM (doc#17): registry, IP Helper, the service control manager,
//! ToolHelp and FirewallAPI.dll's flat functions. [`run`] takes the same
//! JSON requests and returns the same rows, so the callers do not change.
use super::WinError;
use etd_sysfx::SettingValue;
use serde_json::{Value, json};

mod fw;
mod net;
mod reg;
mod scm;

pub(super) use fw::{SHUTDOWN_WAIT, UNSUPPORTED_BUILD, shutdown};

/// Sweep mode: an object that fails becomes a `{warning, object}` row
/// instead of failing the whole query.
#[derive(Debug, Clone, Copy)]
struct Sweep(bool);

fn field<'a>(request: &'a Value, key: &str) -> Result<&'a str, WinError> {
    request[key]
        .as_str()
        .ok_or_else(|| WinError::invalid(format!("missing {key}")))
}

fn setting(request: &Value, key: &str) -> Result<SettingValue, WinError> {
    serde_json::from_value(request[key].clone())
        .map_err(|e| WinError::invalid(format!("invalid {key}: {e}")))
}

/// One management request, answered with the rows the worker printed.
pub(super) fn run(request: &Value) -> Result<Vec<Value>, WinError> {
    let sweep = Sweep(request["sweep"].as_bool() == Some(true));
    let one = |v: Value| Ok(vec![v]);
    match field(request, "op")? {
        "firewall" => fw::rows(
            request["name"]
                .as_str()
                .filter(|n| !n.is_empty())
                .map(str::to_owned),
            sweep,
        ),
        "nrpt" => reg::nrpt(sweep),
        "profiles" => reg::profiles(sweep),
        "registry_rows" => reg::interface_values(sweep),
        "delete_firewall" => {
            let program = match request["program"].as_str().filter(|p| !p.is_empty()) {
                Some(p) => Some((p.to_owned(), field(request, "direction")?.to_owned())),
                None => None,
            };
            one(json!(fw::delete(fw::Credential {
                id: field(request, "id")?.to_owned(),
                name: field(request, "name")?.to_owned(),
                group: request["group"].as_str().map(str::to_owned),
                program,
            })?))
        }
        "delete_nrpt" => one(json!(reg::delete_nrpt(
            field(request, "id")?,
            field(request, "name")?,
            request["group"].as_str(),
        )?)),
        "delete_profile" => one(json!(reg::delete_profile(
            field(request, "id")?,
            field(request, "name")?,
        )?)),
        "registry" => one(reg::read(field(request, "key")?, field(request, "value")?)?),
        "restore_registry" => one(json!(reg::restore(
            field(request, "key")?,
            field(request, "value")?,
            &setting(request, "ours")?,
            &setting(request, "original")?,
        )?)),
        "magic" => one(json!(reg::magic()?)),
        "ip_addresses" => net::ip_addresses(),
        "routes" => net::routes(),
        "listeners" => net::listeners(),
        "services" => scm::win32_services(),
        "drivers" => scm::drivers(),
        "processes" => scm::processes(),
        _ => Err(WinError::invalid("Unknown OS operation")),
    }
}

/// Whether this Windows build is one firewall cleanup supports.
pub(super) fn firewall_supported() -> Result<(), WinError> {
    fw::supported()
}
