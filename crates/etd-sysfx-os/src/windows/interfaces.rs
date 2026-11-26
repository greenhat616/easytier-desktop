//! GetIfTable2 can include phantom devices. An IP interface or a live PnP
//! devnode is required before a Wintun adapter counts as present (S2).
use super::{WinError, observation, opaque, owned_name, query};
use ::windows::{
    Win32::{
        Devices::DeviceAndDriverInstallation::{
            CM_LOCATE_DEVNODE_NORMAL, CM_Locate_DevNodeW, CR_NO_SUCH_DEVNODE, CR_SUCCESS,
        },
        NetworkManagement::IpHelper::{
            FreeMibTable, GetIfTable2, GetIpInterfaceTable, MIB_IF_TABLE2, MIB_IPINTERFACE_TABLE,
        },
        Networking::WinSock::AF_UNSPEC,
    },
    core::HSTRING,
};
use etd_sysfx::{Credential, InterfaceInfo, ObjectKey, Observation, naming};
use serde_json::json;
use std::{collections::HashSet, ptr::null_mut};
use uuid::Uuid;

struct Row {
    name: String,
    guid: Uuid,
    luid: u64,
    index: u32,
    up: bool,
    ip_live: bool,
}
fn rows() -> Result<Vec<Row>, WinError> {
    // SAFETY: both MIB tables are API-owned variable-length arrays. Copy
    // entries before FreeMibTable; use documented NumEntries as length.
    unsafe {
        let mut ip: *mut MIB_IPINTERFACE_TABLE = null_mut();
        let rc = GetIpInterfaceTable(AF_UNSPEC, &mut ip);
        if rc.0 != 0 {
            return Err(WinError::new(rc.0 as i64, "GetIpInterfaceTable"));
        }
        let live: HashSet<_> =
            std::slice::from_raw_parts((*ip).Table.as_ptr(), (*ip).NumEntries as usize)
                .iter()
                .map(|r| r.InterfaceLuid.Value)
                .collect();
        FreeMibTable(ip.cast());
        let mut table: *mut MIB_IF_TABLE2 = null_mut();
        let rc = GetIfTable2(&mut table);
        if rc.0 != 0 {
            return Err(WinError::new(rc.0 as i64, "GetIfTable2"));
        }
        let rows =
            std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize)
                .iter()
                .map(|r| {
                    let alias = &r.Alias[..r
                        .Alias
                        .iter()
                        .position(|c| *c == 0)
                        .unwrap_or(r.Alias.len())];
                    Row {
                        name: String::from_utf16_lossy(alias),
                        guid: Uuid::from_u128(r.InterfaceGuid.to_u128()),
                        luid: r.InterfaceLuid.Value,
                        index: r.InterfaceIndex,
                        up: r.OperStatus.0 == 1,
                        ip_live: live.contains(&r.InterfaceLuid.Value),
                    }
                })
                .collect();
        FreeMibTable(table.cast());
        Ok(rows)
    }
}
fn guid_text(guid: Uuid) -> String {
    format!("{{{}}}", guid.to_string().to_ascii_uppercase())
}
fn device_id(guid: Uuid) -> String {
    format!(r"SWD\Wintun\{}", guid_text(guid))
}
fn devnode_live(guid: Uuid) -> Result<bool, WinError> {
    let mut dev = 0;
    let rc = unsafe {
        CM_Locate_DevNodeW(
            &mut dev,
            &HSTRING::from(device_id(guid)),
            CM_LOCATE_DEVNODE_NORMAL,
        )
    };
    match rc {
        CR_SUCCESS => Ok(true),
        CR_NO_SUCH_DEVNODE => Ok(false),
        _ => Err(WinError::new(rc.0 as i64, "CM_Locate_DevNodeW")),
    }
}
fn identity(row: &Row) -> Credential {
    if owned_name(&row.name) && row.guid == naming::wintun_guid(&row.name) {
        Credential::WinAdapter {
            luid: row.luid,
            device_instance_id: device_id(row.guid),
        }
    } else {
        opaque(format!("{}:{}", row.guid, row.luid))
    }
}
fn key_matches(row: &Row, key: &ObjectKey) -> Result<bool, WinError> {
    let ObjectKey::Interface { name, guid } = key else {
        return Err(WinError::invalid("expected interface key"));
    };
    let guid = guid
        .as_ref()
        .map(|g| Uuid::parse_str(g))
        .transpose()
        .map_err(|_| WinError::invalid("invalid adapter GUID"))?;
    if name.is_none() && guid.is_none() {
        return Err(WinError::invalid("missing adapter key"));
    }
    Ok(name
        .as_ref()
        .is_some_and(|n| n.eq_ignore_ascii_case(&row.name))
        || guid == Some(row.guid))
}
fn find(key: &ObjectKey) -> Result<Option<Row>, WinError> {
    let mut out = None;
    for row in rows()? {
        if key_matches(&row, key)? && (row.ip_live || devnode_live(row.guid)?) {
            if out.is_some() {
                return Err(WinError::invalid("ambiguous interface identity"));
            }
            out = Some(row);
        }
    }
    if out.is_none()
        && let ObjectKey::Interface {
            guid: Some(guid), ..
        } = key
    {
        let guid = Uuid::parse_str(guid).map_err(|_| WinError::invalid("invalid adapter GUID"))?;
        if devnode_live(guid)? {
            return Err(WinError::invalid(
                "live device has no interface identity yet",
            ));
        }
    }
    Ok(out)
}
pub fn observe(key: &ObjectKey) -> Result<Option<Observation>, WinError> {
    Ok(find(key)?.map(|r| {
        observation(
            Some(identity(&r)),
            key.clone(),
            format!("{} live LUID={}", r.name, r.luid),
        )
    }))
}
async fn addresses() -> Result<Vec<serde_json::Value>, WinError> {
    query(json!({"op":"ip_addresses"})).await
}
fn info_row(row: &Row, addresses: &[serde_json::Value]) -> Result<InterfaceInfo, WinError> {
    let mut out = Vec::new();
    for r in addresses
        .iter()
        .filter(|r| r["index"].as_u64() == Some(row.index as u64))
    {
        let ip = r["address"]
            .as_str()
            .and_then(|s| s.split('%').next())
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| WinError::invalid("invalid IP address"))?;
        let prefix = r["prefix"]
            .as_u64()
            .and_then(|n| u8::try_from(n).ok())
            .ok_or_else(|| WinError::invalid("invalid IP prefix"))?;
        out.push((ip, prefix));
    }
    out.sort();
    Ok(InterfaceInfo {
        name: row.name.clone(),
        credential: identity(row),
        addresses: out,
        up: row.up,
    })
}
pub async fn info(key: &ObjectKey) -> Result<Option<InterfaceInfo>, WinError> {
    let Some(row) = find(key)? else {
        return Ok(None);
    };
    info_row(&row, &addresses().await?).map(Some)
}
pub async fn enumerate() -> Result<Vec<(ObjectKey, InterfaceInfo)>, WinError> {
    let addresses = addresses().await?;
    let mut out = Vec::new();
    for row in rows()? {
        if row.ip_live || devnode_live(row.guid)? {
            out.push((
                ObjectKey::Interface {
                    name: Some(row.name.clone()),
                    guid: Some(guid_text(row.guid)),
                },
                info_row(&row, &addresses)?,
            ));
        }
    }
    Ok(out)
}
