//! GetIfTable2 can include phantom devices. An IP interface or a live PnP
//! devnode is required before a Wintun adapter counts as present (S2).
use super::{WinError, observation, opaque, owned_name, query};
use ::windows::{
    Win32::{
        Devices::DeviceAndDriverInstallation::{
            CM_Get_Device_ID_Size, CM_Get_Device_IDW, CM_LOCATE_DEVNODE_NORMAL, CM_Locate_DevNodeW,
            CR_NO_SUCH_DEVNODE, CR_SUCCESS,
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
        let live: HashSet<_> = std::slice::from_raw_parts(
            std::ptr::addr_of!((*ip).Table)
                .cast::<::windows::Win32::NetworkManagement::IpHelper::MIB_IPINTERFACE_ROW>(),
            (*ip).NumEntries as usize,
        )
        .iter()
        .map(|r| r.InterfaceLuid.Value)
        .collect();
        FreeMibTable(ip.cast());
        let mut table: *mut MIB_IF_TABLE2 = null_mut();
        let rc = GetIfTable2(&mut table);
        if rc.0 != 0 {
            return Err(WinError::new(rc.0 as i64, "GetIfTable2"));
        }
        let rows = std::slice::from_raw_parts(
            std::ptr::addr_of!((*table).Table)
                .cast::<::windows::Win32::NetworkManagement::IpHelper::MIB_IF_ROW2>(),
            (*table).NumEntries as usize,
        )
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
fn devnode(guid: Uuid) -> Result<Option<u32>, WinError> {
    let mut dev = 0;
    let rc = unsafe {
        CM_Locate_DevNodeW(
            &mut dev,
            &HSTRING::from(device_id(guid)),
            CM_LOCATE_DEVNODE_NORMAL,
        )
    };
    match rc {
        CR_SUCCESS => Ok(Some(dev)),
        CR_NO_SUCH_DEVNODE => Ok(None),
        _ => Err(WinError::new(rc.0 as i64, "CM_Locate_DevNodeW")),
    }
}
fn devnode_live(guid: Uuid) -> Result<bool, WinError> {
    Ok(devnode(guid)?.is_some())
}
fn identity(row: &Row) -> Result<Credential, WinError> {
    if owned_name(&row.name)
        && row.guid == naming::wintun_guid(&row.name)
        && let Some(node) = devnode(row.guid)?
    {
        let mut size = 0;
        let code = unsafe { CM_Get_Device_ID_Size(&mut size, node, 0) };
        if code != CR_SUCCESS {
            return Err(WinError::new(code.0 as i64, "CM_Get_Device_ID_Size"));
        }
        let mut buf = vec![0u16; size as usize + 1];
        let code = unsafe { CM_Get_Device_IDW(node, &mut buf, 0) };
        if code != CR_SUCCESS {
            return Err(WinError::new(code.0 as i64, "CM_Get_Device_IDW"));
        }
        let instance = String::from_utf16_lossy(&buf[..size as usize]);
        if !instance.eq_ignore_ascii_case(&device_id(row.guid)) {
            return Err(WinError::invalid("unexpected Wintun device identity"));
        }
        Ok(Credential::WinAdapter {
            luid: row.luid,
            device_instance_id: instance.to_uppercase(),
        })
    } else {
        Ok(opaque(format!("{}:{}", row.guid, row.luid)))
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
    find(key)?
        .map(|r| {
            Ok(observation(
                Some(identity(&r)?),
                key.clone(),
                format!("{} live LUID={}", r.name, r.luid),
            ))
        })
        .transpose()
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
        credential: identity(row)?,
        addresses: out,
        up: row.up,
    })
}
pub async fn info(key: &ObjectKey) -> Result<Option<InterfaceInfo>, WinError> {
    let Some(row) = find(key)? else {
        return Ok(None);
    };
    // Observation deliberately locates by name *or* GUID to report a
    // conflict. Readiness instead needs every supplied identity component.
    let ObjectKey::Interface { name, guid } = key else {
        return Err(WinError::invalid("not an interface key"));
    };
    if name
        .as_ref()
        .is_some_and(|n| !n.eq_ignore_ascii_case(&row.name))
        || guid
            .as_ref()
            .is_some_and(|g| Uuid::parse_str(g).ok() != Some(row.guid))
    {
        return Err(WinError::invalid(
            "interface identity differs from the expected name/GUID",
        ));
    }
    let info = info_row(&row, &addresses().await?)?;
    if owned_name(&row.name) && !matches!(info.credential, Credential::WinAdapter { .. }) {
        return Err(WinError::invalid(
            "Wintun is live but its device identity is not yet confirmed",
        ));
    }
    Ok(Some(info))
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
