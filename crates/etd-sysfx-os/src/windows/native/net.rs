//! IP Helper: unicast addresses, routes and TCP listeners, in the rows the
//! PowerShell worker produced (Get-NetIPAddress, Get-NetRoute,
//! Get-NetTCPConnection -State Listen).
use super::super::WinError;
use ::windows::Win32::{
    Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR, WIN32_ERROR},
    NetworkManagement::IpHelper::{
        ConvertInterfaceLuidToAlias, FreeMibTable, GetExtendedTcpTable, GetIpForwardTable2,
        GetUnicastIpAddressTable, MIB_IPFORWARD_TABLE2, MIB_TCP6ROW_OWNER_PID,
        MIB_TCPROW_OWNER_PID, MIB_UNICASTIPADDRESS_TABLE, TCP_TABLE_OWNER_PID_LISTENER,
    },
    NetworkManagement::Ndis::NET_LUID_LH,
    Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_INET},
};
use serde_json::{Value, json};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn check(rc: WIN32_ERROR, what: &str) -> Result<(), WinError> {
    if rc == NO_ERROR {
        Ok(())
    } else {
        Err(WinError::new(rc.0 as i64, what))
    }
}

/// The address in `a`, and its IPv6 scope id (0 for IPv4).
fn address(a: &SOCKADDR_INET) -> Result<(IpAddr, u32), WinError> {
    // SAFETY: si_family is the discriminant shared by both variants; the
    // variant read is the one it names.
    unsafe {
        if a.si_family == AF_INET {
            Ok((
                IpAddr::V4(Ipv4Addr::from(u32::from_be(a.Ipv4.sin_addr.S_un.S_addr))),
                0,
            ))
        } else if a.si_family == AF_INET6 {
            Ok((
                IpAddr::V6(Ipv6Addr::from(a.Ipv6.sin6_addr.u.Byte)),
                a.Ipv6.Anonymous.sin6_scope_id,
            ))
        } else {
            Err(WinError::invalid("unexpected address family"))
        }
    }
}

/// A MIB table from the iphlpapi allocator, freed on drop.
struct Mib<T>(*mut T);
impl<T> Drop for Mib<T> {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: allocated by the IP Helper call that filled it.
            unsafe { FreeMibTable(self.0.cast()) };
        }
    }
}

/// `{index, address, prefix}` for every unicast address, IPv6 ones with a
/// scope written `%<scope>` as Get-NetIPAddress shows them.
pub(super) fn ip_addresses() -> Result<Vec<Value>, WinError> {
    let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
    // SAFETY: the out pointer is valid; the table is freed by Mib.
    check(
        unsafe { GetUnicastIpAddressTable(AF_UNSPEC, &mut table) },
        "GetUnicastIpAddressTable",
    )?;
    let table = Mib(table);
    // SAFETY: the table holds NumEntries rows after its header.
    let rows = unsafe {
        std::slice::from_raw_parts((*table.0).Table.as_ptr(), (*table.0).NumEntries as usize)
    };
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let (ip, scope) = address(&row.Address)?;
        let text = match ip {
            IpAddr::V6(_) if scope != 0 => format!("{ip}%{scope}"),
            _ => ip.to_string(),
        };
        out.push(json!({
            "index": row.InterfaceIndex,
            "address": text,
            "prefix": row.OnLinkPrefixLength,
        }));
    }
    Ok(out)
}

fn alias(luid: &NET_LUID_LH) -> Result<String, WinError> {
    let mut buf = [0u16; 257];
    // SAFETY: the LUID and the buffer are valid for the call.
    check(
        unsafe { ConvertInterfaceLuidToAlias(luid, &mut buf) },
        "ConvertInterfaceLuidToAlias",
    )?;
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16(&buf[..end]).map_err(|_| WinError::invalid("invalid interface alias"))
}

/// `{name, index, description}` for every route: the interface alias and
/// `"<prefix>/<length> via <next hop> metric <metric>"`.
pub(super) fn routes() -> Result<Vec<Value>, WinError> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    // SAFETY: as for the address table.
    check(
        unsafe { GetIpForwardTable2(AF_UNSPEC, &mut table) },
        "GetIpForwardTable2",
    )?;
    let table = Mib(table);
    // SAFETY: the table holds NumEntries rows after its header.
    let rows = unsafe {
        std::slice::from_raw_parts((*table.0).Table.as_ptr(), (*table.0).NumEntries as usize)
    };
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let (prefix, _) = address(&row.DestinationPrefix.Prefix)?;
        let (hop, _) = address(&row.NextHop)?;
        out.push(json!({
            "name": alias(&row.InterfaceLuid)?,
            "index": row.InterfaceIndex,
            "description": format!(
                "{prefix}/{} via {hop} metric {}",
                row.DestinationPrefix.PrefixLength, row.Metric
            ),
        }));
    }
    Ok(out)
}

/// The owner-PID listener table of one family, as raw bytes.
fn tcp_table(family: u32) -> Result<Vec<u8>, WinError> {
    let mut size = 0u32;
    for _ in 0..8 {
        let mut buf = vec![0u8; size as usize];
        let ptr = if buf.is_empty() {
            None
        } else {
            Some(buf.as_mut_ptr().cast())
        };
        // SAFETY: the buffer is `size` bytes (or absent to ask for the size).
        let rc = unsafe {
            GetExtendedTcpTable(
                ptr,
                &mut size,
                false,
                family,
                TCP_TABLE_OWNER_PID_LISTENER,
                0,
            )
        };
        if rc == NO_ERROR.0 && !buf.is_empty() {
            buf.truncate(size as usize);
            return Ok(buf);
        }
        if rc != ERROR_INSUFFICIENT_BUFFER.0 && !(rc == NO_ERROR.0 && buf.is_empty()) {
            return Err(WinError::new(rc as i64, "GetExtendedTcpTable"));
        }
        size = size.saturating_add(4096);
    }
    Err(WinError::invalid("the TCP table kept growing"))
}

/// The rows of a table read from `bytes`: a u32 count, then rows aligned
/// like the C struct.
fn table_rows<T: Copy>(bytes: &[u8]) -> Result<Vec<T>, WinError> {
    let count = u32::from_ne_bytes(
        bytes
            .get(..4)
            .ok_or_else(|| WinError::invalid("short TCP table"))?
            .try_into()
            .expect("four bytes"),
    ) as usize;
    let first = std::mem::align_of::<T>().max(4);
    let end = count
        .checked_mul(size_of::<T>())
        .and_then(|n| n.checked_add(first))
        .filter(|&n| n <= bytes.len())
        .ok_or_else(|| WinError::invalid("TCP table count exceeds its size"))?;
    Ok(bytes[first..end]
        .chunks_exact(size_of::<T>())
        // SAFETY: each chunk holds one plain-data row; read unaligned.
        .map(|c| unsafe { c.as_ptr().cast::<T>().read_unaligned() })
        .collect())
}

/// The port in the low 16 bits of a table field, in network order.
fn port(field: u32) -> u16 {
    u16::from_be(field as u16)
}

/// `{address, port, pid}` for every listening TCP socket, IPv4 and IPv6.
pub(super) fn listeners() -> Result<Vec<Value>, WinError> {
    let mut out = Vec::new();
    for row in table_rows::<MIB_TCPROW_OWNER_PID>(&tcp_table(AF_INET.0 as u32)?)? {
        out.push(json!({
            "address": Ipv4Addr::from(u32::from_be(row.dwLocalAddr)).to_string(),
            "port": port(row.dwLocalPort),
            "pid": row.dwOwningPid,
        }));
    }
    for row in table_rows::<MIB_TCP6ROW_OWNER_PID>(&tcp_table(AF_INET6.0 as u32)?)? {
        out.push(json!({
            "address": Ipv6Addr::from(row.ucLocalAddr).to_string(),
            "port": port(row.dwLocalPort),
            "pid": row.dwOwningPid,
        }));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_rows_are_bounded_by_the_buffer() {
        let mut bytes = 2u32.to_ne_bytes().to_vec();
        bytes.extend([0u8; 24]);
        assert!(table_rows::<MIB_TCPROW_OWNER_PID>(&bytes).is_err());
        bytes.extend([0u8; 24]);
        assert_eq!(table_rows::<MIB_TCPROW_OWNER_PID>(&bytes).unwrap().len(), 2);
        assert!(table_rows::<MIB_TCPROW_OWNER_PID>(&[1, 0]).is_err());
    }

    #[test]
    fn ports_are_in_network_order() {
        assert_eq!(port(u32::from(8080u16.to_be())), 8080);
    }
}
