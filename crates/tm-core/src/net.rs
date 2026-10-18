//! Network by adapter: receive and send speed for every active interface
//! (Ethernet, Wi-Fi, VPN tunnels such as WireGuard). One `GetIfTable2` call.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use windows_sys::Win32::NetworkManagement::IpHelper::{FreeMibTable, GetIfTable2, MIB_IF_ROW2, MIB_IF_TABLE2};

const IF_TYPE_ETHERNET: u32 = 6;
const IF_TYPE_LOOPBACK: u32 = 24;
const IF_TYPE_PROP_VIRTUAL: u32 = 53;
const IF_TYPE_WIFI: u32 = 71;
const IF_TYPE_TUNNEL: u32 = 131;
const IF_OPER_UP: i32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetStat {
    /// Stable adapter key (LUID).
    pub key: String,
    /// The name as in “Network Connections”: “Ethernet”, “Wi-Fi” and so on.
    pub name: String,
    pub description: String,
    /// ethernet | wifi | vpn | other
    pub kind: String,
    pub rx_bps: f64,
    pub tx_bps: f64,
    /// Link speed, bit/s (0 — unknown).
    pub link_bps: u64,
}

struct Prev {
    rx: u64,
    tx: u64,
}

#[derive(Default)]
pub struct NetSampler {
    prev: HashMap<u64, Prev>,
    at: Option<Instant>,
    addrs: HashMap<IpAddr, String>,
    addrs_at: Option<Instant>,
}

fn wstr(buf: &[u16]) -> String {
    let n = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..n])
}

impl NetSampler {
    pub fn sample(&mut self) -> Vec<NetStat> {
        let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
        if unsafe { GetIfTable2(&mut table) } != 0 || table.is_null() {
            return Vec::new();
        }
        // SAFETY: the table is allocated by GetIfTable2 and freed below with FreeMibTable.
        let rows: &[MIB_IF_ROW2] = unsafe {
            let n = (*table).NumEntries as usize;
            std::slice::from_raw_parts((*table).Table.as_ptr(), n)
        };
        let now = Instant::now();
        let dt = self.at.map(|a| now.duration_since(a).as_secs_f64()).unwrap_or(0.0);
        let mut next = HashMap::new();
        let mut out = Vec::new();
        for r in rows {
            let flags = r.InterfaceAndOperStatusFlags._bitfield;
            let hardware = flags & 1 != 0;
            let filter = flags & 2 != 0;
            let tunnel = matches!(r.Type, IF_TYPE_PROP_VIRTUAL | IF_TYPE_TUNNEL);
            // Windows service tunnels for IPv6 (Teredo, ISATAP, 6to4, IP-HTTPS) — not a VPN, just noise
            let transition = r.Type == IF_TYPE_TUNNEL && matches!(r.TunnelType as i32, 11 | 13 | 14 | 15);
            if r.OperStatus != IF_OPER_UP || r.Type == IF_TYPE_LOOPBACK || filter || transition || !(hardware || tunnel) {
                continue;
            }
            let luid = unsafe { r.InterfaceLuid.Value };
            let (rx, tx) = (r.InOctets, r.OutOctets);
            let (rx_bps, tx_bps) = match self.prev.get(&luid) {
                Some(p) if dt > 0.0 => (rx.saturating_sub(p.rx) as f64 / dt, tx.saturating_sub(p.tx) as f64 / dt),
                _ => (0.0, 0.0),
            };
            next.insert(luid, Prev { rx, tx });
            let kind = match r.Type {
                IF_TYPE_ETHERNET => "ethernet",
                IF_TYPE_WIFI => "wifi",
                _ if tunnel => "vpn",
                _ => "other",
            };
            out.push(NetStat {
                key: format!("{luid:x}"),
                name: wstr(&r.Alias),
                description: wstr(&r.Description),
                kind: kind.into(),
                rx_bps,
                tx_bps,
                link_bps: r.ReceiveLinkSpeed.max(r.TransmitLinkSpeed).min(u64::MAX / 2),
            });
        }
        unsafe { FreeMibTable(table.cast()) };
        self.prev = next;
        self.at = Some(now);
        // VPNs first: all app traffic goes through the tunnel
        out.sort_by_key(|n| (n.kind != "vpn", n.name.to_lowercase()));
        out
    }

    /// Addresses of this computer → adapter key. Every 5 s: after a VPN reconnect the tunnel address changes.
    pub fn addresses(&mut self) -> &HashMap<IpAddr, String> {
        use windows_sys::Win32::NetworkManagement::IpHelper::{GetUnicastIpAddressTable, MIB_UNICASTIPADDRESS_ROW, MIB_UNICASTIPADDRESS_TABLE};
        if self.addrs_at.is_some_and(|t| t.elapsed() < Duration::from_secs(5)) {
            return &self.addrs;
        }
        self.addrs_at = Some(Instant::now());
        let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
        if unsafe { GetUnicastIpAddressTable(0, &mut table) } != 0 || table.is_null() {
            return &self.addrs;
        }
        // SAFETY: the table is allocated by GetUnicastIpAddressTable and freed below.
        let rows: &[MIB_UNICASTIPADDRESS_ROW] = unsafe { std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize) };
        self.addrs.clear();
        for r in rows {
            let luid = unsafe { r.InterfaceLuid.Value };
            let ip: Option<IpAddr> = unsafe {
                match r.Address.si_family {
                    2 => Some(Ipv4Addr::from(r.Address.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes()).into()),
                    23 => Some(Ipv6Addr::from(r.Address.Ipv6.sin6_addr.u.Byte).into()),
                    _ => None,
                }
            };
            if let Some(ip) = ip {
                self.addrs.insert(ip, format!("{luid:x}"));
            }
        }
        unsafe { FreeMibTable(table.cast()) };
        &self.addrs
    }
}
