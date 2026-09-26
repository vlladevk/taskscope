//! Сеть по адаптерам: скорость приёма и отправки для каждого работающего интерфейса
//! (Ethernet, Wi-Fi, туннели VPN вроде WireGuard). Один вызов `GetIfTable2`.

use std::collections::HashMap;
use std::time::Instant;

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
    /// Стабильный ключ адаптера (LUID).
    pub key: String,
    /// Имя, как в «Сетевых подключениях»: «Ethernet», «VPN» и т.п.
    pub name: String,
    pub description: String,
    /// ethernet | wifi | vpn | other
    pub kind: String,
    pub rx_bps: f64,
    pub tx_bps: f64,
    /// Скорость подключения, бит/с (0 — неизвестна).
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
        // SAFETY: таблица выделена GetIfTable2 и освобождается ниже через FreeMibTable.
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
            // служебные туннели Windows для IPv6 (Teredo, ISATAP, 6to4, IP-HTTPS) — не VPN, только шум
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
        // VPN первыми: весь трафик приложений идёт через туннель
        out.sort_by_key(|n| (n.kind != "vpn", n.name.to_lowercase()));
        out
    }
}
