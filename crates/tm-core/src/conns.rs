//! Network connections and open ports of processes: the TCP and UDP tables (IPv4 and IPv6)
//! with the owner — GetExtendedTcpTable / GetExtendedUdpTable, no administrator rights needed.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4};

use serde::Serialize;
use windows_sys::Win32::NetworkManagement::IpHelper::{GetExtendedTcpTable, GetExtendedUdpTable, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID};

const AF_INET: u32 = 2;
const AF_INET6: u32 = 23;

#[derive(Clone, Debug, Serialize)]
pub struct Conn {
    /// tcp or udp.
    pub proto: &'static str,
    pub local: String,
    pub local_port: u16,
    /// Empty for UDP and for TCP in the listen state.
    pub remote: String,
    pub remote_port: u16,
    /// listen, established, time_wait, … (empty for UDP).
    pub state: &'static str,
    pub pid: u32,
}

fn tcp_state(s: u32) -> &'static str {
    match s {
        1 => "closed",
        2 => "listen",
        3 => "syn_sent",
        4 => "syn_received",
        5 => "established",
        6 => "fin_wait1",
        7 => "fin_wait2",
        8 => "close_wait",
        9 => "closing",
        10 => "last_ack",
        11 => "time_wait",
        12 => "delete_tcb",
        _ => "",
    }
}

/// The whole table: the buffer grows until it fits (connections appear between calls).
fn table(get: impl Fn(*mut u8, &mut u32) -> u32) -> Vec<u8> {
    let mut size = 64 * 1024u32;
    for _ in 0..6 {
        let mut buf = vec![0u8; size as usize];
        match get(buf.as_mut_ptr(), &mut size) {
            0 => {
                buf.truncate(size as usize);
                return buf;
            }
            122 => size = size.saturating_mul(2).max(size + 4096), // ERROR_INSUFFICIENT_BUFFER
            _ => break,
        }
    }
    Vec::new()
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

/// The port in the tables is in network byte order in the low 16 bits.
fn port(v: u32) -> u16 {
    u16::from_be(v as u16)
}

fn v4(v: u32) -> String {
    Ipv4Addr::from(v.to_ne_bytes()).to_string()
}

/// IPv6 with the zone number for link-local addresses (fe80::…%12): without it addresses of different
/// network adapters cannot be told apart.
fn v6(b: &[u8], scope: u32) -> String {
    let a = Ipv6Addr::from(<[u8; 16]>::try_from(b).unwrap());
    if scope != 0 && a.segments()[0] & 0xffc0 == 0xfe80 {
        format!("{a}%{scope}")
    } else {
        a.to_string()
    }
}

/// Table rows: first the number of entries (u32), then fixed-size entries.
fn rows(b: &[u8], size: usize) -> impl Iterator<Item = &[u8]> {
    let n = if b.len() >= 4 { u32_at(b, 0) as usize } else { 0 };
    // in all *_OWNER_PID tables the entries start at offset 4 (u32 alignment)
    b.get(4..).unwrap_or(&[]).chunks_exact(size).take(n)
}

/// All connections and open ports.
pub fn list() -> Vec<Conn> {
    let mut out = Vec::new();
    let tcp = |af: u32| table(|p, s| unsafe { GetExtendedTcpTable(p.cast(), s, 0, af, TCP_TABLE_OWNER_PID_ALL, 0) });
    let udp = |af: u32| table(|p, s| unsafe { GetExtendedUdpTable(p.cast(), s, 0, af, UDP_TABLE_OWNER_PID, 0) });
    // MIB_TCPROW_OWNER_PID: state, local addr, local port, remote addr, remote port, pid — 24 bytes
    for r in rows(&tcp(AF_INET), 24) {
        let state = tcp_state(u32_at(r, 0));
        let listen = state == "listen";
        out.push(Conn {
            proto: "tcp",
            local: v4(u32_at(r, 4)),
            local_port: port(u32_at(r, 8)),
            remote: if listen { String::new() } else { v4(u32_at(r, 12)) },
            remote_port: if listen { 0 } else { port(u32_at(r, 16)) },
            state,
            pid: u32_at(r, 20),
        });
    }
    // MIB_TCP6ROW_OWNER_PID: local addr[16], scope, port, remote addr[16], scope, port, state, pid — 56 bytes
    for r in rows(&tcp(AF_INET6), 56) {
        let state = tcp_state(u32_at(r, 48));
        let listen = state == "listen";
        out.push(Conn {
            proto: "tcp",
            local: v6(&r[0..16], u32_at(r, 16)),
            local_port: port(u32_at(r, 20)),
            remote: if listen { String::new() } else { v6(&r[24..40], u32_at(r, 40)) },
            remote_port: if listen { 0 } else { port(u32_at(r, 44)) },
            state,
            pid: u32_at(r, 52),
        });
    }
    // MIB_UDPROW_OWNER_PID: local addr, local port, pid — 12 bytes
    for r in rows(&udp(AF_INET), 12) {
        out.push(Conn { proto: "udp", local: v4(u32_at(r, 0)), local_port: port(u32_at(r, 4)), remote: String::new(), remote_port: 0, state: "", pid: u32_at(r, 8) });
    }
    // MIB_UDP6ROW_OWNER_PID: local addr[16], scope, port, pid — 28 bytes
    for r in rows(&udp(AF_INET6), 28) {
        out.push(Conn { proto: "udp", local: v6(&r[0..16], u32_at(r, 16)), local_port: port(u32_at(r, 20)), remote: String::new(), remote_port: 0, state: "", pid: u32_at(r, 24) });
    }
    out
}

/// The process that opened the TCP connection `local` → `remote` (IPv4): local connections have
/// both sides in the table, the client’s row is the one where its address is local.
pub fn tcp_owner(local: SocketAddrV4, remote: SocketAddrV4) -> Option<u32> {
    let tcp = table(|p, s| unsafe { GetExtendedTcpTable(p.cast(), s, 0, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) });
    let ip = |v: u32| Ipv4Addr::from(v.to_ne_bytes());
    let pid = rows(&tcp, 24)
        .find(|r| {
            ip(u32_at(r, 4)) == *local.ip() && port(u32_at(r, 8)) == local.port() && ip(u32_at(r, 12)) == *remote.ip() && port(u32_at(r, 16)) == remote.port()
        })
        .map(|r| u32_at(r, 20));
    pid
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ports_and_addresses() {
        // port 443 in the table: 0x01BB in network order → bytes BB 01 in the low word
        assert_eq!(port(0x0000_BB01), 443);
        // 127.0.0.1 is stored in memory as the bytes 7F 00 00 01
        assert_eq!(v4(u32::from_ne_bytes([127, 0, 0, 1])), "127.0.0.1");
    }
}
