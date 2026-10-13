use std::collections::{HashMap, HashSet};

use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};

use crate::netdecode::{interesting_tcp_state, ipv4_from_dword, tcp_port};
use crate::{diff_connections, diff_processes, EndpointMonitor, Observation, ProcessStart, TcpConnect};

pub struct WindowsMonitor {
    seen_pids: HashSet<i32>,
    seen_flows: HashSet<(i32, String, u16)>,
    primed: bool,
}

impl WindowsMonitor {
    pub fn new() -> Self {
        Self {
            seen_pids: HashSet::new(),
            seen_flows: HashSet::new(),
            primed: false,
        }
    }
}

impl EndpointMonitor for WindowsMonitor {
    fn poll(&mut self) -> Vec<Observation> {
        let processes = read_processes();
        let names = processes
            .iter()
            .map(|process| (process.pid, process.name.clone()))
            .collect::<HashMap<_, _>>();
        let connections = read_connections(&names);
        if !self.primed {
            for process in &processes {
                self.seen_pids.insert(process.pid);
            }
            for flow in &connections {
                self.seen_flows
                    .insert((flow.pid, flow.address.clone(), flow.port));
            }
            self.primed = true;
            return Vec::new();
        }
        let mut out = diff_processes(&mut self.seen_pids, &processes);
        out.extend(diff_connections(&mut self.seen_flows, &connections));
        out
    }
}

pub(crate) fn read_processes() -> Vec<ProcessStart> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return Vec::new();
        }
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut out = Vec::new();
        if Process32FirstW(snapshot, &mut entry) != 0 {
            loop {
                let pid = entry.th32ProcessID as i32;
                if pid > 0 {
                    out.push(ProcessStart {
                        pid,
                        parent_pid: entry.th32ParentProcessID as i32,
                        name: utf16_name(&entry.szExeFile),
                    });
                }
                entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
                if Process32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snapshot);
        out
    }
}

pub(crate) fn read_connections(names: &HashMap<i32, String>) -> Vec<TcpConnect> {
    let mut out = parse_ipv4_table(&tcp_table(AF_INET as u32), names);
    out.extend(parse_ipv6_table(&tcp_table(AF_INET6 as u32), names));
    out
}

fn tcp_table(family: u32) -> Vec<u8> {
    let mut size = 0u32;
    for _ in 0..3 {
        if size == 0 {
            size = 64 * 1024;
        }
        let mut buf = vec![0u8; size as usize];
        let code = unsafe {
            GetExtendedTcpTable(
                buf.as_mut_ptr().cast(),
                &mut size,
                0,
                family,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        if code == 0 {
            buf.truncate(size as usize);
            return buf;
        }
        if code != 122 {
            return Vec::new();
        }
    }
    Vec::new()
}

fn parse_ipv4_table(buf: &[u8], names: &HashMap<i32, String>) -> Vec<TcpConnect> {
    rows::<MIB_TCPROW_OWNER_PID>(buf)
        .into_iter()
        .filter_map(|row| {
            if !interesting_tcp_state(row.dwState) {
                return None;
            }
            let port = tcp_port(row.dwRemotePort);
            let address = ipv4_from_dword(row.dwRemoteAddr);
            if port == 0 || address == "0.0.0.0" {
                return None;
            }
            Some(flow(row.dwOwningPid, address, port, names))
        })
        .collect()
}

fn parse_ipv6_table(buf: &[u8], names: &HashMap<i32, String>) -> Vec<TcpConnect> {
    rows::<MIB_TCP6ROW_OWNER_PID>(buf)
        .into_iter()
        .filter_map(|row| {
            if !interesting_tcp_state(row.dwState) {
                return None;
            }
            let port = tcp_port(row.dwRemotePort);
            let address = std::net::Ipv6Addr::from(row.ucRemoteAddr).to_string();
            if port == 0 || address == "::" {
                return None;
            }
            Some(flow(row.dwOwningPid, address, port, names))
        })
        .collect()
}

fn flow(pid: u32, address: String, port: u16, names: &HashMap<i32, String>) -> TcpConnect {
    let pid = pid as i32;
    let name = names.get(&pid).cloned().unwrap_or_else(|| "unknown".into());
    TcpConnect {
        pid,
        name,
        address,
        port,
    }
}

fn rows<T>(buf: &[u8]) -> Vec<T> {
    if buf.len() < 4 {
        return Vec::new();
    }
    let count = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let row_size = std::mem::size_of::<T>();
    let mut out = Vec::new();
    for index in 0..count {
        let start = 4 + index * row_size;
        let end = start + row_size;
        if end > buf.len() {
            break;
        }
        let row = unsafe { std::ptr::read_unaligned(buf[start..].as_ptr().cast::<T>()) };
        out.push(row);
    }
    out
}

fn utf16_name(chars: &[u16]) -> String {
    let end = chars.iter().position(|ch| *ch == 0).unwrap_or(chars.len());
    let name = String::from_utf16_lossy(&chars[..end]);
    if name.is_empty() {
        "unknown".into()
    } else {
        name
    }
}
