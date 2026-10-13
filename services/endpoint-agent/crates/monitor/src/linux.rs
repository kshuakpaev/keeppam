use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::{diff_connections, diff_processes, EndpointMonitor, Observation, ProcessStart, TcpConnect};

pub struct LinuxMonitor {
    seen_pids: HashSet<i32>,
    seen_flows: HashSet<(i32, String, u16)>,
    primed: bool,
}

impl LinuxMonitor {
    pub fn new() -> Self {
        Self {
            seen_pids: HashSet::new(),
            seen_flows: HashSet::new(),
            primed: false,
        }
    }
}

impl EndpointMonitor for LinuxMonitor {
    fn poll(&mut self) -> Vec<Observation> {
        let processes = read_processes();
        let connections = read_connections();
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

fn read_processes() -> Vec<ProcessStart> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        let Ok(text) = std::fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        if let Some(process) = parse_stat(pid, &text) {
            out.push(process);
        }
    }
    out
}

fn read_connections() -> Vec<TcpConnect> {
    let names = process_names();
    let inodes = socket_inodes();
    let mut out = Vec::new();
    if let Ok(text) = std::fs::read_to_string("/proc/net/tcp") {
        out.extend(flows_from_table(&text, false, &inodes, &names));
    }
    if let Ok(text) = std::fs::read_to_string("/proc/net/tcp6") {
        out.extend(flows_from_table(&text, true, &inodes, &names));
    }
    out
}

fn process_names() -> HashMap<i32, String> {
    read_processes()
        .into_iter()
        .map(|process| (process.pid, process.name))
        .collect()
}

fn socket_inodes() -> HashMap<u64, i32> {
    let mut map = HashMap::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return map;
    };
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            let Ok(target) = std::fs::read_link(fd.path()) else {
                continue;
            };
            let target = target.to_string_lossy();
            let Some(inode) = target
                .strip_prefix("socket:[")
                .and_then(|rest| rest.strip_suffix(']'))
                .and_then(|value| value.parse::<u64>().ok())
            else {
                continue;
            };
            map.entry(inode).or_insert(pid);
        }
    }
    map
}

pub fn parse_stat(pid: i32, text: &str) -> Option<ProcessStart> {
    let open = text.find('(')?;
    let close = text.rfind(')')?;
    if close < open {
        return None;
    }
    let name = text[open + 1..close].to_string();
    let rest = text[close + 1..].split_whitespace().collect::<Vec<_>>();
    let parent_pid = rest.get(1)?.parse().ok()?;
    Some(ProcessStart {
        pid,
        parent_pid,
        name,
    })
}

pub fn parse_proc_net(text: &str, ipv6: bool) -> Vec<(String, u16, u64)> {
    let mut out = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if index == 0 {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }
        let state = fields[3];
        if state == "0A" {
            continue;
        }
        let Some((address, port)) = parse_endpoint(fields[2], ipv6) else {
            continue;
        };
        if port == 0 || address == "0.0.0.0" || address == "::" {
            continue;
        }
        let Ok(inode) = fields[9].parse::<u64>() else {
            continue;
        };
        if inode == 0 {
            continue;
        }
        out.push((address, port, inode));
    }
    out
}

fn flows_from_table(
    text: &str,
    ipv6: bool,
    inodes: &HashMap<u64, i32>,
    names: &HashMap<i32, String>,
) -> Vec<TcpConnect> {
    parse_proc_net(text, ipv6)
        .into_iter()
        .map(|(address, port, inode)| {
            let pid = inodes.get(&inode).copied().unwrap_or(0);
            let name = names.get(&pid).cloned().unwrap_or_default();
            TcpConnect {
                pid,
                name,
                address,
                port,
            }
        })
        .collect()
}

fn parse_endpoint(token: &str, ipv6: bool) -> Option<(String, u16)> {
    let (addr_hex, port_hex) = token.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let address = if ipv6 {
        parse_ipv6(addr_hex)?
    } else {
        parse_ipv4(addr_hex)?
    };
    Some((address, port))
}

fn parse_ipv4(hex: &str) -> Option<String> {
    if hex.len() != 8 {
        return None;
    }
    let value = u32::from_str_radix(hex, 16).ok()?;
    let bytes = value.to_le_bytes();
    Some(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string())
}

fn parse_ipv6(hex: &str) -> Option<String> {
    if hex.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for index in 0..4 {
        let word = u32::from_str_radix(&hex[index * 8..index * 8 + 8], 16).ok()?;
        bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    Some(Ipv6Addr::from(bytes).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_comm_with_spaces_and_remote_ipv4() {
        let stat = "42 (ssh: child) R 7 1 1 0";
        let process = parse_stat(42, stat).unwrap();
        assert_eq!(process.name, "ssh: child");
        assert_eq!(process.parent_pid, 7);

        let table = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   \
   0: 0100007F:1F90 140A0A0A:0016 01 00000000:00000000 00:00000000 00000000  1000        0 54321 1 0000000000000000 20 4 30 10 -1\n   \
   1: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 99 1 0000000000000000 100 0 0 10 0\n";
        let rows = parse_proc_net(table, false);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, "10.10.10.20");
        assert_eq!(rows[0].1, 22);
        assert_eq!(rows[0].2, 54321);
    }

    #[test]
    fn second_poll_does_not_panic_when_proc_is_readable() {
        let mut monitor = LinuxMonitor::new();
        let _ = monitor.poll();
        let _ = monitor.poll();
    }
}
