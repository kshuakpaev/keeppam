//! Снимок процессов и TCP на macOS. Разбор вывода ps и lsof проверяется без самой системы.

#[cfg(target_os = "macos")]
use std::collections::HashSet;

#[cfg(target_os = "macos")]
use crate::{diff_connections, diff_processes, EndpointMonitor, Observation};

use crate::{ProcessStart, TcpConnect};

#[cfg(target_os = "macos")]
pub struct MacMonitor {
    seen_pids: HashSet<i32>,
    seen_flows: HashSet<(i32, String, u16)>,
    primed: bool,
}

#[cfg(target_os = "macos")]
impl MacMonitor {
    pub fn new() -> Self {
        Self {
            seen_pids: HashSet::new(),
            seen_flows: HashSet::new(),
            primed: false,
        }
    }
}

#[cfg(target_os = "macos")]
impl EndpointMonitor for MacMonitor {
    fn poll(&mut self) -> Vec<Observation> {
        let processes = parse_ps(
            &command_output("/bin/ps", &["-ax", "-o", "pid=", "-o", "ppid=", "-o", "comm="]).unwrap_or_default(),
        );
        let connections = parse_lsof(&lsof_output());
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

#[cfg(target_os = "macos")]
fn lsof_output() -> String {
    command_output("/usr/sbin/lsof", &["-nP", "-iTCP", "-sTCP:ESTABLISHED"])
        .or_else(|| command_output("lsof", &["-nP", "-iTCP", "-sTCP:ESTABLISHED"]))
        .unwrap_or_default()
}

#[cfg(target_os = "macos")]
fn command_output(program: &str, args: &[&str]) -> Option<String> {
    let output = std::process::Command::new(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

pub fn parse_ps(text: &str) -> Vec<ProcessStart> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(pid) = parts.next().and_then(|value| value.parse::<i32>().ok()) else {
            continue;
        };
        let Some(parent_pid) = parts.next().and_then(|value| value.parse::<i32>().ok()) else {
            continue;
        };
        let raw = parts.collect::<Vec<_>>().join(" ");
        if raw.is_empty() || pid <= 0 {
            continue;
        }
        let name = raw.rsplit('/').next().unwrap_or(&raw).to_string();
        out.push(ProcessStart {
            pid,
            parent_pid,
            name,
        });
    }
    out
}

pub fn parse_lsof(text: &str) -> Vec<TcpConnect> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("COMMAND") {
            continue;
        }
        if !line.contains("->") {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(name) = parts.next() else {
            continue;
        };
        let Some(pid) = parts.next().and_then(|value| value.parse::<i32>().ok()) else {
            continue;
        };
        let Some(endpoint) = line.split_whitespace().find(|part| part.contains("->")) else {
            continue;
        };
        let Some(remote) = endpoint.split("->").nth(1) else {
            continue;
        };
        let Some((address, port)) = split_host_port(remote) else {
            continue;
        };
        if port == 0 || address == "0.0.0.0" || address == "::" || address == "*" {
            continue;
        }
        out.push(TcpConnect {
            pid,
            name: name.to_string(),
            address,
            port,
        });
    }
    out
}

fn split_host_port(value: &str) -> Option<(String, u16)> {
    let value = value.trim_matches(|ch: char| ch == '(' || ch == ')');
    if let Some(rest) = value.strip_prefix('[') {
        let (host, port) = rest.split_once("]:")?;
        return Some((host.to_string(), port.parse().ok()?));
    }
    let (host, port) = value.rsplit_once(':')?;
    if host.is_empty() {
        return None;
    }
    Some((host.to_string(), port.parse().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ps_and_lsof_keep_ssh_session() {
        let processes = parse_ps("  10     1 /usr/bin/login\n  42    10 ssh\n  77    1 Google Chrome\n");
        assert_eq!(processes.len(), 3);
        assert_eq!(processes[1].pid, 42);
        assert_eq!(processes[1].parent_pid, 10);
        assert_eq!(processes[1].name, "ssh");
        assert_eq!(processes[2].name, "Google Chrome");

        let table = "\
COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\n\
ssh      42 alice    3u  IPv4 0x1       0t0  TCP 192.168.1.10:51234->10.1.1.8:22 (ESTABLISHED)\n\
ssh      42 alice    4u  IPv6 0x2       0t0  TCP [fe80::1]:51235->[2001:db8::5]:22 (ESTABLISHED)\n\
listen    9 alice    5u  IPv4 0x3       0t0  TCP *:22 (LISTEN)\n";
        let flows = parse_lsof(table);
        assert_eq!(flows.len(), 2);
        assert_eq!(flows[0].name, "ssh");
        assert_eq!(flows[0].pid, 42);
        assert_eq!(flows[0].address, "10.1.1.8");
        assert_eq!(flows[0].port, 22);
        assert_eq!(flows[1].address, "2001:db8::5");
        assert_eq!(flows[1].port, 22);
    }
}
