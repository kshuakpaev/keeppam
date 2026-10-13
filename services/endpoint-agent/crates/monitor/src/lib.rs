use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessStart {
    pub pid: i32,
    pub parent_pid: i32,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpConnect {
    pub pid: i32,
    pub name: String,
    pub address: String,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Observation {
    Process(ProcessStart),
    Tcp(TcpConnect),
}

pub trait EndpointMonitor {
    fn poll(&mut self) -> Vec<Observation>;
}

/// На сборке не для Windows вызовов Win32 нет.
#[cfg(not(windows))]
#[derive(Debug, Default)]
pub struct WindowsMonitor;

#[cfg(not(windows))]
impl EndpointMonitor for WindowsMonitor {
    fn poll(&mut self) -> Vec<Observation> {
        Vec::new()
    }
}

#[derive(Debug, Default)]
pub struct IdleMonitor;

impl EndpointMonitor for IdleMonitor {
    fn poll(&mut self) -> Vec<Observation> {
        Vec::new()
    }
}

mod netdecode;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(windows)]
mod windows;

#[cfg(any(target_os = "macos", test))]
mod macos;

#[cfg(windows)]
pub fn established_tcp() -> Vec<TcpConnect> {
    let processes = windows::read_processes();
    let names = processes
        .into_iter()
        .map(|process| (process.pid, process.name))
        .collect::<std::collections::HashMap<_, _>>();
    windows::read_connections(&names)
}

pub fn host_monitor() -> Box<dyn EndpointMonitor> {
    #[cfg(target_os = "linux")]
    {
        Box::new(linux::LinuxMonitor::new())
    }
    #[cfg(windows)]
    {
        Box::new(windows::WindowsMonitor::new())
    }
    #[cfg(target_os = "macos")]
    {
        Box::new(macos::MacMonitor::new())
    }
    #[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
    {
        Box::new(IdleMonitor)
    }
}

pub fn diff_processes(seen: &mut HashSet<i32>, current: &[ProcessStart]) -> Vec<Observation> {
    let mut out = Vec::new();
    for process in current {
        if seen.insert(process.pid) {
            out.push(Observation::Process(process.clone()));
        }
    }
    out
}

pub fn diff_connections(seen: &mut HashSet<(i32, String, u16)>, current: &[TcpConnect]) -> Vec<Observation> {
    let mut out = Vec::new();
    for flow in current {
        let key = (flow.pid, flow.address.clone(), flow.port);
        if seen.insert(key) {
            out.push(Observation::Tcp(flow.clone()));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

#[cfg(not(windows))]
#[test]
fn windows_stub_emits_nothing() {
    let mut monitor = WindowsMonitor;
    assert!(monitor.poll().is_empty());
}

    #[test]
    fn diff_emits_only_new_pids_and_flows() {
        let mut pids = HashSet::new();
        let first = vec![ProcessStart {
            pid: 1,
            parent_pid: 0,
            name: "init".into(),
        }];
        assert!(diff_processes(&mut pids, &first).is_empty() == false);
        assert!(diff_processes(&mut pids, &first).is_empty());

        let mut flows = HashSet::new();
        let conn = vec![TcpConnect {
            pid: 10,
            name: "ssh".into(),
            address: "10.10.10.20".into(),
            port: 22,
        }];
        assert_eq!(diff_connections(&mut flows, &conn).len(), 1);
        assert!(diff_connections(&mut flows, &conn).is_empty());
    }
}
