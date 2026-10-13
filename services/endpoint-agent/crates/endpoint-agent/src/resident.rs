//! Резидентный агент Linux и macOS: пока процесс жив, SSH этой учётной записи идёт через локальный прокси.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::settings::{save_dev_settings, LiveSettings, DevSettings};
use crate::state::LocalState;
use crate::{default_state_dir, run_supervised, AgentConfig, AgentError};

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_stop(_: i32) {
    STOP.store(true, Ordering::SeqCst);
}

extern "C" {
    fn signal(sig: i32, handler: extern "C" fn(i32)) -> usize;
}

pub fn run_resident(config: AgentConfig) -> Result<(), AgentError> {
    std::fs::create_dir_all(&config.state_dir).map_err(|err| AgentError::State(err.to_string()))?;
    if let Some(pid) = read_pid(&config.state_dir) {
        if process_alive(pid) {
            return Err(AgentError::Proxy(format!(
                "агент уже запущен, pid {pid}. Остановка: endpoint-agent stop --state-dir {}",
                config.state_dir.display()
            )));
        }
    }
    write_pid(&config.state_dir)?;
    let _pid_file = PidFile(config.state_dir.join("agent.pid"));

    let mut settings = crate::settings::load_dev_settings(
        &config.state_dir,
        &config.server_url,
        config.enroll_token.as_deref(),
    );
    if server_flag_present() {
        let parsed = DevSettings::from_server_url(&config.server_url, None);
        settings.ip = parsed.ip;
        settings.server = parsed.server;
        settings.port = parsed.port;
    }
    if let Some(token) = config.enroll_token.as_deref() {
        settings.enroll_token = token.to_string();
    }
    let identity = LocalState::load(&config.state_dir)
        .ok()
        .and_then(|state| state.identity);
    let mut generation = 0u64;
    if identity.is_none() && !settings.enroll_token.is_empty() {
        generation = 1;
    }
    let _ = save_dev_settings(&config.state_dir, &settings);
    let endpoint = settings.endpoint();
    let status = match crate::proxy::enable_redirect(&endpoint, &config.state_dir, None) {
        Ok(text) => text,
        Err(err) => format!("перехват SSH не включён: {err}"),
    };
    let live = Arc::new(Mutex::new(LiveSettings {
        state_dir: config.state_dir.clone(),
        interval: config.interval,
        settings,
        enroll_generation: generation,
        status: status.clone(),
        agent_id: identity.map(|item| item.agent_id).unwrap_or_default(),
        stop: false,
    }));
    let worker_live = Arc::clone(&live);
    let worker = std::thread::Builder::new()
        .name("keeppam-agent".into())
        .spawn(move || run_supervised(worker_live))
        .map_err(|err| AgentError::State(err.to_string()))?;
    eprintln!("KeepPAM агент запущен");
    eprintln!("{status}");
    eprintln!(
        "остановка: endpoint-agent stop --state-dir {}",
        config.state_dir.display()
    );
    wait_until_stop(&live);
    live.lock().expect("настройки").stop = true;
    let _ = worker.join();
    if let Err(err) = crate::proxy::disable_redirect() {
        eprintln!("перехват SSH не снят: {err}");
    }
    eprintln!("агент остановлен");
    Ok(())
}

pub fn stop(args: &[String]) -> Result<(), AgentError> {
    let dir = state_dir_arg(args);
    let Some(pid) = read_pid(&dir) else {
        return Err(AgentError::Proxy(format!(
            "агент не запущен ({})",
            dir.display()
        )));
    };
    if !process_alive(pid) {
        let _ = std::fs::remove_file(dir.join("agent.pid"));
        return Err(AgentError::Proxy("процесс агента уже завершён".into()));
    }
    let status = std::process::Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status()
        .map_err(|err| AgentError::Proxy(err.to_string()))?;
    if status.success() {
        eprintln!("остановка агента {pid}");
        Ok(())
    } else {
        Err(AgentError::Proxy("не удалось остановить агент".into()))
    }
}

fn wait_until_stop(live: &Arc<Mutex<LiveSettings>>) {
    STOP.store(false, Ordering::SeqCst);
    unsafe {
        signal(1, on_stop);
        signal(2, on_stop);
        signal(15, on_stop);
    }
    let mut shown = String::new();
    loop {
        if STOP.load(Ordering::SeqCst) {
            return;
        }
        let (stop, status, dir) = {
            let guard = live.lock().expect("настройки");
            (guard.stop, guard.status.clone(), guard.state_dir.clone())
        };
        if stop {
            return;
        }
        if !status.is_empty() && status != shown {
            eprintln!("{status}");
            let _ = std::fs::write(dir.join("status.txt"), &status);
            shown = status;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn server_flag_present() -> bool {
    std::env::var("AGENT_SERVER_URL").is_ok()
        || std::env::args().skip(1).any(|arg| arg == "--server" || arg.starts_with("--server="))
}

fn state_dir_arg(args: &[String]) -> PathBuf {
    let mut dir = std::env::var("AGENT_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| default_state_dir());
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if let Some(value) = arg.strip_prefix("--state-dir=") {
            dir = PathBuf::from(value);
        } else if arg == "--state-dir" {
            if let Some(value) = args.get(index + 1) {
                dir = PathBuf::from(value);
            }
        }
        index += 1;
    }
    dir
}

fn read_pid(dir: &Path) -> Option<i32> {
    let text = std::fs::read_to_string(dir.join("agent.pid")).ok()?;
    text.trim().parse::<i32>().ok().filter(|pid| *pid > 0)
}

fn write_pid(dir: &Path) -> Result<(), AgentError> {
    std::fs::write(dir.join("agent.pid"), format!("{}\n", std::process::id()))
        .map_err(|err| AgentError::State(err.to_string()))
}

fn process_alive(pid: i32) -> bool {
    std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

struct PidFile(PathBuf);

impl Drop for PidFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pid_file_roundtrip_and_live_process() {
        let dir = std::env::temp_dir().join(format!("keeppam-agent-pid-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        write_pid(&dir).unwrap();
        assert_eq!(read_pid(&dir), Some(std::process::id() as i32));
        assert!(process_alive(std::process::id() as i32));
        assert!(!process_alive(i32::MAX));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stop_reads_state_dir_flag() {
        let dir = state_dir_arg(&["--state-dir".into(), "/tmp/keeppam-agent-state".into()]);
        assert_eq!(dir, PathBuf::from("/tmp/keeppam-agent-state"));
        let dir = state_dir_arg(&["--state-dir=/var/lib/keeppam-agent".into()]);
        assert_eq!(dir, PathBuf::from("/var/lib/keeppam-agent"));
    }
}
