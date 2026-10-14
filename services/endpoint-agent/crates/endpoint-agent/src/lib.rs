mod http_plane;
mod proxy;
mod rdp;
#[cfg(unix)]
mod resident;
mod settings;
mod spool;
mod state;
mod sync;
#[cfg(windows)]
mod tray;
mod upload;

use std::path::PathBuf;
use std::time::Duration;

use keeppam_agent_protocol::{EndpointEvent, SignedPolicy};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use http_plane::HttpPlane;
pub use proxy::serve_proxy_stream;
pub use spool::Spool;
pub use state::LocalState;
pub use sync::{sync_once, SyncReport};

use keeppam_agent_monitor::host_monitor;

#[derive(Debug, Error)]
pub enum AgentError {
    #[error("нужен токен зачисления")]
    NeedToken,
    #[error("сервис недоступен: {0}")]
    Transport(String),
    #[error("сервис вернул {0}")]
    Status(u16),
    #[error("локальное состояние: {0}")]
    State(String),
    #[error("агент в этом каталоге не зачислен")]
    NotEnrolled,
    #[error("прокси: {0}")]
    Proxy(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub agent_id: String,
    pub agent_secret: String,
}

pub trait ControlPlane {
    fn heartbeat(
        &self,
        identity: &Identity,
        hostname: &str,
        version: &str,
    ) -> Result<Option<u64>, AgentError>;

    fn fetch_policy(&self, identity: &Identity) -> Result<SignedPolicy, AgentError>;

    fn send_events(&self, identity: &Identity, events: &[EndpointEvent]) -> Result<(), AgentError>;
}

pub struct AgentConfig {
    pub server_url: String,
    pub state_dir: PathBuf,
    pub enroll_token: Option<String>,
    pub interval: Duration,
    pub cycles: Option<u32>,
}

pub fn run(config: AgentConfig) -> Result<(), AgentError> {
    std::fs::create_dir_all(&config.state_dir).map_err(|err| AgentError::State(err.to_string()))?;
    let mut local = LocalState::load(&config.state_dir)?;
    let plane = HttpPlane::new(&config.server_url);
    if local.identity.is_none() {
        let token = config.enroll_token.as_deref().ok_or(AgentError::NeedToken)?;
        local.identity = Some(plane.enroll(token, &hostname(), env!("CARGO_PKG_VERSION"))?);
        local.save(&config.state_dir)?;
    }
    let identity = local
        .identity
        .clone()
        .ok_or_else(|| AgentError::State("нет идентификатора агента".into()))?;
    let mut spool = Spool::open(&config.state_dir.join("spool.sqlite"))?;
    let mut monitor = host_monitor();
    let mut completed = 0u32;
    loop {
        if let Err(err) = upload::flush_spool(&config.state_dir, &config.server_url, &identity) {
            eprintln!("очередь записей: {err}");
        }
        let observations = monitor.poll();
        match sync_once(
            &plane,
            &mut spool,
            &identity,
            &mut local.signed_policy,
            &mut local.pinned_public_key,
            &hostname(),
            env!("CARGO_PKG_VERSION"),
            &observations,
            now_unix(),
        ) {
            Ok(report) => {
                local.save(&config.state_dir)?;
                if report.delivered {
                    eprintln!(
                        "синхронизация: политика {:?}, в очереди {}",
                        report.policy_version, report.queued_remaining
                    );
                } else {
                    eprintln!("сервис недоступен, в очереди {}", report.queued_remaining);
                }
                if report.policy_rejected {
                    eprintln!("новая политика отклонена, остаётся предыдущая проверенная копия");
                }
            }
            Err(err) => eprintln!("цикл агента: {err}"),
        }
        completed += 1;
        if config.cycles.is_some_and(|limit| completed >= limit) {
            return Ok(());
        }
        std::thread::sleep(config.interval);
    }
}

pub(crate) fn run_supervised(live: std::sync::Arc<std::sync::Mutex<settings::LiveSettings>>) -> Result<(), AgentError> {
    #[cfg(windows)]
    let watcher = rdp::spawn(std::sync::Arc::clone(&live));
    let (state_dir, interval) = {
        let guard = live.lock().expect("настройки");
        (guard.state_dir.clone(), guard.interval)
    };
    std::fs::create_dir_all(&state_dir).map_err(|err| AgentError::State(err.to_string()))?;
    let mut local = LocalState::load(&state_dir)?;
    let mut spool = Spool::open(&state_dir.join("spool.sqlite"))?;
    let mut monitor = host_monitor();
    let mut plane = HttpPlane::new("http://127.0.0.1:8090");
    let mut applied_url = String::new();
    let mut applied_generation = 0u64;
    loop {
        if live.lock().expect("настройки").stop {
            break;
        }
        let (settings, generation) = {
            let guard = live.lock().expect("настройки");
            (guard.settings.clone(), guard.enroll_generation)
        };
        let url = settings.endpoint();
        if url != applied_url {
            plane = HttpPlane::new(&url);
            applied_url = url;
        }
        if generation != applied_generation && !settings.enroll_token.is_empty() {
            match plane.enroll(&settings.enroll_token, &hostname(), env!("CARGO_PKG_VERSION")) {
                Ok(identity) => {
                    local.identity = Some(identity);
                    local.save(&state_dir)?;
                    applied_generation = generation;
                    set_live(&live, "токен принят, агент зачислен", local.identity.as_ref().map(|item| item.agent_id.clone()));
                }
                Err(err) => {
                    applied_generation = generation;
                    set_live(&live, &format!("токен не принят: {err}"), None);
                }
            }
        }
        let Some(identity) = local.identity.clone() else {
            let current = live.lock().expect("настройки").status.clone();
            if !current.starts_with("токен не принят") {
                set_live(&live, "ожидание токена зачисления", None);
            }
            interruptible_sleep(&live, interval);
            continue;
        };
        set_live(&live, "", Some(identity.agent_id.clone()));
        if let Err(err) = upload::flush_spool(&state_dir, &applied_url, &identity) {
            eprintln!("очередь записей: {err}");
        }
        let observations = monitor.poll();
        match sync_once(
            &plane,
            &mut spool,
            &identity,
            &mut local.signed_policy,
            &mut local.pinned_public_key,
            &hostname(),
            env!("CARGO_PKG_VERSION"),
            &observations,
            now_unix(),
        ) {
            Ok(report) => {
                local.save(&state_dir)?;
                let status = if report.delivered {
                    "на связи с сервисом".to_string()
                } else {
                    "сервис недоступен, события в очереди".to_string()
                };
                set_live(&live, &status, Some(identity.agent_id.clone()));
            }
            Err(err) => set_live(&live, &format!("цикл агента: {err}"), Some(identity.agent_id)),
        }
        interruptible_sleep(&live, interval);
    }
    #[cfg(windows)]
    let _ = watcher.join();
    Ok(())
}

fn set_live(
    live: &std::sync::Arc<std::sync::Mutex<settings::LiveSettings>>,
    status: &str,
    agent_id: Option<String>,
) {
    let mut guard = live.lock().expect("настройки");
    if !status.is_empty() {
        guard.status = status.to_string();
    }
    if let Some(agent_id) = agent_id {
        guard.agent_id = agent_id;
    }
}

fn interruptible_sleep(
    live: &std::sync::Arc<std::sync::Mutex<settings::LiveSettings>>,
    interval: Duration,
) {
    let slices = interval.as_secs().max(1);
    for _ in 0..slices {
        if live.lock().expect("настройки").stop {
            return;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

pub fn run_from_env() -> Result<(), AgentError> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("proxy") => proxy::run_proxy(&args[1..]),
        Some("install-proxy") => {
            attach_parent_console();
            proxy::run_install(&args[1..])
        }
        Some("uninstall-proxy") => {
            attach_parent_console();
            proxy::run_uninstall(&args[1..])
        }
        Some("stop") => {
            attach_parent_console();
            #[cfg(unix)]
            {
                return resident::stop(&args[1..]);
            }
            #[cfg(windows)]
            {
                let _ = args;
                Err(AgentError::Proxy(
                    "на Windows агент останавливается из значка в трее".into(),
                ))
            }
        }
        _ => {
            let config = config_from_env();
            if config.cycles.is_none() && std::env::var("AGENT_NO_TRAY").ok().as_deref() != Some("1")
            {
                #[cfg(windows)]
                {
                    return tray::run_resident(config);
                }
                #[cfg(unix)]
                {
                    return resident::run_resident(config);
                }
            }
            run(config)
        }
    }
}

fn default_state_dir() -> PathBuf {
    if let Some(dir) = std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|parent| parent.join("agent-state")))
    {
        if std::fs::create_dir_all(&dir).is_ok() {
            return dir;
        }
    }
    user_state_dir().unwrap_or_else(|| PathBuf::from("agent-state"))
}

fn user_state_dir() -> Option<PathBuf> {
    if let Ok(xdg) = std::env::var("XDG_STATE_HOME") {
        let xdg = xdg.trim();
        if !xdg.is_empty() {
            return Some(PathBuf::from(xdg).join("keeppam-agent"));
        }
    }
    let home = std::env::var("HOME").ok()?;
    let home = PathBuf::from(home.trim());
    if home.as_os_str().is_empty() {
        return None;
    }
    #[cfg(target_os = "macos")]
    {
        return Some(
            home.join("Library")
                .join("Application Support")
                .join("KeepPAM")
                .join("agent"),
        );
    }
    #[cfg(not(target_os = "macos"))]
    {
        Some(home.join(".local").join("share").join("keeppam-agent"))
    }
}

pub fn config_from_env() -> AgentConfig {
    let mut server_url = std::env::var("AGENT_SERVER_URL").unwrap_or_else(|_| "http://127.0.0.1:8090".into());
    let mut state_dir = std::env::var("AGENT_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| default_state_dir());
    let mut enroll_token = std::env::var("AGENT_ENROLL_TOKEN").ok();
    let mut interval_secs = std::env::var("AGENT_INTERVAL")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(5);
    let mut cycles = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let (key, inline) = arg
            .split_once('=')
            .map(|(key, value)| (key.to_string(), Some(value.to_string())))
            .unwrap_or((arg, None));
        let mut take = || inline.clone().or_else(|| args.next());
        match key.as_str() {
            "--server" => {
                if let Some(value) = take() {
                    server_url = value;
                }
            }
            "--state-dir" => {
                if let Some(value) = take() {
                    state_dir = PathBuf::from(value);
                }
            }
            "--enroll-token" => enroll_token = take(),
            "--interval" => {
                if let Some(value) = take() {
                    if let Ok(parsed) = value.parse::<u64>() {
                        interval_secs = parsed.max(1);
                    }
                }
            }
            "--cycles" => {
                if let Some(value) = take() {
                    cycles = value.parse::<u32>().ok();
                }
            }
            _ => {}
        }
    }
    AgentConfig {
        server_url,
        state_dir,
        enroll_token,
        interval: Duration::from_secs(interval_secs.max(1)),
        cycles,
    }
}

pub fn hostname() -> String {
    if let Ok(value) = std::env::var("AGENT_HOSTNAME") {
        let value = value.trim();
        if !value.is_empty() {
            return value.to_string();
        }
    }
    if let Ok(value) = std::env::var("COMPUTERNAME") {
        let value = value.trim();
        if !value.is_empty() {
            return value.to_string();
        }
    }
    if let Ok(value) = std::fs::read_to_string("/etc/hostname") {
        let value = value.trim();
        if !value.is_empty() {
            return value.to_string();
        }
    }
    if let Some(value) = command_hostname() {
        return value;
    }
    "unknown".into()
}

#[cfg(windows)]
fn attach_parent_console() {
    use windows_sys::Win32::System::Console::{AttachConsole, ATTACH_PARENT_PROCESS};
    unsafe {
        AttachConsole(ATTACH_PARENT_PROCESS);
    }
}

#[cfg(not(windows))]
fn attach_parent_console() {}

fn command_hostname() -> Option<String> {
    let mut command = std::process::Command::new("hostname");
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let output = command.output().ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}
