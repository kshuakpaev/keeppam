use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevSettings {
    pub ip: String,
    pub server: String,
    pub port: u16,
    pub enroll_token: String,
    pub dev_mode: bool,
    #[serde(default)]
    pub token_changed_at: String,
}

impl DevSettings {
    pub fn from_server_url(url: &str, token: Option<&str>) -> Self {
        let (host, port) = split_endpoint(url);
        let ip_like = host.parse::<IpAddr>().is_ok();
        Self {
            ip: if ip_like { host.clone() } else { String::new() },
            server: if ip_like { String::new() } else { host },
            port,
            enroll_token: token.unwrap_or("").trim().to_string(),
            dev_mode: true,
            token_changed_at: String::new(),
        }
    }

    pub fn endpoint(&self) -> String {
        let server = self.server.trim();
        let ip = self.ip.trim();
        let host = if !server.is_empty() { server } else { ip };
        if host.starts_with("http://") || host.starts_with("https://") {
            return host.to_string();
        }
        let port = if self.port == 0 { 8090 } else { self.port };
        format!("http://{host}:{port}")
    }

    pub fn apply_edit(&mut self, edited: Self) -> bool {
        let token_changed = edited.enroll_token.trim() != self.enroll_token.trim();
        if edited.dev_mode {
            self.ip = edited.ip.trim().to_string();
            self.server = edited.server.trim().to_string();
            self.port = if edited.port == 0 { 8090 } else { edited.port };
            self.enroll_token = edited.enroll_token.trim().to_string();
            if token_changed {
                self.token_changed_at = edited.token_changed_at;
            }
        }
        self.dev_mode = edited.dev_mode;
        token_changed && edited.dev_mode
    }
}

pub struct LiveSettings {
    pub state_dir: PathBuf,
    pub interval: Duration,
    pub settings: DevSettings,
    pub enroll_generation: u64,
    pub status: String,
    pub agent_id: String,
    pub stop: bool,
}

pub fn load_dev_settings(dir: &Path, fallback_url: &str, fallback_token: Option<&str>) -> DevSettings {
    let path = dir.join("dev-config.json");
    if let Ok(text) = std::fs::read_to_string(&path) {
        if let Ok(settings) = serde_json::from_str::<DevSettings>(&text) {
            return settings;
        }
    }
    DevSettings::from_server_url(fallback_url, fallback_token)
}

pub fn save_dev_settings(dir: &Path, settings: &DevSettings) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|err| err.to_string())?;
    let text = serde_json::to_string_pretty(settings).map_err(|err| err.to_string())?;
    std::fs::write(dir.join("dev-config.json"), text).map_err(|err| err.to_string())
}

fn split_endpoint(url: &str) -> (String, u16) {
    let trimmed = url.trim().trim_end_matches('/');
    let hostport = trimmed
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    if let Some((host, port)) = hostport.rsplit_once(':') {
        if !host.is_empty() && !host.contains(']') {
            if let Ok(port) = port.parse::<u16>() {
                return (host.to_string(), port);
            }
        }
    }
    (hostport.to_string(), 8090)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_url_splits_address_and_port() {
        let settings = DevSettings::from_server_url("http://10.0.126.235:8090", Some("token-1"));
        assert_eq!(settings.ip, "10.0.126.235");
        assert_eq!(settings.server, "");
        assert_eq!(settings.port, 8090);
        assert_eq!(settings.endpoint(), "http://10.0.126.235:8090");
        assert!(settings.dev_mode);
    }

    #[test]
    fn server_name_wins_over_ip() {
        let mut settings = DevSettings::from_server_url("http://10.0.126.235:8090", None);
        settings.server = "agent.example".into();
        settings.port = 9000;
        assert_eq!(settings.endpoint(), "http://agent.example:9000");
    }

    #[test]
    fn token_change_is_recorded_only_in_dev_mode() {
        let mut current = DevSettings::from_server_url("http://10.0.0.5:8090", Some("old"));
        let mut edited = current.clone();
        edited.enroll_token = "new-token".into();
        edited.token_changed_at = "17:31:02".into();
        assert!(current.apply_edit(edited));
        assert_eq!(current.enroll_token, "new-token");
        assert_eq!(current.token_changed_at, "17:31:02");

        let mut locked = current.clone();
        locked.dev_mode = false;
        let mut attempt = locked.clone();
        attempt.dev_mode = false;
        attempt.enroll_token = "other".into();
        attempt.ip = "1.2.3.4".into();
        attempt.token_changed_at = "18:00:00".into();
        assert!(!locked.apply_edit(attempt));
        assert_eq!(locked.enroll_token, "new-token");
        assert_eq!(locked.ip, "10.0.0.5");
        assert!(!locked.dev_mode);
    }
}
