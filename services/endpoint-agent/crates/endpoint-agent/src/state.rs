use std::path::Path;

use serde::{Deserialize, Serialize};

use keeppam_agent_protocol::{verify_signed, SignedPolicy};

use crate::{AgentError, Identity};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FileState {
    identity: Option<Identity>,
    pinned_public_key: Option<String>,
    signed_policy: Option<SignedPolicy>,
}

#[derive(Debug, Clone, Default)]
pub struct LocalState {
    pub identity: Option<Identity>,
    pub pinned_public_key: Option<String>,
    pub signed_policy: Option<SignedPolicy>,
}

impl LocalState {
    pub fn load(dir: &Path) -> Result<Self, AgentError> {
        let path = dir.join("state.json");
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(&path).map_err(|err| AgentError::State(err.to_string()))?;
        let file: FileState =
            serde_json::from_str(&text).map_err(|err| AgentError::State(err.to_string()))?;
        let mut state = Self {
            identity: file.identity,
            pinned_public_key: file.pinned_public_key,
            signed_policy: None,
        };
        if let Some(signed) = file.signed_policy {
            if verify_signed(&signed).is_ok()
                && state
                    .pinned_public_key
                    .as_ref()
                    .map(|key| key == &signed.public_key)
                    .unwrap_or(true)
            {
                if state.pinned_public_key.is_none() {
                    state.pinned_public_key = Some(signed.public_key.clone());
                }
                state.signed_policy = Some(signed);
            }
        }
        Ok(state)
    }

    pub fn save(&self, dir: &Path) -> Result<(), AgentError> {
        std::fs::create_dir_all(dir).map_err(|err| AgentError::State(err.to_string()))?;
        let file = FileState {
            identity: self.identity.clone(),
            pinned_public_key: self.pinned_public_key.clone(),
            signed_policy: self.signed_policy.clone(),
        };
        let text = serde_json::to_string_pretty(&file).map_err(|err| AgentError::State(err.to_string()))?;
        let path = dir.join("state.json");
        std::fs::write(&path, text).map_err(|err| AgentError::State(err.to_string()))?;
        restrict(&path);
        Ok(())
    }
}

#[cfg(unix)]
pub(crate) fn restrict(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
pub(crate) fn restrict(_path: &Path) {}
