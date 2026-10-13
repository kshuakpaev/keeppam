use std::fs::OpenOptions;
use std::io::{ErrorKind, Write};
use std::path::Path;
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD, Engine};
use keeppam_agent_protocol::{RecordingAck, RecordingChunk, RecordingEnd, RecordingStart};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::{AgentError, Identity};

const MAX_CHUNK: usize = 256 * 1024;

#[derive(Debug)]
pub enum UploadItem {
    Start {
        id: String,
        destination: String,
        port: u16,
        username: String,
        started_at: i64,
        kind: String,
    },
    Chunk {
        id: String,
        t_ms: u64,
        direction: String,
        data: Vec<u8>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum SpoolOp {
    Start {
        id: String,
        destination: String,
        port: u16,
        username: String,
        started_at: i64,
        #[serde(default)]
        kind: String,
    },
    Chunk {
        id: String,
        t_ms: u64,
        direction: String,
        data: String,
    },
    End {
        id: String,
        ended_at: i64,
    },
}

pub struct UploadWorker {
    tx: Option<mpsc::Sender<UploadItem>>,
    join: Option<JoinHandle<()>>,
}

impl UploadWorker {
    pub fn start(server_url: String, state_dir: std::path::PathBuf, identity: Option<Identity>) -> Self {
        let (tx, mut rx) = mpsc::channel(256);
        let join = std::thread::spawn(move || match identity {
            Some(identity) => worker_loop(rx, &server_url, &state_dir, &identity),
            None => {
                while rx.blocking_recv().is_some() {}
            }
        });
        Self {
            tx: Some(tx),
            join: Some(join),
        }
    }

    pub fn sender(&self) -> mpsc::Sender<UploadItem> {
        self.tx.clone().expect("отправка записи")
    }

    pub fn finish(mut self) {
        self.tx.take();
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl Drop for UploadWorker {
    fn drop(&mut self) {
        self.tx.take();
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn worker_loop(mut rx: mpsc::Receiver<UploadItem>, server_url: &str, state_dir: &Path, identity: &Identity) {
    let client = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(5))
        .redirects(0)
        .build();
    let mut recording_id: Option<String> = None;
    while let Some(item) = rx.blocking_recv() {
        match item {
            UploadItem::Start {
                id,
                destination,
                port,
                username,
                started_at,
                kind,
            } => {
                let op = SpoolOp::Start {
                    id: id.clone(),
                    destination,
                    port,
                    username,
                    started_at,
                    kind,
                };
                if post_op(&client, server_url, identity, &op).is_err() {
                    let _ = spool_append(state_dir, &op);
                }
                recording_id = Some(id);
            }
            UploadItem::Chunk {
                id,
                t_ms,
                direction,
                data,
            } => {
                for piece in data.chunks(MAX_CHUNK) {
                    let op = SpoolOp::Chunk {
                        id: id.clone(),
                        t_ms,
                        direction: direction.clone(),
                        data: STANDARD.encode(piece),
                    };
                    if post_op(&client, server_url, identity, &op).is_err() {
                        let _ = spool_append(state_dir, &op);
                    }
                }
            }
        }
    }
    if let Some(id) = recording_id {
        let op = SpoolOp::End {
            id,
            ended_at: unix_now(),
        };
        if post_op(&client, server_url, identity, &op).is_err() {
            let _ = spool_append(state_dir, &op);
        }
    }
}

pub fn flush_spool(state_dir: &Path, server_url: &str, identity: &Identity) -> Result<(), AgentError> {
    let path = state_dir.join("recording-spool.jsonl");
    if !path.exists() {
        return Ok(());
    }
    let lines = spool_take(state_dir)?;
    if lines.is_empty() {
        return Ok(());
    }
    let client = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(5))
        .redirects(0)
        .build();
    let mut pending = Vec::new();
    for (index, line) in lines.into_iter().enumerate() {
        if index >= 20 {
            pending.push(line);
            continue;
        }
        let op: SpoolOp = match serde_json::from_str(&line) {
            Ok(op) => op,
            Err(_) => continue,
        };
        if post_op(&client, server_url, identity, &op).is_err() {
            pending.push(line);
        }
    }
    if !pending.is_empty() {
        spool_restore(state_dir, &pending)?;
    }
    Ok(())
}

fn post_op(client: &ureq::Agent, server_url: &str, identity: &Identity, op: &SpoolOp) -> Result<(), ()> {
    let base = server_url.trim_end_matches('/');
    let (url, body) = match op {
        SpoolOp::Start {
            id,
            destination,
            port,
            username,
            started_at,
            kind,
        } => (
            format!("{base}/v1/agents/{}/recordings", identity.agent_id),
            serde_json::to_value(RecordingStart {
                id: id.clone(),
                destination: destination.clone(),
                port: *port,
                username: username.clone(),
                started_at: *started_at,
                kind: kind.clone(),
            })
            .map_err(|_| ())?,
        ),
        SpoolOp::Chunk {
            id,
            t_ms,
            direction,
            data,
        } => (
            format!(
                "{base}/v1/agents/{}/recordings/{id}/chunks",
                identity.agent_id
            ),
            serde_json::to_value(RecordingChunk {
                t_ms: *t_ms,
                direction: direction.clone(),
                data: data.clone(),
            })
            .map_err(|_| ())?,
        ),
        SpoolOp::End { id, ended_at } => (
            format!("{base}/v1/agents/{}/recordings/{id}/end", identity.agent_id),
            serde_json::to_value(RecordingEnd { ended_at: *ended_at }).map_err(|_| ())?,
        ),
    };
    let response = client
        .post(&url)
        .set("Authorization", &format!("Bearer {}", identity.agent_secret))
        .send_json(body)
        .map_err(|_| ())?;
    let ack: RecordingAck = response.into_json().map_err(|_| ())?;
    if ack.ok {
        Ok(())
    } else {
        Err(())
    }
}

#[cfg(windows)]
pub(crate) fn submit_start(
    state_dir: &Path,
    server_url: &str,
    identity: &Identity,
    id: &str,
    destination: &str,
    port: u16,
    username: &str,
    started_at: i64,
    kind: &str,
) {
    submit(
        state_dir,
        server_url,
        identity,
        &SpoolOp::Start {
            id: id.to_string(),
            destination: destination.to_string(),
            port,
            username: username.to_string(),
            started_at,
            kind: kind.to_string(),
        },
    );
}

#[cfg(windows)]
pub(crate) fn submit_chunk(
    state_dir: &Path,
    server_url: &str,
    identity: &Identity,
    id: &str,
    t_ms: u64,
    direction: &str,
    data: &[u8],
) {
    let pieces: Vec<&[u8]> = if direction == "frame" {
        vec![data]
    } else {
        data.chunks(MAX_CHUNK).collect()
    };
    for piece in pieces {
        if piece.is_empty() || piece.len() > 1024 * 1024 {
            continue;
        }
        submit(
            state_dir,
            server_url,
            identity,
            &SpoolOp::Chunk {
                id: id.to_string(),
                t_ms,
                direction: direction.to_string(),
                data: STANDARD.encode(piece),
            },
        );
    }
}

#[cfg(windows)]
pub(crate) fn submit_end(state_dir: &Path, server_url: &str, identity: &Identity, id: &str, ended_at: i64) {
    submit(
        state_dir,
        server_url,
        identity,
        &SpoolOp::End {
            id: id.to_string(),
            ended_at,
        },
    );
}

#[cfg(windows)]
fn submit(state_dir: &Path, server_url: &str, identity: &Identity, op: &SpoolOp) {
    let client = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(5))
        .redirects(0)
        .build();
    if post_op(&client, server_url, identity, op).is_err() {
        let _ = spool_append(state_dir, op);
    }
}

fn spool_path(dir: &Path) -> std::path::PathBuf {
    dir.join("recording-spool.jsonl")
}

fn spool_append(dir: &Path, op: &SpoolOp) -> Result<(), AgentError> {
    let line = serde_json::to_string(op).map_err(|err| AgentError::Proxy(err.to_string()))?;
    with_lock(dir, || {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(spool_path(dir))
            .map_err(|err| AgentError::Proxy(err.to_string()))?;
        writeln!(file, "{line}").map_err(|err| AgentError::Proxy(err.to_string()))?;
        Ok(())
    })
}

fn spool_take(dir: &Path) -> Result<Vec<String>, AgentError> {
    with_lock(dir, || {
        let path = spool_path(dir);
        if !path.exists() {
            return Ok(Vec::new());
        }
        let text = std::fs::read_to_string(&path).map_err(|err| AgentError::Proxy(err.to_string()))?;
        std::fs::write(&path, "").map_err(|err| AgentError::Proxy(err.to_string()))?;
        Ok(text.lines().filter(|line| !line.trim().is_empty()).map(str::to_string).collect())
    })
}

fn spool_restore(dir: &Path, lines: &[String]) -> Result<(), AgentError> {
    with_lock(dir, || {
        let path = spool_path(dir);
        let current = if path.exists() {
            std::fs::read_to_string(&path).map_err(|err| AgentError::Proxy(err.to_string()))?
        } else {
            String::new()
        };
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .map_err(|err| AgentError::Proxy(err.to_string()))?;
        for line in lines {
            writeln!(file, "{line}").map_err(|err| AgentError::Proxy(err.to_string()))?;
        }
        if !current.is_empty() {
            file.write_all(current.as_bytes())
                .map_err(|err| AgentError::Proxy(err.to_string()))?;
            if !current.ends_with('\n') {
                writeln!(file).map_err(|err| AgentError::Proxy(err.to_string()))?;
            }
        }
        Ok(())
    })
}

fn with_lock<T>(dir: &Path, body: impl FnOnce() -> Result<T, AgentError>) -> Result<T, AgentError> {
    std::fs::create_dir_all(dir).map_err(|err| AgentError::Proxy(err.to_string()))?;
    let lock_path = dir.join("recording-spool.lock");
    let started = Instant::now();
    loop {
        match OpenOptions::new().write(true).create_new(true).open(&lock_path) {
            Ok(_file) => {
                let result = body();
                let _ = std::fs::remove_file(&lock_path);
                return result;
            }
            Err(err) if err.kind() == ErrorKind::AlreadyExists => {
                let stale = std::fs::metadata(&lock_path)
                    .and_then(|meta| meta.modified())
                    .ok()
                    .and_then(|modified| modified.elapsed().ok())
                    .map(|age| age > Duration::from_secs(30))
                    .unwrap_or(false);
                if stale {
                    let _ = std::fs::remove_file(&lock_path);
                    continue;
                }
                if started.elapsed() > Duration::from_secs(5) {
                    return Err(AgentError::Proxy("очередь записей занята".into()));
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(err) => return Err(AgentError::Proxy(err.to_string())),
        }
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}
