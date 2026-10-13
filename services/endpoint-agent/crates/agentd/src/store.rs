use std::path::Path;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use keeppam_agent_protocol::{
    validate_publish, EnrollResponse, EndpointEvent, Policy, RecordingStart, ServiceKey, SignedPolicy,
};
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Protocol(#[from] keeppam_agent_protocol::ProtocolError),
    #[error("токен зачисления не принят")]
    EnrollmentRejected,
    #[error("агент не авторизован")]
    Unauthorized,
    #[error("запись не найдена")]
    NotFound,
    #[error("{0}")]
    BadInput(String),
}

pub struct AgentRow {
    pub agent_id: String,
    pub hostname: String,
    pub version: String,
    pub last_seen: Option<i64>,
    #[allow(dead_code)]
    pub enrolled_at: i64,
}

pub struct EventRow {
    pub agent_id: String,
    pub received_at: i64,
    pub event: EndpointEvent,
}

pub struct RecordingRow {
    pub id: String,
    pub agent_id: String,
    pub hostname: String,
    pub destination: String,
    pub port: u16,
    pub username: String,
    pub started_at: i64,
    pub ended_at: Option<i64>,
    pub kind: String,
}

pub struct RecordingFrame {
    pub t_ms: u64,
    pub direction: String,
    pub text: String,
}

pub struct RecordingView {
    pub row: RecordingRow,
    pub frames: Vec<RecordingFrame>,
    pub truncated: bool,
}

pub struct Store {
    conn: Connection,
    key: ServiceKey,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|err| StoreError::BadInput(err.to_string()))?;
        }
        let conn = Connection::open(path)?;
        conn.busy_timeout(std::time::Duration::from_secs(3))?;
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS service_key (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                secret BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS enrollment_tokens (
                token_hash TEXT PRIMARY KEY,
                created_at INTEGER NOT NULL,
                used_at INTEGER
            );
            CREATE TABLE IF NOT EXISTS agents (
                agent_id TEXT PRIMARY KEY,
                secret_hash TEXT NOT NULL,
                hostname TEXT NOT NULL,
                version TEXT NOT NULL,
                last_seen INTEGER,
                enrolled_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS policy (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                version INTEGER NOT NULL,
                document TEXT NOT NULL,
                signature TEXT NOT NULL,
                public_key TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                received_at INTEGER NOT NULL,
                event_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                body TEXT NOT NULL,
                UNIQUE (agent_id, event_id)
            );
            CREATE TABLE IF NOT EXISTS recordings (
                id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                destination TEXT NOT NULL,
                port INTEGER NOT NULL,
                username TEXT NOT NULL,
                started_at INTEGER NOT NULL,
                ended_at INTEGER,
                kind TEXT NOT NULL DEFAULT 'ssh'
            );
            CREATE TABLE IF NOT EXISTS recording_chunks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                recording_id TEXT NOT NULL,
                t_ms INTEGER NOT NULL,
                direction TEXT NOT NULL,
                data BLOB NOT NULL
            );
            CREATE INDEX IF NOT EXISTS recording_chunks_by_recording
                ON recording_chunks (recording_id, id);
            ",
        )?;
        ensure_recording_kind(&conn)?;
        let key = load_or_create_key(&conn)?;
        Ok(Self { conn, key })
    }

    pub fn create_enrollment_token(&mut self, now: i64) -> Result<String, StoreError> {
        let token = random_token();
        self.conn.execute(
            "INSERT INTO enrollment_tokens (token_hash, created_at, used_at) VALUES (?1, ?2, NULL)",
            params![sha256_hex(&token), now],
        )?;
        Ok(token)
    }

    pub fn enroll(
        &mut self,
        token: &str,
        hostname: &str,
        version: &str,
        now: i64,
    ) -> Result<EnrollResponse, StoreError> {
        let hash = sha256_hex(token);
        let tx = self.conn.transaction()?;
        let row: Option<Option<i64>> = tx
            .query_row(
                "SELECT used_at FROM enrollment_tokens WHERE token_hash=?1",
                [&hash],
                |row| row.get(0),
            )
            .optional()?;
        match row {
            Some(None) => {}
            _ => return Err(StoreError::EnrollmentRejected),
        }
        let agent_id = Uuid::new_v4().to_string();
        let secret = random_token();
        tx.execute(
            "UPDATE enrollment_tokens SET used_at=?1 WHERE token_hash=?2",
            params![now, hash],
        )?;
        tx.execute(
            "INSERT INTO agents (agent_id, secret_hash, hostname, version, last_seen, enrolled_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![agent_id, sha256_hex(&secret), hostname, version, now, now],
        )?;
        tx.commit()?;
        Ok(EnrollResponse {
            agent_id,
            agent_secret: secret,
        })
    }

    pub fn authorize(&self, agent_id: &str, secret: &str) -> Result<(), StoreError> {
        let hash: Option<String> = self
            .conn
            .query_row(
                "SELECT secret_hash FROM agents WHERE agent_id=?1",
                [agent_id],
                |row| row.get(0),
            )
            .optional()?;
        match hash {
            Some(stored) if stored == sha256_hex(secret) => Ok(()),
            _ => Err(StoreError::Unauthorized),
        }
    }

    pub fn heartbeat(
        &mut self,
        agent_id: &str,
        hostname: &str,
        version: &str,
        now: i64,
    ) -> Result<Option<u64>, StoreError> {
        let updated = self.conn.execute(
            "UPDATE agents SET hostname=?1, version=?2, last_seen=?3 WHERE agent_id=?4",
            params![hostname, version, now, agent_id],
        )?;
        if updated == 0 {
            return Err(StoreError::Unauthorized);
        }
        self.policy_version()
    }

    pub fn policy_version(&self) -> Result<Option<u64>, StoreError> {
        let version: Option<i64> = self
            .conn
            .query_row("SELECT version FROM policy WHERE id=1", [], |row| row.get(0))
            .optional()?;
        Ok(version.map(|value| value as u64))
    }

    pub fn signed_policy(&self) -> Result<Option<SignedPolicy>, StoreError> {
        let row: Option<(String, String, String)> = self
            .conn
            .query_row(
                "SELECT document, signature, public_key FROM policy WHERE id=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((document, signature, public_key)) = row else {
            return Ok(None);
        };
        let policy: Policy = serde_json::from_str(&document)
            .map_err(|err| StoreError::BadInput(err.to_string()))?;
        Ok(Some(SignedPolicy {
            policy,
            signature,
            public_key,
        }))
    }

    pub fn publish(&mut self, mut policy: Policy, now: i64) -> Result<SignedPolicy, StoreError> {
        policy.version = self.policy_version()?.unwrap_or(0) + 1;
        policy = policy.normalized();
        validate_publish(&policy, now)?;
        let signed = self.key.sign(&policy);
        let document = serde_json::to_string(&signed.policy)
            .map_err(|err| StoreError::BadInput(err.to_string()))?;
        self.conn.execute(
            "INSERT INTO policy (id, version, document, signature, public_key, updated_at)
             VALUES (1, ?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(id) DO UPDATE SET
                version = excluded.version,
                document = excluded.document,
                signature = excluded.signature,
                public_key = excluded.public_key,
                updated_at = excluded.updated_at",
            params![
                signed.policy.version as i64,
                document,
                signed.signature,
                signed.public_key,
                now
            ],
        )?;
        Ok(signed)
    }

    pub fn insert_events(
        &mut self,
        agent_id: &str,
        events: &[EndpointEvent],
        now: i64,
    ) -> Result<(), StoreError> {
        if events.len() > 500 {
            return Err(StoreError::BadInput("слишком много событий".into()));
        }
        let tx = self.conn.transaction()?;
        for event in events {
            if event.event_id.trim().is_empty() || event.event_type.trim().is_empty() {
                return Err(StoreError::BadInput("пустое событие".into()));
            }
            let body = serde_json::to_string(event)
                .map_err(|err| StoreError::BadInput(err.to_string()))?;
            tx.execute(
                "INSERT OR IGNORE INTO events (agent_id, received_at, event_id, event_type, body)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![agent_id, now, event.event_id, event.event_type, body],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn list_agents(&self) -> Result<Vec<AgentRow>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT agent_id, hostname, version, last_seen, enrolled_at
             FROM agents ORDER BY COALESCE(last_seen, enrolled_at) DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(AgentRow {
                agent_id: row.get(0)?,
                hostname: row.get(1)?,
                version: row.get(2)?,
                last_seen: row.get(3)?,
                enrolled_at: row.get(4)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(StoreError::from)
    }

    pub fn list_events(&self) -> Result<Vec<EventRow>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT agent_id, received_at, body FROM events ORDER BY id DESC LIMIT 200",
        )?;
        let rows = stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?, row.get::<_, String>(2)?)))?;
        let mut out = Vec::new();
        for row in rows {
            let (agent_id, received_at, body) = row?;
            let event: EndpointEvent = serde_json::from_str(&body)
                .map_err(|err| StoreError::BadInput(err.to_string()))?;
            out.push(EventRow {
                agent_id,
                received_at,
                event,
            });
        }
        Ok(out)
    }

    pub fn open_recording(
        &mut self,
        agent_id: &str,
        start: &RecordingStart,
        now: i64,
    ) -> Result<(), StoreError> {
        let id = normalize_recording_id(&start.id)?;
        let destination = one_line(&start.destination, 255, "адрес назначения")?;
        let username = one_line(&start.username, 128, "имя пользователя")?;
        if start.port == 0 {
            return Err(StoreError::BadInput("порт 0 не используется".into()));
        }
        let started_at = if start.started_at > 0 { start.started_at } else { now };
        let kind = if start.kind.eq_ignore_ascii_case("rdp") { "rdp" } else { "ssh" };
        let existing: Option<String> = self
            .conn
            .query_row(
                "SELECT agent_id FROM recordings WHERE id=?1",
                [&id],
                |row| row.get(0),
            )
            .optional()?;
        match existing {
            Some(owner) if owner == agent_id => Ok(()),
            Some(_) => Err(StoreError::NotFound),
            None => {
                self.conn.execute(
                    "INSERT INTO recordings (id, agent_id, destination, port, username, started_at, ended_at, kind)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7)",
                    params![id, agent_id, destination, start.port as i64, username, started_at, kind],
                )?;
                Ok(())
            }
        }
    }

    pub fn add_chunk(
        &mut self,
        agent_id: &str,
        recording_id: &str,
        t_ms: u64,
        direction: &str,
        data: &[u8],
    ) -> Result<(), StoreError> {
        let id = normalize_recording_id(recording_id)?;
        if !matches!(direction, "in" | "out" | "err" | "frame") {
            return Err(StoreError::BadInput("неизвестное направление".into()));
        }
        if data.len() > 1024 * 1024 {
            return Err(StoreError::BadInput("слишком большой фрагмент".into()));
        }
        if data.is_empty() {
            return Ok(());
        }
        self.recording_owner(&id, agent_id)?;
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM recording_chunks WHERE recording_id=?1",
            [&id],
            |row| row.get(0),
        )?;
        if count >= 200_000 {
            return Err(StoreError::BadInput("слишком много фрагментов записи".into()));
        }
        let t_ms = i64::try_from(t_ms).map_err(|_| StoreError::BadInput("метка времени".into()))?;
        self.conn.execute(
            "INSERT INTO recording_chunks (recording_id, t_ms, direction, data) VALUES (?1, ?2, ?3, ?4)",
            params![id, t_ms, direction, data],
        )?;
        Ok(())
    }

    pub fn finish_recording(
        &mut self,
        agent_id: &str,
        recording_id: &str,
        ended_at: i64,
        now: i64,
    ) -> Result<(), StoreError> {
        let id = normalize_recording_id(recording_id)?;
        self.recording_owner(&id, agent_id)?;
        let ended_at = if ended_at > 0 { ended_at } else { now };
        self.conn.execute(
            "UPDATE recordings SET ended_at=?1 WHERE id=?2 AND agent_id=?3",
            params![ended_at, id, agent_id],
        )?;
        Ok(())
    }

    pub fn list_recordings(&self) -> Result<Vec<RecordingRow>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT r.id, r.agent_id, COALESCE(a.hostname, ''), r.destination, r.port,
                    r.username, r.started_at, r.ended_at, COALESCE(r.kind, 'ssh')
             FROM recordings r
             LEFT JOIN agents a ON a.agent_id = r.agent_id
             ORDER BY r.started_at DESC
             LIMIT 100",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(RecordingRow {
                id: row.get(0)?,
                agent_id: row.get(1)?,
                hostname: row.get(2)?,
                destination: row.get(3)?,
                port: row.get::<_, i64>(4)? as u16,
                username: row.get(5)?,
                started_at: row.get(6)?,
                ended_at: row.get(7)?,
                kind: row.get(8)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(StoreError::from)
    }

    pub fn recording(&self, id: &str) -> Result<Option<RecordingView>, StoreError> {
        let id = normalize_recording_id(id)?;
        let row = self.recording_row(&id)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let mut stmt = self.conn.prepare(
            "SELECT t_ms, direction, data FROM recording_chunks WHERE recording_id=?1 ORDER BY id",
        )?;
        let chunks = stmt.query_map([&id], |chunk| {
            Ok((
                chunk.get::<_, i64>(0)?,
                chunk.get::<_, String>(1)?,
                chunk.get::<_, Vec<u8>>(2)?,
            ))
        })?;
        let mut frames = Vec::new();
        let mut kept = 0usize;
        let mut video = 0usize;
        let mut truncated = false;
        for chunk in chunks {
            let (t_ms, direction, data) = chunk?;
            if data.is_empty() {
                continue;
            }
            if direction == "frame" {
                if video >= 20_000 {
                    truncated = true;
                    continue;
                }
                frames.push(RecordingFrame {
                    t_ms: u64::try_from(t_ms).unwrap_or(0),
                    direction,
                    text: video.to_string(),
                });
                video += 1;
                continue;
            }
            if kept >= 400_000 {
                truncated = true;
                continue;
            }
            let mut text = String::from_utf8_lossy(&data).into_owned();
            if kept + text.len() > 400_000 {
                text.truncate(400_000 - kept);
                truncated = true;
            }
            kept += text.len();
            frames.push(RecordingFrame {
                t_ms: u64::try_from(t_ms).unwrap_or(0),
                direction,
                text,
            });
        }
        Ok(Some(RecordingView {
            row,
            frames,
            truncated,
        }))
    }

    pub fn recording_frame(&self, id: &str, index: u32) -> Result<Option<Vec<u8>>, StoreError> {
        let id = normalize_recording_id(id)?;
        self.conn
            .query_row(
                "SELECT data FROM recording_chunks
                 WHERE recording_id=?1 AND direction='frame'
                 ORDER BY id LIMIT 1 OFFSET ?2",
                params![id, i64::from(index)],
                |row| row.get(0),
            )
            .optional()
            .map_err(StoreError::from)
    }

    fn recording_owner(&self, id: &str, agent_id: &str) -> Result<(), StoreError> {
        let owner: Option<String> = self
            .conn
            .query_row("SELECT agent_id FROM recordings WHERE id=?1", [id], |row| row.get(0))
            .optional()?;
        match owner {
            Some(owner) if owner == agent_id => Ok(()),
            _ => Err(StoreError::NotFound),
        }
    }

    fn recording_row(&self, id: &str) -> Result<Option<RecordingRow>, StoreError> {
        self.conn
            .query_row(
                "SELECT r.id, r.agent_id, COALESCE(a.hostname, ''), r.destination, r.port,
                        r.username, r.started_at, r.ended_at, COALESCE(r.kind, 'ssh')
                 FROM recordings r
                 LEFT JOIN agents a ON a.agent_id = r.agent_id
                 WHERE r.id=?1",
                [id],
                |row| {
                    Ok(RecordingRow {
                        id: row.get(0)?,
                        agent_id: row.get(1)?,
                        hostname: row.get(2)?,
                        destination: row.get(3)?,
                        port: row.get::<_, i64>(4)? as u16,
                        username: row.get(5)?,
                        started_at: row.get(6)?,
                        ended_at: row.get(7)?,
                        kind: row.get(8)?,
                    })
                },
            )
            .optional()
            .map_err(StoreError::from)
    }
}

fn ensure_recording_kind(conn: &Connection) -> Result<(), StoreError> {
    let mut stmt = conn.prepare("PRAGMA table_info(recordings)")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        if name == "kind" {
            return Ok(());
        }
    }
    conn.execute(
        "ALTER TABLE recordings ADD COLUMN kind TEXT NOT NULL DEFAULT 'ssh'",
        [],
    )?;
    Ok(())
}

fn load_or_create_key(conn: &Connection) -> Result<ServiceKey, StoreError> {
    let existing: Option<Vec<u8>> = conn
        .query_row("SELECT secret FROM service_key WHERE id=1", [], |row| row.get(0))
        .optional()?;
    if let Some(bytes) = existing {
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| StoreError::BadInput("повреждён ключ подписи".into()))?;
        return Ok(ServiceKey::from_secret_bytes(&bytes));
    }
    let key = ServiceKey::generate();
    conn.execute(
        "INSERT INTO service_key (id, secret) VALUES (1, ?1)",
        params![key.secret_bytes().to_vec()],
    )?;
    Ok(key)
}

fn normalize_recording_id(id: &str) -> Result<String, StoreError> {
    let parsed = Uuid::parse_str(id.trim()).map_err(|_| StoreError::BadInput("некорректный id записи".into()))?;
    Ok(parsed.to_string())
}

fn one_line(value: &str, max: usize, label: &str) -> Result<String, StoreError> {
    let value = value.trim();
    if value.is_empty() || value.chars().any(|ch| ch.is_control()) || value.chars().count() > max {
        return Err(StoreError::BadInput(format!("некорректное поле: {label}")));
    }
    Ok(value.to_string())
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn sha256_hex(value: &str) -> String {
    Sha256::digest(value.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use keeppam_agent_protocol::RecordingStart;

    #[test]
    fn rdp_frames_stay_binary_and_are_addressed_by_index() {
        let dir = std::env::temp_dir().join(format!("agentd-rdp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut store = Store::open(&dir.join("t.sqlite")).unwrap();
        let id = "11111111-1111-1111-1111-111111111111";
        store
            .open_recording(
                "agent",
                &RecordingStart {
                    id: id.into(),
                    destination: "10.1.1.8".into(),
                    port: 3389,
                    username: "rdp".into(),
                    started_at: 10,
                    kind: "rdp".into(),
                },
                10,
            )
            .unwrap();
        let jpeg = [0xff, 0xd8, 0xff, 0xd9];
        store.add_chunk("agent", id, 0, "frame", &jpeg).unwrap();
        store.add_chunk("agent", id, 1000, "frame", &[1, 2, 3]).unwrap();
        assert!(store.add_chunk("agent", id, 0, "video", &[1]).is_err());
        let view = store.recording(id).unwrap().unwrap();
        assert_eq!(view.row.kind, "rdp");
        assert_eq!(view.frames[0].text, "0");
        assert_eq!(view.frames[1].text, "1");
        assert!(!view.frames[0].text.contains('\u{fffd}'));
        assert_eq!(store.recording_frame(id, 0).unwrap().unwrap(), jpeg);
        assert_eq!(store.recording_frame(id, 1).unwrap().unwrap(), vec![1, 2, 3]);
        assert!(store.recording_frame(id, 2).unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

pub fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

use rand::rngs::OsRng;
