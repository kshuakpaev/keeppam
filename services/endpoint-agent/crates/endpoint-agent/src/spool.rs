use std::path::Path;

use rusqlite::{params, Connection};

use keeppam_agent_protocol::EndpointEvent;

use crate::AgentError;

pub struct Spool {
    conn: Connection,
}

impl Spool {
    pub fn open(path: &Path) -> Result<Self, AgentError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|err| AgentError::State(err.to_string()))?;
        }
        let conn = Connection::open(path).map_err(|err| AgentError::State(err.to_string()))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS outbox (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                body TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );",
        )
        .map_err(|err| AgentError::State(err.to_string()))?;
        Ok(Self { conn })
    }

    pub fn enqueue(&mut self, events: &[EndpointEvent], now: i64) -> Result<(), AgentError> {
        if events.is_empty() {
            return Ok(());
        }
        let tx = self
            .conn
            .transaction()
            .map_err(|err| AgentError::State(err.to_string()))?;
        for event in events {
            let body = serde_json::to_string(event).map_err(|err| AgentError::State(err.to_string()))?;
            tx.execute(
                "INSERT INTO outbox (body, created_at) VALUES (?1, ?2)",
                params![body, now],
            )
            .map_err(|err| AgentError::State(err.to_string()))?;
        }
        tx.commit()
            .map_err(|err| AgentError::State(err.to_string()))?;
        Ok(())
    }

    pub fn peek(&self, limit: usize) -> Result<Vec<(i64, EndpointEvent)>, AgentError> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, body FROM outbox ORDER BY id LIMIT ?1")
            .map_err(|err| AgentError::State(err.to_string()))?;
        let rows = stmt
            .query_map([limit as i64], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)))
            .map_err(|err| AgentError::State(err.to_string()))?;
        let mut out = Vec::new();
        for row in rows {
            let (id, body) = row.map_err(|err| AgentError::State(err.to_string()))?;
            let event = serde_json::from_str(&body).map_err(|err| AgentError::State(err.to_string()))?;
            out.push((id, event));
        }
        Ok(out)
    }

    pub fn delete(&mut self, ids: &[i64]) -> Result<(), AgentError> {
        let tx = self
            .conn
            .transaction()
            .map_err(|err| AgentError::State(err.to_string()))?;
        for id in ids {
            tx.execute("DELETE FROM outbox WHERE id=?1", [id])
                .map_err(|err| AgentError::State(err.to_string()))?;
        }
        tx.commit()
            .map_err(|err| AgentError::State(err.to_string()))?;
        Ok(())
    }

    pub fn len(&self) -> Result<usize, AgentError> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM outbox", [], |row| row.get(0))
            .map_err(|err| AgentError::State(err.to_string()))?;
        Ok(count as usize)
    }
}
