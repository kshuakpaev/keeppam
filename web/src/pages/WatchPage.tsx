import { FitAddon } from "@xterm/addon-fit";
import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { Terminal } from "xterm";
import { api, hasPerm, type PamSession } from "../api";
import { useAuth } from "../auth";
import "xterm/css/xterm.css";

type SqlPayload = {
  statement?: string;
  reason?: string;
  error?: string;
  duration_ms?: number;
  row_count?: number;
  denied?: boolean;
  via?: string;
};

type LogLine = { ts: string; text: string; kind: "ok" | "deny" | "err" | "info" };

function formatSql(p: SqlPayload): LogLine {
  const stmt = (p.statement || "").replace(/\s+/g, " ").trim();
  const short = stmt.length > 240 ? stmt.slice(0, 240) + "…" : stmt;
  if (p.denied || p.reason) {
    return { ts: new Date().toLocaleTimeString(), text: `${short || "SQL"} — ${p.reason || "denied"}`, kind: "deny" };
  }
  if (p.error) {
    return { ts: new Date().toLocaleTimeString(), text: `${short || "SQL"} — ${p.error}`, kind: "err" };
  }
  const meta = [
    p.duration_ms != null ? `${p.duration_ms}ms` : "",
    p.row_count != null ? `${p.row_count} rows` : "",
    p.via || "",
  ]
    .filter(Boolean)
    .join(", ");
  return { ts: new Date().toLocaleTimeString(), text: `${short || "SQL"}${meta ? ` (${meta})` : ""}`, kind: "ok" };
}

function isDesktop(s: PamSession | null): boolean {
  if (!s) return false;
  return s.protocol === "rdp" || s.protocol === "vnc" || !!s.isolated;
}

function isSQL(s: PamSession | null): boolean {
  return s?.protocol === "postgres" || s?.protocol === "mysql";
}

function canKillSession(userId: string | undefined, perms: string[] | undefined, sess: PamSession): boolean {
  if (!userId) return false;
  if (sess.user_id === userId) return !!perms?.includes("sessions.connect");
  return !!perms?.includes("users.write") || !!perms?.includes("audit.read");
}

export function WatchPage() {
  const { id } = useParams<{ id: string }>();
  const { user } = useAuth();
  const hostRef = useRef<HTMLDivElement>(null);
  const termRef = useRef<Terminal | null>(null);
  const [sess, setSess] = useState<PamSession | null>(null);
  const [status, setStatus] = useState("подключение…");
  const [error, setError] = useState("");
  const [log, setLog] = useState<LogLine[]>([]);
  const [ended, setEnded] = useState(false);
  const [killing, setKilling] = useState(false);

  const pushLog = useCallback((line: LogLine) => {
    setLog((prev) => [...prev.slice(-200), line]);
  }, []);

  useEffect(() => {
    if (!id) return;
    let cancelled = false;
    void api
      .getSession(id)
      .then((s) => {
        if (!cancelled) setSess(s);
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "сессия недоступна");
      });
    return () => {
      cancelled = true;
    };
  }, [id]);

  useEffect(() => {
    if (!id || !sess) return;
    const ssh = sess.protocol === "ssh" || (!isSQL(sess) && !isDesktop(sess) && sess.protocol !== "https");
    let term: Terminal | null = null;
    let fit: FitAddon | null = null;

    if (ssh && hostRef.current) {
      term = new Terminal({
        disableStdin: true,
        cursorBlink: false,
        fontFamily: '"IBM Plex Mono", ui-monospace, monospace',
        fontSize: 14,
        theme: {
          background: "#0b1016",
          foreground: "#e8eef5",
          cursor: "#2f9e7a",
          selectionBackground: "#2a3544",
        },
      });
      fit = new FitAddon();
      term.loadAddon(fit);
      term.open(hostRef.current);
      fit.fit();
      termRef.current = term;
    }

    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(`${proto}//${window.location.host}/api/v1/sessions/${id}/watch`);
    ws.binaryType = "arraybuffer";

    ws.onopen = () => setStatus("наблюдение…");
    ws.onmessage = (ev) => {
      if (typeof ev.data !== "string") {
        const bytes = new Uint8Array(ev.data as ArrayBuffer);
        term?.write(bytes);
        return;
      }
      try {
        const msg = JSON.parse(ev.data) as {
          type?: string;
          event_type?: string;
          payload?: SqlPayload;
          protocol?: string;
          username?: string;
          asset?: string;
          account?: string;
          ts?: string;
        };
        if (msg.type === "ready") {
          setStatus("live · только просмотр");
        } else if (msg.type === "ended") {
          setEnded(true);
          setStatus("сессия завершена");
        } else if (msg.type === "sql") {
          pushLog(formatSql(msg.payload || {}));
        } else if (msg.type === "event") {
          const et = msg.event_type || "";
          if (et === "sql" || et === "sql_denied") {
            const line = formatSql(msg.payload || {});
            if (msg.ts) line.ts = new Date(msg.ts).toLocaleTimeString();
            if (et === "sql_denied") line.kind = "deny";
            pushLog(line);
          } else if (et === "command_denied") {
            const p = msg.payload || {};
            pushLog({
              ts: msg.ts ? new Date(msg.ts).toLocaleTimeString() : new Date().toLocaleTimeString(),
              text: `JEA deny: ${String((p as { command?: string }).command || (p as { reason?: string }).reason || et)}`,
              kind: "deny",
            });
          }
        }
      } catch {
        term?.write(ev.data);
      }
    };
    ws.onerror = () => {
      setError("WebSocket error");
      setStatus("ошибка");
    };
    ws.onclose = () => {
      setStatus((s) => (s === "ошибка" ? s : "соединение закрыто"));
    };

    const onResize = () => fit?.fit();
    window.addEventListener("resize", onResize);

    return () => {
      window.removeEventListener("resize", onResize);
      ws.close();
      term?.dispose();
      termRef.current = null;
    };
  }, [id, sess, pushLog]);

  async function onKill() {
    if (!id) return;
    setKilling(true);
    setError("");
    try {
      await api.endSession(id);
      setEnded(true);
      setStatus("сессия завершена");
    } catch (err) {
      setError(err instanceof Error ? err.message : "не удалось завершить");
    } finally {
      setKilling(false);
    }
  }

  if (!hasPerm(user, "sessions.read")) {
    return <p className="error">Недостаточно прав</p>;
  }

  const desktop = isDesktop(sess);
  const sql = isSQL(sess);
  const https = sess?.protocol === "https" && !sess.isolated;
  const showTerm = sess && !desktop && !sql && !https;
  const killOk = sess ? canKillSession(user?.id, user?.permissions, sess) : false;

  return (
    <div className="terminal-page">
      <div className="toolbar">
        <div>
          <h1>Наблюдение</h1>
          <p className="muted">
            {sess ? `${sess.asset_name} · ${sess.account_username} · ${sess.username}` : "…"}
            {sess?.protocol ? ` · ${sess.protocol}` : ""}
            {` · ${status}`}
            {id ? <span className="mono"> · {id.slice(0, 8)}</span> : null}
          </p>
        </div>
        <div className="row">
          {killOk && !ended && (
            <button className="btn danger" type="button" disabled={killing} onClick={() => void onKill()}>
              {killing ? "Завершение…" : "Завершить сессию"}
            </button>
          )}
          <Link className="btn secondary" to="/sessions">
            Назад
          </Link>
        </div>
      </div>
      {error && <p className="error">{error}</p>}
      {(desktop || https) && (
        <div className="card" style={{ padding: "1rem", marginBottom: "0.75rem" }}>
          <p>
            {desktop
              ? "Live-видео RDP/VNC/isolated browser в этом режиме не транслируется. Можно следить за статусом и принудительно завершить сессию."
              : "HTTPS-сессия приложения: поток экрана не зеркалируется. Доступны статус и kill."}
          </p>
          <p className="muted">
            {ended ? "Сессия уже завершена." : "Сессия активна. Закрытие этой страницы не прерывает работу оператора."}
          </p>
        </div>
      )}
      {showTerm && <div className="terminal-host card" ref={hostRef} />}
      {(sql || log.length > 0) && (
        <div className="card watch-log">
          <div className="muted" style={{ marginBottom: "0.5rem" }}>
            {sql ? "SQL-журнал (live)" : "События сессии"}
          </div>
          {log.length === 0 && <p className="muted">Ожидание запросов…</p>}
          {log.map((l, i) => (
            <div key={i} className={`watch-log-line ${l.kind}`}>
              <span className="mono muted">{l.ts}</span> {l.text}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
