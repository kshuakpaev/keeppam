import { useEffect, useRef, useState } from "react";
import { ApiError, api } from "../api";
import { StepUpDialog } from "../pages/StepUpDialog";

type ResultMsg = {
  type: string;
  columns?: string[];
  rows?: string[][];
  row_count?: number;
  duration_ms?: number;
  truncated?: boolean;
  error?: string;
  ephemeral_role?: string;
  db_privilege?: string;
  database_name?: string;
  code?: string;
  challenge_token?: string;
  totp?: boolean;
  webauthn?: boolean;
  risk_score?: number;
  max_risk?: number;
  risk_factors?: string[];
  operation?: string;
};

type Props = {
  id: string;
  title: string;
  visible: boolean;
  onClose: () => void;
};

export function SqlSession({ id, title, visible, onClose }: Props) {
  const [sql, setSql] = useState("SELECT 1");
  const [status, setStatus] = useState("connecting…");
  const [error, setError] = useState("");
  const [result, setResult] = useState<ResultMsg | null>(null);
  const [wire, setWire] = useState<{ user?: string; addr?: string; db?: string }>({});
  const [eph, setEph] = useState<{ role?: string; privilege?: string }>({});
  const [database, setDatabase] = useState("");
  const wsRef = useRef<WebSocket | null>(null);
  const [ready, setReady] = useState(false);
  const [closing, setClosing] = useState(false);
  const [stepUp, setStepUp] = useState<ApiError | null>(null);

  useEffect(() => {
    void api
      .getSession(id)
      .then((s) => {
        setWire({
          user: s.id,
          addr: s.protocol === "mysql" ? ":13306" : s.protocol === "mssql" ? ":11433" : ":15432",
          db: s.database_name || "",
        });
        if (s.database_name) setDatabase(s.database_name);
        if (s.db_privilege) setEph((e) => ({ ...e, privilege: s.db_privilege }));
        if (s.protocol === "mssql") setSql("SELECT TOP 10 name FROM sys.tables");
        else setSql("SELECT * FROM tickets LIMIT 10");
      })
      .catch(() => undefined);

    const proto = location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${proto}://${location.host}/api/v1/sessions/${id}/sql`);
    wsRef.current = ws;
    ws.onopen = () => setStatus("connected");
    ws.onclose = () => {
      setReady(false);
      setStatus("closed");
    };
    ws.onerror = () => setError("WebSocket error");
    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(String(ev.data)) as ResultMsg;
        if (msg.type === "ready") {
          setReady(true);
          setStatus("ready");
          setEph({ role: msg.ephemeral_role, privilege: msg.db_privilege });
          if (msg.database_name) setDatabase(msg.database_name);
        } else if (msg.type === "mfa_required") {
          setStepUp(
            new ApiError(msg.error || "mfa_required", 403, {
              code: "mfa_required",
              challenge_token: msg.challenge_token,
              totp: msg.totp,
              webauthn: msg.webauthn,
              risk_score: msg.risk_score,
              max_risk: msg.max_risk,
              risk_factors: msg.risk_factors,
              operation: msg.operation,
            }),
          );
          setError(msg.error || "Нужен повторный MFA");
        } else if (msg.type === "result" || msg.type === "error") {
          setResult(msg);
          if (msg.error) setError(msg.error);
          else setError("");
        }
      } catch {
        /* ignore */
      }
    };
    return () => {
      ws.close();
    };
  }, [id]);

  void visible;

  function run() {
    if (!wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) return;
    setError("");
    setResult(null);
    wsRef.current.send(JSON.stringify({ type: "query", statement: sql }));
  }

  async function handleClose() {
    if (closing) return;
    setClosing(true);
    try {
      wsRef.current?.close();
    } catch {
      /* ignore */
    }
    onClose();
  }

  return (
    <div className="session-panel-inner">
      <div className="page-head">
        <div>
          <h1>SQL · {title}</h1>
          <p className="muted">
            {status}
            {database && (
              <>
                {" "}
                · db <span className="mono">{database}</span>
              </>
            )}
            {eph.role && (
              <>
                {" "}
                · ephemeral <span className="mono">{eph.role}</span>
                {eph.privilege ? ` (${eph.privilege})` : ""}
              </>
            )}
            {wire.user && (
              <>
                {" "}
                · wire: user=<span className="mono">{wire.user}</span> port={wire.addr}
                {wire.db ? (
                  <>
                    {" "}
                    dbname=<span className="mono">{wire.db}</span>
                  </>
                ) : null}
              </>
            )}
          </p>
        </div>
        <button className="btn secondary" type="button" disabled={closing} onClick={() => void handleClose()}>
          {closing ? "Завершение…" : "Завершить"}
        </button>
      </div>
      {error && <p className="error">{error}</p>}
      <div className="card">
        <textarea
          className="sql-input"
          value={sql}
          onChange={(e) => setSql(e.target.value)}
          rows={6}
          spellCheck={false}
        />
        <button className="btn" type="button" disabled={!ready} onClick={run}>
          Выполнить
        </button>
      </div>
      {stepUp && (
        <StepUpDialog
          err={stepUp}
          onDone={() => {
            setStepUp(null);
            run();
          }}
          onCancel={() => setStepUp(null)}
        />
      )}
      {result?.type === "result" && (
        <div className="card" style={{ marginTop: "1rem", overflowX: "auto" }}>
          <p className="muted">
            {result.row_count} строк · {result.duration_ms} ms
            {result.truncated ? " · truncated" : ""}
          </p>
          <table>
            <thead>
              <tr>
                {(result.columns || []).map((c) => (
                  <th key={c}>{c}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {(result.rows || []).map((row, i) => (
                <tr key={i}>
                  {row.map((cell, j) => (
                    <td key={j} className="mono">
                      {cell}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
