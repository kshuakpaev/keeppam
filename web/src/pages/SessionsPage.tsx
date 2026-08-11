import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, hasPerm, type PamSession } from "../api";
import { useAuth } from "../auth";
import { kindForProtocol, useSessionTabs } from "../sessionTabs";

const PAGE_SIZE = 50;

type Tab = "all" | "live";

export function SessionsPage() {
  const { user } = useAuth();
  const { openTab, closeTab } = useSessionTabs();
  const [sessions, setSessions] = useState<PamSession[]>([]);
  const [total, setTotal] = useState(0);
  const [error, setError] = useState("");
  const [tab, setTab] = useState<Tab>("all");
  const [status, setStatus] = useState("");
  const [protocol, setProtocol] = useState("");
  const [q, setQ] = useState("");
  const [appliedQ, setAppliedQ] = useState("");
  const [offset, setOffset] = useState(0);
  const canRead = hasPerm(user, "sessions.read");

  const effectiveStatus = tab === "live" ? "active" : status;

  const load = useCallback(async () => {
    try {
      const res = await api.listSessions({
        status: effectiveStatus || undefined,
        protocol: protocol || undefined,
        q: appliedQ || undefined,
        limit: PAGE_SIZE,
        offset,
      });
      setSessions(res.sessions || []);
      setTotal(res.total || 0);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка");
    }
  }, [effectiveStatus, protocol, appliedQ, offset]);

  async function onEnd(id: string) {
    setError("");
    try {
      await closeTab(id, { endSession: true });
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Не удалось завершить");
    }
  }

  useEffect(() => {
    if (!canRead) return;
    void load();
  }, [canRead, load]);

  useEffect(() => {
    if (!canRead || tab !== "live") return;
    const t = window.setInterval(() => void load(), 5000);
    return () => window.clearInterval(t);
  }, [canRead, tab, load]);

  if (!canRead) {
    return <p className="error">Недостаточно прав</p>;
  }

  const page = Math.floor(offset / PAGE_SIZE) + 1;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <div>
      <div className="toolbar">
        <div>
          <h1>Сессии</h1>
          <p className="muted">
            Привилегированные подключения и записи · также{" "}
            <span className="mono">ssh -p 2222 user@host</span>
          </p>
        </div>
        <button className="btn secondary" type="button" onClick={() => void load()}>
          Обновить
        </button>
      </div>

      <div className="row" style={{ marginBottom: "0.75rem", gap: "0.5rem", flexWrap: "wrap" }}>
        <button
          className={`btn secondary${tab === "live" ? " active" : ""}`}
          type="button"
          onClick={() => {
            setTab("live");
            setOffset(0);
          }}
        >
          Онлайн
        </button>
        <button
          className={`btn secondary${tab === "all" ? " active" : ""}`}
          type="button"
          onClick={() => {
            setTab("all");
            setOffset(0);
          }}
        >
          Все
        </button>
      </div>

      <form
        className="row card"
        style={{ marginBottom: "0.75rem", gap: "0.75rem", flexWrap: "wrap", alignItems: "end" }}
        onSubmit={(e) => {
          e.preventDefault();
          setAppliedQ(q.trim());
          setOffset(0);
        }}
      >
        {tab === "all" && (
          <label>
            Статус
            <select value={status} onChange={(e) => { setStatus(e.target.value); setOffset(0); }}>
              <option value="">все</option>
              <option value="pending">pending</option>
              <option value="active">active</option>
              <option value="ended">ended</option>
              <option value="failed">failed</option>
            </select>
          </label>
        )}
        <label>
          Протокол
          <select value={protocol} onChange={(e) => { setProtocol(e.target.value); setOffset(0); }}>
            <option value="">все</option>
            <option value="ssh">ssh</option>
            <option value="rdp">rdp</option>
            <option value="vnc">vnc</option>
          </select>
        </label>
        <label style={{ flex: 1, minWidth: 160 }}>
          Поиск
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="user / актив / адрес"
          />
        </label>
        <button className="btn secondary" type="submit">
          Найти
        </button>
        <button
          className="btn secondary"
          type="button"
          onClick={() => {
            setQ("");
            setAppliedQ("");
            setStatus("");
            setProtocol("");
            setOffset(0);
          }}
        >
          Сброс
        </button>
      </form>

      {error && <p className="error">{error}</p>}
      <div className="card">
        <table>
          <thead>
            <tr>
              <th>Время</th>
              <th>Пользователь</th>
              <th>Актив</th>
              <th>Учётка</th>
              <th>Протокол</th>
              <th>Статус</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {sessions.map((s) => (
              <tr key={s.id}>
                <td className="mono">
                  {new Date(s.created_at).toLocaleString()}
                  {s.status === "active" && s.last_seen_at && (
                    <div className="muted">seen {new Date(s.last_seen_at).toLocaleTimeString()}</div>
                  )}
                </td>
                <td>{s.username}</td>
                <td>
                  <Link to={`/assets/${s.asset_id}`}>{s.asset_name}</Link>
                  <div className="muted mono">{s.asset_address}</div>
                </td>
                <td className="mono">{s.account_username}</td>
                <td className="mono">{s.protocol}</td>
                <td>
                  <span
                    className={`badge ${
                      s.status === "active" ? "active" : s.status === "failed" ? "locked" : ""
                    }`}
                  >
                    {s.status === "active" ? "live" : s.status}
                  </span>
                </td>
                <td>
                  <div className="row">
                    {(s.status === "active" || s.status === "pending") && (
                      <>
                        <button
                          className="btn secondary"
                          type="button"
                          onClick={() =>
                            openTab({
                              id: s.id,
                              kind: kindForProtocol(s.protocol),
                              title: s.asset_name || s.protocol,
                              protocol: s.protocol,
                            })
                          }
                        >
                          {s.protocol === "rdp" || s.protocol === "vnc"
                            ? "Desktop"
                            : s.protocol === "postgres" || s.protocol === "mysql"
                              ? "SQL"
                              : s.protocol === "https"
                                ? "App"
                                : "Terminal"}
                        </button>
                        <button
                          className="btn danger"
                          type="button"
                          onClick={() => void onEnd(s.id)}
                        >
                          Завершить
                        </button>
                      </>
                    )}
                    {(s.status === "ended" || s.status === "failed") && (
                      <>
                        {s.protocol === "postgres" ||
                        s.protocol === "mysql" ||
                        s.protocol === "https" ? (
                          <a className="btn secondary" href={api.getRecordingUrl(s.id)}>
                            Recording
                          </a>
                        ) : (
                          <>
                            <Link className="btn secondary" to={`/sessions/${s.id}/replay`}>
                              Replay
                            </Link>
                            {(s.protocol === "rdp" || s.protocol === "vnc") && (
                              <a className="btn secondary" href={api.getRecordingUrl(s.id)}>
                                Скачать
                              </a>
                            )}
                          </>
                        )}
                      </>
                    )}
                  </div>
                </td>
              </tr>
            ))}
            {sessions.length === 0 && (
              <tr>
                <td colSpan={7} className="muted">
                  {tab === "live"
                    ? "Сейчас никто не подключён."
                    : "Сессий пока нет. Подключитесь к активу со страницы актива."}
                </td>
              </tr>
            )}
          </tbody>
        </table>
        <div className="row" style={{ marginTop: "0.75rem", justifyContent: "space-between" }}>
          <span className="muted">
            {total === 0 ? "Нет записей" : `Стр. ${page} из ${pages} · всего ${total}`}
          </span>
          <div className="row">
            <button
              className="btn secondary"
              type="button"
              disabled={offset <= 0}
              onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
            >
              ←
            </button>
            <button
              className="btn secondary"
              type="button"
              disabled={offset + PAGE_SIZE >= total}
              onClick={() => setOffset(offset + PAGE_SIZE)}
            >
              →
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
