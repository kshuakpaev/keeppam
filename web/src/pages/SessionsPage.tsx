import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, hasPerm, type PamSession, type SessionEventHit } from "../api";
import { useAuth } from "../auth";
import { kindForProtocol, useSessionTabs } from "../sessionTabs";

const PAGE_SIZE = 50;

function snapshotHint(s: PamSession): string {
  const p = s.policy_snapshot;
  if (!p) return "";
  const bits: string[] = [];
  if (p.access_policy_name) bits.push(p.access_policy_name);
  if (p.max_risk) bits.push(`risk≤${p.max_risk}/${p.risk_action || "deny"}`);
  if (p.command_policy_pack_name) bits.push(`ssh:${p.command_policy_pack_name}`);
  if (p.sql_policy_pack_name) bits.push(`sql:${p.sql_policy_pack_name}`);
  if (p.http_policy_pack_name) bits.push(`http:${p.http_policy_pack_name}`);
  if (p.app_object_pack_name) bits.push(`obj:${p.app_object_pack_name}`);
  if (p.tag_acl) bits.push("tag-acl");
  if (p.admin_bypass) bits.push("bypass");
  return bits.join(" · ");
}

type Tab = "all" | "live" | "events";

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
  const [eventType, setEventType] = useState("");
  const [hours, setHours] = useState(168);
  const [events, setEvents] = useState<SessionEventHit[]>([]);
  const [eventTotal, setEventTotal] = useState(0);
  const canRead = hasPerm(user, "sessions.read");
  const canWatch = hasPerm(user, "sessions.read");

  const effectiveStatus = tab === "live" ? "active" : status;

  const load = useCallback(async () => {
    try {
      if (tab === "events") {
        const res = await api.searchSessionEvents({
          q: appliedQ || undefined,
          type: eventType || undefined,
          hours,
          limit: PAGE_SIZE,
          offset,
        });
        setEvents(res.events || []);
        setEventTotal(res.total || 0);
      } else {
        const res = await api.listSessions({
          status: effectiveStatus || undefined,
          protocol: protocol || undefined,
          q: appliedQ || undefined,
          limit: PAGE_SIZE,
          offset,
        });
        setSessions(res.sessions || []);
        setTotal(res.total || 0);
      }
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка");
    }
  }, [tab, effectiveStatus, protocol, appliedQ, offset, eventType, hours]);

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

  const listTotal = tab === "events" ? eventTotal : total;
  const page = Math.floor(offset / PAGE_SIZE) + 1;
  const pages = Math.max(1, Math.ceil(listTotal / PAGE_SIZE));

  return (
    <div>
      <div className="toolbar">
        <div>
          <h1>Сессии</h1>
          <p className="muted">
            Привилегированные подключения и записи · вкладка «События» ищет SQL / kubectl / JEA deny.
            Лента по пользователю — <Link to="/forensic">Расследование</Link>.
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
        <button
          className={`btn secondary${tab === "events" ? " active" : ""}`}
          type="button"
          onClick={() => {
            setTab("events");
            setOffset(0);
          }}
        >
          События
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
        {tab === "events" ? (
          <>
            <label>
              Тип
              <select value={eventType} onChange={(e) => { setEventType(e.target.value); setOffset(0); }}>
                <option value="">forensic</option>
                <option value="sql">sql</option>
                <option value="sql_denied">sql_denied</option>
                <option value="k8s">k8s</option>
                <option value="command_denied">command_denied</option>
                <option value="dlp">dlp</option>
                <option value="http_denied">http_denied</option>
                <option value="app_denied">app_denied</option>
                <option value="app_approval">app_approval</option>
                <option value="risk">risk</option>
                <option value="all">все типы</option>
              </select>
            </label>
            <label>
              Окно
              <select value={hours} onChange={(e) => { setHours(Number(e.target.value)); setOffset(0); }}>
                <option value={24}>24ч</option>
                <option value={72}>3д</option>
                <option value={168}>7д</option>
                <option value={720}>30д</option>
              </select>
            </label>
          </>
        ) : (
          <label>
            Протокол
            <select value={protocol} onChange={(e) => { setProtocol(e.target.value); setOffset(0); }}>
              <option value="">все</option>
              <option value="ssh">ssh</option>
              <option value="rdp">rdp</option>
              <option value="vnc">vnc</option>
              <option value="postgres">postgres</option>
              <option value="mysql">mysql</option>
              <option value="kubectl">kubectl</option>
              <option value="https">https</option>
            </select>
          </label>
        )}
        <label style={{ flex: 1, minWidth: 160 }}>
          Поиск
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder={tab === "events" ? "SELECT / kubectl / rm -rf" : "user / актив / адрес"}
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
            setEventType("");
            setHours(168);
            setOffset(0);
          }}
        >
          Сброс
        </button>
      </form>

      {error && <p className="error">{error}</p>}
      {tab === "events" ? (
      <div className="card">
        <table>
          <thead>
            <tr>
              <th>Время</th>
              <th>Тип</th>
              <th>Сниппет</th>
              <th>Кто / куда</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {events.map((e) => (
              <tr key={e.id}>
                <td className="mono">{new Date(e.ts).toLocaleString()}</td>
                <td className="mono">{e.type}</td>
                <td className="mono" style={{ maxWidth: 420, whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
                  {e.snippet}
                </td>
                <td>
                  {e.username}
                  <div className="muted">
                    <Link to={`/assets/${e.asset_id}`}>{e.asset_name}</Link>
                    {" · "}
                    <span className="mono">{e.protocol}</span>
                    {e.break_glass ? " · glass" : ""}
                  </div>
                </td>
                <td>
                  <div className="row">
                    {(e.status === "active" || e.status === "pending") && (
                      <Link className="btn secondary" to={`/sessions/${e.session_id}/watch`}>
                        Watch
                      </Link>
                    )}
                    {(e.status === "ended" || e.status === "failed") &&
                      (e.protocol === "postgres" || e.protocol === "mysql" || e.protocol === "kubectl" ? (
                        <a className="btn secondary" href={api.getRecordingUrl(e.session_id)}>
                          Recording
                        </a>
                      ) : (
                        <Link className="btn secondary" to={`/sessions/${e.session_id}/replay`}>
                          Replay
                        </Link>
                      ))}
                  </div>
                </td>
              </tr>
            ))}
            {events.length === 0 && (
              <tr>
                <td colSpan={5} className="muted">
                  Нет событий за выбранное окно. SQL / kubectl / JEA deny попадают сюда; интерактивный SSH — в replay.
                </td>
              </tr>
            )}
          </tbody>
        </table>
        <div className="row" style={{ marginTop: "0.75rem", justifyContent: "space-between" }}>
          <span className="muted">
            {listTotal === 0 ? "Нет записей" : `Стр. ${page} из ${pages} · всего ${listTotal}`}
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
              disabled={offset + PAGE_SIZE >= listTotal}
              onClick={() => setOffset(offset + PAGE_SIZE)}
            >
              →
            </button>
          </div>
        </div>
      </div>
      ) : (
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
                  {s.break_glass && (
                    <span className="badge locked" style={{ marginLeft: 6 }} title="break-glass session">
                      glass
                    </span>
                  )}
                  {snapshotHint(s) && (
                    <div className="muted mono" style={{ fontSize: "0.8rem" }} title="политика на момент connect">
                      {snapshotHint(s)}
                    </div>
                  )}
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
                              kind: kindForProtocol(s.protocol, s.isolated),
                              title: s.asset_name || s.protocol,
                              protocol: s.protocol,
                            })
                          }
                        >
                          {s.protocol === "rdp" || s.protocol === "vnc" || s.isolated
                            ? "Desktop"
                            : s.protocol === "postgres" || s.protocol === "mysql"
                              ? "SQL"
                              : s.protocol === "https"
                                ? "App"
                                : s.protocol === "kubectl"
                                  ? "kubectl"
                                  : "Terminal"}
                        </button>
                        {canWatch && (
                          <Link className="btn secondary" to={`/sessions/${s.id}/watch`}>
                            Наблюдать
                          </Link>
                        )}
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
                        s.protocol === "kubectl" ||
                        (s.protocol === "https" && !s.isolated) ? (
                          <a className="btn secondary" href={api.getRecordingUrl(s.id)}>
                            Recording
                          </a>
                        ) : (
                          <>
                            <Link className="btn secondary" to={`/sessions/${s.id}/replay`}>
                              Replay
                            </Link>
                            {(s.protocol === "rdp" || s.protocol === "vnc" || s.isolated) && (
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
            {listTotal === 0 ? "Нет записей" : `Стр. ${page} из ${pages} · всего ${listTotal}`}
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
              disabled={offset + PAGE_SIZE >= listTotal}
              onClick={() => setOffset(offset + PAGE_SIZE)}
            >
              →
            </button>
          </div>
        </div>
      </div>
      )}
    </div>
  );
}
