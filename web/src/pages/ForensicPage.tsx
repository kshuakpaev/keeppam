import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { api, hasPerm, type TimelineEvent, type User } from "../api";
import { useAuth } from "../auth";

const PAGE_SIZE = 50;

function pad(n: number) {
  return String(n).padStart(2, "0");
}

function toLocalInput(d: Date) {
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function fromLocalInput(s: string) {
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? "" : d.toISOString();
}

function sessionHref(e: TimelineEvent) {
  if (!e.session_id) return "";
  const p = e.protocol || "";
  if (p === "postgres" || p === "mysql") return `/sessions/${e.session_id}/sql`;
  if (p === "kubectl") return `/sessions/${e.session_id}/k8s`;
  if (p === "rdp" || p === "vnc") return `/sessions/${e.session_id}/desktop`;
  if (p === "https") return `/sessions/${e.session_id}/app`;
  return `/sessions/${e.session_id}/replay`;
}

export function ForensicPage() {
  const { user } = useAuth();
  const canRead = hasPerm(user, "sessions.read");
  const canPickUser = hasPerm(user, "audit.read") || hasPerm(user, "users.write") || hasPerm(user, "users.read");
  const initialFrom = toLocalInput(new Date(Date.now() - 24 * 3600 * 1000));
  const initialTo = toLocalInput(new Date());
  const [users, setUsers] = useState<User[]>([]);
  const [userId, setUserId] = useState("");
  const [from, setFrom] = useState(initialFrom);
  const [to, setTo] = useState(initialTo);
  const [q, setQ] = useState("");
  const [source, setSource] = useState("all");
  const [applied, setApplied] = useState({ userId: "", from: initialFrom, to: initialTo, q: "", source: "all" });
  const [offset, setOffset] = useState(0);
  const [events, setEvents] = useState<TimelineEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [actor, setActor] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!canPickUser) return;
    void api
      .listUsers()
      .then((r) => setUsers(r.users || []))
      .catch(() => undefined);
  }, [canPickUser]);

  useEffect(() => {
    if (!user?.id) return;
    setUserId((cur) => cur || user.id);
    setApplied((a) => (a.userId ? a : { ...a, userId: user.id }));
  }, [user?.id]);

  const load = useCallback(async () => {
    if (!canRead || !applied.userId) return;
    setBusy(true);
    try {
      const res = await api.searchTimeline({
        user_id: applied.userId,
        q: applied.q || undefined,
        source: applied.source !== "all" ? applied.source : undefined,
        from: fromLocalInput(applied.from) || undefined,
        to: fromLocalInput(applied.to) || undefined,
        limit: PAGE_SIZE,
        offset,
      });
      setEvents(res.events || []);
      setTotal(res.total || 0);
      setActor(res.username || "");
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка");
    } finally {
      setBusy(false);
    }
  }, [canRead, applied, offset]);

  useEffect(() => {
    if (!canRead || !applied.userId) return;
    void load();
  }, [canRead, load, applied, offset]);

  function onSearch(e: FormEvent) {
    e.preventDefault();
    setOffset(0);
    setApplied({ userId, from, to, q: q.trim(), source });
  }

  async function onCsv() {
    setError("");
    try {
      await api.downloadTimelineCsv({
        user_id: applied.userId || undefined,
        q: applied.q || undefined,
        source: applied.source !== "all" ? applied.source : undefined,
        from: fromLocalInput(applied.from) || undefined,
        to: fromLocalInput(applied.to) || undefined,
        limit: 200,
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка CSV");
    }
  }

  if (!canRead) {
    return <p className="error">Недостаточно прав (sessions.read)</p>;
  }

  const page = Math.floor(offset / PAGE_SIZE) + 1;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <div>
      <div className="toolbar">
        <div>
          <h1>Расследование</h1>
          <p className="muted">
            Лента действий пользователя: аудит (вход, ACL, JIT) и события сессий (SQL, k8s, команды SSH, JEA, DLP).
            RDP/видео не индексируются.
          </p>
        </div>
        <button className="btn secondary" type="button" onClick={() => void onCsv()} disabled={busy || total === 0}>
          CSV
        </button>
      </div>

      <form
        className="row card"
        style={{ marginBottom: "0.75rem", gap: "0.75rem", flexWrap: "wrap", alignItems: "end" }}
        onSubmit={onSearch}
      >
        <label>
          Пользователь
          {canPickUser && users.length > 0 ? (
            <select value={userId} onChange={(e) => setUserId(e.target.value)}>
              {users.map((u) => (
                <option key={u.id} value={u.id}>
                  {u.username}
                </option>
              ))}
            </select>
          ) : (
            <input value={user?.username || ""} disabled />
          )}
        </label>
        <label>
          С
          <input type="datetime-local" value={from} onChange={(e) => setFrom(e.target.value)} />
        </label>
        <label>
          По
          <input type="datetime-local" value={to} onChange={(e) => setTo(e.target.value)} />
        </label>
        <label>
          Источник
          <select value={source} onChange={(e) => setSource(e.target.value)}>
            <option value="all">все</option>
            <option value="audit">аудит</option>
            <option value="session">сессии</option>
          </select>
        </label>
        <label>
          Поиск
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="sql, login, denied…" />
        </label>
        <button className="btn" type="submit" disabled={busy}>
          Показать
        </button>
      </form>

      {error && <p className="error">{error}</p>}

      <div className="card">
        <p className="muted" style={{ marginBottom: "0.75rem" }}>
          {actor ? (
            <>
              <span className="mono">{actor}</span>
              {total ? ` · ${total} событий` : " · нет событий"}
            </>
          ) : (
            "Задайте окно и пользователя"
          )}
        </p>
        <table>
          <thead>
            <tr>
              <th>Время</th>
              <th>Источник</th>
              <th>Событие</th>
              <th>Актив</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {events.map((e) => {
              const href = sessionHref(e);
              return (
                <tr key={`${e.source}-${e.id}`}>
                  <td className="mono" style={{ whiteSpace: "nowrap" }}>
                    {new Date(e.ts).toLocaleString()}
                  </td>
                  <td className="mono">{e.source}</td>
                  <td>
                    <div className="mono" style={{ fontSize: "0.85rem" }}>
                      {e.kind}
                    </div>
                    <div>{e.snippet}</div>
                    {(e.labels || []).length > 0 || e.risk_score ? (
                      <div className="muted" style={{ fontSize: "0.8rem" }}>
                        {(e.labels || []).length ? (e.labels || []).join(", ") : ""}
                        {e.risk_score ? ` · risk ${e.risk_score}` : ""}
                        {e.ip ? ` · ${e.ip}` : ""}
                      </div>
                    ) : e.ip ? (
                      <div className="muted" style={{ fontSize: "0.8rem" }}>
                        {e.ip}
                      </div>
                    ) : null}
                  </td>
                  <td>
                    {e.asset_id ? (
                      <>
                        <Link to={`/assets/${e.asset_id}`}>{e.asset_name || e.asset_id}</Link>
                        {e.protocol ? <div className="muted mono">{e.protocol}</div> : null}
                      </>
                    ) : (
                      <span className="muted">—</span>
                    )}
                  </td>
                  <td>
                    {href ? (
                      <Link className="btn secondary" to={href}>
                        Сессия
                      </Link>
                    ) : null}
                  </td>
                </tr>
              );
            })}
            {events.length === 0 && (
              <tr>
                <td colSpan={5} className="muted">
                  Нет событий за выбранное окно
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
