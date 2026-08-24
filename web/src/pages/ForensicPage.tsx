import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { api, hasPerm, type TimelineEvent, type User } from "../api";
import { useAuth } from "../auth";
import { useI18n } from "../i18n";

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
  if (p === "postgres" || p === "mysql" || p === "mssql") return `/sessions/${e.session_id}/sql`;
  if (p === "kubectl") return `/sessions/${e.session_id}/k8s`;
  if (p === "rdp" || p === "vnc") return `/sessions/${e.session_id}/desktop`;
  if (p === "https") return `/sessions/${e.session_id}/app`;
  return `/sessions/${e.session_id}/replay`;
}

export function ForensicPage() {
  const { user } = useAuth();
  const { t, te } = useI18n();
  const canRead = hasPerm(user, "sessions.read");
  const canPickUser = hasPerm(user, "audit.read") || hasPerm(user, "users.write") || hasPerm(user, "users.read");
  const initialFrom = toLocalInput(new Date(Date.now() - 24 * 3600 * 1000));
  const initialTo = toLocalInput(new Date());
  const [users, setUsers] = useState<User[]>([]);
  const [userId, setUserId] = useState("");
  const [from, setFrom] = useState(initialFrom);
  const [to, setTo] = useState(initialTo);
  const [q, setQ] = useState("");
  const [filename, setFilename] = useState("");
  const [process, setProcess] = useState("");
  const [source, setSource] = useState("all");
  const [applied, setApplied] = useState({
    userId: "",
    from: initialFrom,
    to: initialTo,
    q: "",
    filename: "",
    process: "",
    source: "all",
  });
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
        filename: applied.filename || undefined,
        process: applied.process || undefined,
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
      setError(te(err, "common.error"));
    } finally {
      setBusy(false);
    }
  }, [canRead, applied, offset, te]);

  useEffect(() => {
    if (!canRead || !applied.userId) return;
    void load();
  }, [canRead, load, applied, offset]);

  function onSearch(e: FormEvent) {
    e.preventDefault();
    setOffset(0);
    setApplied({ userId, from, to, q: q.trim(), filename: filename.trim(), process: process.trim(), source });
  }

  async function onCsv() {
    setError("");
    try {
      await api.downloadTimelineCsv({
        user_id: applied.userId || undefined,
        q: applied.q || undefined,
        filename: applied.filename || undefined,
        process: applied.process || undefined,
        source: applied.source !== "all" ? applied.source : undefined,
        from: fromLocalInput(applied.from) || undefined,
        to: fromLocalInput(applied.to) || undefined,
        limit: 200,
      });
    } catch (err) {
      setError(te(err, "forensic.csvError"));
    }
  }

  if (!canRead) {
    return <p className="error">{t("forensic.forbiddenDetail")}</p>;
  }

  const page = Math.floor(offset / PAGE_SIZE) + 1;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <div>
      <div className="toolbar">
        <div>
          <h1>{t("nav.forensic")}</h1>
          <p className="muted">{t("forensic.lead")}</p>
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
          {t("common.user")}
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
          {t("forensic.from")}
          <input type="datetime-local" value={from} onChange={(e) => setFrom(e.target.value)} />
        </label>
        <label>
          {t("forensic.to")}
          <input type="datetime-local" value={to} onChange={(e) => setTo(e.target.value)} />
        </label>
        <label>
          {t("forensic.source")}
          <select value={source} onChange={(e) => setSource(e.target.value)}>
            <option value="all">{t("common.all")}</option>
            <option value="audit">{t("forensic.sourceAudit")}</option>
            <option value="session">{t("forensic.sourceSession")}</option>
          </select>
        </label>
        <label>
          {t("common.search")}
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder={t("forensic.searchPlaceholder")} />
        </label>
        <label>
          {t("sess.filename")}
          <input value={filename} onChange={(e) => setFilename(e.target.value)} placeholder="secret.bin" />
        </label>
        <label>
          {t("sess.process")}
          <input value={process} onChange={(e) => setProcess(e.target.value)} placeholder="notepad.exe" />
        </label>
        <button className="btn" type="submit" disabled={busy}>
          {t("forensic.show")}
        </button>
      </form>

      {error && <p className="error">{error}</p>}

      <div className="card">
        <p className="muted" style={{ marginBottom: "0.75rem" }}>
          {actor ? (
            <>
              <span className="mono">{actor}</span>
              {total ? t("forensic.eventsCount", { count: total }) : t("forensic.noEventsShort")}
            </>
          ) : (
            t("forensic.setWindowAndUser")
          )}
        </p>
        <table>
          <thead>
            <tr>
              <th>{t("sess.time")}</th>
              <th>{t("forensic.source")}</th>
              <th>{t("forensic.event")}</th>
              <th>{t("common.asset")}</th>
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
                        {e.risk_score ? t("forensic.riskScore", { score: e.risk_score }) : ""}
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
                        {t("forensic.session")}
                      </Link>
                    ) : null}
                  </td>
                </tr>
              );
            })}
            {events.length === 0 && (
              <tr>
                <td colSpan={5} className="muted">
                  {t("forensic.noEventsInWindow")}
                </td>
              </tr>
            )}
          </tbody>
        </table>
        <div className="row" style={{ marginTop: "0.75rem", justifyContent: "space-between" }}>
          <span className="muted">
            {total === 0 ? t("common.noRecords") : t("common.pageOf", { page, pages, total })}
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
