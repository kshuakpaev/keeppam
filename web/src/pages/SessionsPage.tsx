import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, hasPerm, type PamSession, type SessionEventHit } from "../api";
import { useAuth } from "../auth";
import { useI18n } from "../i18n";
import { isSQLProtocol, kindForProtocol, useSessionTabs } from "../sessionTabs";

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
  if ((p.allowed_egress || []).length) bits.push(`egress:${(p.allowed_egress || []).length}`);
  if (p.pii_action) bits.push(`pii:${p.pii_action}`);
  if (p.file_transfer && p.file_transfer !== "deny") bits.push(`files:${p.file_transfer}`);
  if (p.ocr_lang) bits.push(`ocr:${p.ocr_lang}`);
  if (p.tag_acl) bits.push(p.match_mode === "any" ? "tag-acl:any" : "tag-acl");
  if (p.admin_bypass) bits.push("bypass");
  return bits.join(" · ");
}

type Tab = "all" | "live" | "events";

export function SessionsPage() {
  const { user } = useAuth();
  const { t, te } = useI18n();
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
  const canSupervise = hasPerm(user, "sessions.supervise");

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
      setError(te(err));
    }
  }, [tab, effectiveStatus, protocol, appliedQ, offset, eventType, hours]);

  async function onEnd(id: string) {
    setError("");
    try {
      await closeTab(id, { endSession: true });
      await load();
    } catch (err) {
      setError(te(err, "sess.endError"));
    }
  }

  async function onApproveSupervisor(id: string) {
    setError("");
    try {
      await api.approveSupervisor(id);
      await load();
    } catch (err) {
      setError(te(err, "req.failSupervise"));
    }
  }

  async function onDenySupervisor(id: string) {
    setError("");
    try {
      await api.denySupervisor(id);
      await load();
    } catch (err) {
      setError(te(err, "req.failSuperviseDeny"));
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
    return <p className="error">{t("common.forbidden")}</p>;
  }

  const listTotal = tab === "events" ? eventTotal : total;
  const page = Math.floor(offset / PAGE_SIZE) + 1;
  const pages = Math.max(1, Math.ceil(listTotal / PAGE_SIZE));

  return (
    <div>
      <div className="toolbar">
        <div>
          <h1>{t("sess.title")}</h1>
          <p className="muted">
            {t("sess.lead")} <Link to="/forensic">{t("nav.forensic")}</Link>.
          </p>
        </div>
        <button className="btn secondary" type="button" onClick={() => void load()}>
          {t("common.refresh")}
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
          {t("sess.live")}
        </button>
        <button
          className={`btn secondary${tab === "all" ? " active" : ""}`}
          type="button"
          onClick={() => {
            setTab("all");
            setOffset(0);
          }}
        >
          {t("sess.all")}
        </button>
        <button
          className={`btn secondary${tab === "events" ? " active" : ""}`}
          type="button"
          onClick={() => {
            setTab("events");
            setOffset(0);
          }}
        >
          {t("sess.events")}
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
            {t("common.status")}
            <select value={status} onChange={(e) => { setStatus(e.target.value); setOffset(0); }}>
              <option value="">{t("common.all")}</option>
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
              {t("common.type")}
              <select value={eventType} onChange={(e) => { setEventType(e.target.value); setOffset(0); }}>
                <option value="">forensic</option>
                <option value="sql">sql</option>
                <option value="sql_denied">sql_denied</option>
                <option value="k8s">k8s</option>
                <option value="command">command</option>
                <option value="command_denied">command_denied</option>
                <option value="command_approval">command_approval</option>
                <option value="command_approved">command_approved</option>
                <option value="output">output (SSH stdout)</option>
                <option value="keystroke">keystroke (RDP/VNC)</option>
                <option value="screen_text">screen_text (OCR RDP/VNC)</option>
                <option value="dlp">dlp</option>
                <option value="egress">egress</option>
                <option value="egress_denied">egress_denied</option>
                <option value="http_denied">http_denied</option>
                <option value="app_denied">app_denied</option>
                <option value="app_approval">app_approval</option>
                <option value="app_approved">app_approved</option>
                <option value="file_transfer">file_transfer</option>
                <option value="risk">risk</option>
                <option value="all">{t("sess.allTypes")}</option>
              </select>
            </label>
            <label>
              {t("sess.window")}
              <select value={hours} onChange={(e) => { setHours(Number(e.target.value)); setOffset(0); }}>
                <option value={24}>{t("sess.h24")}</option>
                <option value={72}>{t("sess.d3")}</option>
                <option value={168}>{t("sess.d7")}</option>
                <option value={720}>{t("sess.d30")}</option>
              </select>
            </label>
          </>
        ) : (
          <label>
            {t("common.protocol")}
            <select value={protocol} onChange={(e) => { setProtocol(e.target.value); setOffset(0); }}>
              <option value="">{t("common.all")}</option>
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
          {t("sess.search")}
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder={tab === "events" ? "SELECT / kubectl / rm -rf / notepad" : t("sess.searchHint")}
          />
        </label>
        <button className="btn secondary" type="submit">
          {t("common.find")}
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
          {t("common.reset")}
        </button>
      </form>

      {error && <p className="error">{error}</p>}
      {tab === "events" ? (
      <div className="card">
        <table>
          <thead>
            <tr>
              <th>{t("sess.time")}</th>
              <th>{t("common.type")}</th>
              <th>{t("sess.snippet")}</th>
              <th>{t("sess.whoWhere")}</th>
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
                      (e.protocol === "postgres" || e.protocol === "mysql" || e.protocol === "mssql" || e.protocol === "kubectl" ? (
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
                  {t("sess.noEvents")}
                </td>
              </tr>
            )}
          </tbody>
        </table>
        <div className="row" style={{ marginTop: "0.75rem", justifyContent: "space-between" }}>
          <span className="muted">
            {listTotal === 0 ? t("common.noRecords") : t("common.pageOf", { page, pages, total: listTotal })}
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
              <th>{t("sess.time")}</th>
              <th>{t("common.user")}</th>
              <th>{t("common.asset")}</th>
              <th>{t("common.account")}</th>
              <th>{t("common.protocol")}</th>
              <th>{t("common.status")}</th>
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
                  {s.waiting_supervisor && (
                    <span className="badge locked" style={{ marginLeft: 6 }} title={t("sess.fourEyes")}>
                      {t("sess.waitingBadge")}
                    </span>
                  )}
                  {s.break_glass && (
                    <span className="badge locked" style={{ marginLeft: 6 }} title="break-glass session">
                      glass
                    </span>
                  )}
                  {s.archived && (
                    <span className="badge" style={{ marginLeft: 6 }} title={s.archive_backend || "archive"}>
                      archive
                    </span>
                  )}
                  {s.supervisor_username && s.supervisor_approved_at && (
                    <div className="muted" style={{ fontSize: "0.8rem" }}>
                      {t("sess.supervisorBy", { name: s.supervisor_username })}
                    </div>
                  )}
                  {snapshotHint(s) && (
                    <div className="muted mono" style={{ fontSize: "0.8rem" }} title={t("sess.policyHint")}>
                      {snapshotHint(s)}
                    </div>
                  )}
                </td>
                <td>
                  <div className="row">
                    {s.waiting_supervisor && canSupervise && s.user_id !== user?.id && (
                      <>
                        <button className="btn" type="button" onClick={() => void onApproveSupervisor(s.id)}>
                          {t("common.allow")}
                        </button>
                        <button className="btn danger" type="button" onClick={() => void onDenySupervisor(s.id)}>
                          {t("common.deny")}
                        </button>
                      </>
                    )}
                    {s.waiting_supervisor && (
                      <button
                        className="btn danger"
                        type="button"
                        onClick={() => void onEnd(s.id)}
                      >
                        {t("common.end")}
                      </button>
                    )}
                    {(s.status === "active" || s.status === "pending") && !s.waiting_supervisor && (
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
                            : isSQLProtocol(s.protocol)
                              ? "SQL"
                              : s.protocol === "https"
                                ? "App"
                                : s.protocol === "kubectl"
                                  ? "kubectl"
                                  : "Terminal"}
                        </button>
                        {canWatch && (
                          <Link className="btn secondary" to={`/sessions/${s.id}/watch`}>
                            {t("common.watch")}
                          </Link>
                        )}
                        <button
                          className="btn danger"
                          type="button"
                          onClick={() => void onEnd(s.id)}
                        >
                          {t("common.end")}
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
                                {t("sess.download")}
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
                    ? t("sess.emptyLive")
                    : t("sess.emptyAll")}
                </td>
              </tr>
            )}
          </tbody>
        </table>
        <div className="row" style={{ marginTop: "0.75rem", justifyContent: "space-between" }}>
          <span className="muted">
            {listTotal === 0 ? t("common.noRecords") : t("common.pageOf", { page, pages, total: listTotal })}
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
