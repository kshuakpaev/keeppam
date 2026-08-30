import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, hasPerm, type AnalyticsOverview, type AnalyticsSLO } from "../api";
import { useAuth } from "../auth";
import { useI18n } from "../i18n";

const WINDOWS = [24, 72, 168] as const;
const SEVS = ["", "high", "medium", "low"] as const;

export function AnalyticsPage() {
  const { user } = useAuth();
  const { t, te } = useI18n();
  const canRead = hasPerm(user, "audit.read");
  const [hours, setHours] = useState<(typeof WINDOWS)[number]>(24);
  const [severity, setSeverity] = useState<(typeof SEVS)[number]>("");
  const [data, setData] = useState<AnalyticsOverview | null>(null);
  const [slo, setSlo] = useState<AnalyticsSLO | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [risks, setRisks] = useState<Record<string, string>>({});

  async function load(h: number, sev: string) {
    setLoading(true);
    setError("");
    try {
      const [res, sloRes] = await Promise.all([
        api.getAnalyticsOverview(h, { severity: sev || undefined }),
        api.getAnalyticsSLO(),
      ]);
      setData(res);
      setSlo(sloRes);
    } catch (err) {
      setError(te(err, "analytics.loadError"));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    if (!canRead) return;
    void load(hours, severity);
  }, [canRead, hours, severity]);

  if (!canRead) {
    return <p className="error">{t("common.forbidden")}</p>;
  }

  const stats = data?.stats;
  const maxLogin = Math.max(
    1,
    ...(data?.series.logins_by_hour || []).flatMap((b) => [b.ok, b.fail]),
  );

  return (
    <div>
      <div className="page-head">
        <div>
          <h1>{t("nav.analytics")}</h1>
          <p className="muted">{t("analytics.lead")}</p>
        </div>
        <div className="row gap">
          {WINDOWS.map((h) => (
            <button
              key={h}
              type="button"
              className={`btn secondary${hours === h ? " active-window" : ""}`}
              onClick={() => setHours(h)}
              disabled={loading}
            >
              {h === 168 ? t("analytics.window7d") : t("analytics.windowHours", { h })}
            </button>
          ))}
          <select
            value={severity}
            onChange={(e) => setSeverity(e.target.value as (typeof SEVS)[number])}
            style={{ marginBottom: 0, width: "auto" }}
          >
            <option value="">{t("analytics.allSeverity")}</option>
            <option value="high">high</option>
            <option value="medium">medium</option>
            <option value="low">low</option>
          </select>
          <button type="button" className="btn secondary" onClick={() => void load(hours, severity)} disabled={loading}>
            {t("common.refresh")}
          </button>
        </div>
      </div>

      {error && <p className="error">{error}</p>}
      {loading && !data && <p className="muted">{t("common.loading")}</p>}

      {data && stats && (
        <>
          {slo && (
            <section className={`card${slo.breached ? " warn" : ""}`} style={{ marginBottom: "1.25rem" }}>
              <h2>SLO</h2>
              <p>
                <span className={`badge sev-${slo.breached ? "high" : "low"}`}>
                  {slo.breached ? "breached" : "ok"}
                </span>{" "}
                {t("analytics.sloTargets", {
                  authP95: fmtSec(slo.targets.auth_p95_seconds),
                  sessionP95: fmtSec(slo.targets.session_setup_p95_seconds),
                  auditLag: slo.targets.audit_lag_seconds,
                })}
              </p>
              <div className="stats-grid" style={{ marginTop: "0.75rem" }}>
                <Stat
                  label={t("analytics.statAuthP95", { samples: slo.auth_samples })}
                  value={slo.auth_p95_seconds == null ? "—" : fmtSec(slo.auth_p95_seconds)}
                  warn={!!slo.auth_burn && slo.auth_burn > 1}
                />
                <Stat
                  label={t("analytics.statSessionP95", { samples: slo.session_setup_samples })}
                  value={
                    slo.session_setup_p95_seconds == null ? "—" : fmtSec(slo.session_setup_p95_seconds)
                  }
                  warn={!!slo.session_setup_burn && slo.session_setup_burn > 1}
                />
                <Stat label={t("analytics.statActiveSessions")} value={slo.active_sessions} />
                <Stat
                  label={
                    slo.siem_enabled
                      ? t("analytics.statAuditLagPending", { pending: slo.audit_pending })
                      : t("analytics.statAuditLagOff")
                  }
                  value={
                    slo.audit_export_lag_seconds == null ? "—" : `${slo.audit_export_lag_seconds}s`
                  }
                  warn={!!slo.audit_lag_burn && slo.audit_lag_burn > 1}
                />
              </div>
              <p className="muted" style={{ marginTop: "0.5rem" }}>
                Prometheus: <a href="http://localhost:9090" target="_blank" rel="noreferrer">:9090</a>
                {" · "}
                Grafana:{" "}
                <a href="http://localhost:3001/d/keeppam-slo" target="_blank" rel="noreferrer">
                  KeepPAM SLO
                </a>
                {" · "}
                Alertmanager: <a href="http://localhost:9093" target="_blank" rel="noreferrer">:9093</a>
                {" · "}
                Tempo:{" "}
                <a
                  href="http://localhost:3001/explore?orgId=1&left=%7B%22datasource%22:%22keeppam-tempo%22%7D"
                  target="_blank"
                  rel="noreferrer"
                >
                  traces
                </a>
                {" · "}
                scrape <span className="mono">GET /metrics</span>
              </p>
            </section>
          )}
          {data.siem && (
            <section className={`card${data.siem.healthy ? "" : " warn"}`} style={{ marginBottom: "1.25rem" }}>
              <h2>SIEM</h2>
              <p>
                <span className={`badge sev-${data.siem.healthy ? "low" : "high"}`}>
                  {data.siem.healthy ? "healthy" : "degraded"}
                </span>{" "}
                {data.siem.enabled ? data.siem.transport : "off"} · {data.siem.detail}
              </p>
              <p className="muted">
                {t("analytics.siemPending", { pending: data.siem.pending_events })}
                {data.siem.lag_seconds != null && t("analytics.siemLag", { lag: data.siem.lag_seconds })}
                {data.siem.last_export_at &&
                  t("analytics.siemLastExport", { at: new Date(data.siem.last_export_at).toLocaleString() })}
                {data.siem.last_error && t("analytics.siemError", { error: data.siem.last_error })}
                {" · "}
                <Link to="/config">{t("analytics.settingsLink")}</Link>
              </p>
            </section>
          )}

          <div className="stats-grid">
            <Stat label={t("analytics.statLoginsOk")} value={stats.logins_ok} />
            <Stat label={t("analytics.statLoginsFail")} value={stats.logins_fail} warn={stats.logins_fail > 0} />
            <Stat label={t("analytics.statSessionsStarted")} value={stats.sessions_started} />
            <Stat label={t("analytics.statSessionsActive")} value={stats.sessions_active} />
            <Stat label={t("analytics.statSessionsDenied")} value={stats.sessions_denied} warn={stats.sessions_denied > 0} />
            <Stat label={t("analytics.statJitRequests")} value={stats.jit_requests} />
            <Stat label={t("analytics.statSecretRotations")} value={stats.secret_rotations} />
            <Stat label={t("analytics.statOffHours")} value={stats.off_hours_sessions} warn={stats.off_hours_sessions > 0} />
            <Stat label={t("analytics.statLongSessions")} value={stats.long_sessions} warn={stats.long_sessions > 0} />
            <Stat label={t("analytics.statForceKills")} value={stats.force_kills} warn={stats.force_kills > 0} />
            <Stat label={t("analytics.statAppAccess")} value={stats.app_access} />
            <Stat label={t("analytics.statSqlStatements")} value={stats.sql_statements} />
          </div>

          <section className="card" style={{ marginTop: "1.25rem" }}>
            <h2>{t("analytics.anomalies")}</h2>
            {data.anomalies.length === 0 ? (
              <p className="muted">{t("analytics.noAnomalies", { hours: data.window_hours })}</p>
            ) : (
              <ul className="anomaly-list">
                {data.anomalies.map((a) => (
                  <li key={`${a.code}-${a.actor || ""}-${a.detail}`} className={`anomaly ${a.severity}`}>
                    <div>
                      <strong>{a.title}</strong>
                      <span className={`badge sev-${a.severity}`}>{a.severity}</span>
                      <span className="badge">{a.code}</span>
                    </div>
                    <p className="muted">
                      {a.detail}
                      {a.actor && t("analytics.actorLabel", { actor: a.actor })}
                    </p>
                    {a.related && /^[0-9a-f-]{36}$/i.test(a.related) ? (
                      <p>
                        <button
                          className="btn secondary"
                          type="button"
                          onClick={() =>
                            void api
                              .getSessionAIRisk(a.related as string)
                              .then((r) => setRisks((m) => ({ ...m, [a.related as string]: r.text })))
                              .catch(() =>
                                setRisks((m) => ({
                                  ...m,
                                  [a.related as string]: t("analytics.aiRisk"),
                                })),
                              )
                          }
                        >
                          {t("analytics.aiRisk")}
                        </button>
                        {risks[a.related] ? <span className="muted"> {risks[a.related]}</span> : null}
                      </p>
                    ) : null}
                  </li>
                ))}
              </ul>
            )}
          </section>

          <section className="card" style={{ marginTop: "1.25rem" }}>
            <h2>{t("analytics.uebaTitle")}</h2>
            <p className="muted">{t("analytics.uebaHint")}</p>
            {(data.ueba || []).length === 0 ? (
              <p className="muted">{t("analytics.noUeba", { hours: data.window_hours })}</p>
            ) : (
              <ul className="plain-list">
                {(data.ueba || []).map((u) => (
                  <li key={u.actor}>
                    <span>
                      {u.actor}
                      {u.spread ? <span className="badge sev-high">spread</span> : <span className="badge sev-medium">new</span>}
                      <span className="muted">
                        {" "}
                        {t("analytics.uebaBaseline", {
                          baseline: u.baseline,
                          recent: u.recent_distinct,
                          new: u.new_assets,
                        })}
                        {u.new_names && u.new_names.length > 0 ? ` (${u.new_names.join(", ")})` : ""}
                      </span>
                    </span>
                    <strong>{u.new_assets}</strong>
                  </li>
                ))}
              </ul>
            )}
          </section>

          <section className="card" style={{ marginTop: "1.25rem" }}>
            <h2>{t("analytics.chainsTitle")}</h2>
            {data.chains.length === 0 ? (
              <p className="muted">{t("analytics.noChains")}</p>
            ) : (
              <ul className="anomaly-list">
                {data.chains.map((c) => (
                  <li key={`${c.title}-${c.actor || ""}`} className={`anomaly ${c.severity}`}>
                    <div>
                      <strong>{c.title}</strong>
                      <span className={`badge sev-${c.severity}`}>{c.severity}</span>
                    </div>
                    <p className="muted">{c.detail}</p>
                    <p className="mono muted" style={{ fontSize: "0.8rem" }}>
                      {(c.steps || []).join(" → ")}
                    </p>
                  </li>
                ))}
              </ul>
            )}
          </section>

          <div className="two-col" style={{ marginTop: "1.25rem" }}>
            <section className="card">
              <h2>{t("analytics.loginsByHour")}</h2>
              {data.series.logins_by_hour.length === 0 ? (
                <p className="muted">{t("analytics.noData")}</p>
              ) : (
                <div className="spark-rows">
                  {data.series.logins_by_hour.map((b) => (
                    <div key={b.hour} className="spark-row">
                      <span className="mono muted spark-label">
                        {new Date(b.hour).toLocaleString(undefined, {
                          month: "short",
                          day: "numeric",
                          hour: "2-digit",
                        })}
                      </span>
                      <div className="spark-bars">
                        <div className="spark ok" style={{ width: `${(b.ok / maxLogin) * 100}%` }} title={`OK: ${b.ok}`} />
                        <div
                          className="spark fail"
                          style={{ width: `${(b.fail / maxLogin) * 100}%` }}
                          title={`Fail: ${b.fail}`}
                        />
                      </div>
                      <span className="mono muted">
                        {b.ok}/{b.fail}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </section>

            <section className="card">
              <h2>{t("analytics.topAuditActions")}</h2>
              {(data.series.actions_by_type || []).length === 0 ? (
                <p className="muted">{t("analytics.noData")}</p>
              ) : (
                <ul className="plain-list">
                  {data.series.actions_by_type.map((p) => (
                    <li key={p.name}>
                      <span className="mono">{p.name}</span>
                      <strong>{p.count}</strong>
                    </li>
                  ))}
                </ul>
              )}
            </section>
          </div>

          <div className="two-col" style={{ marginTop: "1.25rem" }}>
            <section className="card">
              <h2>{t("analytics.sessionsByProtocol")}</h2>
              {data.series.sessions_by_protocol.length === 0 ? (
                <p className="muted">{t("analytics.noData")}</p>
              ) : (
                <ul className="plain-list">
                  {data.series.sessions_by_protocol.map((p) => (
                    <li key={p.name}>
                      <span className="mono">{p.name}</span>
                      <strong>{p.count}</strong>
                    </li>
                  ))}
                </ul>
              )}
            </section>
            <section className="card">
              <h2>{t("analytics.topUsersAssets")}</h2>
              <div className="two-col">
                <ul className="plain-list">
                  {data.top_actors.map((a) => (
                    <li key={a.name}>
                      <span>{a.name}</span>
                      <strong>{a.count}</strong>
                    </li>
                  ))}
                </ul>
                <ul className="plain-list">
                  {data.top_assets.map((a) => (
                    <li key={a.name}>
                      <span>{a.name}</span>
                      <strong>{a.count}</strong>
                    </li>
                  ))}
                </ul>
              </div>
            </section>
          </div>

          <p className="muted" style={{ marginTop: "1rem" }}>
            {t("analytics.generatedAt", { at: new Date(data.generated_at).toLocaleString() })}
            {" · "}
            <Link to="/audit">{t("nav.audit")}</Link>
            {" · "}
            <Link to="/compliance">{t("nav.compliance")}</Link>
          </p>
        </>
      )}
    </div>
  );
}

function Stat({ label, value, warn }: { label: string; value: number | string; warn?: boolean }) {
  return (
    <div className={`card stat-card${warn ? " warn" : ""}`}>
      <div className="stat-value">{value}</div>
      <div className="muted">{label}</div>
    </div>
  );
}

function fmtSec(v: number) {
  if (v < 1) return `${Math.round(v * 1000)}ms`;
  return `${v.toFixed(2)}s`;
}
