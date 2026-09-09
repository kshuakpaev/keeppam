import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import {
  api,
  hasPerm,
  isPamAdmin,
  type AnalyticsOverview,
  type AnalyticsSLO,
} from "../api";
import { useAuth } from "../auth";
import { useI18n } from "../i18n";

const PROTO_COLORS = ["#3d7ea6", "#2f6f4e", "#8b6a2a", "#6b4c9a", "#8b3a3a", "#3d6b6b", "#5c5c5c"];

export function HomePage() {
  const { user } = useAuth();
  const { t, te } = useI18n();
  const admin = isPamAdmin(user);
  const canAnalytics = admin && hasPerm(user, "audit.read");
  const [data, setData] = useState<AnalyticsOverview | null>(null);
  const [slo, setSlo] = useState<AnalyticsSLO | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!canAnalytics) return;
    let cancelled = false;
    setLoading(true);
    setError("");
    void Promise.all([api.getAnalyticsOverview(24), api.getAnalyticsSLO()])
      .then(([overview, sloRes]) => {
        if (cancelled) return;
        setData(overview);
        setSlo(sloRes);
      })
      .catch((err) => {
        if (!cancelled) setError(te(err, "analytics.loadError"));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [canAnalytics, te]);

  if (!admin) {
    return (
      <div>
        <h1>{t("nav.overview")}</h1>
        <p className="muted">{t("home.operatorLead")}</p>
        <div className="card" style={{ marginTop: "1rem" }}>
          <p>
            <strong>{user?.display_name || user?.username}</strong>
            {user?.email ? ` · ${user.email}` : ""}
          </p>
          <p className="muted">{t("home.sessionActive", { roles: (user?.roles || []).join(", ") || "—" })}</p>
        </div>
        <p className="row gap" style={{ marginTop: "1rem" }}>
          {hasPerm(user, "assets.read") && (
            <Link className="btn" to="/assets">
              {t("nav.assets")}
            </Link>
          )}
          {hasPerm(user, "sessions.read") && (
            <Link className="btn secondary" to="/sessions">
              {t("nav.sessions")}
            </Link>
          )}
        </p>
      </div>
    );
  }

  const stats = data?.stats;
  const anomalies = (data?.anomalies || []).slice(0, 6);
  const actions = (data?.series.actions_by_type || []).slice(0, 8);
  const maxAction = Math.max(1, ...actions.map((a) => a.count));

  return (
    <div className="home-dash">
      <div className="page-head">
        <div>
          <h1>{t("nav.overview")}</h1>
          <p className="muted">{t("home.adminLead")}</p>
        </div>
        {canAnalytics && (
          <div className="row gap">
            <Link className="btn secondary" to="/analytics">
              {t("home.openAnalytics")}
            </Link>
          </div>
        )}
      </div>

      {!canAnalytics && <p className="muted">{t("home.adminNoAudit")}</p>}
      {error && <p className="error">{error}</p>}
      {loading && !data && <p className="muted">{t("common.loading")}</p>}

      {slo && (
        <p className="muted" style={{ marginBottom: "0.75rem" }}>
          <span className={`badge sev-${slo.breached ? "high" : "low"}`}>{slo.breached ? "SLO" : "SLO ok"}</span>
          {slo.breached ? ` ${t("home.sloBreached")}` : ` ${t("home.sloOk")}`}
          {data?.siem && !data.siem.healthy ? ` · SIEM: ${data.siem.detail}` : ""}
        </p>
      )}

      {stats && (
        <div className="stats-grid">
          <Stat label={t("home.activeSessions")} value={stats.sessions_active} />
          <Stat label={t("analytics.statSessionsStarted")} value={stats.sessions_started} />
          <Stat label={t("home.failedLogins")} value={stats.logins_fail} warn={stats.logins_fail > 0} />
          <Stat label={t("analytics.statLoginsOk")} value={stats.logins_ok} />
          <Stat label={t("analytics.statSessionsDenied")} value={stats.sessions_denied} warn={stats.sessions_denied > 0} />
          <Stat label={t("home.anomalies")} value={data?.anomalies.length || 0} warn={(data?.anomalies.length || 0) > 0} />
          <Stat label={t("analytics.statOffHours")} value={stats.off_hours_sessions} warn={stats.off_hours_sessions > 0} />
          <Stat label={t("analytics.statJitRequests")} value={stats.jit_requests} />
        </div>
      )}

      {data && (
        <>
          <div className="two-col" style={{ marginTop: "1.25rem" }}>
            <section className="card">
              <h2>{t("analytics.loginsByHour")}</h2>
              <LoginChart points={data.series.logins_by_hour} empty={t("analytics.noData")} />
            </section>
            <section className="card">
              <h2>{t("analytics.sessionsByProtocol")}</h2>
              <ProtocolChart
                rows={data.series.sessions_by_protocol}
                empty={t("analytics.noData")}
              />
            </section>
          </div>

          <div className="two-col" style={{ marginTop: "1.25rem" }}>
            <section className="card">
              <h2>{t("analytics.topAuditActions")}</h2>
              {actions.length === 0 ? (
                <p className="muted">{t("analytics.noData")}</p>
              ) : (
                <ul className="bar-list">
                  {actions.map((p) => (
                    <li key={p.name}>
                      <span className="mono bar-label" title={p.name}>
                        {p.name}
                      </span>
                      <div className="bar-track">
                        <div className="bar-fill" style={{ width: `${(p.count / maxAction) * 100}%` }} />
                      </div>
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
                  {(data.top_actors || []).slice(0, 6).map((a) => (
                    <li key={a.name}>
                      <span>{a.name}</span>
                      <strong>{a.count}</strong>
                    </li>
                  ))}
                </ul>
                <ul className="plain-list">
                  {(data.top_assets || []).slice(0, 6).map((a) => (
                    <li key={a.name}>
                      <span>{a.name}</span>
                      <strong>{a.count}</strong>
                    </li>
                  ))}
                </ul>
              </div>
            </section>
          </div>

          <section className="card" style={{ marginTop: "1.25rem" }}>
            <h2>{t("analytics.anomalies")}</h2>
            {anomalies.length === 0 ? (
              <p className="muted">{t("analytics.noAnomalies", { hours: data.window_hours })}</p>
            ) : (
              <ul className="anomaly-list">
                {anomalies.map((a) => (
                  <li key={`${a.code}-${a.actor || ""}-${a.detail}`}>
                    <div>
                      <strong>{a.title}</strong>
                      <span className={`badge sev-${a.severity}`}>{a.severity}</span>
                      <span className="badge">{a.code}</span>
                    </div>
                    <p className="muted">
                      {a.detail}
                      {a.actor ? t("analytics.actorLabel", { actor: a.actor }) : ""}
                    </p>
                  </li>
                ))}
              </ul>
            )}
          </section>

          <p className="muted" style={{ marginTop: "1rem" }}>
            {t("analytics.generatedAt", { at: new Date(data.generated_at).toLocaleString() })}
            {" · "}
            <Link to="/sessions">{t("nav.sessions")}</Link>
            {" · "}
            <Link to="/audit">{t("nav.audit")}</Link>
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

function LoginChart({
  points,
  empty,
}: {
  points: { hour: string; ok: number; fail: number }[];
  empty: string;
}) {
  const { t } = useI18n();
  const series = useMemo(() => points.slice(-24), [points]);
  if (series.length === 0) {
    return <p className="muted">{empty}</p>;
  }
  const w = 520;
  const h = 160;
  const padL = 8;
  const padR = 8;
  const padT = 12;
  const padB = 22;
  const max = Math.max(1, ...series.flatMap((p) => [p.ok, p.fail, p.ok + p.fail]));
  const n = series.length;
  const xAt = (i: number) => padL + (i / Math.max(1, n - 1)) * (w - padL - padR);
  const yAt = (v: number) => padT + (1 - v / max) * (h - padT - padB);
  const line = (key: "ok" | "fail") =>
    series.map((p, i) => `${i === 0 ? "M" : "L"}${xAt(i).toFixed(1)},${yAt(p[key]).toFixed(1)}`).join(" ");
  const areaOk = `${line("ok")} L${xAt(n - 1).toFixed(1)},${yAt(0).toFixed(1)} L${xAt(0).toFixed(1)},${yAt(0).toFixed(1)} Z`;
  const last = series[series.length - 1];
  const firstLabel = new Date(series[0].hour).toLocaleString(undefined, { hour: "2-digit", day: "numeric", month: "short" });
  const lastLabel = new Date(last.hour).toLocaleString(undefined, { hour: "2-digit", day: "numeric", month: "short" });

  return (
    <div>
      <svg className="dash-chart" viewBox={`0 0 ${w} ${h}`} role="img" aria-label={t("analytics.loginsByHour")}>
        <path d={areaOk} fill="#2f6f4e" opacity="0.22" />
        <path d={line("ok")} fill="none" stroke="#3d9a68" strokeWidth="2" />
        <path d={line("fail")} fill="none" stroke="#c45c5c" strokeWidth="2" />
        <text x={padL} y={h - 6} className="dash-chart-axis">
          {firstLabel}
        </text>
        <text x={w - padR} y={h - 6} textAnchor="end" className="dash-chart-axis">
          {lastLabel}
        </text>
      </svg>
      <p className="muted dash-legend">
        <span className="legend-swatch ok" /> {t("analytics.statLoginsOk")}
        {" · "}
        <span className="legend-swatch fail" /> {t("analytics.statLoginsFail")}
        {" · "}
        {last.ok}/{last.fail}
      </p>
    </div>
  );
}

function ProtocolChart({
  rows,
  empty,
}: {
  rows: { name: string; count: number }[];
  empty: string;
}) {
  const total = rows.reduce((s, r) => s + r.count, 0);
  if (rows.length === 0 || total === 0) {
    return <p className="muted">{empty}</p>;
  }
  let acc = 0;
  const stops = rows.map((r, i) => {
    const start = acc;
    acc += (r.count / total) * 100;
    return `${PROTO_COLORS[i % PROTO_COLORS.length]} ${start.toFixed(2)}% ${acc.toFixed(2)}%`;
  });
  return (
    <div>
      <div className="proto-donut-wrap">
        <div className="proto-donut" style={{ background: `conic-gradient(${stops.join(", ")})` }} />
        <div className="proto-donut-center">
          <strong>{total}</strong>
        </div>
      </div>
      <ul className="plain-list">
        {rows.map((p, i) => (
          <li key={p.name}>
            <span>
              <span className="legend-swatch" style={{ background: PROTO_COLORS[i % PROTO_COLORS.length] }} />{" "}
              <span className="mono">{p.name}</span>
            </span>
            <strong>
              {p.count}{" "}
              <span className="muted">{Math.round((p.count / total) * 100)}%</span>
            </strong>
          </li>
        ))}
      </ul>
    </div>
  );
}
