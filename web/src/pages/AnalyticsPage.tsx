import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, hasPerm, type AnalyticsOverview, type AnalyticsSLO } from "../api";
import { useAuth } from "../auth";

const WINDOWS = [24, 72, 168] as const;
const SEVS = ["", "high", "medium", "low"] as const;

export function AnalyticsPage() {
  const { user } = useAuth();
  const canRead = hasPerm(user, "audit.read");
  const [hours, setHours] = useState<(typeof WINDOWS)[number]>(24);
  const [severity, setSeverity] = useState<(typeof SEVS)[number]>("");
  const [data, setData] = useState<AnalyticsOverview | null>(null);
  const [slo, setSlo] = useState<AnalyticsSLO | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

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
      setError(err instanceof Error ? err.message : "Ошибка загрузки");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    if (!canRead) return;
    void load(hours, severity);
  }, [canRead, hours, severity]);

  if (!canRead) {
    return <p className="error">Недостаточно прав</p>;
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
          <h1>Аналитика</h1>
          <p className="muted">SLO, аномалии, SIEM-корреляция и цепочки сигналов</p>
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
              {h === 168 ? "7д" : `${h}ч`}
            </button>
          ))}
          <select
            value={severity}
            onChange={(e) => setSeverity(e.target.value as (typeof SEVS)[number])}
            style={{ marginBottom: 0, width: "auto" }}
          >
            <option value="">Все severity</option>
            <option value="high">high</option>
            <option value="medium">medium</option>
            <option value="low">low</option>
          </select>
          <button type="button" className="btn secondary" onClick={() => void load(hours, severity)} disabled={loading}>
            Обновить
          </button>
        </div>
      </div>

      {error && <p className="error">{error}</p>}
      {loading && !data && <p className="muted">Загрузка…</p>}

      {data && stats && (
        <>
          {slo && (
            <section className={`card${slo.breached ? " warn" : ""}`} style={{ marginBottom: "1.25rem" }}>
              <h2>SLO</h2>
              <p>
                <span className={`badge sev-${slo.breached ? "high" : "low"}`}>
                  {slo.breached ? "breached" : "ok"}
                </span>{" "}
                цели: auth p95 &lt; {fmtSec(slo.targets.auth_p95_seconds)} · session setup p95 &lt;{" "}
                {fmtSec(slo.targets.session_setup_p95_seconds)} · audit lag &lt; {slo.targets.audit_lag_seconds}s
              </p>
              <div className="stats-grid" style={{ marginTop: "0.75rem" }}>
                <Stat
                  label={`Auth p95 (${slo.auth_samples})`}
                  value={slo.auth_p95_seconds == null ? "—" : fmtSec(slo.auth_p95_seconds)}
                  warn={!!slo.auth_burn && slo.auth_burn > 1}
                />
                <Stat
                  label={`Session setup p95 (${slo.session_setup_samples})`}
                  value={
                    slo.session_setup_p95_seconds == null ? "—" : fmtSec(slo.session_setup_p95_seconds)
                  }
                  warn={!!slo.session_setup_burn && slo.session_setup_burn > 1}
                />
                <Stat label="Активные сессии" value={slo.active_sessions} />
                <Stat
                  label={slo.siem_enabled ? `Audit lag (pending ${slo.audit_pending})` : "Audit lag (SIEM off)"}
                  value={
                    slo.audit_export_lag_seconds == null ? "—" : `${slo.audit_export_lag_seconds}s`
                  }
                  warn={!!slo.audit_lag_burn && slo.audit_lag_burn > 1}
                />
              </div>
              <p className="muted" style={{ marginTop: "0.5rem" }}>
                Prometheus: <span className="mono">GET /metrics</span>
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
                pending={data.siem.pending_events}
                {data.siem.lag_seconds != null && <> · lag={data.siem.lag_seconds}s</>}
                {data.siem.last_export_at && <> · last export {new Date(data.siem.last_export_at).toLocaleString()}</>}
                {data.siem.last_error && <> · error: {data.siem.last_error}</>}
                {" · "}
                <Link to="/config">настройки</Link>
              </p>
            </section>
          )}

          <div className="stats-grid">
            <Stat label="Входы OK" value={stats.logins_ok} />
            <Stat label="Входы fail" value={stats.logins_fail} warn={stats.logins_fail > 0} />
            <Stat label="Сессии стартовали" value={stats.sessions_started} />
            <Stat label="Активные сейчас" value={stats.sessions_active} />
            <Stat label="Отказы политики" value={stats.sessions_denied} warn={stats.sessions_denied > 0} />
            <Stat label="JIT-запросы" value={stats.jit_requests} />
            <Stat label="Ротации секретов" value={stats.secret_rotations} />
            <Stat label="Ночные сессии" value={stats.off_hours_sessions} warn={stats.off_hours_sessions > 0} />
            <Stat label="Долгие >4ч" value={stats.long_sessions} warn={stats.long_sessions > 0} />
            <Stat label="Force-kill" value={stats.force_kills} warn={stats.force_kills > 0} />
            <Stat label="App access" value={stats.app_access} />
            <Stat label="SQL statements" value={stats.sql_statements} />
          </div>

          <section className="card" style={{ marginTop: "1.25rem" }}>
            <h2>Аномалии</h2>
            {data.anomalies.length === 0 ? (
              <p className="muted">За окно {data.window_hours} ч сигналов нет</p>
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
                      {a.actor && <> · actor={a.actor}</>}
                    </p>
                  </li>
                ))}
              </ul>
            )}
          </section>

          <section className="card" style={{ marginTop: "1.25rem" }}>
            <h2>Корреляционные цепочки</h2>
            {data.chains.length === 0 ? (
              <p className="muted">Связанных цепочек не обнаружено</p>
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
              <h2>Входы по часам</h2>
              {data.series.logins_by_hour.length === 0 ? (
                <p className="muted">Нет данных</p>
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
              <h2>Топ audit actions</h2>
              {(data.series.actions_by_type || []).length === 0 ? (
                <p className="muted">Нет данных</p>
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
              <h2>Сессии по протоколам</h2>
              {data.series.sessions_by_protocol.length === 0 ? (
                <p className="muted">Нет данных</p>
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
              <h2>Топ пользователей / активов</h2>
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
            Сгенерировано {new Date(data.generated_at).toLocaleString()} ·{" "}
            <Link to="/audit">аудит</Link> · <Link to="/compliance">compliance</Link>
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
