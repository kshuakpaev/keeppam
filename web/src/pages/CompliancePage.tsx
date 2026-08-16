import { useEffect, useState, type FormEvent } from "react";
import {
  api,
  hasPerm,
  type CompliancePack,
  type ComplianceReport,
  type ComplianceStatus,
  type DRSettings,
  type DRStatus,
  type LegalHold,
  type RetentionPolicy,
} from "../api";
import { useAuth } from "../auth";

function pad(n: number) {
  return String(n).padStart(2, "0");
}

function isoDate(d: Date) {
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

const SUMMARY_LABELS: { key: keyof ComplianceReport["summary"]; label: string }[] = [
  { key: "access", label: "Доступ" },
  { key: "privileged", label: "Privileged" },
  { key: "approvals", label: "Согласования" },
  { key: "connections", label: "Подключения" },
  { key: "commands", label: "Команды" },
  { key: "sql", label: "SQL" },
  { key: "downloads", label: "Скачивания" },
  { key: "changes", label: "Изменения" },
  { key: "revoked", label: "Отозван" },
];

const CAT_LABELS: Record<string, string> = {
  access: "Доступ",
  privileged: "Privileged",
  approvals: "Согласования",
  connections: "Подключения",
  commands: "Команды",
  sql: "SQL",
  downloads: "Скачивания",
  changes: "Изменения",
  revoked: "Отозван",
};

export function CompliancePage() {
  const { user } = useAuth();
  const canRead = hasPerm(user, "compliance.read");
  const canWrite = hasPerm(user, "compliance.write");
  const [status, setStatus] = useState<ComplianceStatus | null>(null);
  const [packs, setPacks] = useState<CompliancePack[]>([]);
  const [holds, setHolds] = useState<LegalHold[]>([]);
  const [retention, setRetention] = useState<RetentionPolicy | null>(null);
  const [dr, setDr] = useState<DRStatus | null>(null);
  const [drForm, setDrForm] = useState<DRSettings | null>(null);
  const [drillNotes, setDrillNotes] = useState("");
  const [error, setError] = useState("");
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState(false);
  const [holdForm, setHoldForm] = useState({
    resource_type: "session",
    resource_id: "",
    reason: "",
  });
  const [reportFrom, setReportFrom] = useState(() => {
    const d = new Date();
    d.setDate(d.getDate() - 30);
    return isoDate(d);
  });
  const [reportTo, setReportTo] = useState(() => isoDate(new Date()));
  const [reportFw, setReportFw] = useState("all");
  const [report, setReport] = useState<ComplianceReport | null>(null);

  async function load() {
    setError("");
    try {
      const [st, pk, ret, hd, drSt] = await Promise.all([
        api.getComplianceStatus(),
        api.listCompliancePacks(),
        api.getRetention(),
        api.listLegalHolds(true),
        api.getDRStatus(),
      ]);
      setStatus(st);
      setPacks(pk.packs || []);
      setRetention(ret);
      setHolds(hd.holds || []);
      setDr(drSt);
      setDrForm(drSt.settings);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка загрузки");
    }
  }

  useEffect(() => {
    if (!canRead) return;
    void load();
  }, [canRead]);

  if (!canRead) {
    return <p className="error">Недостаточно прав</p>;
  }

  async function applyPack(id: string) {
    if (!canWrite) return;
    setBusy(true);
    setError("");
    setMsg("");
    try {
      await api.applyCompliancePack(id);
      setMsg(`Пакет ${id} применён`);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка apply");
    } finally {
      setBusy(false);
    }
  }

  async function saveRetention(e: FormEvent) {
    e.preventDefault();
    if (!canWrite || !retention) return;
    setBusy(true);
    setError("");
    setMsg("");
    try {
      const updated = await api.putRetention({
        audit_retention_days: retention.audit_retention_days,
        session_retention_days: retention.session_retention_days,
        recording_retention_days: retention.recording_retention_days,
        purge_enabled: retention.purge_enabled,
      });
      setRetention(updated);
      setMsg("Retention сохранён");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка retention");
    } finally {
      setBusy(false);
    }
  }

  async function createHold(e: FormEvent) {
    e.preventDefault();
    if (!canWrite) return;
    setBusy(true);
    setError("");
    try {
      await api.createLegalHold(holdForm);
      setHoldForm({ resource_type: "session", resource_id: "", reason: "" });
      setMsg("Legal hold создан");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка hold");
    } finally {
      setBusy(false);
    }
  }

  async function releaseHold(id: string) {
    if (!canWrite) return;
    setBusy(true);
    try {
      await api.releaseLegalHold(id);
      setMsg("Hold снят");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка release");
    } finally {
      setBusy(false);
    }
  }

  async function runPurge() {
    if (!canWrite) return;
    setBusy(true);
    setError("");
    try {
      const st = await api.runCompliancePurge();
      setMsg(
        `Purge: recordings=${st.recordings_removed}, sessions=${st.sessions_purged}, skipped=${st.skipped_holds}. ${st.audit_note || ""}`,
      );
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка purge");
    } finally {
      setBusy(false);
    }
  }

  async function loadReport(e?: FormEvent) {
    e?.preventDefault();
    setBusy(true);
    setError("");
    try {
      const r = await api.getComplianceReport({
        from: reportFrom,
        to: reportTo,
        framework: reportFw,
        limit: 200,
      });
      setReport(r);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка отчёта");
    } finally {
      setBusy(false);
    }
  }

  async function downloadReportCsv() {
    setError("");
    try {
      await api.downloadComplianceReportCsv({
        from: reportFrom,
        to: reportTo,
        framework: reportFw,
        limit: 500,
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка CSV");
    }
  }

  return (
    <div>
      <div className="page-head">
        <div>
          <h1>Compliance</h1>
          <p className="muted">Отчёт за период, пакеты контролей, retention и legal hold</p>
        </div>
        <div className="row gap">
          <button className="btn secondary" type="button" disabled={busy} onClick={() => void load()}>
            Обновить
          </button>
          {canWrite && (
            <button className="btn secondary" type="button" disabled={busy} onClick={() => void runPurge()}>
              Запустить purge
            </button>
          )}
        </div>
      </div>

      {error && <p className="error">{error}</p>}
      {msg && <p className="ok">{msg}</p>}

      {status && (
        <section className="card" style={{ marginBottom: "1.25rem" }}>
          <h2>Статус контролей</h2>
          <p className="muted">
            Активный пакет: <strong>{status.active_pack_id || "—"}</strong>
            {status.applied_at && <> · применён {new Date(status.applied_at).toLocaleString()}</>}
            {status.last_purge_at && <> · последний purge {new Date(status.last_purge_at).toLocaleString()}</>}
          </p>
          <p>
            <button
              className="btn secondary"
              type="button"
              onClick={() =>
                void api.downloadSBOM().catch((e) => setError(e instanceof Error ? e.message : "SBOM"))
              }
            >
              Скачать SBOM (CycloneDX)
            </button>
          </p>
          <ul className="anomaly-list">
            {status.controls.map((c) => (
              <li key={c.id} className={`anomaly ${c.status === "pass" ? "low" : c.status === "warn" ? "medium" : "high"}`}>
                <div>
                  <strong>{c.title}</strong>
                  <span className={`badge sev-${c.status === "pass" ? "low" : c.status === "warn" ? "medium" : "high"}`}>
                    {c.status}
                  </span>
                </div>
                <p className="muted">{c.detail}</p>
              </li>
            ))}
          </ul>
        </section>
      )}

      <section className="card" style={{ marginBottom: "1.25rem" }}>
        <h2>Отчёт за период</h2>
        <p className="muted">
          Кто имел доступ, согласовал, подключался, какие SQL/команды (deny), скачивания, изменения и отзывы. Не
          полнотекст asciicast.
        </p>
        <form
          className="row"
          style={{ gap: "0.75rem", flexWrap: "wrap", alignItems: "end", marginBottom: "0.75rem" }}
          onSubmit={(e) => void loadReport(e)}
        >
          <label>
            С
            <input type="date" value={reportFrom} onChange={(e) => setReportFrom(e.target.value)} />
          </label>
          <label>
            По
            <input type="date" value={reportTo} onChange={(e) => setReportTo(e.target.value)} />
          </label>
          <label>
            Framework
            <select value={reportFw} onChange={(e) => setReportFw(e.target.value)}>
              <option value="all">все</option>
              <option value="iso27001">ISO 27001</option>
              <option value="pci">PCI DSS</option>
              <option value="soc2">SOC 2</option>
              <option value="nist">NIST</option>
            </select>
          </label>
          <button className="btn" type="submit" disabled={busy}>
            Сформировать
          </button>
          <button
            className="btn secondary"
            type="button"
            disabled={busy}
            onClick={() => void downloadReportCsv()}
          >
            CSV
          </button>
        </form>

        {report && (
          <>
            <div className="stats-grid" style={{ marginBottom: "0.75rem" }}>
              {SUMMARY_LABELS.map((s) => (
                <div key={s.key} className="card stat-card" style={{ margin: 0 }}>
                  <div className="stat-value">{report.summary[s.key]}</div>
                  <div className="muted">{s.label}</div>
                </div>
              ))}
            </div>
            <p className="muted" style={{ marginBottom: "0.75rem" }}>
              Live: ACL {report.snapshot.acl_live} · сессии {report.snapshot.sessions_active} · JIT pending{" "}
              {report.snapshot.jit_pending} · break-glass {report.snapshot.break_glass_active} · holds{" "}
              {report.snapshot.legal_holds}
              {report.truncated ? ` · evidence ${report.evidence.length} из ${report.evidence_total}` : ""}
            </p>
            {report.controls.length > 0 && (
              <p className="muted" style={{ marginBottom: "0.75rem", fontSize: "0.85rem" }}>
                {report.controls.map((c) => `${c.id} ${c.title}`).join(" · ")}
              </p>
            )}
            <table>
              <thead>
                <tr>
                  <th>Время</th>
                  <th>Категория</th>
                  <th>Актор</th>
                  <th>Действие</th>
                  <th>Деталь</th>
                </tr>
              </thead>
              <tbody>
                {report.evidence.map((e) => (
                  <tr key={e.id}>
                    <td className="mono" style={{ whiteSpace: "nowrap" }}>
                      {new Date(e.ts).toLocaleString()}
                    </td>
                    <td>
                      <span className="badge">{CAT_LABELS[e.category] || e.category}</span>
                    </td>
                    <td className="mono">{e.actor || "—"}</td>
                    <td className="mono">{e.action}</td>
                    <td className="muted" style={{ maxWidth: 420, overflow: "hidden", textOverflow: "ellipsis" }}>
                      {e.detail}
                    </td>
                  </tr>
                ))}
                {report.evidence.length === 0 && (
                  <tr>
                    <td colSpan={5} className="muted">
                      Нет событий в окне
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </>
        )}
      </section>

      <section className="card" style={{ marginBottom: "1.25rem" }}>
        <h2>Пакеты</h2>
        <div className="two-col">
          {packs.map((p) => (
            <div key={p.id} className={`card${p.active ? " warn" : ""}`} style={{ margin: 0 }}>
              <h3>
                {p.title} {p.active && <span className="badge active">active</span>}
              </h3>
              <p className="muted">{p.description}</p>
              <p className="mono muted" style={{ fontSize: "0.8rem" }}>
                retention: audit {p.audit_days}d / session {p.session_days}d / recording {p.recording_days}d
              </p>
              <p className="muted" style={{ fontSize: "0.85rem" }}>
                controls: {(p.controls || []).join(", ")}
              </p>
              {canWrite && !p.active && (
                <button className="btn" type="button" disabled={busy} onClick={() => void applyPack(p.id)}>
                  Применить
                </button>
              )}
            </div>
          ))}
        </div>
      </section>

      {retention && (
        <form className="card" style={{ marginBottom: "1.25rem", maxWidth: 560 }} onSubmit={saveRetention}>
          <h2>Retention</h2>
          <p className="muted">audit_events не удаляются (append-only). Purge чистит recordings и старые session metadata.</p>
          <label>Audit retention (дней, информативно)</label>
          <input
            type="number"
            value={retention.audit_retention_days}
            disabled={!canWrite}
            onChange={(e) => setRetention({ ...retention, audit_retention_days: Number(e.target.value) })}
          />
          <label>Session metadata (дней)</label>
          <input
            type="number"
            value={retention.session_retention_days}
            disabled={!canWrite}
            onChange={(e) => setRetention({ ...retention, session_retention_days: Number(e.target.value) })}
          />
          <label>Recordings (дней)</label>
          <input
            type="number"
            value={retention.recording_retention_days}
            disabled={!canWrite}
            onChange={(e) => setRetention({ ...retention, recording_retention_days: Number(e.target.value) })}
          />
          <label>
            <input
              type="checkbox"
              checked={retention.purge_enabled}
              disabled={!canWrite}
              onChange={(e) => setRetention({ ...retention, purge_enabled: e.target.checked })}
            />{" "}
            purge enabled
          </label>
          {canWrite && (
            <button className="btn" type="submit" disabled={busy}>
              Сохранить retention
            </button>
          )}
        </form>
      )}

      <section className="card" style={{ marginBottom: "1.25rem" }}>
        <h2>Legal holds</h2>
        {canWrite && (
          <form onSubmit={createHold} style={{ maxWidth: 560, marginBottom: "1rem" }}>
            <label>Тип</label>
            <select
              value={holdForm.resource_type}
              onChange={(e) => setHoldForm({ ...holdForm, resource_type: e.target.value })}
            >
              <option value="session">session</option>
              <option value="asset">asset</option>
              <option value="user">user</option>
              <option value="global">global</option>
            </select>
            <label>Resource ID</label>
            <input
              value={holdForm.resource_id}
              onChange={(e) => setHoldForm({ ...holdForm, resource_id: e.target.value })}
              placeholder="UUID или пусто для global"
            />
            <label>Причина</label>
            <input
              value={holdForm.reason}
              onChange={(e) => setHoldForm({ ...holdForm, reason: e.target.value })}
              required
            />
            <button className="btn" type="submit" disabled={busy}>
              Создать hold
            </button>
          </form>
        )}
        <table>
          <thead>
            <tr>
              <th>Тип</th>
              <th>Resource</th>
              <th>Причина</th>
              <th>Создан</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {holds.map((h) => (
              <tr key={h.id}>
                <td className="mono">{h.resource_type}</td>
                <td className="mono">{h.resource_id || "—"}</td>
                <td>{h.reason}</td>
                <td className="muted">{new Date(h.created_at).toLocaleString()}</td>
                <td>
                  {canWrite && h.active && (
                    <button className="btn secondary" type="button" onClick={() => void releaseHold(h.id)}>
                      Снять
                    </button>
                  )}
                </td>
              </tr>
            ))}
            {holds.length === 0 && (
              <tr>
                <td colSpan={5} className="muted">
                  Нет активных holds
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </section>

      {dr && drForm && (
        <section className="card" style={{ marginBottom: "1.25rem" }}>
          <h2>Disaster Recovery</h2>
          <p className="muted">{dr.runbook_hint}</p>
          <div className="stats-grid" style={{ marginBottom: "1rem" }}>
            <div className={`card stat-card${dr.primary_ok ? "" : " warn"}`}>
              <div className="stat-value">{dr.primary_ok ? "OK" : "DOWN"}</div>
              <div className="muted">Primary DB</div>
            </div>
            <div className={`card stat-card${dr.rpo_breached ? " warn" : ""}`}>
              <div className="stat-value">{dr.backup_fresh ? "OK" : "STALE"}</div>
              <div className="muted">
                Backup{dr.backup_age_minutes != null ? ` · ${dr.backup_age_minutes}м` : " · нет"}
              </div>
            </div>
            <div className="card stat-card">
              <div className="stat-value">
                {dr.replica_ok == null ? "—" : dr.replica_ok ? "OK" : "FAIL"}
              </div>
              <div className="muted">Replica</div>
            </div>
            <div className="card stat-card">
              <div className="stat-value">
                {dr.settings.last_drill_ok == null ? "—" : dr.settings.last_drill_ok ? "OK" : "FAIL"}
              </div>
              <div className="muted">Last drill</div>
            </div>
          </div>
          {dr.replica_error && <p className="error">Replica: {dr.replica_error}</p>}

          <form
            style={{ maxWidth: 560 }}
            onSubmit={(e) => {
              e.preventDefault();
              if (!canWrite || !drForm) return;
              setBusy(true);
              void api
                .putDRSettings({
                  site_name: drForm.site_name,
                  role: drForm.role,
                  rpo_minutes: drForm.rpo_minutes,
                  rto_minutes: drForm.rto_minutes,
                  replica_dsn_hint: drForm.replica_dsn_hint,
                  backup_dir: drForm.backup_dir,
                })
                .then(() => {
                  setMsg("DR settings сохранены");
                  return load();
                })
                .catch((err) => setError(err instanceof Error ? err.message : "DR error"))
                .finally(() => setBusy(false));
            }}
          >
            <label>Site name</label>
            <input
              value={drForm.site_name}
              disabled={!canWrite}
              onChange={(e) => setDrForm({ ...drForm, site_name: e.target.value })}
            />
            <label>Role</label>
            <select
              value={drForm.role}
              disabled={!canWrite}
              onChange={(e) => setDrForm({ ...drForm, role: e.target.value })}
            >
              <option value="primary">primary</option>
              <option value="dr">dr</option>
              <option value="standalone">standalone</option>
            </select>
            <label>RPO (минуты)</label>
            <input
              type="number"
              value={drForm.rpo_minutes}
              disabled={!canWrite}
              onChange={(e) => setDrForm({ ...drForm, rpo_minutes: Number(e.target.value) })}
            />
            <label>RTO (минуты)</label>
            <input
              type="number"
              value={drForm.rto_minutes}
              disabled={!canWrite}
              onChange={(e) => setDrForm({ ...drForm, rto_minutes: Number(e.target.value) })}
            />
            <label>Replica DSN (опционально, для ping)</label>
            <input
              value={drForm.replica_dsn_hint}
              disabled={!canWrite}
              onChange={(e) => setDrForm({ ...drForm, replica_dsn_hint: e.target.value })}
              placeholder="postgres://..."
            />
            <label>Backup dir (в API-контейнере)</label>
            <input
              value={drForm.backup_dir}
              disabled={!canWrite}
              onChange={(e) => setDrForm({ ...drForm, backup_dir: e.target.value })}
            />
            {canWrite && (
              <div className="row gap">
                <button className="btn" type="submit" disabled={busy}>
                  Сохранить DR
                </button>
                <button
                  className="btn secondary"
                  type="button"
                  disabled={busy}
                  onClick={() => {
                    setBusy(true);
                    void api
                      .runDRBackup()
                      .then((r) => {
                        setMsg(`Backup ${r.status}: ${r.path} (${r.bytes} B)`);
                        return load();
                      })
                      .catch((err) => setError(err instanceof Error ? err.message : "backup error"))
                      .finally(() => setBusy(false));
                  }}
                >
                  Снять backup
                </button>
              </div>
            )}
          </form>

          {canWrite && (
            <div style={{ marginTop: "1rem", maxWidth: 560 }}>
              <label>Fire-drill notes</label>
              <input value={drillNotes} onChange={(e) => setDrillNotes(e.target.value)} />
              <div className="row gap">
                <button
                  className="btn"
                  type="button"
                  disabled={busy}
                  onClick={() => {
                    setBusy(true);
                    void api
                      .recordDRDrill({ ok: true, notes: drillNotes })
                      .then(() => {
                        setMsg("Drill OK записан");
                        setDrillNotes("");
                        return load();
                      })
                      .catch((err) => setError(err instanceof Error ? err.message : "drill error"))
                      .finally(() => setBusy(false));
                  }}
                >
                  Drill OK
                </button>
                <button
                  className="btn secondary"
                  type="button"
                  disabled={busy}
                  onClick={() => {
                    setBusy(true);
                    void api
                      .recordDRDrill({ ok: false, notes: drillNotes })
                      .then(() => {
                        setMsg("Drill FAIL записан");
                        return load();
                      })
                      .catch((err) => setError(err instanceof Error ? err.message : "drill error"))
                      .finally(() => setBusy(false));
                  }}
                >
                  Drill FAIL
                </button>
              </div>
            </div>
          )}
        </section>
      )}
    </div>
  );
}
