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
import { useI18n } from "../i18n";
import type { MsgKey } from "../i18n/catalog";

function pad(n: number) {
  return String(n).padStart(2, "0");
}

function isoDate(d: Date) {
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

const SUMMARY_KEYS: { key: keyof ComplianceReport["summary"]; msgKey: MsgKey }[] = [
  { key: "access", msgKey: "compliance.cat.access" },
  { key: "privileged", msgKey: "compliance.cat.privileged" },
  { key: "approvals", msgKey: "compliance.cat.approvals" },
  { key: "connections", msgKey: "compliance.cat.connections" },
  { key: "commands", msgKey: "compliance.cat.commands" },
  { key: "sql", msgKey: "compliance.cat.sql" },
  { key: "downloads", msgKey: "compliance.cat.downloads" },
  { key: "changes", msgKey: "compliance.cat.changes" },
  { key: "revoked", msgKey: "compliance.cat.revoked" },
];

const CAT_MSG_KEYS: Record<string, MsgKey> = {
  access: "compliance.cat.access",
  privileged: "compliance.cat.privileged",
  approvals: "compliance.cat.approvals",
  connections: "compliance.cat.connections",
  commands: "compliance.cat.commands",
  sql: "compliance.cat.sql",
  downloads: "compliance.cat.downloads",
  changes: "compliance.cat.changes",
  revoked: "compliance.cat.revoked",
};

export function CompliancePage() {
  const { user } = useAuth();
  const { t, te } = useI18n();
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
  const [reportProse, setReportProse] = useState(false);
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
      setError(te(err, "compliance.loadError"));
    }
  }

  useEffect(() => {
    if (!canRead) return;
    void load();
  }, [canRead]);

  if (!canRead) {
    return <p className="error">{t("common.forbidden")}</p>;
  }

  function pdfLeadSuffix() {
    if (!status) return "";
    if (status.pdf_signed) {
      let suffix = t("compliance.pdfSignedPrefix", {
        pades: status.pdf_pades || "B-B",
        signer: status.pdf_signer || t("compliance.pdfSignerDefault"),
      });
      if (status.pdf_qualified) {
        suffix += t("compliance.pdfQualified", { profile: status.pdf_eidas_profile || "eIDAS" });
      } else if (status.pdf_eidas_mode && status.pdf_eidas_mode !== "off") {
        suffix += t("compliance.pdfEidasMode", { mode: status.pdf_eidas_mode });
      }
      return `${suffix}.`;
    }
    return t("compliance.pdfUnsigned");
  }

  async function applyPack(id: string) {
    if (!canWrite) return;
    setBusy(true);
    setError("");
    setMsg("");
    try {
      await api.applyCompliancePack(id);
      setMsg(t("compliance.packApplied", { id }));
      await load();
    } catch (err) {
      setError(te(err, "compliance.applyError"));
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
      setMsg(t("compliance.retentionSaved"));
      await load();
    } catch (err) {
      setError(te(err, "compliance.retentionError"));
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
      setMsg(t("compliance.holdCreated"));
      await load();
    } catch (err) {
      setError(te(err, "compliance.holdError"));
    } finally {
      setBusy(false);
    }
  }

  async function releaseHold(id: string) {
    if (!canWrite) return;
    setBusy(true);
    try {
      await api.releaseLegalHold(id);
      setMsg(t("compliance.holdReleased"));
      await load();
    } catch (err) {
      setError(te(err, "compliance.releaseError"));
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
        t("compliance.purgeResult", {
          recordings: st.recordings_removed,
          sessions: st.sessions_purged,
          skipped: st.skipped_holds,
          note: st.audit_note || "",
        }),
      );
      await load();
    } catch (err) {
      setError(te(err, "compliance.purgeError"));
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
        prose: reportProse,
      });
      setReport(r);
    } catch (err) {
      setError(te(err, "compliance.reportError"));
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
      setError(te(err, "compliance.csvError"));
    }
  }

  async function downloadReportPdf() {
    setError("");
    try {
      await api.downloadComplianceReportPdf({
        from: reportFrom,
        to: reportTo,
        framework: reportFw,
        limit: 500,
      });
    } catch (err) {
      setError(te(err, "compliance.pdfError"));
    }
  }

  return (
    <div>
      <div className="page-head">
        <div>
          <h1>{t("nav.compliance")}</h1>
          <p className="muted">{t("compliance.lead")}</p>
        </div>
        <div className="row gap">
          <button className="btn secondary" type="button" disabled={busy} onClick={() => void load()}>
            {t("common.refresh")}
          </button>
          {canWrite && (
            <button className="btn secondary" type="button" disabled={busy} onClick={() => void runPurge()}>
              {t("compliance.runPurge")}
            </button>
          )}
        </div>
      </div>

      {error && <p className="error">{error}</p>}
      {msg && <p className="ok">{msg}</p>}

      {status && (
        <section className="card" style={{ marginBottom: "1.25rem" }}>
          <h2>{t("compliance.controlsStatus")}</h2>
          <p className="muted">
            {t("compliance.activePack")} <strong>{status.active_pack_id || "—"}</strong>
            {status.applied_at && t("compliance.appliedAt", { at: new Date(status.applied_at).toLocaleString() })}
            {status.last_purge_at && t("compliance.lastPurge", { at: new Date(status.last_purge_at).toLocaleString() })}
          </p>
          <p>
            <button
              className="btn secondary"
              type="button"
              onClick={() =>
                void api.downloadSBOM().catch((e) => setError(e instanceof Error ? e.message : t("compliance.sbomError")))
              }
            >
              {t("compliance.downloadSbom")}
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
        <h2>{t("compliance.periodReport")}</h2>
        <p className="muted">
          {t("compliance.reportLead")}
          {pdfLeadSuffix()}
        </p>
        <form
          className="row"
          style={{ gap: "0.75rem", flexWrap: "wrap", alignItems: "end", marginBottom: "0.75rem" }}
          onSubmit={(e) => void loadReport(e)}
        >
          <label>
            {t("compliance.dateFrom")}
            <input type="date" value={reportFrom} onChange={(e) => setReportFrom(e.target.value)} />
          </label>
          <label>
            {t("compliance.dateTo")}
            <input type="date" value={reportTo} onChange={(e) => setReportTo(e.target.value)} />
          </label>
          <label>
            {t("compliance.framework")}
            <select value={reportFw} onChange={(e) => setReportFw(e.target.value)}>
              <option value="all">{t("common.all")}</option>
              <option value="iso27001">ISO 27001</option>
              <option value="pci">PCI DSS</option>
              <option value="soc2">SOC 2</option>
              <option value="nist">NIST</option>
            </select>
          </label>
          <label style={{ display: "flex", alignItems: "center", gap: "0.35rem" }}>
            <input type="checkbox" checked={reportProse} onChange={(e) => setReportProse(e.target.checked)} />
            {t("compliance.prose")}
          </label>
          <button className="btn" type="submit" disabled={busy}>
            {t("compliance.generate")}
          </button>
          <button
            className="btn secondary"
            type="button"
            disabled={busy}
            onClick={() => void downloadReportCsv()}
          >
            CSV
          </button>
          <button
            className="btn secondary"
            type="button"
            disabled={busy}
            onClick={() => void downloadReportPdf()}
          >
            {status?.pdf_signed
              ? t("compliance.pdfSignedBtn", { pades: status.pdf_pades || "B-B" })
              : t("compliance.pdfBtn")}
          </button>
        </form>

        {report && (
          <>
            <div className="stats-grid" style={{ marginBottom: "0.75rem" }}>
              {SUMMARY_KEYS.map((s) => (
                <div key={s.key} className="card stat-card" style={{ margin: 0 }}>
                  <div className="stat-value">{report.summary[s.key]}</div>
                  <div className="muted">{t(s.msgKey)}</div>
                </div>
              ))}
            </div>
            {report.prose ? (
              <p className="muted" style={{ marginBottom: "0.75rem", whiteSpace: "pre-wrap" }}>
                {report.prose}
              </p>
            ) : null}
            <p className="muted" style={{ marginBottom: "0.75rem" }}>
              {t("compliance.liveSnapshot", {
                acl: report.snapshot.acl_live,
                sessions: report.snapshot.sessions_active,
                jit: report.snapshot.jit_pending,
                bg: report.snapshot.break_glass_active,
                holds: report.snapshot.legal_holds,
                truncated: report.truncated
                  ? t("compliance.evidenceTruncated", {
                      shown: report.evidence.length,
                      total: report.evidence_total,
                    })
                  : "",
              })}
            </p>
            {report.controls.length > 0 && (
              <p className="muted" style={{ marginBottom: "0.75rem", fontSize: "0.85rem" }}>
                {report.controls.map((c) => `${c.id} ${c.title}`).join(" · ")}
              </p>
            )}
            <table>
              <thead>
                <tr>
                  <th>{t("compliance.time")}</th>
                  <th>{t("compliance.category")}</th>
                  <th>{t("compliance.actor")}</th>
                  <th>{t("compliance.action")}</th>
                  <th>{t("compliance.detail")}</th>
                </tr>
              </thead>
              <tbody>
                {report.evidence.map((e) => (
                  <tr key={e.id}>
                    <td className="mono" style={{ whiteSpace: "nowrap" }}>
                      {new Date(e.ts).toLocaleString()}
                    </td>
                    <td>
                      <span className="badge">
                        {CAT_MSG_KEYS[e.category] ? t(CAT_MSG_KEYS[e.category]) : e.category}
                      </span>
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
                      {t("compliance.noEventsInWindow")}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </>
        )}
      </section>

      <section className="card" style={{ marginBottom: "1.25rem" }}>
        <h2>{t("compliance.packs")}</h2>
        <div className="two-col">
          {packs.map((p) => (
            <div key={p.id} className={`card${p.active ? " warn" : ""}`} style={{ margin: 0 }}>
              <h3>
                {p.title} {p.active && <span className="badge active">active</span>}
              </h3>
              <p className="muted">{p.description}</p>
              <p className="mono muted" style={{ fontSize: "0.8rem" }}>
                {t("compliance.packRetention", {
                  audit: p.audit_days,
                  session: p.session_days,
                  recording: p.recording_days,
                })}
              </p>
              <p className="muted" style={{ fontSize: "0.85rem" }}>
                {t("compliance.packControls")} {(p.controls || []).join(", ")}
              </p>
              {canWrite && !p.active && (
                <button className="btn" type="button" disabled={busy} onClick={() => void applyPack(p.id)}>
                  {t("compliance.apply")}
                </button>
              )}
            </div>
          ))}
        </div>
      </section>

      {retention && (
        <form className="card" style={{ marginBottom: "1.25rem", maxWidth: 560 }} onSubmit={saveRetention}>
          <h2>Retention</h2>
          <p className="muted">{t("compliance.retentionHint")}</p>
          <label>{t("compliance.auditRetentionDays")}</label>
          <input
            type="number"
            value={retention.audit_retention_days}
            disabled={!canWrite}
            onChange={(e) => setRetention({ ...retention, audit_retention_days: Number(e.target.value) })}
          />
          <label>{t("compliance.sessionRetentionDays")}</label>
          <input
            type="number"
            value={retention.session_retention_days}
            disabled={!canWrite}
            onChange={(e) => setRetention({ ...retention, session_retention_days: Number(e.target.value) })}
          />
          <label>{t("compliance.recordingRetentionDays")}</label>
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
            {t("compliance.purgeEnabled")}
          </label>
          {canWrite && (
            <button className="btn" type="submit" disabled={busy}>
              {t("compliance.saveRetention")}
            </button>
          )}
        </form>
      )}

      <section className="card" style={{ marginBottom: "1.25rem" }}>
        <h2>{t("compliance.legalHolds")}</h2>
        {canWrite && (
          <form onSubmit={createHold} style={{ maxWidth: 560, marginBottom: "1rem" }}>
            <label>{t("common.type")}</label>
            <select
              value={holdForm.resource_type}
              onChange={(e) => setHoldForm({ ...holdForm, resource_type: e.target.value })}
            >
              <option value="session">session</option>
              <option value="asset">asset</option>
              <option value="user">user</option>
              <option value="global">global</option>
            </select>
            <label>{t("compliance.holdResourceId")}</label>
            <input
              value={holdForm.resource_id}
              onChange={(e) => setHoldForm({ ...holdForm, resource_id: e.target.value })}
              placeholder={t("compliance.holdResourcePlaceholder")}
            />
            <label>{t("compliance.holdReason")}</label>
            <input
              value={holdForm.reason}
              onChange={(e) => setHoldForm({ ...holdForm, reason: e.target.value })}
              required
            />
            <button className="btn" type="submit" disabled={busy}>
              {t("compliance.createHold")}
            </button>
          </form>
        )}
        <table>
          <thead>
            <tr>
              <th>{t("common.type")}</th>
              <th>{t("compliance.holdResource")}</th>
              <th>{t("compliance.holdReason")}</th>
              <th>{t("compliance.holdCreatedAt")}</th>
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
                      {t("compliance.releaseHold")}
                    </button>
                  )}
                </td>
              </tr>
            ))}
            {holds.length === 0 && (
              <tr>
                <td colSpan={5} className="muted">
                  {t("compliance.noActiveHolds")}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </section>

      {dr && drForm && (
        <section className="card" style={{ marginBottom: "1.25rem" }}>
          <h2>{t("compliance.drTitle")}</h2>
          <p className="muted">{dr.runbook_hint}</p>
          <div className="stats-grid" style={{ marginBottom: "1rem" }}>
            <div className={`card stat-card${dr.primary_ok ? "" : " warn"}`}>
              <div className="stat-value">{dr.primary_ok ? "OK" : "DOWN"}</div>
              <div className="muted">{t("compliance.drPrimaryDb")}</div>
            </div>
            <div className={`card stat-card${dr.rpo_breached ? " warn" : ""}`}>
              <div className="stat-value">{dr.backup_fresh ? "OK" : "STALE"}</div>
              <div className="muted">
                {t("compliance.drBackup")}
                {dr.backup_age_minutes != null
                  ? t("compliance.drBackupAge", { minutes: dr.backup_age_minutes })
                  : t("compliance.drBackupNone")}
              </div>
            </div>
            <div className="card stat-card">
              <div className="stat-value">
                {dr.replica_ok == null ? "—" : dr.replica_ok ? "OK" : "FAIL"}
              </div>
              <div className="muted">{t("compliance.drReplica")}</div>
            </div>
            <div className="card stat-card">
              <div className="stat-value">
                {dr.settings.last_drill_ok == null ? "—" : dr.settings.last_drill_ok ? "OK" : "FAIL"}
              </div>
              <div className="muted">{t("compliance.drLastDrill")}</div>
            </div>
          </div>
          {dr.replica_error && <p className="error">{t("compliance.drReplicaError", { error: dr.replica_error })}</p>}

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
                  setMsg(t("compliance.drSaved"));
                  return load();
                })
                .catch((err) => setError(te(err, "compliance.drError")))
                .finally(() => setBusy(false));
            }}
          >
            <label>{t("compliance.drSiteName")}</label>
            <input
              value={drForm.site_name}
              disabled={!canWrite}
              onChange={(e) => setDrForm({ ...drForm, site_name: e.target.value })}
            />
            <label>{t("compliance.drRole")}</label>
            <select
              value={drForm.role}
              disabled={!canWrite}
              onChange={(e) => setDrForm({ ...drForm, role: e.target.value })}
            >
              <option value="primary">primary</option>
              <option value="dr">dr</option>
              <option value="standalone">standalone</option>
            </select>
            <label>{t("compliance.drRpo")}</label>
            <input
              type="number"
              value={drForm.rpo_minutes}
              disabled={!canWrite}
              onChange={(e) => setDrForm({ ...drForm, rpo_minutes: Number(e.target.value) })}
            />
            <label>{t("compliance.drRto")}</label>
            <input
              type="number"
              value={drForm.rto_minutes}
              disabled={!canWrite}
              onChange={(e) => setDrForm({ ...drForm, rto_minutes: Number(e.target.value) })}
            />
            <label>{t("compliance.drReplicaDsn")}</label>
            <input
              value={drForm.replica_dsn_hint}
              disabled={!canWrite}
              onChange={(e) => setDrForm({ ...drForm, replica_dsn_hint: e.target.value })}
              placeholder="postgres://..."
            />
            <label>{t("compliance.drBackupDir")}</label>
            <input
              value={drForm.backup_dir}
              disabled={!canWrite}
              onChange={(e) => setDrForm({ ...drForm, backup_dir: e.target.value })}
            />
            {canWrite && (
              <div className="row gap">
                <button className="btn" type="submit" disabled={busy}>
                  {t("compliance.saveDr")}
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
                        setMsg(
                          t("compliance.backupResult", {
                            status: r.status,
                            path: r.path,
                            bytes: r.bytes,
                          }),
                        );
                        return load();
                      })
                      .catch((err) => setError(te(err, "compliance.backupError")))
                      .finally(() => setBusy(false));
                  }}
                >
                  {t("compliance.takeBackup")}
                </button>
              </div>
            )}
          </form>

          {canWrite && (
            <div style={{ marginTop: "1rem", maxWidth: 560 }}>
              <label>{t("compliance.drillNotes")}</label>
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
                        setMsg(t("compliance.drillOkRecorded"));
                        setDrillNotes("");
                        return load();
                      })
                      .catch((err) => setError(te(err, "compliance.drillError")))
                      .finally(() => setBusy(false));
                  }}
                >
                  {t("compliance.drillOk")}
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
                        setMsg(t("compliance.drillFailRecorded"));
                        return load();
                      })
                      .catch((err) => setError(te(err, "compliance.drillError")))
                      .finally(() => setBusy(false));
                  }}
                >
                  {t("compliance.drillFail")}
                </button>
              </div>
            </div>
          )}
        </section>
      )}
    </div>
  );
}
