import { useCallback, useEffect, useState, type FormEvent } from "react";
import { api, hasPerm, type ProtectedFile, type ProtectedFileGrant } from "../api";
import { useAuth } from "../auth";
import { useI18n } from "../i18n";

export function FileVaultPage() {
  const { user } = useAuth();
  const { t, te } = useI18n();
  const canRead = hasPerm(user, "files.vault.read");
  const canWrite = hasPerm(user, "files.vault.write");
  const [files, setFiles] = useState<ProtectedFile[]>([]);
  const [grants, setGrants] = useState<ProtectedFileGrant[]>([]);
  const [error, setError] = useState("");
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [reason, setReason] = useState("");

  const load = useCallback(async () => {
    setError("");
    try {
      const fl = await api.listProtectedFiles();
      setFiles(fl.files || []);
      if (canWrite) {
        const g = await api.listProtectedFileGrants(true);
        setGrants(g.grants || []);
      } else {
        setGrants([]);
      }
    } catch (err) {
      setError(te(err, "common.error"));
    }
  }, [canWrite, te]);

  useEffect(() => {
    if (canRead) void load();
  }, [canRead, load]);

  async function onUpload(e: FormEvent) {
    e.preventDefault();
    if (!file) return;
    setBusy(true);
    setError("");
    setMsg("");
    try {
      await api.uploadProtectedFile(file, { name, description });
      setName("");
      setDescription("");
      setFile(null);
      setMsg(t("vault.uploaded"));
      await load();
    } catch (err) {
      setError(te(err, "common.error"));
    } finally {
      setBusy(false);
    }
  }

  async function onRequest(id: string) {
    setBusy(true);
    setError("");
    try {
      await api.requestProtectedFile(id, { reason, ttl_minutes: 60 });
      setReason("");
      setMsg(t("vault.requested"));
      await load();
    } catch (err) {
      setError(te(err, "common.error"));
    } finally {
      setBusy(false);
    }
  }

  async function onDecide(id: string, approve: boolean) {
    setBusy(true);
    setError("");
    try {
      if (approve) await api.approveProtectedFileGrant(id);
      else await api.denyProtectedFileGrant(id);
      setMsg(approve ? t("vault.approved") : t("vault.denied"));
      await load();
    } catch (err) {
      setError(te(err, "common.error"));
    } finally {
      setBusy(false);
    }
  }

  async function onDelete(id: string) {
    if (!window.confirm(t("vault.deleteConfirm"))) return;
    setBusy(true);
    setError("");
    try {
      await api.deleteProtectedFile(id);
      setMsg(t("vault.deleted"));
      await load();
    } catch (err) {
      setError(te(err, "common.error"));
    } finally {
      setBusy(false);
    }
  }

  if (!canRead) {
    return <p className="error">{t("common.forbidden")}</p>;
  }

  return (
    <div>
      <div className="toolbar">
        <div>
          <h1>{t("vault.title")}</h1>
          <p className="muted">{t("vault.lead")}</p>
        </div>
        <button className="btn secondary" type="button" onClick={() => void load()}>
          {t("common.refresh")}
        </button>
      </div>
      {error && <p className="error">{error}</p>}
      {msg && <p className="ok">{msg}</p>}

      {canWrite && (
        <form className="card" style={{ marginBottom: "1rem", maxWidth: 640 }} onSubmit={(e) => void onUpload(e)}>
          <h2 style={{ marginTop: 0 }}>{t("vault.upload")}</h2>
          <label>{t("common.name")}</label>
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder={t("vault.namePlaceholder")} />
          <label>{t("common.description")}</label>
          <input value={description} onChange={(e) => setDescription(e.target.value)} />
          <label>{t("vault.file")}</label>
          <input type="file" onChange={(e) => setFile(e.target.files?.[0] || null)} required />
          <div className="row" style={{ marginTop: "0.75rem" }}>
            <button className="btn" type="submit" disabled={busy || !file}>
              {busy ? t("common.loading") : t("vault.upload")}
            </button>
          </div>
        </form>
      )}

      <div className="card" style={{ marginBottom: "1rem" }}>
        <h2 style={{ marginTop: 0 }}>{t("vault.files")}</h2>
        {files.length === 0 && <p className="muted">{t("vault.empty")}</p>}
        {files.length > 0 && (
          <table>
            <thead>
              <tr>
                <th>{t("common.name")}</th>
                <th>{t("common.description")}</th>
                <th>{t("vault.size")}</th>
                <th>{t("common.status")}</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {files.map((f) => {
                const canDl = f.access === "custodian" || f.access === "approved";
                return (
                  <tr key={f.id}>
                    <td>{f.name}</td>
                    <td className="muted">{f.description}</td>
                    <td className="mono">{f.size_bytes}</td>
                    <td>
                      {t(
                        f.access === "custodian"
                          ? "vault.access.custodian"
                          : f.access === "approved"
                            ? "vault.access.approved"
                            : f.access === "pending"
                              ? "vault.access.pending"
                              : "vault.access.none",
                      )}
                    </td>
                    <td>
                      <div className="row">
                        {canDl && (
                          <a className="btn secondary" href={api.getProtectedFileUrl(f.id)}>
                            {t("sess.download")}
                          </a>
                        )}
                        {!canWrite && f.access !== "approved" && f.access !== "pending" && (
                          <button className="btn secondary" type="button" disabled={busy} onClick={() => void onRequest(f.id)}>
                            {t("vault.request")}
                          </button>
                        )}
                        {canWrite && (
                          <button className="btn danger" type="button" disabled={busy} onClick={() => void onDelete(f.id)}>
                            {t("common.delete")}
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
        {!canWrite && (
          <div style={{ marginTop: "0.75rem" }}>
            <label>{t("vault.reason")}</label>
            <input value={reason} onChange={(e) => setReason(e.target.value)} />
          </div>
        )}
      </div>

      {canWrite && (
        <div className="card">
          <h2 style={{ marginTop: 0 }}>{t("vault.grants")}</h2>
          {grants.length === 0 && <p className="muted">{t("vault.noGrants")}</p>}
          {grants.map((g) => (
            <div key={g.id} className="row" style={{ justifyContent: "space-between", marginBottom: "0.5rem" }}>
              <div>
                <strong>{g.file_name}</strong> · {g.requester} · {g.status}
                {g.reason ? <div className="muted">{g.reason}</div> : null}
              </div>
              {g.status === "pending" && (
                <div className="row">
                  <button className="btn" type="button" disabled={busy} onClick={() => void onDecide(g.id, true)}>
                    {t("vault.approve")}
                  </button>
                  <button className="btn secondary" type="button" disabled={busy} onClick={() => void onDecide(g.id, false)}>
                    {t("vault.deny")}
                  </button>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
