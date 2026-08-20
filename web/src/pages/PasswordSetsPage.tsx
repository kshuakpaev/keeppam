import { useEffect, useMemo, useState, type FormEvent } from "react";
import { api, hasPerm, type Asset, type PasswordSet } from "../api";
import { useAuth } from "../auth";
import { useI18n } from "../i18n";

type AccOpt = { id: string; label: string; asset_id: string };

export function PasswordSetsPage() {
  const { user } = useAuth();
  const { t } = useI18n();
  const canRead = hasPerm(user, "assets.read");
  const canWrite = hasPerm(user, "assets.write");
  const [sets, setSets] = useState<PasswordSet[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [error, setError] = useState("");
  const [msg, setMsg] = useState("");
  const [editId, setEditId] = useState<string | null>(null);
  const [form, setForm] = useState({
    name: "",
    description: "",
    sync_order: "directory_last" as "directory_first" | "directory_last",
    account_ids: [] as string[],
  });
  const [rotateLog, setRotateLog] = useState("");

  const accountOpts = useMemo(() => {
    const out: AccOpt[] = [];
    for (const a of assets) {
      for (const acc of a.accounts || []) {
        if (acc.auth_method !== "password") continue;
        out.push({
          id: acc.id,
          asset_id: a.id,
          label: `${a.name} / ${acc.username} (${a.protocol})`,
        });
      }
    }
    return out.sort((x, y) => x.label.localeCompare(y.label));
  }, [assets]);

  async function load() {
    setError("");
    try {
      const [ps, as] = await Promise.all([api.listPasswordSets(), api.listAssets()]);
      setSets(ps.sets || []);
      const detailed = await Promise.all((as.assets || []).map((a) => api.getAsset(a.id)));
      setAssets(detailed);
    } catch (err) {
      setError(err instanceof Error ? err.message : t("common.error"));
    }
  }

  useEffect(() => {
    if (!canRead) return;
    void load();
  }, [canRead]);

  function startCreate() {
    setEditId(null);
    setForm({ name: "", description: "", sync_order: "directory_last", account_ids: [] });
    setRotateLog("");
  }

  async function startEdit(id: string) {
    setError("");
    setRotateLog("");
    try {
      const set = await api.getPasswordSet(id);
      setEditId(set.id);
      setForm({
        name: set.name,
        description: set.description || "",
        sync_order: set.sync_order === "directory_first" ? "directory_first" : "directory_last",
        account_ids: (set.members || []).map((m) => m.account_id),
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : t("common.error"));
    }
  }

  function toggleAccount(id: string) {
    setForm((f) => ({
      ...f,
      account_ids: f.account_ids.includes(id)
        ? f.account_ids.filter((x) => x !== id)
        : [...f.account_ids, id],
    }));
  }

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    if (!canWrite) return;
    setError("");
    setMsg("");
    try {
      if (editId) {
        await api.updatePasswordSet(editId, {
          name: form.name,
          description: form.description,
          sync_order: form.sync_order,
          account_ids: form.account_ids,
        });
        setMsg(t("pwset.saved"));
      } else {
        const created = await api.createPasswordSet({
          name: form.name,
          description: form.description,
          sync_order: form.sync_order,
          account_ids: form.account_ids,
        });
        setEditId(created.id);
        setMsg(t("pwset.created"));
      }
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : t("common.error"));
    }
  }

  async function onDelete() {
    if (!editId || !canWrite) return;
    if (!window.confirm(t("pwset.deleteConfirm"))) return;
    try {
      await api.deletePasswordSet(editId);
      startCreate();
      setMsg(t("pwset.deleted"));
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : t("common.error"));
    }
  }

  async function onRotate() {
    if (!editId || !canWrite) return;
    if (!window.confirm(t("pwset.rotateConfirm"))) return;
    setError("");
    setRotateLog("");
    try {
      const res = await api.rotatePasswordSet(editId, { apply_remote: true });
      const lines = (res.results || []).map((r) =>
        r.ok
          ? `OK ${r.username} (remote=${r.remote_applied})`
          : `FAIL ${r.username}: ${r.error || "?"}`,
      );
      setRotateLog(lines.join("\n"));
      setMsg(t("pwset.rotated"));
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : t("common.error"));
    }
  }

  if (!canRead) {
    return <p className="muted">{t("common.noAccess")}</p>;
  }

  return (
    <div>
      <h1>{t("pwset.title")}</h1>
      <p className="muted">{t("pwset.hint")}</p>
      {error && <p className="error">{error}</p>}
      {msg && <p className="ok">{msg}</p>}

      <div className="row" style={{ gap: "1.5rem", alignItems: "flex-start", flexWrap: "wrap" }}>
        <div style={{ minWidth: 260, flex: "0 0 280px" }}>
          <div className="row" style={{ marginBottom: "0.5rem" }}>
            {canWrite && (
              <button className="btn secondary" type="button" onClick={startCreate}>
                {t("common.create")}
              </button>
            )}
          </div>
          <ul style={{ listStyle: "none", padding: 0, margin: 0 }}>
            {sets.map((s) => (
              <li key={s.id} style={{ marginBottom: 6 }}>
                <button
                  type="button"
                  className="btn secondary"
                  style={{ width: "100%", textAlign: "left" }}
                  onClick={() => void startEdit(s.id)}
                >
                  {s.name}
                </button>
              </li>
            ))}
            {sets.length === 0 && <li className="muted">{t("pwset.empty")}</li>}
          </ul>
        </div>

        <form className="card" style={{ flex: 1, minWidth: 320, maxWidth: 640 }} onSubmit={onSubmit}>
          <h2 style={{ marginTop: 0 }}>{editId ? t("pwset.edit") : t("pwset.create")}</h2>
          <label>{t("common.name")}</label>
          <input
            value={form.name}
            onChange={(e) => setForm({ ...form, name: e.target.value })}
            disabled={!canWrite}
            required
          />
          <label>{t("common.description")}</label>
          <input
            value={form.description}
            onChange={(e) => setForm({ ...form, description: e.target.value })}
            disabled={!canWrite}
          />
          <label>{t("pwset.syncOrder")}</label>
          <select
            value={form.sync_order}
            onChange={(e) =>
              setForm({
                ...form,
                sync_order: e.target.value as "directory_first" | "directory_last",
              })
            }
            disabled={!canWrite}
          >
            <option value="directory_last">{t("pwset.orderLast")}</option>
            <option value="directory_first">{t("pwset.orderFirst")}</option>
          </select>
          <p className="muted" style={{ marginTop: 0 }}>
            {t("pwset.orderHint")}
          </p>
          <label>{t("pwset.members")}</label>
          <div
            style={{
              maxHeight: 280,
              overflow: "auto",
              border: "1px solid var(--border, #ccc)",
              padding: "0.5rem",
              marginBottom: "0.75rem",
            }}
          >
            {accountOpts.map((o) => (
              <label key={o.id} className="row" style={{ gap: 8, alignItems: "center", marginBottom: 4 }}>
                <input
                  type="checkbox"
                  checked={form.account_ids.includes(o.id)}
                  onChange={() => toggleAccount(o.id)}
                  disabled={!canWrite}
                />
                <span className="mono" style={{ fontSize: "0.9rem" }}>
                  {o.label}
                </span>
              </label>
            ))}
            {accountOpts.length === 0 && <p className="muted">{t("pwset.noAccounts")}</p>}
          </div>
          <div className="row" style={{ gap: "0.5rem", flexWrap: "wrap" }}>
            {canWrite && (
              <button className="btn" type="submit">
                {t("common.save")}
              </button>
            )}
            {canWrite && editId && (
              <button className="btn secondary" type="button" onClick={() => void onRotate()}>
                {t("pwset.rotate")}
              </button>
            )}
            {canWrite && editId && (
              <button className="btn danger" type="button" onClick={() => void onDelete()}>
                {t("common.delete")}
              </button>
            )}
          </div>
          {rotateLog && (
            <pre className="mono" style={{ marginTop: "1rem", whiteSpace: "pre-wrap", fontSize: "0.85rem" }}>
              {rotateLog}
            </pre>
          )}
        </form>
      </div>
    </div>
  );
}
