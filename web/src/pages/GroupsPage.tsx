import { useEffect, useState, type FormEvent } from "react";
import { api, hasPerm, type PamGroup, type User } from "../api";
import { useAuth } from "../auth";
import { useI18n } from "../i18n";

export function GroupsPage() {
  const { user } = useAuth();
  const { t, te } = useI18n();
  const canRead = hasPerm(user, "users.read");
  const canWrite = hasPerm(user, "users.write");
  const [groups, setGroups] = useState<PamGroup[]>([]);
  const [users, setUsers] = useState<User[]>([]);
  const [error, setError] = useState("");
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState(false);
  const [editId, setEditId] = useState<string | null>(null);
  const [form, setForm] = useState({ name: "", description: "", parent_id: "", member_ids: [] as string[] });

  async function load() {
    setError("");
    try {
      const [g, u] = await Promise.all([api.listGroups(), api.listUsers()]);
      setGroups(g.groups || []);
      setUsers(u.users || []);
    } catch (err) {
      setError(te(err, "groups.loadError"));
    }
  }

  useEffect(() => {
    if (!canRead) return;
    void load();
  }, [canRead]);

  function startCreate() {
    setEditId(null);
    setForm({ name: "", description: "", parent_id: "", member_ids: [] });
  }

  async function startEdit(id: string) {
    setError("");
    try {
      const g = await api.getGroup(id);
      setEditId(g.id);
      setForm({
        name: g.name,
        description: g.description,
        parent_id: g.parent_id || "",
        member_ids: (g.members || []).map((m) => m.id),
      });
    } catch (err) {
      setError(te(err, "groups.loadGroupError"));
    }
  }

  function toggleMember(id: string) {
    setForm((f) => ({
      ...f,
      member_ids: f.member_ids.includes(id) ? f.member_ids.filter((x) => x !== id) : [...f.member_ids, id],
    }));
  }

  async function onSave(e: FormEvent) {
    e.preventDefault();
    if (!canWrite) return;
    setBusy(true);
    setError("");
    setMsg("");
    try {
      if (editId) {
        await api.updateGroup(editId, form);
        setMsg(t("groups.saved"));
      } else {
        await api.createGroup(form);
        setMsg(t("groups.created"));
        startCreate();
      }
      await load();
    } catch (err) {
      setError(te(err, "groups.saveError"));
    } finally {
      setBusy(false);
    }
  }

  async function onDelete(id: string) {
    if (!canWrite || !confirm(t("groups.deleteConfirm"))) return;
    setBusy(true);
    setError("");
    try {
      await api.deleteGroup(id);
      if (editId === id) startCreate();
      await load();
    } catch (err) {
      setError(te(err, "groups.deleteError"));
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
          <h1>{t("groups.title")}</h1>
          <p className="muted">{t("groups.lead")}</p>
        </div>
      </div>
      {error && <p className="error">{error}</p>}
      {msg && <p className="ok">{msg}</p>}
      <div className="two-col">
        <div className="card">
          <table>
            <thead>
              <tr>
                <th>{t("common.name")}</th>
                <th>{t("groups.parent")}</th>
                <th>{t("common.description")}</th>
                <th>{t("groups.members")}</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {groups.map((g) => (
                <tr key={g.id}>
                  <td className="mono">{g.name}</td>
                  <td className="mono">{g.parent_name || "—"}</td>
                  <td>{g.description || "—"}</td>
                  <td>{g.member_count}</td>
                  <td>
                    <div className="row" style={{ gap: "0.4rem" }}>
                      <button className="btn secondary" type="button" onClick={() => void startEdit(g.id)}>
                        {t("common.open")}
                      </button>
                      {canWrite && (
                        <button className="btn danger" type="button" disabled={busy} onClick={() => void onDelete(g.id)}>
                          {t("common.delete")}
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {canWrite && (
          <form className="card" onSubmit={(e) => void onSave(e)}>
            <h2>{editId ? t("groups.edit") : t("groups.new")}</h2>
            <label>{t("common.name")}</label>
            <input
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              required
              placeholder="dba"
            />
            <label>{t("common.description")}</label>
            <input
              value={form.description}
              onChange={(e) => setForm({ ...form, description: e.target.value })}
            />
            <label>{t("groups.parentOpt")}</label>
            <select
              value={form.parent_id}
              onChange={(e) => setForm({ ...form, parent_id: e.target.value })}
            >
              <option value="">{t("groups.root")}</option>
              {groups
                .filter((g) => g.id !== editId)
                .map((g) => (
                  <option key={g.id} value={g.id}>
                    {g.parent_name ? `${g.parent_name} / ${g.name}` : g.name}
                  </option>
                ))}
            </select>
            <label>{t("groups.members")}</label>
            <div style={{ maxHeight: 240, overflow: "auto", border: "1px solid var(--border)", borderRadius: 6, padding: "0.5rem" }}>
              {users.map((u) => (
                <label key={u.id} className="row" style={{ gap: 8, alignItems: "center", marginBottom: 4 }}>
                  <input
                    type="checkbox"
                    checked={form.member_ids.includes(u.id)}
                    onChange={() => toggleMember(u.id)}
                  />
                  <span className="mono">{u.username}</span>
                  <span className="muted">{u.email}</span>
                </label>
              ))}
            </div>
            <div className="row" style={{ gap: "0.5rem", marginTop: "0.75rem" }}>
              <button className="btn" type="submit" disabled={busy}>
                {editId ? t("common.save") : t("common.create")}
              </button>
              {editId && (
                <button className="btn secondary" type="button" onClick={startCreate}>
                  {t("common.cancel")}
                </button>
              )}
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
