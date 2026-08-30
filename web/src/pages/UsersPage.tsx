import { useEffect, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { api, hasPerm, type Role, type User } from "../api";
import { useAuth } from "../auth";
import { useI18n } from "../i18n";

export function UsersPage() {
  const { user } = useAuth();
  const { t, te } = useI18n();
  const [users, setUsers] = useState<User[]>([]);
  const [roles, setRoles] = useState<Role[]>([]);
  const [error, setError] = useState("");
  const [tempPwd, setTempPwd] = useState("");
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({
    username: "",
    email: "",
    display_name: "",
    roles: ["operator"],
  });

  const canWrite = hasPerm(user, "users.write");
  const canRead = hasPerm(user, "users.read");

  async function load() {
    try {
      const [u, r] = await Promise.all([api.listUsers(), api.listRoles()]);
      setUsers(u.users || []);
      setRoles(r.roles || []);
    } catch (err) {
      setError(te(err, "users.loadError"));
    }
  }

  useEffect(() => {
    void load();
  }, []);

  async function onCreate(e: FormEvent) {
    e.preventDefault();
    setError("");
    setTempPwd("");
    try {
      const res = await api.createUser(form);
      if (res.temporary_password) setTempPwd(res.temporary_password);
      setShowCreate(false);
      setForm({ username: "", email: "", display_name: "", roles: ["operator"] });
      await load();
    } catch (err) {
      setError(te(err, "users.createError"));
    }
  }

  return (
    <div>
      <div className="toolbar">
        <div>
          <h1>{t("users.title")}</h1>
          <p className="muted">{t("users.lead")}</p>
        </div>
        {canWrite && (
          <button className="btn" type="button" onClick={() => setShowCreate((v) => !v)}>
            {showCreate ? t("common.cancel") : t("common.create")}
          </button>
        )}
      </div>
      {error && <p className="error">{error}</p>}
      {tempPwd && (
        <p className="ok">
          {t("users.tempPassword")} <span className="mono">{tempPwd}</span>
        </p>
      )}
      {showCreate && (
        <form className="card" onSubmit={onCreate} style={{ marginBottom: "1rem" }}>
          <h2>{t("users.new")}</h2>
          <p className="muted">{t("users.createHint")}</p>
          <label>{t("login.username")}</label>
          <input
            value={form.username}
            onChange={(e) => setForm({ ...form, username: e.target.value })}
            required
          />
          <label>Email</label>
          <input
            type="email"
            value={form.email}
            onChange={(e) => setForm({ ...form, email: e.target.value })}
            required
          />
          <label>{t("common.name")}</label>
          <input
            value={form.display_name}
            onChange={(e) => setForm({ ...form, display_name: e.target.value })}
          />
          <label>{t("users.role")}</label>
          <select
            value={form.roles[0]}
            onChange={(e) => setForm({ ...form, roles: [e.target.value] })}
          >
            {roles.map((r) => (
              <option key={r.id} value={r.name}>
                {r.name}
              </option>
            ))}
          </select>
          <button className="btn" type="submit">
            {t("common.create")}
          </button>
        </form>
      )}
      <div className="card">
        <table>
          <thead>
            <tr>
              <th>{t("login.username")}</th>
              <th>Email</th>
              <th>{t("common.status")}</th>
              <th>MFA</th>
              <th>{t("users.roles")}</th>
              <th>{t("nav.groups")}</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.id}>
                <td>
                  {canRead ? <Link to={`/users/${u.id}`}>{u.username}</Link> : u.username}
                </td>
                <td>{u.email}</td>
                <td>
                  <span className={`badge ${u.status}`}>{u.status}</span>
                </td>
                <td>{u.mfa_enabled ? t("common.yes") : t("common.no")}</td>
                <td className="mono">{(u.roles || []).join(", ")}</td>
                <td className="mono">{(u.groups || []).join(", ") || "—"}</td>
                <td>
                  {canRead && (
                    <Link className="btn secondary" to={`/users/${u.id}`}>
                      {t("common.open")}
                    </Link>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
