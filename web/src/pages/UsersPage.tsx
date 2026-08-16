import { useEffect, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { api, hasPerm, type Role, type User } from "../api";
import { useAuth } from "../auth";

export function UsersPage() {
  const { user } = useAuth();
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
      setError(err instanceof Error ? err.message : "Ошибка загрузки");
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
      setError(err instanceof Error ? err.message : "Ошибка создания");
    }
  }

  return (
    <div>
      <div className="toolbar">
        <div>
          <h1>Пользователи</h1>
          <p className="muted">Учётные записи, роли и группы PAM</p>
        </div>
        {canWrite && (
          <button className="btn" type="button" onClick={() => setShowCreate((v) => !v)}>
            {showCreate ? "Отмена" : "Создать"}
          </button>
        )}
      </div>
      {error && <p className="error">{error}</p>}
      {tempPwd && (
        <p className="ok">
          Временный пароль: <span className="mono">{tempPwd}</span>
        </p>
      )}
      {showCreate && (
        <form className="card" onSubmit={onCreate} style={{ marginBottom: "1rem" }}>
          <h2>Новый пользователь</h2>
          <label>Логин</label>
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
          <label>Имя</label>
          <input
            value={form.display_name}
            onChange={(e) => setForm({ ...form, display_name: e.target.value })}
          />
          <label>Роль</label>
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
            Создать
          </button>
        </form>
      )}
      <div className="card">
        <table>
          <thead>
            <tr>
              <th>Логин</th>
              <th>Email</th>
              <th>Статус</th>
              <th>MFA</th>
              <th>Роли</th>
              <th>Группы</th>
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
                <td>{u.mfa_enabled ? "да" : "нет"}</td>
                <td className="mono">{(u.roles || []).join(", ")}</td>
                <td className="mono">{(u.groups || []).join(", ") || "—"}</td>
                <td>
                  {canRead && (
                    <Link className="btn secondary" to={`/users/${u.id}`}>
                      Открыть
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
