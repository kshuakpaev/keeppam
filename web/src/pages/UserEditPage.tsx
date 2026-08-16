import { useEffect, useState, type FormEvent } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, hasPerm, type PamGroup, type Role, type User, type UserSSHKey } from "../api";
import { useAuth } from "../auth";

export function UserEditPage() {
  const { id } = useParams<{ id: string }>();
  const { user: me } = useAuth();
  const nav = useNavigate();
  const [target, setTarget] = useState<User | null>(null);
  const [roles, setRoles] = useState<Role[]>([]);
  const [pamGroups, setPamGroups] = useState<PamGroup[]>([]);
  const [groupIds, setGroupIds] = useState<string[]>([]);
  const [sshKeys, setSshKeys] = useState<UserSSHKey[]>([]);
  const [passkeys, setPasskeys] = useState<{ id: string; name: string; created_at: string }[]>([]);
  const [email, setEmail] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [status, setStatus] = useState("active");
  const [role, setRole] = useState("operator");
  const [tags, setTags] = useState("");
  const [error, setError] = useState("");
  const [msg, setMsg] = useState("");
  const [tempPwd, setTempPwd] = useState("");
  const [loading, setLoading] = useState(true);
  const [keyName, setKeyName] = useState("");
  const [keyPub, setKeyPub] = useState("");

  const canWrite = hasPerm(me, "users.write");
  const canResetMfa = hasPerm(me, "users.reset_mfa");

  async function loadKeys(userId: string) {
    const res = await api.listUserSSHKeys(userId);
    setSshKeys(res.keys || []);
  }

  async function loadPasskeys(userId: string) {
    const res = await api.listUserWebAuthn(userId);
    setPasskeys(res.credentials || []);
  }

  useEffect(() => {
    if (!id) return;
    setLoading(true);
    Promise.all([api.getUser(id), api.listRoles(), api.listGroups(), api.listUserSSHKeys(id), api.listUserWebAuthn(id)])
      .then(([u, r, g, keys, wa]) => {
        setTarget(u);
        setEmail(u.email);
        setDisplayName(u.display_name || "");
        setStatus(u.status);
        setRole((u.roles && u.roles[0]) || "operator");
        setTags((u.tags || []).join(", "));
        setGroupIds(u.group_ids || []);
        setRoles(r.roles || []);
        setPamGroups(g.groups || []);
        setSshKeys(keys.keys || []);
        setPasskeys(wa.credentials || []);
      })
      .catch((err) => setError(err instanceof Error ? err.message : "Ошибка загрузки"))
      .finally(() => setLoading(false));
  }, [id]);

  async function onSave(e: FormEvent) {
    e.preventDefault();
    if (!id || !canWrite) return;
    setError("");
    setMsg("");
    try {
      const updated = await api.updateUser(id, {
        email,
        display_name: displayName,
        status,
        roles: [role],
        group_ids: groupIds,
        tags: tags
          .split(",")
          .map((t) => t.trim())
          .filter(Boolean),
      });
      setTarget(updated);
      setTags((updated.tags || []).join(", "));
      setMsg("Сохранено");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка сохранения");
    }
  }

  async function onResetPassword() {
    if (!id) return;
    setError("");
    try {
      const res = await api.resetPassword(id);
      setTempPwd(res.temporary_password);
      setMsg("Пароль сброшен");
      const u = await api.getUser(id);
      setTarget(u);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка сброса пароля");
    }
  }

  async function onResetMfa() {
    if (!id) return;
    setError("");
    try {
      await api.resetMfa(id);
      setMsg("MFA сброшен (TOTP + Passkeys)");
      const u = await api.getUser(id);
      setTarget(u);
      await loadPasskeys(id);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка сброса MFA");
    }
  }

  async function onAddKey(e: FormEvent) {
    e.preventDefault();
    if (!id || !canWrite) return;
    setError("");
    try {
      await api.addUserSSHKey(id, { name: keyName || undefined, public_key: keyPub });
      setKeyName("");
      setKeyPub("");
      setMsg("SSH-ключ добавлен");
      await loadKeys(id);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка добавления ключа");
    }
  }

  async function onDeleteKey(key: UserSSHKey) {
    if (!id || !canWrite) return;
    if (!confirm(`Удалить ключ ${key.name}?`)) return;
    try {
      await api.deleteUserSSHKey(id, key.id);
      setMsg("SSH-ключ удалён");
      await loadKeys(id);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка удаления ключа");
    }
  }

  if (loading) return <p className="muted">Загрузка…</p>;
  if (!target) {
    return (
      <div>
        <p className="error">{error || "Пользователь не найден"}</p>
        <Link to="/users">← К списку</Link>
      </div>
    );
  }

  return (
    <div>
      <div className="toolbar">
        <div>
          <p className="muted" style={{ marginBottom: "0.35rem" }}>
            <Link to="/users">Пользователи</Link> / {target.username}
          </p>
          <h1>Редактирование</h1>
          <p className="muted mono">{target.id}</p>
        </div>
        <button className="btn secondary" type="button" onClick={() => nav("/users")}>
          Назад
        </button>
      </div>

      {error && <p className="error">{error}</p>}
      {msg && <p className="ok">{msg}</p>}
      {tempPwd && (
        <p className="ok">
          Временный пароль: <span className="mono">{tempPwd}</span>
        </p>
      )}

      <form className="card" onSubmit={onSave} style={{ maxWidth: 520 }}>
        <label>Логин</label>
        <input value={target.username} disabled />

        <label htmlFor="email">Email</label>
        <input
          id="email"
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          disabled={!canWrite}
          required
        />

        <label htmlFor="display_name">Отображаемое имя</label>
        <input
          id="display_name"
          value={displayName}
          onChange={(e) => setDisplayName(e.target.value)}
          disabled={!canWrite}
        />

        <label htmlFor="status">Статус</label>
        <select
          id="status"
          value={status}
          onChange={(e) => setStatus(e.target.value)}
          disabled={!canWrite}
        >
          <option value="active">active</option>
          <option value="disabled">disabled</option>
          <option value="locked">locked</option>
        </select>

        <label htmlFor="role">Роль</label>
        <select
          id="role"
          value={role}
          onChange={(e) => setRole(e.target.value)}
          disabled={!canWrite}
        >
          {roles.map((r) => (
            <option key={r.id} value={r.name}>
              {r.name}
            </option>
          ))}
        </select>

        <label>Группы PAM</label>
        <div style={{ marginBottom: "0.75rem" }}>
          {pamGroups.map((g) => (
            <label key={g.id} className="row" style={{ gap: 8, alignItems: "center", marginBottom: 4 }}>
              <input
                type="checkbox"
                checked={groupIds.includes(g.id)}
                disabled={!canWrite}
                onChange={() =>
                  setGroupIds((ids) => (ids.includes(g.id) ? ids.filter((x) => x !== g.id) : [...ids, g.id]))
                }
              />
              <span className="mono">{g.name}</span>
              <span className="muted">{g.description}</span>
            </label>
          ))}
          {pamGroups.length === 0 && <p className="muted">Нет групп — создайте на странице «Группы»</p>}
        </div>

        <label htmlFor="tags">ABAC-теги (через запятую)</label>
        <input
          id="tags"
          value={tags}
          onChange={(e) => setTags(e.target.value)}
          disabled={!canWrite}
          placeholder="pci, prod, contractor"
        />

        <div className="meta-grid">
          <div>
            <span className="muted">MFA</span>
            <div>{target.mfa_enabled ? "включён" : "выключен"}</div>
          </div>
          <div>
            <span className="muted">Источник</span>
            <div className="mono">{target.auth_source}</div>
          </div>
          <div>
            <span className="muted">Последний вход</span>
            <div className="mono">
              {target.last_login_at ? new Date(target.last_login_at).toLocaleString() : "—"}
            </div>
          </div>
          <div>
            <span className="muted">Смена пароля</span>
            <div>{target.must_change_password ? "требуется" : "нет"}</div>
          </div>
        </div>

        <div className="row" style={{ marginTop: "1rem" }}>
          {canWrite && (
            <button className="btn" type="submit">
              Сохранить
            </button>
          )}
          {canWrite && (
            <button className="btn secondary" type="button" onClick={() => void onResetPassword()}>
              Сброс пароля
            </button>
          )}
          {canResetMfa && (
            <button className="btn danger" type="button" onClick={() => void onResetMfa()}>
              Сброс MFA
            </button>
          )}
        </div>
      </form>

      <div className="card" style={{ maxWidth: 640, marginTop: "1.25rem" }}>
        <h2>Passkeys (WebAuthn)</h2>
        <p className="muted">Сброс MFA удаляет все ключи вместе с TOTP.</p>
        {passkeys.length === 0 ? (
          <p className="muted">Ключей нет</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Имя</th>
                <th>Создан</th>
              </tr>
            </thead>
            <tbody>
              {passkeys.map((k) => (
                <tr key={k.id}>
                  <td>{k.name}</td>
                  <td className="mono">{new Date(k.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="card" style={{ maxWidth: 640, marginTop: "1.25rem" }}>
        <h2>SSH-ключи (gateway :2222)</h2>
        <p className="muted">
          Вход без пароля: <span className="mono">ssh -i key -p 2222 {target.username}@host</span> → TOTP
        </p>
        {sshKeys.length === 0 ? (
          <p className="muted">Ключей нет</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Имя</th>
                <th>Fingerprint</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {sshKeys.map((k) => (
                <tr key={k.id}>
                  <td>{k.name}</td>
                  <td className="mono" style={{ wordBreak: "break-all" }}>
                    {k.fingerprint}
                  </td>
                  <td>
                    {canWrite && (
                      <button className="btn danger" type="button" onClick={() => void onDeleteKey(k)}>
                        Удалить
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {canWrite && (
          <form onSubmit={onAddKey} style={{ marginTop: "1rem" }}>
            <label>Имя</label>
            <input value={keyName} onChange={(e) => setKeyName(e.target.value)} placeholder="laptop" />
            <label>Public key</label>
            <textarea
              value={keyPub}
              onChange={(e) => setKeyPub(e.target.value)}
              required
              rows={3}
              placeholder="ssh-ed25519 AAAA… comment"
              style={{ width: "100%", fontFamily: "monospace" }}
            />
            <button className="btn" type="submit" style={{ marginTop: "0.5rem" }}>
              Добавить ключ
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
