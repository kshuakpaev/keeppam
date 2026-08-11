import { useEffect, useState, type FormEvent } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, hasPerm, type AccessBinding, type AppIntegration, type Asset, type AssetAccount, type CommandPolicyPack, type Role, type User } from "../api";
import { useAuth } from "../auth";
import { kindForProtocol, useSessionTabs } from "../sessionTabs";

const PROTOCOLS = ["ssh", "rdp", "vnc", "https", "postgres", "mysql"];
const TYPES = ["host", "db", "k8s", "api"];
const DAY_LABELS = ["Вс", "Пн", "Вт", "Ср", "Чт", "Пт", "Сб"];

export function AssetEditPage() {
  const { id } = useParams<{ id: string }>();
  const { user } = useAuth();
  const nav = useNavigate();
  const { openTab } = useSessionTabs();
  const [asset, setAsset] = useState<Asset | null>(null);
  const [bindings, setBindings] = useState<AccessBinding[]>([]);
  const [roles, setRoles] = useState<Role[]>([]);
  const [users, setUsers] = useState<User[]>([]);
  const [cmdPacks, setCmdPacks] = useState<CommandPolicyPack[]>([]);
  const [error, setError] = useState("");
  const [msg, setMsg] = useState("");
  const [loading, setLoading] = useState(true);
  const [connecting, setConnecting] = useState<string | null>(null);
  const [rotating, setRotating] = useState<string | null>(null);
  const [form, setForm] = useState({
    name: "",
    asset_type: "host",
    hostname: "",
    address: "",
    port: 22,
    protocol: "ssh",
    description: "",
    status: "active",
    tags: "",
  });
  const [accForm, setAccForm] = useState({
    username: "",
    auth_method: "password",
    secret: "",
    description: "",
  });
  const [aclForm, setAclForm] = useState({
    kind: "role" as "role" | "user",
    role_id: "",
    user_id: "",
    time_start: "",
    time_end: "",
    days_of_week: 127,
    duration_minutes: "",
    required_tags: "",
    require_ticket: false,
    command_policy_pack_id: "",
  });
  const [jitForm, setJitForm] = useState({ reason: "", duration_minutes: 60, ticket_id: "" });
  const [connectTicket, setConnectTicket] = useState("");
  const [dbPrivilege, setDbPrivilege] = useState<"readonly" | "readwrite">("readonly");
  const [appForm, setAppForm] = useState({
    auth_mode: "vault_password",
    login_url: "",
    oidc_issuer: "",
    oidc_client_id: "",
    oidc_client_secret: "",
    recording_mode: "off",
    header_name: "",
  });
  const [appLoaded, setAppLoaded] = useState(false);

  const canWrite = hasPerm(user, "assets.write");
  const canConnect = hasPerm(user, "sessions.connect");
  const canACL = hasPerm(user, "assets.acl");
  const canUsers = hasPerm(user, "users.read");
  const canRequest = hasPerm(user, "access.request");
  const canAppsRead = hasPerm(user, "apps.read") || canWrite;
  const canAppsWrite = hasPerm(user, "apps.write");

  async function load() {
    if (!id) return;
    setLoading(true);
    try {
      const a = await api.getAsset(id);
      setAsset(a);
      setForm({
        name: a.name,
        asset_type: a.asset_type,
        hostname: a.hostname || "",
        address: a.address,
        port: a.port,
        protocol: a.protocol,
        description: a.description || "",
        status: a.status,
        tags: (a.tags || []).join(", "),
      });
      const acl = await api.listACL(id);
      setBindings(acl.bindings || []);
      if (canACL || canUsers) {
        const r = await api.listRoles();
        setRoles(r.roles || []);
      }
      if (canUsers) {
        const u = await api.listUsers();
        setUsers(u.users || []);
      }
      if (canACL || hasPerm(user, "jea.read")) {
        try {
          const pk = await api.listCommandPacks();
          setCmdPacks(pk.packs || []);
        } catch {
          setCmdPacks([]);
        }
      }
      if (a.protocol === "https" && (hasPerm(user, "apps.read") || canWrite)) {
        try {
          const app = await api.getAppIntegration(id);
          setAppForm({
            auth_mode: app.auth_mode || "vault_password",
            login_url: app.login_url || "",
            oidc_issuer: app.oidc_issuer || "",
            oidc_client_id: app.oidc_client_id || "",
            oidc_client_secret: "",
            recording_mode: app.recording_mode || "off",
            header_name: app.header_name || "",
          });
          setAppLoaded(true);
        } catch {
          setAppLoaded(true);
        }
      } else {
        setAppLoaded(false);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка загрузки");
      setAsset(null);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void load();
  }, [id]);

  async function onConnect(acc: AssetAccount) {
    if (!id || !asset) return;
    setError("");
    setConnecting(acc.id);
    try {
      const sess = await api.createSession(id, acc.id, {
        ticket_id: connectTicket.trim() || undefined,
        db_privilege:
          asset.protocol === "postgres" || asset.protocol === "mysql" ? dbPrivilege : undefined,
      });
      const title = `${asset.name} · ${acc.username}`;
      const kind = kindForProtocol(asset.protocol);
      if (asset.protocol === "postgres" || asset.protocol === "mysql") {
        if (sess.wire_token) {
          setMsg(
            `Wire: host=PAM port=${sess.wire_addr || (asset.protocol === "mysql" ? ":13306" : ":15432")} user=${sess.wire_user || sess.id} password=${sess.wire_token}`,
          );
        }
      }
      openTab({
        id: sess.id,
        kind,
        title,
        protocol: asset.protocol,
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Не удалось начать сессию");
    } finally {
      setConnecting(null);
    }
  }

  async function onAppAccess(acc: AssetAccount) {
    if (!id || !asset) return;
    setError("");
    setMsg("");
    setConnecting(acc.id);
    try {
      const lease = await api.requestAppAccess(id, {
        account_id: acc.id,
        ticket_id: connectTicket.trim() || undefined,
      });
      if (lease.auth_mode === "oidc_broker" && lease.open_url) {
        window.open(lease.open_url, "_blank");
        setMsg("OIDC redirect открыт в новой вкладке");
      } else {
        setMsg(
          `Lease до ${new Date(lease.expires_at).toLocaleString()}: ${lease.username} / ${lease.secret || "—"} → ${lease.open_url || lease.login_url || ""}`,
        );
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка доступа к приложению");
    } finally {
      setConnecting(null);
    }
  }

  async function onSave(e: FormEvent) {
    e.preventDefault();
    if (!id || !canWrite) return;
    setError("");
    setMsg("");
    try {
      const updated = await api.updateAsset(id, {
        name: form.name,
        asset_type: form.asset_type,
        hostname: form.hostname,
        address: form.address,
        port: Number(form.port),
        protocol: form.protocol,
        description: form.description,
        status: form.status,
        tags: form.tags
          .split(",")
          .map((t) => t.trim())
          .filter(Boolean),
      });
      setAsset(updated);
      setMsg("Сохранено");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка сохранения");
    }
  }

  async function onDelete() {
    if (!id || !canWrite) return;
    if (!confirm("Удалить актив и все учётные записи?")) return;
    try {
      await api.deleteAsset(id);
      nav("/assets");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка удаления");
    }
  }

  async function onClearHostKey() {
    if (!id || !canWrite) return;
    if (!confirm("Сбросить запомненный SSH host key? Следующее подключение запомнит ключ заново.")) return;
    setError("");
    try {
      const a = await api.clearAssetHostKey(id);
      setAsset(a);
      setMsg("Host key сброшен");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка сброса host key");
    }
  }

  async function onAddAccount(e: FormEvent) {
    e.preventDefault();
    if (!id || !canWrite) return;
    setError("");
    try {
      await api.createAccount(id, {
        username: accForm.username,
        auth_method: accForm.auth_method,
        secret: accForm.secret || undefined,
        description: accForm.description,
      });
      setAccForm({ username: "", auth_method: "password", secret: "", description: "" });
      setMsg("Учётная запись добавлена");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка создания учётки");
    }
  }

  async function onDeleteAccount(acc: AssetAccount) {
    if (!id || !canWrite) return;
    if (!confirm(`Удалить учётную запись ${acc.username}?`)) return;
    try {
      await api.deleteAccount(id, acc.id);
      setMsg("Учётная запись удалена");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка удаления");
    }
  }

  async function onToggleAccount(acc: AssetAccount) {
    if (!id || !canWrite) return;
    const status = acc.status === "active" ? "disabled" : "active";
    try {
      await api.updateAccount(id, acc.id, { status });
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка");
    }
  }

  async function onRotateAccount(acc: AssetAccount, applyRemote: boolean) {
    if (!id || !canWrite || !asset) return;
    const kind = acc.auth_method === "ssh_key" ? "SSH-ключ" : "пароль";
    const confirmMsg = applyRemote
      ? `Ротировать ${kind} для ${acc.username} на цели и обновить vault?\nНовый секрет не будет показан.`
      : `Обновить только vault для ${acc.username} (${kind})?`;
    if (!confirm(confirmMsg)) return;

    let body: {
      apply_remote?: boolean;
      new_secret?: string;
      remove_old_key?: boolean;
    } = { apply_remote: applyRemote };

    if (!applyRemote) {
      const hint =
        acc.auth_method === "ssh_key"
          ? "Новый приватный ключ (PEM). Пусто = сгенерировать ed25519:"
          : "Новый пароль (пусто = сгенерировать):";
      const secret = window.prompt(hint, "");
      if (secret === null) return;
      if (secret.trim()) body.new_secret = secret.trim();
    } else if (acc.auth_method === "ssh_key") {
      body.remove_old_key = confirm("Удалить старый публичный ключ из authorized_keys после проверки?");
    }

    setRotating(acc.id);
    setError("");
    setMsg("");
    try {
      const res = await api.rotateAccount(id, acc.id, body);
      setMsg(
        res.remote_applied
          ? `Секрет ${acc.username} (${res.method}) сменён на цели и в vault`
          : `Vault обновлён для ${acc.username} (${res.method})`,
      );
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка ротации");
    } finally {
      setRotating(null);
    }
  }

  function canRemoteRotate(acc: AssetAccount): boolean {
    if (!asset || acc.status !== "active" || !acc.has_secret) return false;
    const p = asset.protocol;
    if (acc.auth_method === "password") {
      return p === "ssh" || p === "rdp" || p === "vnc" || p === "postgres" || p === "mysql";
    }
    if (acc.auth_method === "ssh_key") {
      return p === "ssh" || p === "rdp" || p === "vnc";
    }
    return false;
  }

  async function onAddACL(e: FormEvent) {
    e.preventDefault();
    if (!id || !canACL) return;
    setError("");
    try {
      const body: {
        user_id?: string;
        role_id?: string;
        time_start?: string;
        time_end?: string;
        days_of_week?: number;
        duration_minutes?: number;
        required_tags?: string[];
        require_ticket?: boolean;
        command_policy_pack_id?: string;
      } = {
        days_of_week: aclForm.days_of_week,
        require_ticket: aclForm.require_ticket,
      };
      if (aclForm.kind === "role") {
        if (!aclForm.role_id) throw new Error("выберите роль");
        body.role_id = aclForm.role_id;
      } else {
        if (!aclForm.user_id) throw new Error("выберите пользователя");
        body.user_id = aclForm.user_id;
      }
      if (aclForm.time_start) body.time_start = aclForm.time_start;
      if (aclForm.time_end) body.time_end = aclForm.time_end;
      if (aclForm.duration_minutes) {
        body.duration_minutes = Number(aclForm.duration_minutes);
      }
      const tags = aclForm.required_tags
        .split(",")
        .map((x) => x.trim())
        .filter(Boolean);
      if (tags.length) body.required_tags = tags;
      if (aclForm.command_policy_pack_id) {
        body.command_policy_pack_id = aclForm.command_policy_pack_id;
      }
      await api.createACL(id, body);
      setMsg("Доступ выдан");
      setAclForm({
        kind: "role",
        role_id: roles[0]?.id || "",
        user_id: "",
        time_start: "",
        time_end: "",
        days_of_week: 127,
        duration_minutes: "",
        required_tags: "",
        require_ticket: false,
        command_policy_pack_id: "",
      });
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка ACL");
    }
  }

  async function onRequestAccess(e: FormEvent) {
    e.preventDefault();
    if (!id || !canRequest) return;
    setError("");
    try {
      await api.createAccessRequest(id, {
        reason: jitForm.reason,
        duration_minutes: Number(jitForm.duration_minutes) || 60,
        ticket_id: jitForm.ticket_id.trim() || undefined,
      });
      setMsg("Запрос отправлен — ждите согласования");
      setJitForm({ reason: "", duration_minutes: 60, ticket_id: "" });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка запроса");
    }
  }

  async function onDeleteACL(b: AccessBinding) {
    if (!id || !canACL) return;
    try {
      await api.deleteACL(id, b.id);
      setMsg("Доступ отозван");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка");
    }
  }

  function toggleDay(bit: number) {
    setAclForm((f) => ({
      ...f,
      days_of_week: f.days_of_week & bit ? f.days_of_week & ~bit : f.days_of_week | bit,
    }));
  }

  function formatDays(mask: number): string {
    if (mask === 127) return "все дни";
    return DAY_LABELS.filter((_, i) => mask & (1 << i)).join(", ") || "—";
  }

  if (loading) return <p className="muted">Загрузка…</p>;
  if (!asset) {
    return (
      <div>
        <p className="error">{error || "Актив не найден"}</p>
        <Link to="/assets">← К списку</Link>
      </div>
    );
  }

  return (
    <div>
      <div className="toolbar">
        <div>
          <p className="muted" style={{ marginBottom: "0.35rem" }}>
            <Link to="/assets">Активы</Link> / {asset.name}
          </p>
          <h1>Редактирование актива</h1>
          <p className="muted mono">
            {asset.id} · протокол <strong>{asset.protocol}</strong> · {asset.address}:{asset.port}
          </p>
        </div>
        <button className="btn secondary" type="button" onClick={() => nav("/assets")}>
          Назад
        </button>
      </div>

      {error && <p className="error">{error}</p>}
      {msg && <p className="ok">{msg}</p>}

      <form className="card" onSubmit={onSave} style={{ maxWidth: 560, marginBottom: "1.25rem" }}>
        <h2>Параметры</h2>
        <label>Имя</label>
        <input
          value={form.name}
          onChange={(e) => setForm({ ...form, name: e.target.value })}
          disabled={!canWrite}
          required
        />
        <label>Тип</label>
        <select
          value={form.asset_type}
          onChange={(e) => setForm({ ...form, asset_type: e.target.value })}
          disabled={!canWrite}
        >
          {TYPES.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
        <label>Адрес</label>
        <input
          value={form.address}
          onChange={(e) => setForm({ ...form, address: e.target.value })}
          disabled={!canWrite}
          required
        />
        <label>Hostname</label>
        <input
          value={form.hostname}
          onChange={(e) => setForm({ ...form, hostname: e.target.value })}
          disabled={!canWrite}
        />
        <div className="row" style={{ alignItems: "flex-end" }}>
          <div style={{ flex: 1 }}>
            <label>Протокол</label>
            <select
              value={form.protocol}
              onChange={(e) => setForm({ ...form, protocol: e.target.value })}
              disabled={!canWrite}
            >
              {PROTOCOLS.map((p) => (
                <option key={p} value={p}>
                  {p}
                </option>
              ))}
            </select>
          </div>
          <div style={{ width: 120 }}>
            <label>Порт</label>
            <input
              type="number"
              value={form.port}
              onChange={(e) => setForm({ ...form, port: Number(e.target.value) })}
              disabled={!canWrite}
            />
          </div>
        </div>
        <label>Статус</label>
        <select
          value={form.status}
          onChange={(e) => setForm({ ...form, status: e.target.value })}
          disabled={!canWrite}
        >
          <option value="active">active</option>
          <option value="disabled">disabled</option>
        </select>
        <label>Теги</label>
        <input
          value={form.tags}
          onChange={(e) => setForm({ ...form, tags: e.target.value })}
          disabled={!canWrite}
        />
        <label>Описание</label>
        <input
          value={form.description}
          onChange={(e) => setForm({ ...form, description: e.target.value })}
          disabled={!canWrite}
        />
        <div className="row" style={{ marginTop: "0.5rem" }}>
          {canWrite && (
            <button className="btn" type="submit">
              Сохранить
            </button>
          )}
          {canWrite && (
            <button className="btn danger" type="button" onClick={() => void onDelete()}>
              Удалить
            </button>
          )}
        </div>
      </form>

      {asset.protocol === "https" && appLoaded && (canAppsRead || canAppsWrite) && (
        <form
          className="card"
          style={{ maxWidth: 560, marginBottom: "1.25rem" }}
          onSubmit={(e) => {
            e.preventDefault();
            if (!id || !canAppsWrite) return;
            void (async () => {
              setError("");
              try {
                const body: Partial<AppIntegration> & {
                  oidc_client_secret?: string;
                } = {
                  auth_mode: appForm.auth_mode,
                  login_url: appForm.login_url,
                  oidc_issuer: appForm.oidc_issuer,
                  oidc_client_id: appForm.oidc_client_id,
                  recording_mode: appForm.recording_mode,
                  header_name: appForm.header_name,
                };
                if (appForm.oidc_client_secret) {
                  body.oidc_client_secret = appForm.oidc_client_secret;
                }
                await api.putAppIntegration(id, body);
                setMsg("Интеграция приложения сохранена");
                setAppForm((f) => ({ ...f, oidc_client_secret: "" }));
              } catch (err) {
                setError(err instanceof Error ? err.message : "Ошибка сохранения app");
              }
            })();
          }}
        >
          <h2>Приложение (PAM)</h2>
          <p className="muted">SSO/JIT lease или HTTPS proxy (recording_mode=full)</p>
          <label>Режим auth</label>
          <select
            value={appForm.auth_mode}
            onChange={(e) => setAppForm({ ...appForm, auth_mode: e.target.value })}
            disabled={!canAppsWrite}
          >
            <option value="vault_password">vault_password</option>
            <option value="oidc_broker">oidc_broker</option>
            <option value="header_inject">header_inject</option>
          </select>
          <label>Login / target URL</label>
          <input
            value={appForm.login_url}
            onChange={(e) => setAppForm({ ...appForm, login_url: e.target.value })}
            disabled={!canAppsWrite}
            placeholder="https://app.example/"
          />
          <label>Recording mode</label>
          <select
            value={appForm.recording_mode}
            onChange={(e) => setAppForm({ ...appForm, recording_mode: e.target.value })}
            disabled={!canAppsWrite}
          >
            <option value="off">off (только lease/OIDC)</option>
            <option value="full">full (HTTPS proxy session)</option>
          </select>
          <label>OIDC issuer</label>
          <input
            value={appForm.oidc_issuer}
            onChange={(e) => setAppForm({ ...appForm, oidc_issuer: e.target.value })}
            disabled={!canAppsWrite}
          />
          <label>OIDC client id</label>
          <input
            value={appForm.oidc_client_id}
            onChange={(e) => setAppForm({ ...appForm, oidc_client_id: e.target.value })}
            disabled={!canAppsWrite}
          />
          <label>OIDC client secret</label>
          <input
            type="password"
            value={appForm.oidc_client_secret}
            onChange={(e) => setAppForm({ ...appForm, oidc_client_secret: e.target.value })}
            disabled={!canAppsWrite}
            placeholder="оставить пустым = не менять"
          />
          <label>Header name (header_inject)</label>
          <input
            value={appForm.header_name}
            onChange={(e) => setAppForm({ ...appForm, header_name: e.target.value })}
            disabled={!canAppsWrite}
          />
          {canAppsWrite && (
            <button className="btn" type="submit">
              Сохранить интеграцию
            </button>
          )}
        </form>
      )}

      {asset.protocol === "ssh" && (
        <div className="card" style={{ maxWidth: 560, marginBottom: "1.25rem" }}>
          <h2>SSH host key (TOFU)</h2>
          {asset.host_key_fingerprint ? (
            <>
              <p className="muted" style={{ marginBottom: "0.5rem" }}>
                Запомнен при первом подключении. Смена ключа без сброса блокирует сессию.
              </p>
              <p className="mono" style={{ wordBreak: "break-all" }}>
                {asset.host_key_algo || "ssh"} · {asset.host_key_fingerprint}
              </p>
              {asset.host_key_learned_at && (
                <p className="muted">learned {new Date(asset.host_key_learned_at).toLocaleString()}</p>
              )}
              {canWrite && (
                <button
                  className="btn secondary"
                  type="button"
                  style={{ marginTop: "0.5rem" }}
                  onClick={() => void onClearHostKey()}
                >
                  Сбросить host key
                </button>
              )}
            </>
          ) : (
            <p className="muted">Ещё не запомнен — сохранится при первом SSH-подключении.</p>
          )}
        </div>
      )}

      <div className="card" style={{ marginBottom: "1.25rem" }}>
        <h2>Учётные записи цели</h2>
        <label>Ticket ID для подключения</label>
        <input
          value={connectTicket}
          onChange={(e) => setConnectTicket(e.target.value)}
          placeholder="INC-12345 (если ACL требует тикет)"
          style={{ maxWidth: 320, marginBottom: "0.75rem" }}
        />
        {(asset.protocol === "postgres" || asset.protocol === "mysql") && (
          <>
            <label>Ephemeral DB privilege</label>
            <select
              value={dbPrivilege}
              onChange={(e) => setDbPrivilege(e.target.value as "readonly" | "readwrite")}
              style={{ maxWidth: 320, marginBottom: "0.75rem" }}
            >
              <option value="readonly">readonly — SELECT only (временная роль)</option>
              <option value="readwrite">readwrite — SELECT/INSERT/UPDATE/DELETE</option>
            </select>
            <p className="muted" style={{ marginTop: 0 }}>
              Vault-учётка используется только для CREATE/DROP ROLE; запросы идут под временным пользователем.
            </p>
          </>
        )}
        <p className="muted">
          {asset.protocol === "rdp" || asset.protocol === "vnc" ? (
            <>
              Протокол <span className="mono">{asset.protocol.toUpperCase()}</span> — у учётки нажмите{" "}
              <strong>Открыть {asset.protocol.toUpperCase()}</strong>, откроется Desktop в браузере.
            </>
          ) : (
            <>
              Секреты хранятся в зашифрованном виде. Подключение: кнопка SSH или{" "}
              <span className="mono">ssh -p 2222 user@pam -t &apos;{asset.name}/account&apos;</span>
            </>
          )}
        </p>
        <table>
          <thead>
            <tr>
              <th>Логин</th>
              <th>Метод</th>
              <th>Секрет</th>
              <th>Ротация</th>
              <th>Статус</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {(asset.accounts || []).map((acc) => (
              <tr key={acc.id}>
                <td className="mono">{acc.username}</td>
                <td className="mono">{acc.auth_method}</td>
                <td>{acc.has_secret ? "задан" : "нет"}</td>
                <td className="muted" style={{ fontSize: "0.85rem" }}>
                  {acc.last_rotated_at
                    ? new Date(acc.last_rotated_at).toLocaleString()
                    : "—"}
                </td>
                <td>
                  <span className={`badge ${acc.status}`}>{acc.status}</span>
                </td>
                <td>
                  <div className="row">
                    {canConnect &&
                      (asset.protocol === "ssh" ||
                        asset.protocol === "rdp" ||
                        asset.protocol === "vnc" ||
                        asset.protocol === "postgres" ||
                        asset.protocol === "mysql" ||
                        asset.protocol === "https") &&
                      asset.status === "active" &&
                      acc.status === "active" &&
                      acc.has_secret && (
                        <>
                          {(asset.protocol === "https" ? (
                            <button
                              className="btn"
                              type="button"
                              disabled={connecting === acc.id}
                              onClick={() => void onAppAccess(acc)}
                            >
                              {connecting === acc.id ? "…" : "Получить доступ"}
                            </button>
                          ) : (
                            <button
                              className="btn"
                              type="button"
                              disabled={connecting === acc.id}
                              onClick={() => void onConnect(acc)}
                            >
                              {connecting === acc.id
                                ? "…"
                                : asset.protocol === "ssh"
                                  ? "Открыть SSH"
                                  : asset.protocol === "postgres" || asset.protocol === "mysql"
                                    ? "SQL-консоль"
                                    : `Открыть ${asset.protocol.toUpperCase()}`}
                            </button>
                          ))}
                          {asset.protocol === "https" && (
                            <button
                              className="btn secondary"
                              type="button"
                              disabled={connecting === acc.id}
                              onClick={() => void onConnect(acc)}
                              title="Требует recording_mode=full"
                            >
                              Proxy-сессия
                            </button>
                          )}
                        </>
                      )}
                    {canWrite && acc.status === "active" && (
                        <>
                          {canRemoteRotate(acc) && (
                            <button
                              className="btn secondary"
                              type="button"
                              disabled={rotating === acc.id}
                              onClick={() => void onRotateAccount(acc, true)}
                              title={
                                asset.protocol === "rdp" || asset.protocol === "vnc"
                                  ? "Remote через SSH :22 на том же хосте"
                                  : "Сменить секрет на цели и в vault"
                              }
                            >
                              {rotating === acc.id ? "Ротация…" : "Ротировать"}
                            </button>
                          )}
                          <button
                            className="btn secondary"
                            type="button"
                            disabled={rotating === acc.id}
                            onClick={() => void onRotateAccount(acc, false)}
                            title="Только обновить секрет в vault"
                          >
                            Vault
                          </button>
                        </>
                      )}
                    {canWrite && (
                      <>
                        <button
                          className="btn secondary"
                          type="button"
                          onClick={() => void onToggleAccount(acc)}
                        >
                          {acc.status === "active" ? "Отключить" : "Включить"}
                        </button>
                        <button
                          className="btn danger"
                          type="button"
                          onClick={() => void onDeleteAccount(acc)}
                        >
                          Удалить
                        </button>
                      </>
                    )}
                  </div>
                </td>
              </tr>
            ))}
            {(asset.accounts || []).length === 0 && (
              <tr>
                <td colSpan={6} className="muted">
                  Нет учёток — добавьте ниже (для RDP/VNC нужен пароль).
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {canWrite && (
        <form className="card" onSubmit={onAddAccount} style={{ maxWidth: 560, marginBottom: "1.25rem" }}>
          <h2>Добавить учётную запись</h2>
          <label>Логин на цели</label>
          <input
            value={accForm.username}
            onChange={(e) => setAccForm({ ...accForm, username: e.target.value })}
            required
          />
          <label>Метод аутентификации</label>
          <select
            value={accForm.auth_method}
            onChange={(e) => setAccForm({ ...accForm, auth_method: e.target.value })}
          >
            <option value="password">password</option>
            <option value="ssh_key">ssh_key</option>
          </select>
          <label>{accForm.auth_method === "ssh_key" ? "Приватный ключ" : "Пароль"}</label>
          <input
            type={accForm.auth_method === "ssh_key" ? "text" : "password"}
            value={accForm.secret}
            onChange={(e) => setAccForm({ ...accForm, secret: e.target.value })}
            autoComplete="off"
          />
          <label>Описание</label>
          <input
            value={accForm.description}
            onChange={(e) => setAccForm({ ...accForm, description: e.target.value })}
          />
          <button className="btn" type="submit">
            Добавить
          </button>
        </form>
      )}

      {canRequest && (
        <form className="card" onSubmit={onRequestAccess} style={{ maxWidth: 560, marginBottom: "1.25rem" }}>
          <h2>Запросить JIT-доступ</h2>
          <p className="muted">
            Временный доступ после согласования администратором.{" "}
            <Link to="/access-requests">Очередь запросов</Link>
          </p>
          <label>Длительность (мин)</label>
          <select
            value={jitForm.duration_minutes}
            onChange={(e) => setJitForm({ ...jitForm, duration_minutes: Number(e.target.value) })}
          >
            <option value={15}>15</option>
            <option value={30}>30</option>
            <option value={60}>60</option>
            <option value={120}>120</option>
            <option value={240}>240</option>
            <option value={480}>480</option>
          </select>
          <label>Ticket ID</label>
          <input
            value={jitForm.ticket_id}
            onChange={(e) => setJitForm({ ...jitForm, ticket_id: e.target.value })}
            placeholder="INC-12345"
          />
          <label>Причина</label>
          <input
            value={jitForm.reason}
            onChange={(e) => setJitForm({ ...jitForm, reason: e.target.value })}
            placeholder="INC-123 / срочный доступ"
          />
          <button className="btn" type="submit">
            Отправить запрос
          </button>
        </form>
      )}

      <div className="card" style={{ marginBottom: "1.25rem" }}>
        <h2>Политика доступа</h2>
        <p className="muted">
          Deny-by-default + ABAC: required_tags (у user и asset) и опциональный ticket. JIT истекает по expires_at.
          JEA-пакет ограничивает команды в SSH (см.{" "}
          <Link to="/jea">JEA</Link>).
        </p>
        <table>
          <thead>
            <tr>
              <th>Субъект</th>
              <th>Окно</th>
              <th>Дни</th>
              <th>ABAC</th>
              <th>JEA</th>
              <th>Истекает</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {bindings.map((b) => (
              <tr key={b.id}>
                <td>
                  {b.username ? (
                    <>
                      user <span className="mono">{b.username}</span>
                    </>
                  ) : (
                    <>
                      role <span className="mono">{b.role_name}</span>
                    </>
                  )}
                </td>
                <td className="mono">
                  {b.time_start || b.time_end
                    ? `${b.time_start || "00:00"}–${b.time_end || "24:00"}`
                    : "всегда"}
                </td>
                <td>{formatDays(b.days_of_week)}</td>
                <td className="mono" style={{ fontSize: "0.85rem" }}>
                  {(b.required_tags || []).length ? (b.required_tags || []).join(", ") : "—"}
                  {b.require_ticket ? " · ticket" : ""}
                </td>
                <td className="mono" style={{ fontSize: "0.85rem" }}>
                  {b.command_policy_pack_name || "—"}
                </td>
                <td className="mono">
                  {b.expires_at ? (
                    <>
                      {new Date(b.expires_at).toLocaleString()}
                      {new Date(b.expires_at).getTime() < Date.now() && (
                        <span className="badge locked" style={{ marginLeft: 6 }}>
                          expired
                        </span>
                      )}
                    </>
                  ) : (
                    "постоянно"
                  )}
                </td>
                <td>
                  {canACL && (
                    <button className="btn danger" type="button" onClick={() => void onDeleteACL(b)}>
                      Отозвать
                    </button>
                  )}
                </td>
              </tr>
            ))}
            {bindings.length === 0 && (
              <tr>
                <td colSpan={7} className="muted">
                  Привязок нет — доступ только у admin
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {canACL && (
        <form className="card" onSubmit={onAddACL} style={{ maxWidth: 560 }}>
          <h2>Выдать доступ</h2>
          <label>Тип</label>
          <select
            value={aclForm.kind}
            onChange={(e) =>
              setAclForm({ ...aclForm, kind: e.target.value as "role" | "user" })
            }
          >
            <option value="role">Роль</option>
            <option value="user">Пользователь</option>
          </select>
          {aclForm.kind === "role" ? (
            <>
              <label>Роль</label>
              <select
                value={aclForm.role_id}
                onChange={(e) => setAclForm({ ...aclForm, role_id: e.target.value })}
                required
              >
                <option value="">—</option>
                {roles.map((r) => (
                  <option key={r.id} value={r.id}>
                    {r.name}
                  </option>
                ))}
              </select>
            </>
          ) : (
            <>
              <label>Пользователь</label>
              <select
                value={aclForm.user_id}
                onChange={(e) => setAclForm({ ...aclForm, user_id: e.target.value })}
                required
              >
                <option value="">—</option>
                {users.map((u) => (
                  <option key={u.id} value={u.id}>
                    {u.username}
                  </option>
                ))}
              </select>
            </>
          )}
          <div className="row" style={{ alignItems: "flex-end" }}>
            <div style={{ flex: 1 }}>
              <label>С (HH:MM, опц.)</label>
              <input
                placeholder="09:00"
                value={aclForm.time_start}
                onChange={(e) => setAclForm({ ...aclForm, time_start: e.target.value })}
              />
            </div>
            <div style={{ flex: 1 }}>
              <label>До (HH:MM, опц.)</label>
              <input
                placeholder="18:00"
                value={aclForm.time_end}
                onChange={(e) => setAclForm({ ...aclForm, time_end: e.target.value })}
              />
            </div>
            <div style={{ width: 140 }}>
              <label>JIT мин (опц.)</label>
              <input
                type="number"
                min={1}
                max={1440}
                placeholder="постоянно"
                value={aclForm.duration_minutes}
                onChange={(e) => setAclForm({ ...aclForm, duration_minutes: e.target.value })}
              />
            </div>
          </div>
          <label>Дни недели</label>
          <div className="row" style={{ marginBottom: "0.9rem" }}>
            {DAY_LABELS.map((label, i) => {
              const bit = 1 << i;
              const on = (aclForm.days_of_week & bit) !== 0;
              return (
                <button
                  key={label}
                  type="button"
                  className={on ? "btn" : "btn secondary"}
                  onClick={() => toggleDay(bit)}
                >
                  {label}
                </button>
              );
            })}
          </div>
          <label>Required tags (через запятую)</label>
          <input
            value={aclForm.required_tags}
            onChange={(e) => setAclForm({ ...aclForm, required_tags: e.target.value })}
            placeholder="pci, prod"
          />
          <label className="row" style={{ gap: "0.5rem", alignItems: "center" }}>
            <input
              type="checkbox"
              checked={aclForm.require_ticket}
              onChange={(e) => setAclForm({ ...aclForm, require_ticket: e.target.checked })}
            />
            Требовать ticket_id при подключении
          </label>
          <label>JEA command pack (опц.)</label>
          <select
            value={aclForm.command_policy_pack_id}
            onChange={(e) => setAclForm({ ...aclForm, command_policy_pack_id: e.target.value })}
          >
            <option value="">— без ограничения команд —</option>
            {cmdPacks.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name} ({p.mode})
              </option>
            ))}
          </select>
          <button className="btn" type="submit">
            Выдать
          </button>
        </form>
      )}
    </div>
  );
}
