import { useEffect, useState, type FormEvent } from "react";
import {
  api,
  hasPerm,
  type AuthSettings,
  type InfraStatus,
  type ITSMSettings,
  type SIEMSettings,
  type SSHSettings,
} from "../api";
import { useAuth } from "../auth";

const empty: AuthSettings = {
  mode: "local",
  public_base_url: "http://localhost:5173",
  oidc_issuer: "",
  oidc_client_id: "",
  has_oidc_secret: false,
  oidc_scopes: "openid profile email",
  oidc_auto_provision: true,
  oidc_skip_mfa: true,
  oidc_default_role: "operator",
  ldap_url: "",
  ldap_bind_dn: "",
  has_ldap_bind_password: false,
  ldap_user_base_dn: "",
  ldap_user_filter: "(uid=%s)",
  ldap_attr_username: "uid",
  ldap_attr_email: "mail",
  ldap_attr_display_name: "cn",
  ldap_start_tls: false,
  ldap_insecure_tls: false,
  ldap_auto_provision: true,
  ldap_skip_mfa: false,
  ldap_default_role: "operator",
};

const emptySSH: SSHSettings = {
  ssh_auth_mode: "vault_secret",
  ssh_ca_public: "",
  ssh_cert_ttl_hours: 8,
  has_ssh_ca: false,
};

const emptySIEM: SIEMSettings = {
  enabled: false,
  transport: "off",
  syslog_addr: "",
  syslog_tag: "keeppam",
  syslog_facility: 16,
  webhook_url: "",
  has_webhook_auth_header: false,
  format: "json",
  batch_size: 100,
  poll_interval_sec: 10,
};

const emptyITSM: ITSMSettings = {
  enabled: false,
  provider: "mock",
  base_url: "",
  has_auth_header: false,
  ticket_path_template: "/rest/api/2/issue/{ticket}",
  status_json_path: "fields.status.name",
  ok_statuses: ["Open", "In Progress", "To Do", "New", "Assigned", "Work in Progress"],
  require_on_request: false,
  require_on_approve: true,
  require_on_connect: true,
  cache_ttl_sec: 60,
  timeout_sec: 8,
};

export function ConfigPage() {
  const { user } = useAuth();
  const [form, setForm] = useState<AuthSettings>(empty);
  const [siem, setSiem] = useState<SIEMSettings>(emptySIEM);
  const [itsm, setItsm] = useState<ITSMSettings>(emptyITSM);
  const [ssh, setSsh] = useState<SSHSettings>(emptySSH);
  const [infra, setInfra] = useState<InfraStatus | null>(null);
  const [secret, setSecret] = useState("");
  const [ldapPass, setLdapPass] = useState("");
  const [webhookAuth, setWebhookAuth] = useState("");
  const [itsmAuth, setItsmAuth] = useState("");
  const [itsmTicket, setItsmTicket] = useState("DEMO-100");
  const [itsmCheck, setItsmCheck] = useState("");
  const [error, setError] = useState("");
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState(false);
  const canWrite = hasPerm(user, "settings.write");

  useEffect(() => {
    if (!canWrite) return;
    void (async () => {
      try {
        const [s, si, sh, inf, it] = await Promise.all([
          api.getAuthSettings(),
          api.getSIEMSettings(),
          api.getSSHSettings(),
          api.getInfraStatus(),
          api.getITSMSettings(),
        ]);
        setForm({ ...empty, ...s });
        setSiem({ ...emptySIEM, ...si });
        setSsh({ ...emptySSH, ...sh });
        setInfra(inf);
        setItsm({
          ...emptyITSM,
          ...it,
          ok_statuses: it.ok_statuses?.length ? it.ok_statuses : emptyITSM.ok_statuses,
        });
      } catch (err) {
        setError(err instanceof Error ? err.message : "Ошибка загрузки");
      }
    })();
  }, [canWrite]);

  if (!canWrite) {
    return <p className="error">Недостаточно прав</p>;
  }

  async function onSave(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    setMsg("");
    try {
      const body: Partial<AuthSettings> = { ...form };
      if (secret.trim()) body.oidc_client_secret = secret.trim();
      if (ldapPass.trim()) body.ldap_bind_password = ldapPass.trim();
      delete body.has_oidc_secret;
      delete body.has_ldap_bind_password;
      const saved = await api.putAuthSettings(body);
      setForm({ ...empty, ...saved });
      setSecret("");
      setLdapPass("");
      setMsg("Авторизация сохранена");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка сохранения");
    } finally {
      setBusy(false);
    }
  }

  async function onSaveITSM(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    setMsg("");
    setItsmCheck("");
    try {
      const body: Partial<ITSMSettings> = {
        ...itsm,
        ok_statuses: (itsm.ok_statuses || [])
          .map((x) => x.trim())
          .filter(Boolean),
      };
      if (itsmAuth.trim()) body.auth_header = itsmAuth.trim();
      delete body.has_auth_header;
      const saved = await api.putITSMSettings(body);
      setItsm({
        ...emptyITSM,
        ...saved,
        ok_statuses: saved.ok_statuses?.length ? saved.ok_statuses : emptyITSM.ok_statuses,
      });
      setItsmAuth("");
      setMsg("ITSM сохранён");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка сохранения ITSM");
    } finally {
      setBusy(false);
    }
  }

  async function onCheckTicket() {
    setBusy(true);
    setError("");
    setItsmCheck("");
    try {
      const info = await api.validateITSMTicket(itsmTicket.trim());
      setItsmCheck(
        `${info.id}: ${info.status}${info.ok ? " · OK" : " · REJECTED"}${info.title ? ` · ${info.title}` : ""}${info.cached ? " (cache)" : ""}`,
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка проверки тикета");
    } finally {
      setBusy(false);
    }
  }

  async function onSaveSIEM(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    setMsg("");
    try {
      const body: Partial<SIEMSettings> = { ...siem };
      if (webhookAuth.trim()) body.webhook_auth_header = webhookAuth.trim();
      delete body.has_webhook_auth_header;
      const saved = await api.putSIEMSettings(body);
      setSiem({ ...emptySIEM, ...saved });
      setWebhookAuth("");
      setMsg("SIEM сохранён");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка сохранения SIEM");
    } finally {
      setBusy(false);
    }
  }

  async function onSaveSSH(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    setMsg("");
    try {
      const saved = await api.putSSHSettings({
        ssh_auth_mode: ssh.ssh_auth_mode,
        ssh_cert_ttl_hours: ssh.ssh_cert_ttl_hours,
      });
      setSsh({ ...emptySSH, ...saved });
      setMsg("SSH сохранён");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка сохранения SSH");
    } finally {
      setBusy(false);
    }
  }

  async function onRotateCA() {
    if (!confirm("Сгенерировать новый CA? Старый ключ перестанет работать на целях.")) return;
    setBusy(true);
    setError("");
    setMsg("");
    try {
      const saved = await api.putSSHSettings({
        ssh_auth_mode: ssh.ssh_auth_mode,
        ssh_cert_ttl_hours: ssh.ssh_cert_ttl_hours,
        rotate_ca: true,
      });
      setSsh({ ...emptySSH, ...saved });
      setMsg("Новый SSH CA сгенерирован — обновите TrustedUserCAKeys на целях");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка ротации CA");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <div className="toolbar">
        <div>
          <h1>Конфигурация</h1>
          <p className="muted">Авторизация, SSH CA, SIEM, ITSM и prod-инфраструктура</p>
        </div>
      </div>
      {error && <p className="error">{error}</p>}
      {msg && <p className="ok">{msg}</p>}

      {infra && (
        <div className="card" style={{ maxWidth: 640, marginBottom: "1.25rem" }}>
          <h2>Инфраструктура (env)</h2>
          <p className="muted" style={{ marginTop: 0 }}>
            Только чтение. Меняется через переменные окружения API / session-worker (см.{" "}
            <span className="mono">docs/prod-infra.txt</span>).
          </p>
          <p>
            Data key: <span className="mono">{infra.data_key_source}</span>
          </p>
          <p>
            Recordings:{" "}
            <span className="mono">
              {infra.recordings_backend}
              {infra.recordings_dir ? ` · ${infra.recordings_dir}` : ""}
            </span>
          </p>
          {infra.recordings_backend === "s3" && (
            <p>
              S3:{" "}
              <span className="mono">
                {infra.s3_endpoint || "—"} / {infra.s3_bucket || "—"}
                {infra.s3_prefix ? ` · prefix=${infra.s3_prefix}` : ""}
              </span>
            </p>
          )}
          <p>
            WORM / Object Lock:{" "}
            <span className="mono">
              {infra.worm_recordings
                ? `${infra.object_lock_mode || "on"} · ${infra.object_lock_days ?? "?"}d`
                : infra.recordings_backend === "s3"
                  ? "s3 без Object Lock"
                  : "n/a (local)"}
            </span>
          </p>
          <p>
            Data key posture:{" "}
            <span className="mono">
              {infra.data_key_source === "vault"
                ? "vault (HSM-capable)"
                : infra.data_key_source}
            </span>
          </p>
          <p>
            TLS / mTLS:{" "}
            <span className="mono">
              {infra.tls_enabled ? "on" : "off"} · client={infra.mtls}
              {infra.cookie_secure ? " · cookie_secure" : ""}
            </span>
          </p>
          <p>
            HTTP: <span className="mono">{infra.http_addr || "—"}</span>
          </p>
        </div>
      )}

      <form className="card" onSubmit={onSave} style={{ maxWidth: 640, marginBottom: "1.25rem" }}>
        <h2>Авторизация</h2>
        <label>Режим входа</label>
        <select
          value={form.mode}
          onChange={(e) => setForm({ ...form, mode: e.target.value })}
        >
          <option value="local">Локальный (логин/пароль + MFA)</option>
          <option value="oidc">OIDC / SSO</option>
          <option value="ldap">LDAP / Active Directory</option>
        </select>

        <label>Public Base URL (для OIDC redirect)</label>
        <input
          value={form.public_base_url}
          onChange={(e) => setForm({ ...form, public_base_url: e.target.value })}
          placeholder="http://localhost:5173"
        />
        <p className="muted" style={{ marginTop: 0 }}>
          Redirect URI: <span className="mono">{form.public_base_url || "…"}/api/v1/auth/oidc/callback</span>
        </p>

        {form.mode === "oidc" && (
          <>
            <h2>OIDC</h2>
            <label>Issuer URL</label>
            <input
              value={form.oidc_issuer}
              onChange={(e) => setForm({ ...form, oidc_issuer: e.target.value })}
              placeholder="https://keycloak.example/realms/keeppam"
              required={form.mode === "oidc"}
            />
            <label>Client ID</label>
            <input
              value={form.oidc_client_id}
              onChange={(e) => setForm({ ...form, oidc_client_id: e.target.value })}
              required={form.mode === "oidc"}
            />
            <label>Client Secret {form.has_oidc_secret ? "(задан, оставьте пустым чтобы не менять)" : ""}</label>
            <input
              type="password"
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
              autoComplete="off"
              placeholder={form.has_oidc_secret ? "••••••••" : ""}
            />
            <label>Scopes</label>
            <input
              value={form.oidc_scopes}
              onChange={(e) => setForm({ ...form, oidc_scopes: e.target.value })}
            />
            <label>Роль по умолчанию при auto-provision</label>
            <input
              value={form.oidc_default_role}
              onChange={(e) => setForm({ ...form, oidc_default_role: e.target.value })}
            />
            <label className="row" style={{ gap: "0.5rem", alignItems: "center" }}>
              <input
                type="checkbox"
                checked={form.oidc_auto_provision}
                onChange={(e) => setForm({ ...form, oidc_auto_provision: e.target.checked })}
              />
              Автосоздание пользователей
            </label>
            <label className="row" style={{ gap: "0.5rem", alignItems: "center" }}>
              <input
                type="checkbox"
                checked={form.oidc_skip_mfa}
                onChange={(e) => setForm({ ...form, oidc_skip_mfa: e.target.checked })}
              />
              Не требовать локальный MFA после SSO
            </label>
          </>
        )}

        {form.mode === "ldap" && (
          <>
            <h2>LDAP</h2>
            <label>URL</label>
            <input
              value={form.ldap_url}
              onChange={(e) => setForm({ ...form, ldap_url: e.target.value })}
              placeholder="ldaps://ldap.example:636"
              required={form.mode === "ldap"}
            />
            <label>Bind DN (service account)</label>
            <input
              value={form.ldap_bind_dn}
              onChange={(e) => setForm({ ...form, ldap_bind_dn: e.target.value })}
            />
            <label>
              Bind password {form.has_ldap_bind_password ? "(задан)" : ""}
            </label>
            <input
              type="password"
              value={ldapPass}
              onChange={(e) => setLdapPass(e.target.value)}
              autoComplete="off"
            />
            <label>User base DN</label>
            <input
              value={form.ldap_user_base_dn}
              onChange={(e) => setForm({ ...form, ldap_user_base_dn: e.target.value })}
              placeholder="ou=people,dc=example,dc=com"
              required={form.mode === "ldap"}
            />
            <label>User filter (%s = username)</label>
            <input
              value={form.ldap_user_filter}
              onChange={(e) => setForm({ ...form, ldap_user_filter: e.target.value })}
            />
            <div className="row" style={{ gap: "0.75rem" }}>
              <div style={{ flex: 1 }}>
                <label>Attr username</label>
                <input
                  value={form.ldap_attr_username}
                  onChange={(e) => setForm({ ...form, ldap_attr_username: e.target.value })}
                />
              </div>
              <div style={{ flex: 1 }}>
                <label>Attr email</label>
                <input
                  value={form.ldap_attr_email}
                  onChange={(e) => setForm({ ...form, ldap_attr_email: e.target.value })}
                />
              </div>
              <div style={{ flex: 1 }}>
                <label>Attr display name</label>
                <input
                  value={form.ldap_attr_display_name}
                  onChange={(e) => setForm({ ...form, ldap_attr_display_name: e.target.value })}
                />
              </div>
            </div>
            <label>Роль по умолчанию</label>
            <input
              value={form.ldap_default_role}
              onChange={(e) => setForm({ ...form, ldap_default_role: e.target.value })}
            />
            <label className="row" style={{ gap: "0.5rem", alignItems: "center" }}>
              <input
                type="checkbox"
                checked={form.ldap_start_tls}
                onChange={(e) => setForm({ ...form, ldap_start_tls: e.target.checked })}
              />
              StartTLS
            </label>
            <label className="row" style={{ gap: "0.5rem", alignItems: "center" }}>
              <input
                type="checkbox"
                checked={form.ldap_insecure_tls}
                onChange={(e) => setForm({ ...form, ldap_insecure_tls: e.target.checked })}
              />
              Не проверять TLS-сертификат
            </label>
            <label className="row" style={{ gap: "0.5rem", alignItems: "center" }}>
              <input
                type="checkbox"
                checked={form.ldap_auto_provision}
                onChange={(e) => setForm({ ...form, ldap_auto_provision: e.target.checked })}
              />
              Автосоздание пользователей
            </label>
            <label className="row" style={{ gap: "0.5rem", alignItems: "center" }}>
              <input
                type="checkbox"
                checked={form.ldap_skip_mfa}
                onChange={(e) => setForm({ ...form, ldap_skip_mfa: e.target.checked })}
              />
              Не требовать локальный MFA после LDAP
            </label>
          </>
        )}

        <button className="btn" type="submit" disabled={busy} style={{ marginTop: "1rem" }}>
          Сохранить авторизацию
        </button>
      </form>

      <form className="card" onSubmit={onSaveSSH} style={{ maxWidth: 640, marginBottom: "1.25rem" }}>
        <h2>SSH-аутентификация к целям</h2>
        <p className="muted">
          Как PAM подключается к SSH-активам. Режим сертификата выдаёт короткоживущий user cert
          (principal = username учётки). На цели нужен{" "}
          <span className="mono">TrustedUserCAKeys</span>.
        </p>
        <label>Режим</label>
        <select
          value={ssh.ssh_auth_mode}
          onChange={(e) => setSsh({ ...ssh, ssh_auth_mode: e.target.value })}
        >
          <option value="vault_secret">Секрет из vault (пароль / ключ учётки)</option>
          <option value="ssh_cert">Эфемерный SSH-сертификат (CA)</option>
        </select>
        <label>TTL сертификата (часы)</label>
        <input
          type="number"
          min={1}
          max={168}
          value={ssh.ssh_cert_ttl_hours}
          onChange={(e) => setSsh({ ...ssh, ssh_cert_ttl_hours: Number(e.target.value) })}
        />
        {ssh.ssh_auth_mode === "ssh_cert" && (
          <>
            <label>CA public key (TrustedUserCAKeys)</label>
            <textarea
              readOnly
              rows={3}
              value={ssh.ssh_ca_public || (ssh.has_ssh_ca ? "" : "Сохраните режим — CA создастся автоматически")}
              className="mono"
              style={{ width: "100%", fontSize: "0.8rem" }}
            />
            {ssh.ssh_ca_public && (
              <button
                className="btn secondary"
                type="button"
                onClick={() => {
                  void navigator.clipboard.writeText(ssh.ssh_ca_public);
                  setMsg("CA pubkey скопирован");
                }}
              >
                Копировать pubkey
              </button>
            )}
            <p className="muted" style={{ marginTop: "0.5rem" }}>
              На цели: положить ключ в <span className="mono">/etc/ssh/keeppam_ca.pub</span>, в{" "}
              <span className="mono">sshd_config</span> добавить{" "}
              <span className="mono">TrustedUserCAKeys /etc/ssh/keeppam_ca.pub</span>, затем{" "}
              <span className="mono">systemctl reload sshd</span>.
            </p>
            <button className="btn secondary" type="button" disabled={busy} onClick={() => void onRotateCA()}>
              Сгенерировать новый CA
            </button>
          </>
        )}
        <button className="btn" type="submit" disabled={busy} style={{ marginTop: "1rem" }}>
          Сохранить SSH
        </button>
      </form>


      <form className="card" onSubmit={onSaveITSM} style={{ maxWidth: 640 }}>
        <h2>ITSM gate (тикеты JIT)</h2>
        <p className="muted">
          Проверка ticket_id против ITSM при запросе / одобрении / подключении. Provider{" "}
          <span className="mono">mock</span>: DEMO-100 открыт, DEMO-CLOSED закрыт.
        </p>
        <label className="row" style={{ gap: "0.5rem", alignItems: "center" }}>
          <input
            type="checkbox"
            checked={itsm.enabled}
            onChange={(e) => setItsm({ ...itsm, enabled: e.target.checked })}
          />
          Включить ITSM gate
        </label>
        <label>Provider</label>
        <select
          value={itsm.provider}
          onChange={(e) => setItsm({ ...itsm, provider: e.target.value })}
        >
          <option value="mock">mock (локальный)</option>
          <option value="jira">Jira</option>
          <option value="servicenow">ServiceNow</option>
          <option value="generic">generic HTTP</option>
        </select>
        <label>Base URL</label>
        <input
          value={itsm.base_url}
          onChange={(e) => setItsm({ ...itsm, base_url: e.target.value })}
          placeholder="https://jira.example.com"
        />
        <label>Path template</label>
        <input
          value={itsm.ticket_path_template}
          onChange={(e) => setItsm({ ...itsm, ticket_path_template: e.target.value })}
          placeholder="/rest/api/2/issue/{ticket}"
        />
        <label>Status JSON path</label>
        <input
          value={itsm.status_json_path}
          onChange={(e) => setItsm({ ...itsm, status_json_path: e.target.value })}
          placeholder="fields.status.name"
        />
        <label>Допустимые статусы (через запятую)</label>
        <input
          value={(itsm.ok_statuses || []).join(", ")}
          onChange={(e) =>
            setItsm({
              ...itsm,
              ok_statuses: e.target.value.split(",").map((x) => x.trim()).filter(Boolean),
            })
          }
        />
        <label>Authorization header {itsm.has_auth_header ? "(задан)" : ""} — пусто = не менять</label>
        <input
          type="password"
          value={itsmAuth}
          onChange={(e) => setItsmAuth(e.target.value)}
          placeholder="Bearer … / Basic …"
          autoComplete="new-password"
        />
        <div className="row" style={{ gap: "1rem", flexWrap: "wrap", marginTop: "0.5rem" }}>
          <label className="row" style={{ gap: "0.4rem", alignItems: "center" }}>
            <input
              type="checkbox"
              checked={itsm.require_on_request}
              onChange={(e) => setItsm({ ...itsm, require_on_request: e.target.checked })}
            />
            На create request
          </label>
          <label className="row" style={{ gap: "0.4rem", alignItems: "center" }}>
            <input
              type="checkbox"
              checked={itsm.require_on_approve}
              onChange={(e) => setItsm({ ...itsm, require_on_approve: e.target.checked })}
            />
            На approve
          </label>
          <label className="row" style={{ gap: "0.4rem", alignItems: "center" }}>
            <input
              type="checkbox"
              checked={itsm.require_on_connect}
              onChange={(e) => setItsm({ ...itsm, require_on_connect: e.target.checked })}
            />
            На connect
          </label>
        </div>
        <div className="row" style={{ gap: "0.75rem", marginTop: "0.75rem" }}>
          <div style={{ flex: 1 }}>
            <label>Cache TTL (sec)</label>
            <input
              type="number"
              min={0}
              max={3600}
              value={itsm.cache_ttl_sec}
              onChange={(e) => setItsm({ ...itsm, cache_ttl_sec: Number(e.target.value) })}
            />
          </div>
          <div style={{ flex: 1 }}>
            <label>Timeout (sec)</label>
            <input
              type="number"
              min={1}
              max={60}
              value={itsm.timeout_sec}
              onChange={(e) => setItsm({ ...itsm, timeout_sec: Number(e.target.value) })}
            />
          </div>
        </div>
        {(itsm.last_check_at || itsm.last_error) && (
          <p className="muted" style={{ marginTop: "0.75rem" }}>
            Проверка: {itsm.last_check_at ? new Date(itsm.last_check_at).toLocaleString() : "—"}
            {itsm.last_error ? (
              <>
                <br />
                <span className="error">Ошибка: {itsm.last_error}</span>
              </>
            ) : null}
          </p>
        )}
        <div className="row" style={{ gap: "0.5rem", marginTop: "1rem", alignItems: "flex-end" }}>
          <div style={{ flex: 1 }}>
            <label>Проверить тикет</label>
            <input value={itsmTicket} onChange={(e) => setItsmTicket(e.target.value)} />
          </div>
          <button className="btn secondary" type="button" disabled={busy} onClick={() => void onCheckTicket()}>
            Validate
          </button>
        </div>
        {itsmCheck && <p className="muted mono">{itsmCheck}</p>}
        <button className="btn" type="submit" disabled={busy} style={{ marginTop: "1rem" }}>
          Сохранить ITSM
        </button>
      </form>

      <form className="card" onSubmit={onSaveSIEM} style={{ maxWidth: 640 }}>
        <h2>SIEM-экспорт аудита</h2>
        <p className="muted">
          Асинхронная отправка событий из audit_events (syslog или HTTPS webhook). Курсор
          продвигается только после успешной доставки.
        </p>
        <label className="row" style={{ gap: "0.5rem", alignItems: "center" }}>
          <input
            type="checkbox"
            checked={siem.enabled}
            onChange={(e) => setSiem({ ...siem, enabled: e.target.checked })}
          />
          Включить экспорт
        </label>
        <label>Транспорт</label>
        <select
          value={siem.transport}
          onChange={(e) => setSiem({ ...siem, transport: e.target.value })}
        >
          <option value="off">Выкл</option>
          <option value="syslog_udp">Syslog UDP</option>
          <option value="syslog_tcp">Syslog TCP</option>
          <option value="webhook">HTTPS Webhook</option>
        </select>
        <label>Формат</label>
        <select value={siem.format} onChange={(e) => setSiem({ ...siem, format: e.target.value })}>
          <option value="json">JSON</option>
          <option value="cef">CEF</option>
        </select>
        {(siem.transport === "syslog_udp" || siem.transport === "syslog_tcp") && (
          <>
            <label>Syslog адрес (host:port)</label>
            <input
              value={siem.syslog_addr}
              onChange={(e) => setSiem({ ...siem, syslog_addr: e.target.value })}
              placeholder="siem.example.com:514"
            />
            <label>Tag</label>
            <input
              value={siem.syslog_tag}
              onChange={(e) => setSiem({ ...siem, syslog_tag: e.target.value })}
            />
            <label>Facility (0–23, default 16 = local0)</label>
            <input
              type="number"
              min={0}
              max={23}
              value={siem.syslog_facility}
              onChange={(e) => setSiem({ ...siem, syslog_facility: Number(e.target.value) })}
            />
          </>
        )}
        {siem.transport === "webhook" && (
          <>
            <label>Webhook URL</label>
            <input
              value={siem.webhook_url}
              onChange={(e) => setSiem({ ...siem, webhook_url: e.target.value })}
              placeholder="https://siem.example.com/hooks/keeppam"
            />
            <label>
              Auth header {siem.has_webhook_auth_header ? "(задан)" : ""} — пусто = не менять
            </label>
            <input
              type="password"
              value={webhookAuth}
              onChange={(e) => setWebhookAuth(e.target.value)}
              placeholder="Bearer … или Authorization: Bearer …"
              autoComplete="off"
            />
          </>
        )}
        <div className="row" style={{ gap: "0.75rem" }}>
          <div style={{ flex: 1 }}>
            <label>Batch size</label>
            <input
              type="number"
              min={1}
              max={1000}
              value={siem.batch_size}
              onChange={(e) => setSiem({ ...siem, batch_size: Number(e.target.value) })}
            />
          </div>
          <div style={{ flex: 1 }}>
            <label>Интервал опроса (сек)</label>
            <input
              type="number"
              min={1}
              max={3600}
              value={siem.poll_interval_sec}
              onChange={(e) => setSiem({ ...siem, poll_interval_sec: Number(e.target.value) })}
            />
          </div>
        </div>
        {(siem.last_export_at || siem.last_error || siem.cursor_ts) && (
          <p className="muted" style={{ marginTop: "0.75rem" }}>
            Курсор: {siem.cursor_ts ? new Date(siem.cursor_ts).toLocaleString() : "—"}
            {siem.last_export_at
              ? ` · последний экспорт: ${new Date(siem.last_export_at).toLocaleString()}`
              : ""}
            {siem.last_error ? (
              <>
                <br />
                <span className="error">Ошибка: {siem.last_error}</span>
              </>
            ) : null}
          </p>
        )}
        <button className="btn" type="submit" disabled={busy} style={{ marginTop: "1rem" }}>
          Сохранить SIEM
        </button>
      </form>
    </div>
  );
}
