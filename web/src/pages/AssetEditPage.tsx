import { useEffect, useState, type FormEvent } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, ApiError, hasPerm, type AccessBinding, type AccessPolicy, type AppIntegration, type AppLease, type AppObjectPack, type Asset, type AssetAccount, type CommandPolicyPack, type HTTPPolicyPack, type PamGroup, type Role, type SQLPolicyPack, type User } from "../api";
import { useAuth } from "../auth";
import { kindForProtocol, useSessionTabs } from "../sessionTabs";
import { StepUpDialog } from "./StepUpDialog";

const PROTOCOLS = ["ssh", "rdp", "vnc", "https", "postgres", "mysql", "kubectl"];
const TYPES = ["host", "db", "k8s", "api"];
const DAY_LABELS = ["Вс", "Пн", "Вт", "Ср", "Чт", "Пт", "Сб"];

const SUPERVISOR_WAIT_MS = 15 * 60 * 1000;

async function waitForSupervisor(sessionId: string) {
  const deadline = Date.now() + SUPERVISOR_WAIT_MS;
  while (Date.now() < deadline) {
    const row = await api.getSession(sessionId);
    if (!row.waiting_supervisor) {
      if (row.status === "ended" || row.status === "failed") {
        throw new Error(row.error_message || "Сессия отклонена супервайзером");
      }
      return row;
    }
    await new Promise((r) => setTimeout(r, 1500));
  }
  throw new Error("Истекло ожидание супервайзера (15 мин)");
}

const emptyAclForm = {
  kind: "role" as "role" | "user" | "group",
  role_id: "",
  user_id: "",
  group_id: "",
  time_start: "",
  time_end: "",
  days_of_week: 127,
  duration_minutes: "",
  required_tags: "",
  require_ticket: false,
  require_reason: false,
  allowed_cidrs: "",
  allowed_countries: "",
  allowed_devices: "",
  allowed_namespaces: "",
  allowed_egress: "",
  pii_action: "",
  command_policy_pack_id: "",
  sql_policy_pack_id: "",
  http_policy_pack_id: "",
  app_object_pack_id: "",
  access_policy_id: "",
  max_risk: "0",
  risk_action: "deny",
};

export function AssetEditPage() {
  const { id } = useParams<{ id: string }>();
  const { user } = useAuth();
  const nav = useNavigate();
  const { openTab } = useSessionTabs();
  const [asset, setAsset] = useState<Asset | null>(null);
  const [bindings, setBindings] = useState<AccessBinding[]>([]);
  const [roles, setRoles] = useState<Role[]>([]);
  const [users, setUsers] = useState<User[]>([]);
  const [pamGroups, setPamGroups] = useState<PamGroup[]>([]);
  const [cmdPacks, setCmdPacks] = useState<CommandPolicyPack[]>([]);
  const [sqlPacks, setSqlPacks] = useState<SQLPolicyPack[]>([]);
  const [httpPacks, setHttpPacks] = useState<HTTPPolicyPack[]>([]);
  const [appPacks, setAppPacks] = useState<AppObjectPack[]>([]);
  const [accessPolicies, setAccessPolicies] = useState<AccessPolicy[]>([]);
  const [error, setError] = useState("");
  const [msg, setMsg] = useState("");
  const [loading, setLoading] = useState(true);
  const [connecting, setConnecting] = useState<string | null>(null);
  const [k8sLease, setK8sLease] = useState<AppLease | null>(null);
  const [stepUp, setStepUp] = useState<{
    err: ApiError;
    retry: (token: string) => Promise<void>;
  } | null>(null);
  const [rotating, setRotating] = useState<string | null>(null);
  const [form, setForm] = useState({
    name: "",
    asset_type: "host",
    hostname: "",
    address: "",
    port: 22,
    protocol: "ssh",
    database_name: "",
    description: "",
    status: "active",
    tags: "",
    approval_mode: "one",
    quorum_n: 2,
    quorum_m: 3,
    approver_group_id: "",
    require_supervisor: false,
    supervisor_group_id: "",
    pam_only: true,
  });
  const [accForm, setAccForm] = useState({
    username: "",
    auth_method: "password",
    secret: "",
    description: "",
    token_request_enabled: false,
    k8s_sa_namespace: "",
    k8s_sa_name: "",
    token_ttl_seconds: 900,
    k8s_impersonate: false,
    k8s_impersonate_prefix: "keeppam:",
    k8s_bind_user: false,
  });
  const [aclForm, setAclForm] = useState({ ...emptyAclForm });
  const [aclEditId, setAclEditId] = useState<string | null>(null);
  const [aclEditExpires, setAclEditExpires] = useState<string | null>(null);
  const [aclPermanent, setAclPermanent] = useState(false);
  const [jitForm, setJitForm] = useState({ reason: "", duration_minutes: 60, ticket_id: "" });
  const [bgForm, setBgForm] = useState({ reason: "", duration_minutes: 30 });
  const [connectTicket, setConnectTicket] = useState("");
  const [connectReason, setConnectReason] = useState("");
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
  const canBreakGlass = hasPerm(user, "access.breakglass");
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
        database_name: a.database_name || "",
        description: a.description || "",
        status: a.status,
        tags: (a.tags || []).join(", "),
        approval_mode:
          a.approval_mode === "quorum" ? "quorum" : (a.approval_stages || []).includes("security") ? "two" : "one",
        quorum_n: a.quorum_n || 2,
        quorum_m: a.quorum_m || 3,
        approver_group_id: a.approver_group_id || "",
        require_supervisor: !!a.require_supervisor,
        supervisor_group_id: a.supervisor_group_id || "",
        pam_only: a.pam_only !== false,
      });
      const acl = await api.listACL(id);
      setBindings(acl.bindings || []);
      if (canACL || canUsers || canWrite) {
        const r = await api.listRoles();
        setRoles(r.roles || []);
        try {
          const g = await api.listGroups();
          setPamGroups(g.groups || []);
        } catch {
          setPamGroups([]);
        }
      }
      if (canUsers) {
        const u = await api.listUsers();
        setUsers(u.users || []);
      }
      if (canACL || hasPerm(user, "jea.read")) {
        try {
          const [pk, sp, hp, ao, ap] = await Promise.all([
            api.listCommandPacks(),
            api.listSQLPacks(),
            api.listHTTPPacks(),
            api.listAppObjectPacks(),
            api.listAccessPolicies(),
          ]);
          setCmdPacks(pk.packs || []);
          setSqlPacks(sp.packs || []);
          setHttpPacks(hp.packs || []);
          setAppPacks(ao.packs || []);
          setAccessPolicies(ap.policies || []);
        } catch {
          setCmdPacks([]);
          setSqlPacks([]);
          setHttpPacks([]);
          setAppPacks([]);
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

  async function onConnect(acc: AssetAccount, stepUpToken?: string) {
    if (!id || !asset) return;
    setError("");
    setConnecting(acc.id);
    try {
      let sess = await api.createSession(id, acc.id, {
        ticket_id: connectTicket.trim() || undefined,
        reason: connectReason.trim() || undefined,
        db_privilege:
          asset.protocol === "postgres" || asset.protocol === "mysql" ? dbPrivilege : undefined,
        step_up_token: stepUpToken,
      });
      setStepUp(null);
      if (sess.waiting_supervisor) {
        setMsg("Ожидание супервайзера (четыре глаза)… Подключение начнётся после разрешения.");
        sess = await waitForSupervisor(sess.id);
        setMsg("");
      }
      const title = `${asset.name} · ${acc.username}`;
      const kind = kindForProtocol(asset.protocol, appForm.recording_mode === "isolated");
      if (asset.protocol === "postgres" || asset.protocol === "mysql") {
        if (sess.wire_token) {
          setMsg(
            `Wire: host=PAM port=${sess.wire_addr || (asset.protocol === "mysql" ? ":13306" : ":15432")} user=${sess.wire_user || sess.id} password=${sess.wire_token} dbname=${sess.database_name || asset.database_name || "postgres"}`,
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
      if (!stepUpToken && ApiError.isStepUp(err)) {
        setStepUp({ err, retry: (tok) => onConnect(acc, tok) });
        return;
      }
      setError(err instanceof Error ? err.message : "Не удалось начать сессию");
    } finally {
      setConnecting(null);
    }
  }

  async function onAppAccess(acc: AssetAccount, stepUpToken?: string) {
    if (!id || !asset) return;
    setError("");
    setMsg("");
    setConnecting(acc.id);
    try {
      const lease = await api.requestAppAccess(id, {
        account_id: acc.id,
        ticket_id: connectTicket.trim() || undefined,
        step_up_token: stepUpToken,
      });
      setStepUp(null);
      if (lease.auth_mode === "oidc_broker" && lease.open_url) {
        window.open(lease.open_url, "_blank");
        setMsg("OIDC redirect открыт в новой вкладке");
      } else {
        setMsg(
          `Lease до ${new Date(lease.expires_at).toLocaleString()}: ${lease.username} / ${lease.secret || "—"} → ${lease.open_url || lease.login_url || ""}`,
        );
      }
    } catch (err) {
      if (!stepUpToken && ApiError.isStepUp(err)) {
        setStepUp({ err, retry: (tok) => onAppAccess(acc, tok) });
        return;
      }
      setError(err instanceof Error ? err.message : "Ошибка доступа к приложению");
    } finally {
      setConnecting(null);
    }
  }

  async function onK8sAccess(acc: AssetAccount, stepUpToken?: string) {
    if (!id || !asset) return;
    setError("");
    setMsg("");
    setConnecting(acc.id);
    try {
      const lease = await api.requestK8sAccess(id, {
        account_id: acc.id,
        ticket_id: connectTicket.trim() || undefined,
        reason: connectReason.trim() || undefined,
        step_up_token: stepUpToken,
      });
      setStepUp(null);
      setK8sLease(lease);
      setMsg(`K8s lease до ${new Date(lease.expires_at).toLocaleString()}`);
    } catch (err) {
      if (!stepUpToken && ApiError.isStepUp(err)) {
        setStepUp({ err, retry: (tok) => onK8sAccess(acc, tok) });
        return;
      }
      setError(err instanceof Error ? err.message : "Ошибка K8s access");
    } finally {
      setConnecting(null);
    }
  }

  function downloadK8sSecret(lease: AppLease) {
    const text = lease.secret || "";
    const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    const ext = lease.auth_method === "sa_token" ? "token" : "kubeconfig";
    a.download = `keeppam-${lease.username || "k8s"}.${ext}`;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  async function onConsumeK8sLease() {
    if (!k8sLease) return;
    try {
      await api.consumeK8sLease(k8sLease.id);
      setMsg("Lease помечен как consumed");
      setK8sLease(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка consume");
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
        database_name: form.database_name,
        description: form.description,
        status: form.status,
        tags: form.tags
          .split(",")
          .map((t) => t.trim())
          .filter(Boolean),
        approval_stages: form.approval_mode === "two" ? ["manager", "security"] : ["manager"],
        approval_mode: form.approval_mode === "quorum" ? "quorum" : "sequential",
        quorum_n: form.approval_mode === "quorum" ? Number(form.quorum_n) || 2 : 1,
        quorum_m: form.approval_mode === "quorum" ? Number(form.quorum_m) || 3 : 1,
        approver_group_id: form.approval_mode === "quorum" && form.approver_group_id ? form.approver_group_id : null,
        require_supervisor: form.require_supervisor,
        supervisor_group_id: form.require_supervisor && form.supervisor_group_id ? form.supervisor_group_id : null,
        pam_only: form.pam_only,
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
        token_request_enabled: accForm.token_request_enabled,
        k8s_sa_namespace: accForm.k8s_sa_namespace,
        k8s_sa_name: accForm.k8s_sa_name,
        token_ttl_seconds: accForm.token_ttl_seconds,
        k8s_impersonate: accForm.k8s_impersonate,
        k8s_impersonate_prefix: accForm.k8s_impersonate_prefix,
        k8s_bind_user: accForm.k8s_bind_user,
      });
      setAccForm({
        username: "",
        auth_method: "password",
        secret: "",
        description: "",
        token_request_enabled: false,
        k8s_sa_namespace: "",
        k8s_sa_name: "",
        token_ttl_seconds: 900,
        k8s_impersonate: false,
        k8s_impersonate_prefix: "keeppam:",
        k8s_bind_user: false,
      });
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

  async function onCheckout(acc: AssetAccount) {
    if (!id || !canWrite) return;
    const reason = window.prompt("Причина checkout (для аудита):", "") ?? "";
    const ttlRaw = window.prompt("TTL минут (по умолчанию 60):", "60");
    if (ttlRaw === null) return;
    const ttl = Number(ttlRaw) || 60;
    setError("");
    setMsg("");
    try {
      const res = await api.checkoutAccount(id, acc.id, { reason, ttl_minutes: ttl });
      if (res.status === "pending_approval") {
        setMsg(`Checkout ${acc.username}: ждёт dual-control одобрения`);
      } else {
        setMsg(`Checkout ${acc.username}: секрет можно показать (Reveal)`);
      }
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка checkout");
    }
  }

  async function onCheckin(acc: AssetAccount) {
    if (!id || !canWrite) return;
    const doRotate = window.confirm(
      acc.rotate_on_checkin
        ? "Сдать секрет (check-in). Ротация включена в политике — выполнить?"
        : "Сдать секрет (check-in). Ротировать сейчас?",
    );
    setError("");
    setMsg("");
    try {
      const res = await api.checkinAccount(id, acc.id, {
        rotate: doRotate,
        apply_remote: doRotate,
      });
      setMsg(`Check-in ${acc.username}: ${res.status}`);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка check-in");
    }
  }

  async function onForceCheckin(acc: AssetAccount) {
    if (!id || !canWrite) return;
    if (!confirm(`Принудительно снять checkout с ${acc.username}?`)) return;
    try {
      await api.forceCheckinAccount(id, acc.id);
      setMsg("Checkout снят");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка force-checkin");
    }
  }

  async function onReveal(acc: AssetAccount) {
    if (!id || !canWrite) return;
    setError("");
    try {
      const res = await api.revealAccount(id, acc.id);
      window.prompt(
        `Секрет ${res.username} (${res.auth_method}). Скопируйте и закройте.`,
        res.secret,
      );
      setMsg("Секрет показан (событие записано в аудит)");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка reveal");
    }
  }

  async function onToggleVaultPolicy(
    acc: AssetAccount,
    patch: {
      rotate_after_session?: boolean;
      rotate_on_checkin?: boolean;
      dual_control_checkout?: boolean;
      rotate_interval_hours?: number;
      token_request_enabled?: boolean;
      k8s_sa_namespace?: string;
      k8s_sa_name?: string;
      token_ttl_seconds?: number;
      k8s_impersonate?: boolean;
      k8s_impersonate_prefix?: string;
      k8s_bind_user?: boolean;
    },
  ) {
    if (!id || !canWrite) return;
    try {
      await api.updateAccount(id, acc.id, patch);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка политики");
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

  function resetAclForm() {
    setAclEditId(null);
    setAclEditExpires(null);
    setAclPermanent(false);
    setAclForm({ ...emptyAclForm, role_id: roles[0]?.id || "" });
  }

  function splitCSV(s: string): string[] {
    return s
      .split(",")
      .map((x) => x.trim())
      .filter(Boolean);
  }

  async function startAclEdit(b: AccessBinding) {
    if (!id || !canACL) return;
    setError("");
    try {
      const raw = await api.getACL(id, b.id);
      setAclEditId(raw.id);
      setAclEditExpires(raw.expires_at || null);
      setAclPermanent(!raw.expires_at);
      setAclForm({
        kind: raw.user_id ? "user" : raw.group_id ? "group" : "role",
        role_id: raw.role_id || "",
        user_id: raw.user_id || "",
        group_id: raw.group_id || "",
        time_start: raw.time_start || "",
        time_end: raw.time_end || "",
        days_of_week: raw.days_of_week,
        duration_minutes: "",
        required_tags: (raw.required_tags || []).join(", "),
        require_ticket: !!raw.require_ticket,
        require_reason: !!raw.require_reason,
        allowed_cidrs: (raw.allowed_cidrs || []).join(", "),
        allowed_countries: (raw.allowed_countries || []).join(", "),
        allowed_devices: (raw.allowed_devices || []).join(", "),
        allowed_namespaces: (raw.allowed_namespaces || []).join(", "),
        allowed_egress: (raw.allowed_egress || []).join(", "),
        pii_action: raw.pii_action || "",
        command_policy_pack_id: raw.command_policy_pack_id || "",
        sql_policy_pack_id: raw.sql_policy_pack_id || "",
        http_policy_pack_id: raw.http_policy_pack_id || "",
        app_object_pack_id: raw.app_object_pack_id || "",
        access_policy_id: raw.access_policy_id || "",
        max_risk: String(raw.max_risk || 0),
        risk_action: raw.risk_action || "deny",
      });
      setMsg("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка загрузки ACL");
    }
  }

  async function onAddACL(e: FormEvent) {
    e.preventDefault();
    if (!id || !canACL) return;
    setError("");
    try {
      const body: {
        user_id?: string;
        role_id?: string;
        group_id?: string;
        time_start?: string;
        time_end?: string;
        days_of_week?: number;
        duration_minutes?: number;
        permanent?: boolean;
        required_tags?: string[];
        require_ticket?: boolean;
        require_reason?: boolean;
        allowed_cidrs?: string[];
        allowed_countries?: string[];
        allowed_devices?: string[];
        allowed_namespaces?: string[];
        allowed_egress?: string[];
        pii_action?: string;
        command_policy_pack_id?: string | null;
        sql_policy_pack_id?: string | null;
        http_policy_pack_id?: string | null;
        app_object_pack_id?: string | null;
        access_policy_id?: string | null;
        max_risk?: number;
        risk_action?: string;
      } = {
        days_of_week: aclForm.days_of_week,
        require_ticket: aclForm.require_ticket,
        require_reason: aclForm.require_reason,
      };
      if (!aclEditId) {
        if (aclForm.kind === "role") {
          if (!aclForm.role_id) throw new Error("выберите роль");
          body.role_id = aclForm.role_id;
        } else if (aclForm.kind === "group") {
          if (!aclForm.group_id) throw new Error("выберите группу");
          body.group_id = aclForm.group_id;
        } else {
          if (!aclForm.user_id) throw new Error("выберите пользователя");
          body.user_id = aclForm.user_id;
        }
      }
      const tags = splitCSV(aclForm.required_tags);
      const cidrs = splitCSV(aclForm.allowed_cidrs);
      const countries = splitCSV(aclForm.allowed_countries);
      const devices = splitCSV(aclForm.allowed_devices);
      const namespaces = splitCSV(aclForm.allowed_namespaces);
      const egress = splitCSV(aclForm.allowed_egress);
      if (aclEditId) {
        body.time_start = aclForm.time_start;
        body.time_end = aclForm.time_end;
        body.required_tags = tags;
        body.allowed_cidrs = cidrs;
        body.allowed_countries = countries;
        body.allowed_devices = devices;
        body.allowed_namespaces = namespaces;
        body.allowed_egress = egress;
        body.pii_action = aclForm.pii_action || "";
        body.command_policy_pack_id = aclForm.command_policy_pack_id || null;
        body.sql_policy_pack_id = aclForm.sql_policy_pack_id || null;
        body.http_policy_pack_id = aclForm.http_policy_pack_id || null;
        body.app_object_pack_id = aclForm.app_object_pack_id || null;
        body.access_policy_id = aclForm.access_policy_id || null;
        body.max_risk = Number(aclForm.max_risk) || 0;
        body.risk_action = aclForm.risk_action;
        if (aclPermanent) body.permanent = true;
        else if (aclForm.duration_minutes) body.duration_minutes = Number(aclForm.duration_minutes);
        await api.updateACL(id, aclEditId, body);
        setMsg("Доступ обновлён");
      } else {
        if (aclForm.time_start) body.time_start = aclForm.time_start;
        if (aclForm.time_end) body.time_end = aclForm.time_end;
        if (aclForm.duration_minutes) body.duration_minutes = Number(aclForm.duration_minutes);
        if (tags.length) body.required_tags = tags;
        if (cidrs.length) body.allowed_cidrs = cidrs;
        if (countries.length) body.allowed_countries = countries;
        if (devices.length) body.allowed_devices = devices;
        if (namespaces.length) body.allowed_namespaces = namespaces;
        if (egress.length) body.allowed_egress = egress;
        if (aclForm.pii_action) body.pii_action = aclForm.pii_action;
        if (aclForm.command_policy_pack_id) body.command_policy_pack_id = aclForm.command_policy_pack_id;
        if (aclForm.sql_policy_pack_id) body.sql_policy_pack_id = aclForm.sql_policy_pack_id;
        if (aclForm.http_policy_pack_id) body.http_policy_pack_id = aclForm.http_policy_pack_id;
        if (aclForm.app_object_pack_id) body.app_object_pack_id = aclForm.app_object_pack_id;
        if (aclForm.access_policy_id) body.access_policy_id = aclForm.access_policy_id;
        const maxRisk = Number(aclForm.max_risk);
        if (maxRisk > 0) {
          body.max_risk = maxRisk;
          body.risk_action = aclForm.risk_action;
        }
        await api.createACL(id, body);
        setMsg("Доступ выдан");
      }
      resetAclForm();
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

  async function onBreakGlass(e: FormEvent) {
    e.preventDefault();
    if (!id || !canBreakGlass) return;
    if (!confirm("Break-glass откроет экстренный доступ с громким аудитом. Продолжить?")) return;
    setError("");
    try {
      const ev = await api.openBreakGlass(id, {
        reason: bgForm.reason,
        duration_minutes: Number(bgForm.duration_minutes) || 30,
      });
      setMsg(
        `Break-glass открыт до ${new Date(ev.expires_at).toLocaleString()} — можно подключаться. Укажите ту же причину в поле Reason.`,
      );
      setBgForm({ reason: "", duration_minutes: 30 });
      setConnectReason(ev.reason);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка break-glass");
    }
  }

  async function onDeleteACL(b: AccessBinding) {
    if (!id || !canACL) return;
    try {
      await api.deleteACL(id, b.id);
      setMsg("Доступ отозван");
      if (aclEditId === b.id) resetAclForm();
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
      {stepUp && (
        <StepUpDialog
          err={stepUp.err}
          onDone={(tok) => void stepUp.retry(tok)}
          onCancel={() => setStepUp(null)}
        />
      )}

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
        {(form.protocol === "postgres" || form.protocol === "mysql") && (
          <>
            <label>Database</label>
            <input
              value={form.database_name}
              onChange={(e) => setForm({ ...form, database_name: e.target.value })}
              disabled={!canWrite}
              placeholder={form.protocol === "postgres" ? "postgres" : "(optional schema)"}
            />
            <p className="muted" style={{ marginTop: 0 }}>
              SQL-консоль и wire (:15432/:13306) подключаются к этой БД; ephemeral GRANT — только на неё.
            </p>
          </>
        )}
        <label className="row" style={{ gap: 8, alignItems: "center" }}>
          <input
            type="checkbox"
            checked={form.pam_only}
            onChange={(e) => setForm({ ...form, pam_only: e.target.checked })}
            disabled={!canWrite}
          />
          Только через PAM (firewall export + блок port-forward на сервисный порт)
        </label>
        {form.pam_only && (
          <p className="muted" style={{ marginTop: 0 }}>
            Firewall:{" "}
            {asset?.firewall_applied_at
              ? `правила отмечены ${new Date(asset.firewall_applied_at).toLocaleString()}`
              : "правила perimeter не отмечены"}
            {canWrite && asset && (
              <>
                {" · "}
                <button
                  type="button"
                  className="linkish"
                  onClick={() =>
                    void api
                      .markFirewallApplied(asset.id)
                      .then((a) => {
                        setAsset(a);
                        setMsg("Firewall: правила отмечены применёнными");
                      })
                      .catch((err) => setError(err instanceof Error ? err.message : "Ошибка"))
                  }
                >
                  отметить применёнными
                </button>
              </>
            )}
          </p>
        )}
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
          placeholder="prod/linux, pci"
        />
        <p className="muted" style={{ marginTop: 0 }}>
          Путь через / : <span className="mono">prod/linux</span> покрывает ACL на <span className="mono">prod</span>.
        </p>
        <label>JIT согласование</label>
        <select
          value={form.approval_mode}
          onChange={(e) => setForm({ ...form, approval_mode: e.target.value })}
          disabled={!canWrite}
        >
          <option value="one">Только руководитель (access.approve)</option>
          <option value="two">Руководитель + ИБ (access.approve.security)</option>
          <option value="quorum">Кворум N из M (2 из 3, 3 из 5)</option>
        </select>
        {form.approval_mode === "quorum" && (
          <>
            <label>Кворум N из M</label>
            <div className="row" style={{ gap: "0.5rem", alignItems: "center" }}>
              <input
                type="number"
                min={1}
                max={16}
                style={{ width: "4rem" }}
                value={form.quorum_n}
                onChange={(e) => setForm({ ...form, quorum_n: Number(e.target.value) })}
                disabled={!canWrite}
              />
              <span className="muted">из</span>
              <input
                type="number"
                min={1}
                max={16}
                style={{ width: "4rem" }}
                value={form.quorum_m}
                onChange={(e) => setForm({ ...form, quorum_m: Number(e.target.value) })}
                disabled={!canWrite}
              />
              <button
                className="btn secondary"
                type="button"
                disabled={!canWrite}
                onClick={() => setForm({ ...form, quorum_n: 2, quorum_m: 3 })}
              >
                2 из 3
              </button>
              <button
                className="btn secondary"
                type="button"
                disabled={!canWrite}
                onClick={() => setForm({ ...form, quorum_n: 3, quorum_m: 5 })}
              >
                3 из 5
              </button>
            </div>
            <label>Группа согласующих</label>
            <select
              value={form.approver_group_id}
              onChange={(e) => setForm({ ...form, approver_group_id: e.target.value })}
              disabled={!canWrite}
            >
              <option value="">Любой с правом access.approve</option>
              {pamGroups.map((g) => (
                <option key={g.id} value={g.id}>
                  {g.name}
                  {g.member_count != null ? ` (${g.member_count})` : ""}
                </option>
              ))}
            </select>
            <p className="muted" style={{ marginTop: 0 }}>
              Заявка одобряется, когда N разных участников группы проголосовали. Любой из них может отклонить.
            </p>
          </>
        )}
        <label className="row" style={{ gap: "0.5rem", alignItems: "center" }}>
          <input
            type="checkbox"
            checked={form.require_supervisor}
            onChange={(e) => setForm({ ...form, require_supervisor: e.target.checked })}
            disabled={!canWrite}
          />
          Четыре глаза: супервайзер до старта сессии
        </label>
        {form.require_supervisor && (
          <>
            <label>Группа супервайзеров</label>
            <select
              value={form.supervisor_group_id}
              onChange={(e) => setForm({ ...form, supervisor_group_id: e.target.value })}
              disabled={!canWrite}
            >
              <option value="">Любой с правом sessions.supervise</option>
              {pamGroups.map((g) => (
                <option key={g.id} value={g.id}>
                  {g.name}
                  {g.member_count != null ? ` (${g.member_count})` : ""}
                </option>
              ))}
            </select>
            <p className="muted" style={{ marginTop: 0 }}>
              SSH/RDP/SQL/k8s не стартуют, пока другой пользователь не нажмёт «Разрешить». Break-glass пропускает ожидание.
              Свою сессию супервизить нельзя. Таймаут 15 мин.
            </p>
          </>
        )}
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
          <p className="muted">SSO/JIT lease, HTTPS proxy (full) или изолированный Chromium через тот же proxy (isolated)</p>
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
            <option value="isolated">isolated (Chromium + VNC, без iframe)</option>
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
        <label>Причина (reason) для подключения</label>
        <input
          value={connectReason}
          onChange={(e) => setConnectReason(e.target.value)}
          placeholder="если ACL / break-glass требует reason"
          style={{ maxWidth: 480, marginBottom: "0.75rem" }}
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
          Checkout → Reveal показывает пароль только держателю. Сессии через PAM checkout не требуют.
          Политики: rotate after session, schedule (часы), dual-control checkout.
        </p>
        <table>
          <thead>
            <tr>
              <th>Логин</th>
              <th>Метод</th>
              <th>Секрет</th>
              <th>Checkout / ротация</th>
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
                  {acc.checked_out ? (
                    <>
                      hold: <span className="mono">{acc.checkout_username || "…"}</span>
                      {acc.checkout_expires_at
                        ? ` до ${new Date(acc.checkout_expires_at).toLocaleString()}`
                        : ""}
                      <br />
                    </>
                  ) : (
                    "свободен · "
                  )}
                  {acc.last_rotated_at
                    ? `rot ${new Date(acc.last_rotated_at).toLocaleString()}`
                    : "rot —"}
                  {acc.rotate_interval_hours
                    ? ` · каждые ${acc.rotate_interval_hours}ч`
                    : ""}
                  {acc.next_rotate_at
                    ? ` · next ${new Date(acc.next_rotate_at).toLocaleString()}`
                    : ""}
                  <br />
                  {canWrite && (
                    <span className="row" style={{ gap: "0.75rem", flexWrap: "wrap", marginTop: 4 }}>
                      <label className="row" style={{ gap: 4, alignItems: "center" }}>
                        <input
                          type="checkbox"
                          checked={!!acc.rotate_after_session}
                          onChange={(e) =>
                            void onToggleVaultPolicy(acc, { rotate_after_session: e.target.checked })
                          }
                        />
                        after session
                      </label>
                      <label className="row" style={{ gap: 4, alignItems: "center" }}>
                        <input
                          type="checkbox"
                          checked={!!acc.rotate_on_checkin}
                          onChange={(e) =>
                            void onToggleVaultPolicy(acc, { rotate_on_checkin: e.target.checked })
                          }
                        />
                        on check-in
                      </label>
                      <label className="row" style={{ gap: 4, alignItems: "center" }}>
                        <input
                          type="checkbox"
                          checked={!!acc.dual_control_checkout}
                          onChange={(e) =>
                            void onToggleVaultPolicy(acc, { dual_control_checkout: e.target.checked })
                          }
                        />
                        dual-control
                      </label>
                      <button
                        className="btn secondary"
                        type="button"
                        style={{ padding: "0.15rem 0.4rem", fontSize: "0.8rem" }}
                        onClick={() => {
                          const v = window.prompt(
                            "Интервал авторотации (часы, 0 = выкл):",
                            String(acc.rotate_interval_hours || 0),
                          );
                          if (v === null) return;
                          const n = Number(v);
                          if (Number.isNaN(n) || n < 0) return;
                          void onToggleVaultPolicy(acc, { rotate_interval_hours: n });
                        }}
                      >
                        schedule…
                      </button>
                    </span>
                  )}
                  {(acc.auth_method === "kubeconfig" || acc.auth_method === "sa_token") && (
                    <>
                      <br />
                      {canWrite ? (
                        <span className="row" style={{ gap: "0.75rem", flexWrap: "wrap", marginTop: 4 }}>
                          <label className="row" style={{ gap: 4, alignItems: "center" }}>
                            <input
                              type="checkbox"
                              checked={!!acc.token_request_enabled}
                              onChange={(e) =>
                                void onToggleVaultPolicy(acc, {
                                  token_request_enabled: e.target.checked,
                                  k8s_bind_user: e.target.checked ? acc.k8s_bind_user : false,
                                })
                              }
                            />
                            TokenRequest
                          </label>
                          <label className="row" style={{ gap: 4, alignItems: "center" }}>
                            <input
                              type="checkbox"
                              checked={!!acc.k8s_bind_user}
                              onChange={(e) =>
                                void onToggleVaultPolicy(acc, {
                                  k8s_bind_user: e.target.checked,
                                  token_request_enabled: e.target.checked ? true : acc.token_request_enabled,
                                })
                              }
                            />
                            Bind user
                          </label>
                          <label className="row" style={{ gap: 4, alignItems: "center" }}>
                            <input
                              type="checkbox"
                              checked={!!acc.k8s_impersonate}
                              onChange={(e) =>
                                void onToggleVaultPolicy(acc, { k8s_impersonate: e.target.checked })
                              }
                            />
                            Impersonate
                          </label>
                          {acc.k8s_impersonate && (
                            <span className="mono" style={{ fontSize: "0.8rem" }}>
                              {acc.k8s_impersonate_prefix === ""
                                ? "<логин>"
                                : `${acc.k8s_impersonate_prefix || "keeppam:"}<логин>`}
                            </span>
                          )}
                          {acc.token_request_enabled && (
                            <>
                              <span className="mono" style={{ fontSize: "0.8rem" }}>
                                {acc.k8s_sa_namespace || "default"}/
                                {acc.k8s_bind_user
                                  ? acc.k8s_sa_name
                                    ? `${acc.k8s_sa_name}-<логин>`
                                    : "keeppam-<логин>"
                                  : acc.k8s_sa_name || acc.username}{" "}
                                · {acc.token_ttl_seconds || 900}s
                              </span>
                              <button
                                className="btn secondary"
                                type="button"
                                style={{ padding: "0.15rem 0.4rem", fontSize: "0.8rem" }}
                                onClick={() => {
                                  const ns = window.prompt(
                                    "SA namespace (пусто = default):",
                                    acc.k8s_sa_namespace || "",
                                  );
                                  if (ns === null) return;
                                  const name = window.prompt(
                                    "SA name (пусто = логин учётки):",
                                    acc.k8s_sa_name || "",
                                  );
                                  if (name === null) return;
                                  const ttl = window.prompt(
                                    "Token TTL, секунды (60–86400):",
                                    String(acc.token_ttl_seconds || 900),
                                  );
                                  if (ttl === null) return;
                                  const n = Number(ttl);
                                  if (Number.isNaN(n) || n < 60 || n > 86400) return;
                                  void onToggleVaultPolicy(acc, {
                                    k8s_sa_namespace: ns,
                                    k8s_sa_name: name,
                                    token_ttl_seconds: n,
                                  });
                                }}
                              >
                                SA…
                              </button>
                            </>
                          )}
                        </span>
                      ) : acc.token_request_enabled || acc.k8s_impersonate || acc.k8s_bind_user ? (
                        <span>
                          {acc.k8s_impersonate ? "impersonate " : ""}
                          {acc.k8s_bind_user ? "bind-user " : ""}
                          {acc.token_request_enabled
                            ? `TokenRequest ${acc.k8s_sa_namespace || "default"}/${
                                acc.k8s_bind_user
                                  ? acc.k8s_sa_name
                                    ? `${acc.k8s_sa_name}-<логин>`
                                    : "keeppam-<логин>"
                                  : acc.k8s_sa_name || acc.username
                              }`
                            : ""}
                        </span>
                      ) : null}
                    </>
                  )}
                </td>
                <td>
                  <span className={`badge ${acc.status}`}>{acc.status}</span>
                </td>
                <td>
                  <div className="row" style={{ flexWrap: "wrap" }}>
                    {canConnect &&
                      (asset.protocol === "ssh" ||
                        asset.protocol === "rdp" ||
                        asset.protocol === "vnc" ||
                        asset.protocol === "postgres" ||
                        asset.protocol === "mysql" ||
                        asset.protocol === "https" ||
                        asset.protocol === "kubectl") &&
                      asset.status === "active" &&
                      acc.status === "active" &&
                      (acc.has_secret ||
                        (asset.protocol === "https" && appForm.recording_mode === "isolated")) && (
                        <>
                          {asset.protocol === "https" ? (
                            <button
                              className="btn"
                              type="button"
                              disabled={connecting === acc.id}
                              onClick={() => void onAppAccess(acc)}
                            >
                              {connecting === acc.id ? "…" : "Получить доступ"}
                            </button>
                          ) : asset.protocol === "kubectl" ? (
                            <>
                              <button
                                className="btn"
                                type="button"
                                disabled={connecting === acc.id}
                                onClick={() => void onConnect(acc)}
                              >
                                {connecting === acc.id ? "…" : "Подключить kubectl"}
                              </button>
                              <button
                                className="btn secondary"
                                type="button"
                                disabled={connecting === acc.id}
                                onClick={() => void onK8sAccess(acc)}
                              >
                                Vault checkout
                              </button>
                            </>
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
                          )}
                          {asset.protocol === "https" &&
                            (appForm.recording_mode === "full" || appForm.recording_mode === "isolated") &&
                            (acc.has_secret || appForm.recording_mode === "isolated") && (
                            <button
                              className="btn secondary"
                              type="button"
                              disabled={connecting === acc.id}
                              onClick={() => void onConnect(acc)}
                            >
                              {appForm.recording_mode === "isolated" ? "Isolated browser" : "Proxy-сессия"}
                            </button>
                          )}
                        </>
                      )}
                    {canWrite && acc.status === "active" && acc.has_secret && (
                      <>
                        {!acc.checked_out && (
                          <button className="btn secondary" type="button" onClick={() => void onCheckout(acc)}>
                            Checkout
                          </button>
                        )}
                        {acc.checked_out && acc.checkout_user_id === user?.id && (
                          <>
                            <button className="btn" type="button" onClick={() => void onReveal(acc)}>
                              Reveal
                            </button>
                            <button className="btn secondary" type="button" onClick={() => void onCheckin(acc)}>
                              Check-in
                            </button>
                          </>
                        )}
                        {acc.checked_out && acc.checkout_user_id !== user?.id && (
                          <button className="btn secondary" type="button" onClick={() => void onForceCheckin(acc)}>
                            Force check-in
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
                            >
                              {rotating === acc.id ? "Ротация…" : "Ротировать"}
                            </button>
                          )}
                          <button
                            className="btn secondary"
                            type="button"
                            disabled={rotating === acc.id}
                            onClick={() => void onRotateAccount(acc, false)}
                            title="Только vault"
                          >
                            Vault
                          </button>
                        </>
                      )}
                    {canWrite && (
                      <>
                        <button className="btn secondary" type="button" onClick={() => void onToggleAccount(acc)}>
                          {acc.status === "active" ? "Отключить" : "Включить"}
                        </button>
                        <button className="btn danger" type="button" onClick={() => void onDeleteAccount(acc)}>
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
                  Нет учёток — добавьте ниже (для RDP/VNC нужен пароль; для k8s — kubeconfig/sa_token).
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
            <option value="kubeconfig">kubeconfig</option>
            <option value="sa_token">sa_token</option>
          </select>
          <label>
            {accForm.auth_method === "ssh_key"
              ? "Приватный ключ"
              : accForm.auth_method === "kubeconfig"
                ? "Kubeconfig YAML"
                : accForm.auth_method === "sa_token"
                  ? "ServiceAccount token"
                  : "Пароль"}
          </label>
          {accForm.auth_method === "kubeconfig" || accForm.auth_method === "sa_token" ? (
            <textarea
              rows={8}
              value={accForm.secret}
              onChange={(e) => setAccForm({ ...accForm, secret: e.target.value })}
              placeholder={accForm.auth_method === "kubeconfig" ? "apiVersion: v1\nkind: Config\n..." : "eyJhbGciOi..."}
              autoComplete="off"
              style={{ fontFamily: "var(--mono)", width: "100%" }}
            />
          ) : (
            <input
              type={accForm.auth_method === "ssh_key" ? "text" : "password"}
              value={accForm.secret}
              onChange={(e) => setAccForm({ ...accForm, secret: e.target.value })}
              autoComplete="off"
            />
          )}
          <label>Описание</label>
          <input
            value={accForm.description}
            onChange={(e) => setAccForm({ ...accForm, description: e.target.value })}
          />
          {(accForm.auth_method === "kubeconfig" || accForm.auth_method === "sa_token") && (
            <>
              <label className="row" style={{ gap: 8, alignItems: "center" }}>
                <input
                  type="checkbox"
                  checked={accForm.token_request_enabled}
                  onChange={(e) =>
                    setAccForm({
                      ...accForm,
                      token_request_enabled: e.target.checked,
                      k8s_bind_user: e.target.checked ? accForm.k8s_bind_user : false,
                    })
                  }
                />
                TokenRequest (короткий SA-токен вместо выдачи vault)
              </label>
              <label className="row" style={{ gap: 8, alignItems: "center" }}>
                <input
                  type="checkbox"
                  checked={accForm.k8s_bind_user}
                  onChange={(e) =>
                    setAccForm({
                      ...accForm,
                      k8s_bind_user: e.target.checked,
                      token_request_enabled: e.target.checked ? true : accForm.token_request_enabled,
                    })
                  }
                />
                Bind PAM-пользователя (SA keeppam-&lt;логин&gt;, JWT привязан к объекту)
              </label>
              <label className="row" style={{ gap: 8, alignItems: "center" }}>
                <input
                  type="checkbox"
                  checked={accForm.k8s_impersonate}
                  onChange={(e) => setAccForm({ ...accForm, k8s_impersonate: e.target.checked })}
                />
                Impersonate PAM-пользователя (proxy :16443)
              </label>
              {accForm.k8s_impersonate && (
                <>
                  <p className="muted" style={{ marginTop: 0 }}>
                    Vault SA должен уметь <span className="mono">impersonate</span> users/groups.
                    В API уходит <span className="mono">Impersonate-User: {accForm.k8s_impersonate_prefix || "keeppam:"}&lt;логин&gt;</span>.
                    TokenRequest для proxy не используется (lease/checkout — как раньше).
                  </p>
                  <label>Prefix пользователя (пусто / keeppam: ; «-» = без префикса)</label>
                  <input
                    value={accForm.k8s_impersonate_prefix}
                    onChange={(e) => setAccForm({ ...accForm, k8s_impersonate_prefix: e.target.value })}
                    placeholder="keeppam:"
                  />
                </>
              )}
              {accForm.token_request_enabled && (
                <>
                  <p className="muted" style={{ marginTop: 0 }}>
                    Vault-секрет должен уметь <span className="mono">create token</span> на целевой SA
                    {accForm.k8s_bind_user ? ", плюс create ServiceAccount и create/delete Secret в том же namespace" : ""}.
                    Пользователю уходит ephemeral JWT; privileged kubeconfig не покидает PAM.
                    {accForm.k8s_bind_user
                      ? " Lease: JWT bound к ServiceAccount keeppam-<логин>. Proxy: bound к Secret сессии (удаляется при закрытии)."
                      : ""}
                  </p>
                  <label>SA namespace</label>
                  <input
                    value={accForm.k8s_sa_namespace}
                    onChange={(e) => setAccForm({ ...accForm, k8s_sa_namespace: e.target.value })}
                    placeholder="default"
                  />
                  <label>SA name</label>
                  <input
                    value={accForm.k8s_sa_name}
                    onChange={(e) => setAccForm({ ...accForm, k8s_sa_name: e.target.value })}
                    placeholder={accForm.k8s_bind_user ? "пусто = keeppam-<логин>" : "логин учётки"}
                  />
                  <label>Token TTL (сек)</label>
                  <input
                    type="number"
                    min={60}
                    max={86400}
                    value={accForm.token_ttl_seconds}
                    onChange={(e) =>
                      setAccForm({ ...accForm, token_ttl_seconds: Number(e.target.value) || 900 })
                    }
                  />
                </>
              )}
            </>
          )}
          <button className="btn" type="submit">
            Добавить
          </button>
        </form>
      )}

      {k8sLease && (
        <div className="card" style={{ maxWidth: 720, marginBottom: "1.25rem" }}>
          <h2>K8s credential lease</h2>
          <p className="muted">
            {k8sLease.username} · {k8sLease.auth_mode === "token_request" ? "TokenRequest" : k8sLease.auth_method || "secret"} · API{" "}
            <span className="mono">
              {k8sLease.cluster_address}
              {k8sLease.cluster_port ? `:${k8sLease.cluster_port}` : ""}
            </span>{" "}
            · до {new Date(k8sLease.expires_at).toLocaleString()}
          </p>
          <p className="muted">Секрет показывается один раз. Аудит не сохраняет тело.</p>
          <textarea
            readOnly
            rows={12}
            value={k8sLease.secret || ""}
            style={{ fontFamily: "var(--mono)", width: "100%", fontSize: "0.85rem" }}
          />
          <div className="row" style={{ gap: "0.5rem", marginTop: "0.75rem" }}>
            <button className="btn" type="button" onClick={() => downloadK8sSecret(k8sLease)}>
              Скачать
            </button>
            <button
              className="btn secondary"
              type="button"
              onClick={() => void navigator.clipboard.writeText(k8sLease.secret || "")}
            >
              Copy
            </button>
            <button className="btn secondary" type="button" onClick={() => void onConsumeK8sLease()}>
              Consume
            </button>
            <button className="btn secondary" type="button" onClick={() => setK8sLease(null)}>
              Закрыть
            </button>
          </div>
        </div>
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

      {canBreakGlass && (
        <form className="card" onSubmit={onBreakGlass} style={{ maxWidth: 560, marginBottom: "1.25rem" }}>
          <h2>Break-glass</h2>
          <p className="muted">
            Экстренный доступ без ожидания JIT. Короткий TTL (макс. 60 мин), обязательная причина ≥20 символов,
            событие <span className="mono">access.breakglass.opened</span> в аудите.
          </p>
          <label>Длительность (мин)</label>
          <select
            value={bgForm.duration_minutes}
            onChange={(e) => setBgForm({ ...bgForm, duration_minutes: Number(e.target.value) })}
          >
            <option value={15}>15</option>
            <option value={30}>30</option>
            <option value={45}>45</option>
            <option value={60}>60</option>
          </select>
          <label>Причина (обязательно)</label>
          <input
            value={bgForm.reason}
            onChange={(e) => setBgForm({ ...bgForm, reason: e.target.value })}
            placeholder="P1 инцидент: недоступен prod-db, нужен SELECT для диагностики"
            required
            minLength={20}
          />
          <button className="btn danger" type="submit">
            Открыть break-glass
          </button>
        </form>
      )}

      <div className="card" style={{ marginBottom: "1.25rem" }}>
        <h2>Политика доступа</h2>
        <p className="muted">
          Deny-by-default + ABAC: tags, ticket, reason, CIDR, geo, device, K8s namespaces. JIT истекает по expires_at. Break-glass — отдельная кнопка выше.
          Именованная Policy — <Link to="/jea">JEA</Link>. ACL на теги активов (без строки на хост) —{" "}
          <Link to="/jea">JEA → Теги активов</Link>.
        </p>
        <table>
          <thead>
            <tr>
              <th>Субъект</th>
              <th>Policy</th>
              <th>Окно</th>
              <th>Дни</th>
              <th>ABAC</th>
              <th>Risk</th>
              <th>SSH JEA</th>
              <th>SQL JEA</th>
              <th>HTTP ACL</th>
              <th>Objects</th>
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
                  ) : b.group_name ? (
                    <>
                      group <span className="mono">{b.group_name}</span>
                    </>
                  ) : (
                    <>
                      role <span className="mono">{b.role_name}</span>
                    </>
                  )}
                  {b.inherited ? (
                    <div className="muted" style={{ fontSize: "0.8rem" }}>
                      по тегу {(b.asset_match_tags || []).join(", ")}
                      {b.asset_match_mode === "any" ? " · любой" : " · все"}
                    </div>
                  ) : null}
                </td>
                <td className="mono" style={{ fontSize: "0.85rem" }}>
                  {b.access_policy_name || "—"}
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
                  {b.require_reason ? " · reason" : ""}
                  {(b.allowed_cidrs || []).length ? ` · ${b.allowed_cidrs!.join(",")}` : ""}
                  {(b.allowed_countries || []).length ? ` · ${b.allowed_countries!.join(",")}` : ""}
                  {(b.allowed_devices || []).length ? ` · ${b.allowed_devices!.join(",")}` : ""}
                  {(b.allowed_namespaces || []).length ? ` · ns=${b.allowed_namespaces!.join(",")}` : ""}
                  {(b.allowed_egress || []).length ? ` · egress=${b.allowed_egress!.join(",")}` : ""}
                  {b.pii_action ? ` · pii=${b.pii_action}` : ""}
                </td>
                <td className="mono" style={{ fontSize: "0.85rem" }}>
                  {b.max_risk ? `${b.max_risk}/${b.risk_action || "deny"}` : "off"}
                </td>
                <td className="mono" style={{ fontSize: "0.85rem" }}>
                  {b.command_policy_pack_name || "—"}
                </td>
                <td className="mono" style={{ fontSize: "0.85rem" }}>
                  {b.sql_policy_pack_name || "—"}
                </td>
                <td className="mono" style={{ fontSize: "0.85rem" }}>
                  {b.http_policy_pack_name || "—"}
                </td>
                <td className="mono" style={{ fontSize: "0.85rem" }}>
                  {b.app_object_pack_name || "—"}
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
                  {canACL && !b.inherited && (
                    <div className="row" style={{ gap: "0.35rem", flexWrap: "wrap" }}>
                      <button className="btn secondary" type="button" onClick={() => void startAclEdit(b)}>
                        Изменить
                      </button>
                      <button className="btn danger" type="button" onClick={() => void onDeleteACL(b)}>
                        Отозвать
                      </button>
                    </div>
                  )}
                  {b.inherited ? (
                    <Link to="/jea" className="muted" style={{ fontSize: "0.85rem" }}>
                      tag ACL
                    </Link>
                  ) : null}
                </td>
              </tr>
            ))}
            {bindings.length === 0 && (
              <tr>
                <td colSpan={12} className="muted">
                  Привязок нет — доступ только у admin
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {canACL && (
        <form className="card" onSubmit={onAddACL} style={{ maxWidth: 560 }}>
          <h2>{aclEditId ? "Изменить доступ" : "Выдать доступ"}</h2>
          {aclEditId && (
            <p className="muted">
              Субъект и актив нельзя сменить. Список выше показывает эффективные поля после Policy; здесь — как
              записано в ACL.
              {aclEditExpires
                ? ` Сейчас истекает ${new Date(aclEditExpires).toLocaleString()}.`
                : " Сейчас без TTL."}
            </p>
          )}
          <label>Access Policy (опц.)</label>
          <select
            value={aclForm.access_policy_id}
            onChange={(e) => setAclForm({ ...aclForm, access_policy_id: e.target.value })}
          >
            <option value="">— без именованной политики —</option>
            {accessPolicies.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
          <p className="muted" style={{ fontSize: "0.85rem" }}>
            Пустые поля ниже наследуются из политики. См. <Link to="/jea">JEA → Policy</Link>.
          </p>
          <label>Тип</label>
          <select
            value={aclForm.kind}
            disabled={!!aclEditId}
            onChange={(e) =>
              setAclForm({ ...aclForm, kind: e.target.value as "role" | "user" | "group" })
            }
          >
            <option value="role">Роль</option>
            <option value="user">Пользователь</option>
            <option value="group">Группа</option>
          </select>
          {aclForm.kind === "role" ? (
            <>
              <label>Роль</label>
              <select
                value={aclForm.role_id}
                onChange={(e) => setAclForm({ ...aclForm, role_id: e.target.value })}
                required
                disabled={!!aclEditId}
              >
                <option value="">—</option>
                {roles.map((r) => (
                  <option key={r.id} value={r.id}>
                    {r.name}
                  </option>
                ))}
              </select>
            </>
          ) : aclForm.kind === "group" ? (
            <>
              <label>Группа</label>
              <select
                value={aclForm.group_id}
                onChange={(e) => setAclForm({ ...aclForm, group_id: e.target.value })}
                required
                disabled={!!aclEditId}
              >
                <option value="">—</option>
                {pamGroups.map((g) => (
                  <option key={g.id} value={g.id}>
                    {g.parent_name ? `${g.parent_name} / ${g.name}` : g.name}
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
                disabled={!!aclEditId}
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
                placeholder={aclEditId ? "оставить" : "постоянно"}
                value={aclForm.duration_minutes}
                onChange={(e) => {
                  setAclPermanent(false);
                  setAclForm({ ...aclForm, duration_minutes: e.target.value });
                }}
              />
            </div>
          </div>
          {aclEditId && (
            <label className="row" style={{ gap: "0.5rem", alignItems: "center" }}>
              <input
                type="checkbox"
                checked={aclPermanent}
                onChange={(e) => {
                  setAclPermanent(e.target.checked);
                  if (e.target.checked) setAclForm({ ...aclForm, duration_minutes: "" });
                }}
              />
              Постоянно (снять TTL)
            </label>
          )}
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
            placeholder="pci, prod/sre"
          />
          <label className="row" style={{ gap: "0.5rem", alignItems: "center" }}>
            <input
              type="checkbox"
              checked={aclForm.require_ticket}
              onChange={(e) => setAclForm({ ...aclForm, require_ticket: e.target.checked })}
            />
            Требовать ticket_id при подключении
          </label>
          <label className="row" style={{ gap: "0.5rem", alignItems: "center" }}>
            <input
              type="checkbox"
              checked={aclForm.require_reason}
              onChange={(e) => setAclForm({ ...aclForm, require_reason: e.target.checked })}
            />
            Требовать reason при подключении
          </label>
          <label>Allowed CIDR / IP (через запятую, пусто = любой)</label>
          <input
            value={aclForm.allowed_cidrs}
            onChange={(e) => setAclForm({ ...aclForm, allowed_cidrs: e.target.value })}
            placeholder="10.0.0.0/8, 192.168.1.10"
          />
          <label>Allowed countries (ISO + LAN, пусто = любая)</label>
          <input
            value={aclForm.allowed_countries}
            onChange={(e) => setAclForm({ ...aclForm, allowed_countries: e.target.value })}
            placeholder="LAN, RU, KZ"
          />
          <label>Allowed devices (TLS / WEBAUTHN / SSH / SPIFFE / spiffe://…, пусто = любое)</label>
          <input
            value={aclForm.allowed_devices}
            onChange={(e) => setAclForm({ ...aclForm, allowed_devices: e.target.value })}
            placeholder="WEBAUTHN, TLS, SPIFFE, spiffe://keeppam.local/ns/prod/*"
          />
          <label>Allowed namespaces (kubectl, пусто = любой)</label>
          <input
            value={aclForm.allowed_namespaces}
            onChange={(e) => setAclForm({ ...aclForm, allowed_namespaces: e.target.value })}
            placeholder="prod, kube-system"
          />
          <label>Allowed egress (SSH -L / direct-tcpip; пусто = туннели запрещены)</label>
          <input
            value={aclForm.allowed_egress}
            onChange={(e) => setAclForm({ ...aclForm, allowed_egress: e.target.value })}
            placeholder="10.1.2.0/24:5432, db.prod.local:5432"
          />
          <label>PII в ответе SQL/HTTP (пусто = выкл.)</label>
          <select
            value={aclForm.pii_action}
            onChange={(e) => setAclForm({ ...aclForm, pii_action: e.target.value })}
          >
            <option value="">выкл.</option>
            <option value="mask">mask (email/PAN/телефон/СНИЛС → ***)</option>
            <option value="deny">deny (не отдавать результат)</option>
          </select>
          <label>JEA command pack (SSH, опц.)</label>
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
          <label>SQL JEA pack (опц.)</label>
          <select
            value={aclForm.sql_policy_pack_id}
            onChange={(e) => setAclForm({ ...aclForm, sql_policy_pack_id: e.target.value })}
          >
            <option value="">— без table/mask политики —</option>
            {sqlPacks.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name} ({p.mode})
              </option>
            ))}
          </select>
          <label>HTTP / URL ACL pack (https и kubectl, опц.)</label>
          <select
            value={aclForm.http_policy_pack_id}
            onChange={(e) => setAclForm({ ...aclForm, http_policy_pack_id: e.target.value })}
          >
            <option value="">— без ограничения URL —</option>
            {httpPacks.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name} ({p.mode})
              </option>
            ))}
          </select>
          <label>Object ACL pack (функции приложения, опц.)</label>
          <select
            value={aclForm.app_object_pack_id}
            onChange={(e) => setAclForm({ ...aclForm, app_object_pack_id: e.target.value })}
          >
            <option value="">— без объектов —</option>
            {appPacks.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name} ({p.unmatched})
              </option>
            ))}
          </select>
          <div className="row" style={{ alignItems: "flex-end" }}>
            <div style={{ flex: 1 }}>
              <label>Max risk (0 = выкл.)</label>
              <input
                type="number"
                min={0}
                max={100}
                value={aclForm.max_risk}
                onChange={(e) => setAclForm({ ...aclForm, max_risk: e.target.value })}
              />
            </div>
            <div style={{ flex: 1 }}>
              <label>Если выше порога</label>
              <select
                value={aclForm.risk_action}
                onChange={(e) => setAclForm({ ...aclForm, risk_action: e.target.value })}
              >
                <option value="deny">deny</option>
                <option value="require_approval">require_approval (JIT)</option>
                <option value="require_mfa">require_mfa (повторный MFA)</option>
              </select>
            </div>
          </div>
          <p className="muted" style={{ fontSize: "0.85rem" }}>
            Score: off_hours 25, break_glass 40, failed_logins 15–45, concurrent 10–20, anom_brute 20,
            anom_multi 15, ueba_new_asset 25, ueba_spread 20 + операция (DROP/DDL 45, delete 30, k8s write 20…).
            Cap 100. 0 = выкл. и на connect, и на операции.
            require_mfa — повторный TOTP/Passkey на connect; операции внутри сессии всё равно deny.
          </p>
          <div className="row" style={{ gap: "0.5rem" }}>
            <button className="btn" type="submit">
              {aclEditId ? "Сохранить" : "Выдать"}
            </button>
            {aclEditId && (
              <button className="btn secondary" type="button" onClick={resetAclForm}>
                Отмена
              </button>
            )}
          </div>
        </form>
      )}
    </div>
  );
}
