import { useEffect, useState, type FormEvent } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, ApiError, hasPerm, type AccessBinding, type AccessPolicy, type AppIntegration, type AppLease, type AppObjectPack, type Asset, type AssetAccount, type CommandPolicyPack, type HTTPPolicyPack, type PamGroup, type Role, type SQLPolicyPack, type User } from "../api";
import { useAuth } from "../auth";
import { useI18n } from "../i18n";
import { isSQLProtocol, kindForProtocol, useSessionTabs } from "../sessionTabs";
import { StepUpDialog } from "./StepUpDialog";

const PROTOCOLS = ["ssh", "rdp", "vnc", "https", "postgres", "mysql", "mssql", "kubectl", "telnet", "tn3270", "citrix"];
const TYPES = ["host", "db", "k8s", "api"];
const SUPERVISOR_WAIT_MS = 15 * 60 * 1000;

async function waitForSupervisor(sessionId: string, denied: string, timeout: string) {
  const deadline = Date.now() + SUPERVISOR_WAIT_MS;
  while (Date.now() < deadline) {
    const row = await api.getSession(sessionId);
    if (!row.waiting_supervisor) {
      if (row.status === "ended" || row.status === "failed") {
        throw new Error(row.error_message || denied);
      }
      return row;
    }
    await new Promise((r) => setTimeout(r, 1500));
  }
  throw new Error(timeout);
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
  file_transfer: "",
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
  const { t, te, formatDate } = useI18n();
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
    ad_privileged_group_dn: "",
    krb_spn: "",
    terminal_charset: "utf-8",
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
    ad_user_dn: "",
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
        ad_privileged_group_dn: a.ad_privileged_group_dn || "",
        krb_spn: a.krb_spn || "",
        terminal_charset: a.terminal_charset || "utf-8",
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
      setError(te(err, "assets.loadError"));
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
        setMsg(t("assets.waitSupervisor"));
        sess = await waitForSupervisor(sess.id, t("assets.supervisorDenied"), t("assets.supervisorTimeout"));
        setMsg("");
      }
      const title = `${asset.name} · ${acc.username}`;
      const kind = kindForProtocol(asset.protocol, appForm.recording_mode === "isolated");
      if (isSQLProtocol(asset.protocol)) {
        if (sess.wire_token) {
          const fallback =
            asset.protocol === "mysql" ? ":13306" : asset.protocol === "mssql" ? ":11433" : ":15432";
          const dbn = sess.database_name || asset.database_name || (asset.protocol === "mssql" ? "master" : "postgres");
          setMsg(
            `Wire: host=PAM port=${sess.wire_addr || fallback} user=${sess.wire_user || sess.id} password=${sess.wire_token} dbname=${dbn} (Encrypt=Optional)`,
          );
        }
      }
      if (asset.protocol === "telnet" && sess.wire_token) {
        setMsg(
          `Telnet wire: telnet PAM ${sess.wire_addr || ":2323"} — login=${sess.wire_user || sess.id} password=${sess.wire_token}`,
        );
      }
      if (asset.protocol === "tn3270" && sess.wire_token) {
        sessionStorage.setItem(
          `kp_wire_${sess.id}`,
          JSON.stringify({
            token: sess.wire_token,
            addr: sess.wire_addr || ":2324",
            user: sess.wire_user || sess.id,
          }),
        );
        setMsg(
          `TN3270: x3270 PAM ${sess.wire_addr || ":2324"} — UUID=${sess.wire_user || sess.id} token=${sess.wire_token}`,
        );
      }
      if (asset.protocol === "citrix" && (sess.citrix_ica || sess.wire_token)) {
        sessionStorage.setItem(
          `kp_wire_${sess.id}`,
          JSON.stringify({
            token: sess.wire_token,
            addr: sess.wire_addr || ":1081",
            user: sess.wire_user || sess.id,
            ica: sess.citrix_ica,
            filename: sess.citrix_filename,
          }),
        );
        if (sess.citrix_ica) {
          const blob = new Blob([sess.citrix_ica], { type: "application/x-ica" });
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a");
          a.href = url;
          a.download = sess.citrix_filename || `keeppam-${sess.id.slice(0, 8)}.ica`;
          a.click();
          URL.revokeObjectURL(url);
        }
        setMsg(sess.wire_hint || `Citrix SOCKS ${sess.wire_addr || ":1081"}`);
      }
      if (asset.protocol === "rdp" && sess.rdp_file) {
        const blob = new Blob([sess.rdp_file], { type: "application/x-rdp" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = sess.rdp_filename || `keeppam-${sess.id.slice(0, 8)}.rdp`;
        a.click();
        URL.revokeObjectURL(url);
        setMsg(sess.rdp_hint || `Native RDP: ${sess.rdp_addr || ""}`);
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
      setError(te(err, "assets.connectError"));
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
      setError(te(err, "common.error"));
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
      setError(te(err, "common.error"));
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
      setError(te(err, "common.error"));
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
        ad_privileged_group_dn: form.ad_privileged_group_dn.trim(),
        krb_spn: form.krb_spn.trim(),
        terminal_charset: form.terminal_charset || "utf-8",
      });
      setAsset(updated);
      setMsg(t("assets.saved"));
    } catch (err) {
      setError(te(err, "assets.saveError"));
    }
  }

  async function onDelete() {
    if (!id || !canWrite) return;
    if (!confirm(t("assets.deleteConfirm"))) return;
    try {
      await api.deleteAsset(id);
      nav("/assets");
    } catch (err) {
      setError(te(err, "assets.deleteError"));
    }
  }

  async function onClearHostKey() {
    if (!id || !canWrite) return;
    if (!confirm(t("assets.hostKeyResetConfirm"))) return;
    setError("");
    try {
      const a = await api.clearAssetHostKey(id);
      setAsset(a);
      setMsg(t("assets.hostKeyResetOk"));
    } catch (err) {
      setError(te(err, "common.error"));
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
        ad_user_dn: accForm.ad_user_dn.trim() || undefined,
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
        ad_user_dn: "",
      });
      setMsg(t("assets.accountAdded"));
      await load();
    } catch (err) {
      setError(te(err, "common.error"));
    }
  }

  async function onDeleteAccount(acc: AssetAccount) {
    if (!id || !canWrite) return;
    if (!confirm(t("assets.deleteAccountConfirm", { name: acc.username }))) return;
    try {
      await api.deleteAccount(id, acc.id);
      setMsg(t("assets.accountDeleted"));
      await load();
    } catch (err) {
      setError(te(err, "assets.deleteError"));
    }
  }

  async function onToggleAccount(acc: AssetAccount) {
    if (!id || !canWrite) return;
    const status = acc.status === "active" ? "disabled" : "active";
    try {
      await api.updateAccount(id, acc.id, { status });
      await load();
    } catch (err) {
      setError(te(err, "common.error"));
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
      setError(te(err, "common.error"));
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
      setError(te(err, "common.error"));
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
      setError(te(err, "common.error"));
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
      setError(te(err, "common.error"));
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
      setError(te(err, "common.error"));
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
      ad_user_dn?: string;
    },
  ) {
    if (!id || !canWrite) return;
    try {
      await api.updateAccount(id, acc.id, patch);
      await load();
    } catch (err) {
      setError(te(err, "common.error"));
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
        file_transfer: raw.file_transfer || "",
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
      setError(te(err, "common.error"));
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
        file_transfer?: string;
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
          if (!aclForm.role_id) throw new Error(t("assets.selectRole"));
          body.role_id = aclForm.role_id;
        } else if (aclForm.kind === "group") {
          if (!aclForm.group_id) throw new Error(t("assets.selectGroup"));
          body.group_id = aclForm.group_id;
        } else {
          if (!aclForm.user_id) throw new Error(t("assets.selectUser"));
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
        body.file_transfer = aclForm.file_transfer || "";
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
        setMsg(t("assets.aclUpdated"));
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
        if (aclForm.file_transfer) body.file_transfer = aclForm.file_transfer;
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
        setMsg(t("assets.aclGranted"));
      }
      resetAclForm();
      await load();
    } catch (err) {
      setError(te(err, "common.error"));
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
      setMsg(t("assets.requestSent"));
      setJitForm({ reason: "", duration_minutes: 60, ticket_id: "" });
    } catch (err) {
      setError(te(err, "assets.requestError"));
    }
  }

  async function onBreakGlass(e: FormEvent) {
    e.preventDefault();
    if (!id || !canBreakGlass) return;
    if (!confirm(t("assets.breakGlassConfirm"))) return;
    setError("");
    try {
      const ev = await api.openBreakGlass(id, {
        reason: bgForm.reason,
        duration_minutes: Number(bgForm.duration_minutes) || 30,
      });
      setMsg(t("assets.breakGlassOpened", { at: formatDate(ev.expires_at) }));
      setBgForm({ reason: "", duration_minutes: 30 });
      setConnectReason(ev.reason);
      await load();
    } catch (err) {
      setError(te(err, "common.error"));
    }
  }

  async function onDeleteACL(b: AccessBinding) {
    if (!id || !canACL) return;
    try {
      await api.deleteACL(id, b.id);
      setMsg(t("assets.aclRevoked"));
      if (aclEditId === b.id) resetAclForm();
      await load();
    } catch (err) {
      setError(te(err, "common.error"));
    }
  }

  function toggleDay(bit: number) {
    setAclForm((f) => ({
      ...f,
      days_of_week: f.days_of_week & bit ? f.days_of_week & ~bit : f.days_of_week | bit,
    }));
  }

  function formatDays(mask: number): string {
    if (mask === 127) return t("cal.allDays");
    return [0, 1, 2, 3, 4, 5, 6].filter((i) => mask & (1 << i)).map((i) => t(`cal.${i}`)).join(", ") || "—";
  }

  if (loading) return <p className="muted">{t("common.loading")}</p>;
  if (!asset) {
    return (
      <div>
        <p className="error">{error || t("assets.notFound")}</p>
        <Link to="/assets">{t("assets.toList")}</Link>
      </div>
    );
  }

  return (
    <div>
      <div className="toolbar">
        <div>
          <p className="muted" style={{ marginBottom: "0.35rem" }}>
            <Link to="/assets">{t("nav.assets")}</Link> / {asset.name}
          </p>
          <h1>{t("assets.editTitle")}</h1>
          <p className="muted mono">
            {asset.id} · {t("assets.protoLine", { protocol: asset.protocol, addr: asset.address, port: asset.port })}
          </p>
        </div>
        <button className="btn secondary" type="button" onClick={() => nav("/assets")}>
          {t("common.back")}
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
        <h2>{t("assets.params")}</h2>
        <label>{t("common.name")}</label>
        <input
          value={form.name}
          onChange={(e) => setForm({ ...form, name: e.target.value })}
          disabled={!canWrite}
          required
        />
        <label>{t("common.type")}</label>
        <select
          value={form.asset_type}
          onChange={(e) => setForm({ ...form, asset_type: e.target.value })}
          disabled={!canWrite}
        >
          {TYPES.map((typ) => (
            <option key={typ} value={typ}>
              {typ}
            </option>
          ))}
        </select>
        <label>{t("common.address")}</label>
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
            <label>{t("common.protocol")}</label>
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
            <label>{t("common.port")}</label>
            <input
              type="number"
              value={form.port}
              onChange={(e) => setForm({ ...form, port: Number(e.target.value) })}
              disabled={!canWrite}
            />
          </div>
        </div>
        {(form.protocol === "postgres" || form.protocol === "mysql" || form.protocol === "mssql") && (
          <>
            <label>Database</label>
            <input
              value={form.database_name}
              onChange={(e) => setForm({ ...form, database_name: e.target.value })}
              disabled={!canWrite}
              placeholder={form.protocol === "postgres" ? "postgres" : form.protocol === "mssql" ? "master" : "(optional schema)"}
            />
            <p className="muted" style={{ marginTop: 0 }}>
              {t("assets.dbHint")}
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
          {t("assets.pamOnly")}
        </label>
        {form.pam_only && (
          <p className="muted" style={{ marginTop: 0 }}>
            Firewall:{" "}
            {asset?.firewall_applied_at
              ? t("assets.fwMarked", { at: formatDate(asset.firewall_applied_at) })
              : t("assets.fwUnmarked")}
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
                        setMsg(t("assets.fwMarkedMsg"));
                      })
                      .catch((err) => setError(te(err, "common.error")))
                  }
                >
                  {t("assets.fwMark")}
                </button>
              </>
            )}
          </p>
        )}
        <label>{t("common.status")}</label>
        <select
          value={form.status}
          onChange={(e) => setForm({ ...form, status: e.target.value })}
          disabled={!canWrite}
        >
          <option value="active">active</option>
          <option value="disabled">disabled</option>
        </select>
        <label>{t("common.tags")}</label>
        <input
          value={form.tags}
          onChange={(e) => setForm({ ...form, tags: e.target.value })}
          disabled={!canWrite}
          placeholder="prod/linux, pci"
        />
        <p className="muted" style={{ marginTop: 0 }}>
          {t("assets.tagPath", { ex: "prod/linux", parent: "prod" })}
        </p>
        <label>{t("assets.jit")}</label>
        <select
          value={form.approval_mode}
          onChange={(e) => setForm({ ...form, approval_mode: e.target.value })}
          disabled={!canWrite}
        >
          <option value="one">{t("assets.jit.one")}</option>
          <option value="two">{t("assets.jit.two")}</option>
          <option value="quorum">{t("assets.jit.quorum")}</option>
        </select>
        {form.approval_mode === "quorum" && (
          <>
            <label>{t("assets.quorumNM")}</label>
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
              <span className="muted">{t("assets.quorumOf")}</span>
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
                {t("assets.quorum23")}
              </button>
              <button
                className="btn secondary"
                type="button"
                disabled={!canWrite}
                onClick={() => setForm({ ...form, quorum_n: 3, quorum_m: 5 })}
              >
                {t("assets.quorum35")}
              </button>
            </div>
            <label>{t("assets.approverGroup")}</label>
            <select
              value={form.approver_group_id}
              onChange={(e) => setForm({ ...form, approver_group_id: e.target.value })}
              disabled={!canWrite}
            >
              <option value="">{t("assets.anyApprove")}</option>
              {pamGroups.map((g) => (
                <option key={g.id} value={g.id}>
                  {g.name}
                  {g.member_count != null ? ` (${g.member_count})` : ""}
                </option>
              ))}
            </select>
            <p className="muted" style={{ marginTop: 0 }}>
              {t("assets.quorumHint")}
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
          {t("assets.fourEyes")}
        </label>
        {form.require_supervisor && (
          <>
            <label>{t("assets.supervisorGroup")}</label>
            <select
              value={form.supervisor_group_id}
              onChange={(e) => setForm({ ...form, supervisor_group_id: e.target.value })}
              disabled={!canWrite}
            >
              <option value="">{t("assets.anySupervise")}</option>
              {pamGroups.map((g) => (
                <option key={g.id} value={g.id}>
                  {g.name}
                  {g.member_count != null ? ` (${g.member_count})` : ""}
                </option>
              ))}
            </select>
            <p className="muted" style={{ marginTop: 0 }}>
              {t("assets.fourEyesHint")}
            </p>
          </>
        )}
        <label>{t("assets.adGroupDN")}</label>
        <input
          className="mono"
          value={form.ad_privileged_group_dn}
          onChange={(e) => setForm({ ...form, ad_privileged_group_dn: e.target.value })}
          disabled={!canWrite}
          placeholder="CN=Domain Admins,CN=Users,DC=example,DC=com"
        />
        <p className="muted" style={{ marginTop: 0 }}>
          {t("assets.adGroupHint")}
        </p>
        <label>Kerberos SPN (опционально)</label>
        <input
          className="mono"
          value={form.krb_spn}
          onChange={(e) => setForm({ ...form, krb_spn: e.target.value })}
          disabled={!canWrite}
          placeholder="host/srv.corp.local"
        />
        <p className="muted" style={{ marginTop: 0 }}>
          Для GSSAPI: host/fqdn или fqdn. Пусто = hostname актива / address.
        </p>
        <label>Кодировка терминала (SSH/Telnet)</label>
        <select
          value={form.terminal_charset || "utf-8"}
          onChange={(e) => setForm({ ...form, terminal_charset: e.target.value })}
          disabled={!canWrite}
        >
          <option value="utf-8">UTF-8</option>
          <option value="cp1251">CP1251 (Windows)</option>
          <option value="koi8-r">KOI8-R</option>
          <option value="auto">auto (detect)</option>
        </select>
        <p className="muted" style={{ marginTop: 0 }}>
          Для индекса и поиска: сырой поток конвертируется в UTF-8 (T-43).
        </p>
        <label>{t("common.description")}</label>
        <input
          value={form.description}
          onChange={(e) => setForm({ ...form, description: e.target.value })}
          disabled={!canWrite}
        />
        <div className="row" style={{ marginTop: "0.5rem" }}>
          {canWrite && (
            <button className="btn" type="submit">
              {t("common.save")}
            </button>
          )}
          {canWrite && (
            <button className="btn danger" type="button" onClick={() => void onDelete()}>
              {t("common.delete")}
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
                setError(te(err, "common.error"));
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
                {t("assets.hostKeyKnown")}
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
                  {t("assets.hostKeyReset")}
                </button>
              )}
            </>
          ) : (
            <p className="muted">{t("assets.hostKeyUnknown")}</p>
          )}
        </div>
      )}

      <div className="card" style={{ marginBottom: "1.25rem" }}>
        <h2>{t("assets.accounts")}</h2>
        <label>{t("assets.connectTicket")}</label>
        <input
          value={connectTicket}
          onChange={(e) => setConnectTicket(e.target.value)}
          placeholder={t("assets.connectTicketPh")}
          style={{ maxWidth: 320, marginBottom: "0.75rem" }}
        />
        <label>{t("assets.connectReason")}</label>
        <input
          value={connectReason}
          onChange={(e) => setConnectReason(e.target.value)}
          placeholder={t("assets.connectReasonPh")}
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
              <option value="readonly">{t("assets.ephemeralRo")}</option>
              <option value="readwrite">{t("assets.ephemeralRw")}</option>
            </select>
            <p className="muted" style={{ marginTop: 0 }}>
              {t("assets.ephemeralHint")}
            </p>
          </>
        )}
        <p className="muted">
          {t("assets.checkoutHint")}
        </p>
        <table>
          <thead>
            <tr>
              <th>{t("login.username")}</th>
              <th>{t("common.type")}</th>
              <th>{t("assets.password")}</th>
              <th>Checkout / {t("assets.rotate")}</th>
              <th>{t("common.status")}</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {(asset.accounts || []).map((acc) => (
              <tr key={acc.id}>
                <td className="mono">{acc.username}</td>
                <td className="mono">{acc.auth_method}</td>
                <td>{acc.has_secret ? t("assets.secretSet") : t("assets.secretNone")}</td>
                <td className="muted" style={{ fontSize: "0.85rem" }}>
                  {acc.checked_out ? (
                    <>
                      hold: <span className="mono">{acc.checkout_username || "…"}</span>
                      {acc.checkout_expires_at
                        ? t("assets.until", { at: formatDate(acc.checkout_expires_at) })
                        : ""}
                      <br />
                    </>
                  ) : (
                    t("assets.checkoutFree")
                  )}
                  {acc.last_rotated_at
                    ? `rot ${formatDate(acc.last_rotated_at)}`
                    : "rot —"}
                  {acc.rotate_interval_hours
                    ? t("assets.everyHours", { n: acc.rotate_interval_hours })
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
                            t("assets.adUserDN"),
                            acc.ad_user_dn || "",
                          );
                          if (v === null) return;
                          void onToggleVaultPolicy(acc, { ad_user_dn: v.trim() });
                        }}
                      >
                        AD DN…
                      </button>
                      <button
                        className="btn secondary"
                        type="button"
                        style={{ padding: "0.15rem 0.4rem", fontSize: "0.8rem" }}
                        onClick={() => {
                          const v = window.prompt(
                            t("assets.rotateInterval"),
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
                        asset.protocol === "telnet" ||
                        asset.protocol === "tn3270" ||
                        asset.protocol === "citrix" ||
                        asset.protocol === "rdp" ||
                        asset.protocol === "vnc" ||
                        asset.protocol === "postgres" ||
                        asset.protocol === "mysql" ||
                        asset.protocol === "mssql" ||
                        asset.protocol === "https" ||
                        asset.protocol === "kubectl") &&
                      asset.status === "active" &&
                      acc.status === "active" &&
                      (acc.has_secret ||
                        asset.protocol === "tn3270" ||
                        asset.protocol === "citrix" ||
                        (asset.protocol === "https" && appForm.recording_mode === "isolated")) && (
                        <>
                          {asset.protocol === "https" ? (
                            <button
                              className="btn"
                              type="button"
                              disabled={connecting === acc.id}
                              onClick={() => void onAppAccess(acc)}
                            >
                              {connecting === acc.id ? "…" : t("assets.connectApp")}
                            </button>
                          ) : asset.protocol === "kubectl" ? (
                            <>
                              <button
                                className="btn"
                                type="button"
                                disabled={connecting === acc.id}
                                onClick={() => void onConnect(acc)}
                              >
                                {connecting === acc.id ? "…" : t("assets.connectK8s")}
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
                                  ? t("assets.connectSsh")
                                  : isSQLProtocol(asset.protocol)
                                    ? t("assets.connectSql")
                                    : t("assets.connectOpen", { proto: asset.protocol.toUpperCase() })}
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
                              {appForm.recording_mode === "isolated" ? "Isolated browser" : t("assets.connectProxy")}
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
                              {rotating === acc.id ? t("assets.rotating") : t("assets.rotate")}
                            </button>
                          )}
                          <button
                            className="btn secondary"
                            type="button"
                            disabled={rotating === acc.id}
                            onClick={() => void onRotateAccount(acc, false)}
                            title={t("assets.vaultOnly")}
                          >
                            Vault
                          </button>
                        </>
                      )}
                    {canWrite && (
                      <>
                        <button className="btn secondary" type="button" onClick={() => void onToggleAccount(acc)}>
                          {acc.status === "active" ? t("assets.disable") : t("assets.enable")}
                        </button>
                        <button className="btn danger" type="button" onClick={() => void onDeleteAccount(acc)}>
                          {t("common.delete")}
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
                  {t("assets.noAccounts")}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {canWrite && (
        <form className="card" onSubmit={onAddAccount} style={{ maxWidth: 560, marginBottom: "1.25rem" }}>
          <h2>{t("assets.addAccount")}</h2>
          <label>{t("assets.loginOnTarget")}</label>
          <input
            value={accForm.username}
            onChange={(e) => setAccForm({ ...accForm, username: e.target.value })}
            required
          />
          <label>{t("assets.authMethod")}</label>
          <select
            value={accForm.auth_method}
            onChange={(e) => setAccForm({ ...accForm, auth_method: e.target.value })}
          >
            <option value="password">password</option>
            <option value="ssh_key">ssh_key</option>
            <option value="gssapi">gssapi (Kerberos)</option>
            <option value="kubeconfig">kubeconfig</option>
            <option value="sa_token">sa_token</option>
          </select>
          <label>
            {accForm.auth_method === "ssh_key"
              ? t("assets.privateKey")
              : accForm.auth_method === "kubeconfig"
                ? "Kubeconfig YAML"
                : accForm.auth_method === "sa_token"
                  ? "ServiceAccount token"
                  : t("assets.password")}
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
          <label>{t("common.description")}</label>
          <input
            value={accForm.description}
            onChange={(e) => setAccForm({ ...accForm, description: e.target.value })}
          />
          <label>{t("assets.adUserDN")}</label>
          <input
            className="mono"
            value={accForm.ad_user_dn}
            onChange={(e) => setAccForm({ ...accForm, ad_user_dn: e.target.value })}
            placeholder="CN=svc-admin,OU=Admins,DC=example,DC=com"
          />
          <p className="muted" style={{ marginTop: 0 }}>
            {t("assets.adUserHint")}
          </p>
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
            {t("common.create")}
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
          <p className="muted">{t("assets.secretOnce")}</p>
          <textarea
            readOnly
            rows={12}
            value={k8sLease.secret || ""}
            style={{ fontFamily: "var(--mono)", width: "100%", fontSize: "0.85rem" }}
          />
          <div className="row" style={{ gap: "0.5rem", marginTop: "0.75rem" }}>
            <button className="btn" type="button" onClick={() => downloadK8sSecret(k8sLease)}>
              {t("sess.download")}
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
              {t("tabs.close")}
            </button>
          </div>
        </div>
      )}

      {canRequest && (
        <form className="card" onSubmit={onRequestAccess} style={{ maxWidth: 560, marginBottom: "1.25rem" }}>
          <h2>{t("assets.jitRequest")}</h2>
          <p className="muted">
            {t("assets.jitRequestLead")}{" "}
            <Link to="/access-requests">{t("assets.queueLink")}</Link>
          </p>
          <label>{t("assets.duration")}</label>
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
          <label>{t("req.reason")}</label>
          <input
            value={jitForm.reason}
            onChange={(e) => setJitForm({ ...jitForm, reason: e.target.value })}
            placeholder={t("assets.reasonPh")}
          />
          <button className="btn" type="submit">
            {t("assets.submitJit")}
          </button>
        </form>
      )}

      {canBreakGlass && (
        <form className="card" onSubmit={onBreakGlass} style={{ maxWidth: 560, marginBottom: "1.25rem" }}>
          <h2>{t("assets.breakGlassTitle")}</h2>
          <p className="muted">
            {t("assets.breakGlassLead")}
          </p>
          <label>{t("assets.duration")}</label>
          <select
            value={bgForm.duration_minutes}
            onChange={(e) => setBgForm({ ...bgForm, duration_minutes: Number(e.target.value) })}
          >
            <option value={15}>15</option>
            <option value={30}>30</option>
            <option value={45}>45</option>
            <option value={60}>60</option>
          </select>
          <label>{t("assets.breakGlassReason")}</label>
          <input
            value={bgForm.reason}
            onChange={(e) => setBgForm({ ...bgForm, reason: e.target.value })}
            placeholder={t("assets.breakGlassReasonPh")}
            required
            minLength={20}
          />
          <button className="btn danger" type="submit">
            {t("assets.breakGlassOpen")}
          </button>
        </form>
      )}

      <div className="card" style={{ marginBottom: "1.25rem" }}>
        <h2>{t("assets.aclTitle")}</h2>
        <p className="muted">
          {t("assets.aclLead")}{" "}
          <Link to="/jea">JEA</Link>.{" "}
          <Link to="/jea">{t("assets.aclTagsLink")}</Link>.
        </p>
        <table>
          <thead>
            <tr>
              <th>{t("assets.subject")}</th>
              <th>Policy</th>
              <th>{t("assets.window")}</th>
              <th>{t("assets.days")}</th>
              <th>ABAC</th>
              <th>Risk</th>
              <th>SSH JEA</th>
              <th>SQL JEA</th>
              <th>HTTP ACL</th>
              <th>Objects</th>
              <th>{t("assets.expires")}</th>
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
                      {t("assets.byTag", { tags: (b.asset_match_tags || []).join(", ") })}
                      {b.asset_match_mode === "any" ? t("assets.matchAny") : t("assets.matchAll")}
                    </div>
                  ) : null}
                </td>
                <td className="mono" style={{ fontSize: "0.85rem" }}>
                  {b.access_policy_name || "—"}
                </td>
                <td className="mono">
                  {b.time_start || b.time_end
                    ? `${b.time_start || "00:00"}–${b.time_end || "24:00"}`
                    : t("assets.always")}
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
                  {b.file_transfer && b.file_transfer !== "deny" ? ` · files=${b.file_transfer}` : ""}
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
                      {formatDate(b.expires_at)}
                      {new Date(b.expires_at).getTime() < Date.now() && (
                        <span className="badge locked" style={{ marginLeft: 6 }}>
                          expired
                        </span>
                      )}
                    </>
                  ) : (
                    t("assets.permanent")
                  )}
                </td>
                <td>
                  {canACL && !b.inherited && (
                    <div className="row" style={{ gap: "0.35rem", flexWrap: "wrap" }}>
                      <button className="btn secondary" type="button" onClick={() => void startAclEdit(b)}>
                        {t("assets.edit")}
                      </button>
                      <button className="btn danger" type="button" onClick={() => void onDeleteACL(b)}>
                        {t("assets.revoke")}
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
                  {t("assets.noBindings")}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {canACL && (
        <form className="card" onSubmit={onAddACL} style={{ maxWidth: 560 }}>
          <h2>{aclEditId ? t("assets.editAccess") : t("assets.grantAccess")}</h2>
          {aclEditId && (
            <p className="muted">
              {t("assets.aclEditHint")}
              {aclEditExpires
                ? t("assets.expiresNow", { at: formatDate(aclEditExpires) })
                : t("assets.noTtlNow")}
            </p>
          )}
          <label>{t("assets.policyOpt")}</label>
          <select
            value={aclForm.access_policy_id}
            onChange={(e) => setAclForm({ ...aclForm, access_policy_id: e.target.value })}
          >
            <option value="">{t("assets.noNamedPolicy")}</option>
            {accessPolicies.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
          <p className="muted" style={{ fontSize: "0.85rem" }}>
            {t("assets.aclInherit")}
          </p>
          <label>{t("common.type")}</label>
          <select
            value={aclForm.kind}
            disabled={!!aclEditId}
            onChange={(e) =>
              setAclForm({ ...aclForm, kind: e.target.value as "role" | "user" | "group" })
            }
          >
            <option value="role">{t("assets.role")}</option>
            <option value="user">{t("common.user")}</option>
            <option value="group">{t("common.group")}</option>
          </select>
          {aclForm.kind === "role" ? (
            <>
              <label>{t("assets.role")}</label>
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
              <label>{t("common.group")}</label>
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
              <label>{t("common.user")}</label>
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
              <label>{t("assets.fromTime")}</label>
              <input
                placeholder="09:00"
                value={aclForm.time_start}
                onChange={(e) => setAclForm({ ...aclForm, time_start: e.target.value })}
              />
            </div>
            <div style={{ flex: 1 }}>
              <label>{t("assets.toTime")}</label>
              <input
                placeholder="18:00"
                value={aclForm.time_end}
                onChange={(e) => setAclForm({ ...aclForm, time_end: e.target.value })}
              />
            </div>
            <div style={{ width: 140 }}>
              <label>{t("assets.jitMin")}</label>
              <input
                type="number"
                min={1}
                max={1440}
                placeholder={aclEditId ? t("assets.keep") : t("assets.permanent")}
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
              {t("assets.clearTtl")}
            </label>
          )}
          <label>{t("assets.weekdays")}</label>
          <div className="row" style={{ marginBottom: "0.9rem" }}>
            {[0, 1, 2, 3, 4, 5, 6].map((i) => {
              const label = t(`cal.${i}`);
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
          <label>{t("assets.tagsCsv")}</label>
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
            {t("assets.requireTicket")}
          </label>
          <label className="row" style={{ gap: "0.5rem", alignItems: "center" }}>
            <input
              type="checkbox"
              checked={aclForm.require_reason}
              onChange={(e) => setAclForm({ ...aclForm, require_reason: e.target.checked })}
            />
            {t("assets.requireReason")}
          </label>
          <label>{t("assets.cidrHint")}</label>
          <input
            value={aclForm.allowed_cidrs}
            onChange={(e) => setAclForm({ ...aclForm, allowed_cidrs: e.target.value })}
            placeholder="10.0.0.0/8, 192.168.1.10"
          />
          <label>{t("assets.countryHint")}</label>
          <input
            value={aclForm.allowed_countries}
            onChange={(e) => setAclForm({ ...aclForm, allowed_countries: e.target.value })}
            placeholder="LAN, RU, KZ"
          />
          <label>{t("assets.deviceHint")}</label>
          <input
            value={aclForm.allowed_devices}
            onChange={(e) => setAclForm({ ...aclForm, allowed_devices: e.target.value })}
            placeholder="WEBAUTHN, TLS, SPIFFE, spiffe://keeppam.local/ns/prod/*"
          />
          <label>{t("assets.nsHint")}</label>
          <input
            value={aclForm.allowed_namespaces}
            onChange={(e) => setAclForm({ ...aclForm, allowed_namespaces: e.target.value })}
            placeholder="prod, kube-system"
          />
          <label>{t("assets.egressHint")}</label>
          <input
            value={aclForm.allowed_egress}
            onChange={(e) => setAclForm({ ...aclForm, allowed_egress: e.target.value })}
            placeholder="10.1.2.0/24:5432, db.prod.local:5432"
          />
          <label>{t("assets.pii")}</label>
          <select
            value={aclForm.pii_action}
            onChange={(e) => setAclForm({ ...aclForm, pii_action: e.target.value })}
          >
            <option value="">{t("assets.off")}</option>
            <option value="mask">mask (email/PAN/телефон/СНИЛС → ***)</option>
            <option value="deny">deny (не отдавать результат)</option>
          </select>
          <label>SCP/SFTP</label>
          <select
            value={aclForm.file_transfer}
            onChange={(e) => setAclForm({ ...aclForm, file_transfer: e.target.value })}
          >
            <option value="">из Policy / deny</option>
            <option value="deny">deny</option>
            <option value="audit">audit (лог, без байт)</option>
            <option value="capture">capture (хранить файл)</option>
          </select>
          <label>JEA command pack (SSH, опц.)</label>
          <select
            value={aclForm.command_policy_pack_id}
            onChange={(e) => setAclForm({ ...aclForm, command_policy_pack_id: e.target.value })}
          >
            <option value="">{t("assets.noCmdLimit")}</option>
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
            <option value="">{t("assets.noSqlPolicy")}</option>
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
            <option value="">{t("assets.noUrlLimit")}</option>
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
            <option value="">{t("assets.noObjects")}</option>
            {appPacks.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name} ({p.unmatched})
              </option>
            ))}
          </select>
          <div className="row" style={{ alignItems: "flex-end" }}>
            <div style={{ flex: 1 }}>
              <label>{t("assets.maxRisk")}</label>
              <input
                type="number"
                min={0}
                max={100}
                value={aclForm.max_risk}
                onChange={(e) => setAclForm({ ...aclForm, max_risk: e.target.value })}
              />
            </div>
            <div style={{ flex: 1 }}>
              <label>{t("assets.ifAbove")}</label>
              <select
                value={aclForm.risk_action}
                onChange={(e) => setAclForm({ ...aclForm, risk_action: e.target.value })}
              >
                <option value="deny">deny</option>
                <option value="require_approval">require_approval (JIT)</option>
                <option value="require_mfa">{t("assets.requireMfaOpt")}</option>
              </select>
            </div>
          </div>
          <p className="muted" style={{ fontSize: "0.85rem" }}>
            {t("assets.riskHint")}
          </p>
          <div className="row" style={{ gap: "0.5rem" }}>
            <button className="btn" type="submit">
              {aclEditId ? t("common.save") : t("assets.grant")}
            </button>
            {aclEditId && (
              <button className="btn secondary" type="button" onClick={resetAclForm}>
                {t("common.cancel")}
              </button>
            )}
          </div>
        </form>
      )}
    </div>
  );
}
