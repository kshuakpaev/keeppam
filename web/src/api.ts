export type User = {
  id: string;
  username: string;
  email: string;
  display_name: string;
  mfa_enabled: boolean;
  status: string;
  auth_source: string;
  must_change_password: boolean;
  last_login_at?: string;
  created_at: string;
  updated_at: string;
  roles?: string[];
  permissions?: string[];
  tags?: string[];
};

export type Role = {
  id: string;
  name: string;
  description: string;
};

export type UserSSHKey = {
  id: string;
  user_id: string;
  name: string;
  public_key: string;
  fingerprint: string;
  created_at: string;
};

export type AuditEvent = {
  id: string;
  ts: string;
  actor_id?: string;
  action: string;
  resource_type: string;
  resource_id: string;
  ip: string;
  user_agent: string;
  payload: Record<string, unknown>;
};

export type AssetAccount = {
  id: string;
  asset_id: string;
  username: string;
  auth_method: string;
  has_secret: boolean;
  description: string;
  status: string;
  last_rotated_at?: string;
  created_at: string;
  updated_at: string;
  checked_out?: boolean;
  checkout_user_id?: string;
  checkout_username?: string;
  checkout_at?: string;
  checkout_expires_at?: string;
  checkout_reason?: string;
  rotate_after_session?: boolean;
  rotate_on_checkin?: boolean;
  rotate_interval_hours?: number;
  next_rotate_at?: string;
  dual_control_checkout?: boolean;
};

export type SecretCheckoutRequest = {
  id: string;
  asset_id: string;
  account_id: string;
  requester_id: string;
  reason: string;
  ttl_minutes: number;
  status: string;
  approver_id?: string;
  decided_at?: string;
  created_at: string;
  expires_at: string;
  asset_name?: string;
  account_username?: string;
  requester_username?: string;
};

export type Asset = {
  id: string;
  name: string;
  asset_type: string;
  hostname: string;
  address: string;
  port: number;
  protocol: string;
  database_name?: string;
  description: string;
  status: string;
  tags: string[];
  host_key_algo?: string;
  host_key_fingerprint?: string;
  host_key_learned_at?: string;
  created_at: string;
  updated_at: string;
  accounts?: AssetAccount[];
};

export type AccessBinding = {
  id: string;
  asset_id: string;
  user_id?: string;
  role_id?: string;
  username?: string;
  role_name?: string;
  time_start?: string;
  time_end?: string;
  days_of_week: number;
  expires_at?: string;
  required_tags: string[];
  require_ticket: boolean;
  require_reason?: boolean;
  allowed_cidrs?: string[];
  command_policy_pack_id?: string;
  command_policy_pack_name?: string;
  sql_policy_pack_id?: string;
  sql_policy_pack_name?: string;
  created_at: string;
};

export type BreakGlassEvent = {
  id: string;
  asset_id: string;
  user_id: string;
  reason: string;
  duration_minutes: number;
  binding_id?: string;
  created_at: string;
  expires_at: string;
  closed_at?: string;
  asset_name?: string;
  username?: string;
  active: boolean;
};

export type AccessRequest = {
  id: string;
  asset_id: string;
  requester_id: string;
  reason: string;
  ticket_id?: string;
  duration_minutes: number;
  status: string;
  approver_id?: string;
  decided_at?: string;
  binding_id?: string;
  created_at: string;
  asset_name?: string;
  asset_address?: string;
  requester_username?: string;
  approver_username?: string;
};

export type AuthSettings = {
  mode: "local" | "oidc" | "ldap" | string;
  public_base_url: string;
  oidc_issuer: string;
  oidc_client_id: string;
  oidc_client_secret?: string;
  has_oidc_secret: boolean;
  oidc_scopes: string;
  oidc_auto_provision: boolean;
  oidc_skip_mfa: boolean;
  oidc_default_role: string;
  ldap_url: string;
  ldap_bind_dn: string;
  ldap_bind_password?: string;
  has_ldap_bind_password: boolean;
  ldap_user_base_dn: string;
  ldap_user_filter: string;
  ldap_attr_username: string;
  ldap_attr_email: string;
  ldap_attr_display_name: string;
  ldap_start_tls: boolean;
  ldap_insecure_tls: boolean;
  ldap_auto_provision: boolean;
  ldap_skip_mfa: boolean;
  ldap_default_role: string;
  updated_at?: string;
};

export type SSHSettings = {
  ssh_auth_mode: "vault_secret" | "ssh_cert" | string;
  ssh_ca_public: string;
  ssh_cert_ttl_hours: number;
  has_ssh_ca: boolean;
  rotate_ca?: boolean;
  updated_at?: string;
};

export type SIEMSettings = {
  enabled: boolean;
  transport: "off" | "syslog_udp" | "syslog_tcp" | "webhook" | string;
  syslog_addr: string;
  syslog_tag: string;
  syslog_facility: number;
  webhook_url: string;
  webhook_auth_header?: string;
  has_webhook_auth_header: boolean;
  format: "json" | "cef" | string;
  batch_size: number;
  poll_interval_sec: number;
  cursor_ts?: string;
  cursor_id?: string;
  last_error?: string;
  last_export_at?: string;
  updated_at?: string;
};

export type ITSMSettings = {
  enabled: boolean;
  provider: "mock" | "generic" | "jira" | "servicenow" | string;
  base_url: string;
  auth_header?: string;
  has_auth_header: boolean;
  ticket_path_template: string;
  status_json_path: string;
  ok_statuses: string[];
  require_on_request: boolean;
  require_on_approve: boolean;
  require_on_connect: boolean;
  cache_ttl_sec: number;
  timeout_sec: number;
  last_error?: string;
  last_check_at?: string;
  updated_at?: string;
};

export type ITSMTicketInfo = {
  id: string;
  status: string;
  ok: boolean;
  cached?: boolean;
  title?: string;
};

export type InfraStatus = {
  data_key_source: string;
  recordings_backend: string;
  recordings_dir: string;
  object_lock_mode?: string;
  object_lock_days?: number;
  worm_recordings?: boolean;
  tls_enabled: boolean;
  mtls: "off" | "optional" | "required" | string;
  s3_endpoint?: string;
  s3_bucket?: string;
  s3_region?: string;
  s3_prefix?: string;
  http_addr?: string;
  cookie_secure?: boolean;
};

export type DiscoveryJob = {
  id: string;
  kind?: string;
  cidr: string;
  ports: string;
  status: string;
  total_hosts: number;
  scanned_hosts: number;
  open_ports: number;
  error?: string;
  created_at: string;
  started_at?: string;
  finished_at?: string;
};

export type DiscoveryCandidate = {
  id: string;
  job_id: string;
  address: string;
  port: number;
  protocol: string;
  username?: string;
  source_asset_id?: string;
  imported_asset_id?: string;
  imported_account_id?: string;
  details?: Record<string, unknown>;
  privileged?: boolean;
  created_at: string;
  already_known: boolean;
};

export type DiscoveryImportResult = {
  kind: "asset" | "account" | string;
  asset?: Asset;
  account?: AssetAccount;
};

export type AnalyticsOverview = {
  window_hours: number;
  generated_at: string;
  stats: {
    logins_ok: number;
    logins_fail: number;
    sessions_started: number;
    sessions_active: number;
    sessions_denied: number;
    secret_rotations: number;
    jit_requests: number;
    off_hours_sessions: number;
    long_sessions: number;
    force_kills: number;
    app_access: number;
    sql_statements: number;
  };
  series: {
    logins_by_hour: { hour: string; ok: number; fail: number }[];
    sessions_by_protocol: { name: string; count: number }[];
    actions_by_type: { name: string; count: number }[];
  };
  anomalies: {
    severity: "high" | "medium" | "low" | string;
    code: string;
    title: string;
    detail: string;
    count: number;
    actor?: string;
    related?: string;
  }[];
  top_actors: { name: string; count: number }[];
  top_assets: { name: string; count: number }[];
  siem: {
    enabled: boolean;
    transport: string;
    last_export_at?: string;
    last_error?: string;
    pending_events: number;
    lag_seconds?: number;
    healthy: boolean;
    detail: string;
  };
  chains: {
    severity: string;
    title: string;
    detail: string;
    actor?: string;
    steps: string[];
    count: number;
  }[];
};

function csrfToken(): string {
  const match = document.cookie.match(/(?:^|; )kp_csrf=([^;]*)/);
  return match ? decodeURIComponent(match[1]) : "";
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (!headers.has("Content-Type") && init.body) {
    headers.set("Content-Type", "application/json");
  }
  const method = (init.method || "GET").toUpperCase();
  if (method !== "GET" && method !== "HEAD") {
    headers.set("X-CSRF-Token", csrfToken());
  }
  const res = await fetch(path, {
    ...init,
    headers,
    credentials: "include",
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error((data as { error?: string }).error || res.statusText);
  }
  return data as T;
}

export const api = {
  login: (username: string, password: string) =>
    request<{
      status: string;
      challenge_token?: string;
      user?: User;
    }>("/api/v1/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),
  verifyMfa: (challenge_token: string, code: string) =>
    request<{ status: string; user?: User }>("/api/v1/auth/mfa/verify", {
      method: "POST",
      body: JSON.stringify({ challenge_token, code }),
    }),
  webauthnLoginBegin: (challenge_token: string) =>
    request<unknown>("/api/v1/auth/mfa/webauthn/begin", {
      method: "POST",
      body: JSON.stringify({ challenge_token }),
    }),
  webauthnLoginFinish: (challenge_token: string, credential: unknown) =>
    request<{ status: string; user?: User }>("/api/v1/auth/mfa/webauthn/finish", {
      method: "POST",
      body: JSON.stringify({ challenge_token, credential }),
    }),
  webauthnRegisterBegin: () =>
    request<unknown>("/api/v1/auth/webauthn/register/begin", { method: "POST" }),
  webauthnRegisterFinish: (credential: unknown, name?: string) =>
    request<{ id: string; name: string }>("/api/v1/auth/webauthn/register/finish", {
      method: "POST",
      body: JSON.stringify({ credential, name }),
    }),
  listMyWebAuthn: () =>
    request<{ credentials: { id: string; name: string; created_at: string }[] }>(
      "/api/v1/auth/webauthn/credentials",
    ),
  deleteMyWebAuthn: (id: string) =>
    request<{ status: string }>(`/api/v1/auth/webauthn/credentials/${id}`, { method: "DELETE" }),
  listUserWebAuthn: (userId: string) =>
    request<{ credentials: { id: string; name: string; created_at: string }[] }>(
      `/api/v1/admin/users/${userId}/webauthn`,
    ),
  logout: () => request<{ status: string }>("/api/v1/auth/logout", { method: "POST" }),
  me: () => request<User>("/api/v1/auth/me"),
  authMethods: () =>
    request<{ mode: string; oidc_ready: boolean; ldap_ready: boolean }>("/api/v1/auth/methods"),
  getAuthSettings: () => request<AuthSettings>("/api/v1/admin/settings/auth"),
  putAuthSettings: (body: Partial<AuthSettings>) =>
    request<AuthSettings>("/api/v1/admin/settings/auth", {
      method: "PUT",
      body: JSON.stringify(body),
    }),
  getSIEMSettings: () => request<SIEMSettings>("/api/v1/admin/settings/siem"),
  putSIEMSettings: (body: Partial<SIEMSettings>) =>
    request<SIEMSettings>("/api/v1/admin/settings/siem", {
      method: "PUT",
      body: JSON.stringify(body),
    }),
  getITSMSettings: () => request<ITSMSettings>("/api/v1/admin/settings/itsm"),
  putITSMSettings: (body: Partial<ITSMSettings>) =>
    request<ITSMSettings>("/api/v1/admin/settings/itsm", {
      method: "PUT",
      body: JSON.stringify(body),
    }),
  validateITSMTicket: (ticket_id: string) =>
    request<ITSMTicketInfo>("/api/v1/admin/itsm/validate", {
      method: "POST",
      body: JSON.stringify({ ticket_id }),
    }),
  getInfraStatus: () => request<InfraStatus>("/api/v1/admin/settings/infra"),
  getSSHSettings: () => request<SSHSettings>("/api/v1/admin/settings/ssh"),
  putSSHSettings: (body: Partial<SSHSettings>) =>
    request<SSHSettings>("/api/v1/admin/settings/ssh", {
      method: "PUT",
      body: JSON.stringify(body),
    }),
  listDiscoveryJobs: () => request<{ jobs: DiscoveryJob[] }>("/api/v1/admin/discovery/jobs"),
  createDiscoveryJob: (body: { kind?: string; cidr?: string; ports?: string; asset_ids?: string[] }) =>
    request<DiscoveryJob>("/api/v1/admin/discovery/jobs", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  getDiscoveryJob: (id: string) => request<DiscoveryJob>(`/api/v1/admin/discovery/jobs/${id}`),
  listDiscoveryCandidates: (jobId: string) =>
    request<{ candidates: DiscoveryCandidate[] }>(
      `/api/v1/admin/discovery/jobs/${jobId}/candidates`,
    ),
  importDiscoveryCandidate: (id: string) =>
    request<DiscoveryImportResult>(`/api/v1/admin/discovery/candidates/${id}/import`, { method: "POST" }),
  getAnalyticsOverview: (hours?: number, opts?: { severity?: string; code?: string }) => {
    const qs = new URLSearchParams();
    if (hours) qs.set("hours", String(hours));
    if (opts?.severity) qs.set("severity", opts.severity);
    if (opts?.code) qs.set("code", opts.code);
    const q = qs.toString();
    return request<AnalyticsOverview>(`/api/v1/admin/analytics/overview${q ? `?${q}` : ""}`);
  },
  changePassword: (current_password: string, new_password: string) =>
    request<{ status: string }>("/api/v1/auth/password", {
      method: "POST",
      body: JSON.stringify({ current_password, new_password }),
    }),
  mfaSetup: () =>
    request<{ secret: string; url: string }>("/api/v1/auth/mfa/setup", { method: "POST" }),
  mfaConfirm: (code: string) =>
    request<{ status: string }>("/api/v1/auth/mfa/confirm", {
      method: "POST",
      body: JSON.stringify({ code }),
    }),
  listUsers: () => request<{ users: User[] }>("/api/v1/admin/users"),
  getUser: (id: string) => request<User>(`/api/v1/admin/users/${id}`),
  createUser: (body: {
    username: string;
    email: string;
    display_name: string;
    password?: string;
    roles: string[];
  }) =>
    request<{ user: User; temporary_password?: string }>("/api/v1/admin/users", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  updateUser: (
    id: string,
    body: {
      email?: string;
      display_name?: string;
      status?: string;
      roles?: string[];
      tags?: string[];
    },
  ) =>
    request<User>(`/api/v1/admin/users/${id}`, {
      method: "PATCH",
      body: JSON.stringify(body),
    }),
  resetPassword: (id: string) =>
    request<{ temporary_password: string }>(`/api/v1/admin/users/${id}/password/reset`, {
      method: "POST",
    }),
  resetMfa: (id: string) =>
    request<{ status: string }>(`/api/v1/admin/users/${id}/mfa/reset`, { method: "POST" }),
  listUserSSHKeys: (id: string) =>
    request<{ keys: UserSSHKey[] }>(`/api/v1/admin/users/${id}/ssh-keys`),
  addUserSSHKey: (id: string, body: { name?: string; public_key: string }) =>
    request<UserSSHKey>(`/api/v1/admin/users/${id}/ssh-keys`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  deleteUserSSHKey: (id: string, keyId: string) =>
    request<{ status: string }>(`/api/v1/admin/users/${id}/ssh-keys/${keyId}`, { method: "DELETE" }),
  listRoles: () => request<{ roles: Role[] }>("/api/v1/admin/roles"),
  listAudit: (params?: {
    q?: string;
    field?: string;
    action?: string;
    page?: number;
    limit?: number;
  }) => {
    const sp = new URLSearchParams();
    if (params?.q) sp.set("q", params.q);
    if (params?.field) sp.set("field", params.field);
    if (params?.action) sp.set("action", params.action);
    if (params?.page) sp.set("page", String(params.page));
    if (params?.limit) sp.set("limit", String(params.limit));
    const q = sp.toString();
    return request<{
      events: AuditEvent[];
      total: number;
      limit: number;
      offset: number;
      page: number;
      pages: number;
    }>(`/api/v1/admin/audit-events${q ? `?${q}` : ""}`);
  },
  listAssets: () => request<{ assets: Asset[] }>("/api/v1/admin/assets"),
  getAsset: (id: string) => request<Asset>(`/api/v1/admin/assets/${id}`),
  createAsset: (body: {
    name: string;
    asset_type: string;
    hostname?: string;
    address: string;
    port?: number;
    protocol: string;
    database_name?: string;
    description?: string;
    tags?: string[];
  }) =>
    request<Asset>("/api/v1/admin/assets", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  updateAsset: (
    id: string,
    body: {
      name?: string;
      asset_type?: string;
      hostname?: string;
      address?: string;
      port?: number;
      protocol?: string;
      database_name?: string;
      description?: string;
      status?: string;
      tags?: string[];
    },
  ) =>
    request<Asset>(`/api/v1/admin/assets/${id}`, {
      method: "PATCH",
      body: JSON.stringify(body),
    }),
  deleteAsset: (id: string) =>
    request<{ status: string }>(`/api/v1/admin/assets/${id}`, { method: "DELETE" }),
  clearAssetHostKey: (id: string) =>
    request<Asset>(`/api/v1/admin/assets/${id}/host-key`, { method: "DELETE" }),
  createAccount: (
    assetId: string,
    body: {
      username: string;
      auth_method: string;
      secret?: string;
      description?: string;
    },
  ) =>
    request<AssetAccount>(`/api/v1/admin/assets/${assetId}/accounts`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  updateAccount: (
    assetId: string,
    accountId: string,
    body: {
      username?: string;
      auth_method?: string;
      secret?: string;
      description?: string;
      status?: string;
      rotate_after_session?: boolean;
      rotate_on_checkin?: boolean;
      rotate_interval_hours?: number;
      dual_control_checkout?: boolean;
    },
  ) =>
    request<AssetAccount>(`/api/v1/admin/assets/${assetId}/accounts/${accountId}`, {
      method: "PATCH",
      body: JSON.stringify(body),
    }),
  deleteAccount: (assetId: string, accountId: string) =>
    request<{ status: string }>(`/api/v1/admin/assets/${assetId}/accounts/${accountId}`, {
      method: "DELETE",
    }),
  rotateAccount: (
    assetId: string,
    accountId: string,
    body?: { apply_remote?: boolean; new_secret?: string; remove_old_key?: boolean },
  ) =>
    request<{ account: AssetAccount; remote_applied: boolean; method: string }>(
      `/api/v1/admin/assets/${assetId}/accounts/${accountId}/rotate`,
      {
        method: "POST",
        body: JSON.stringify(body ?? {}),
      },
    ),
  checkoutAccount: (
    assetId: string,
    accountId: string,
    body?: { reason?: string; ttl_minutes?: number },
  ) =>
    request<{
      account: AssetAccount;
      status: string;
      pending_request?: SecretCheckoutRequest;
    }>(`/api/v1/admin/assets/${assetId}/accounts/${accountId}/checkout`, {
      method: "POST",
      body: JSON.stringify(body ?? {}),
    }),
  checkinAccount: (
    assetId: string,
    accountId: string,
    body?: { rotate?: boolean; apply_remote?: boolean },
  ) =>
    request<{ account: AssetAccount; status: string }>(
      `/api/v1/admin/assets/${assetId}/accounts/${accountId}/checkin`,
      { method: "POST", body: JSON.stringify(body ?? {}) },
    ),
  forceCheckinAccount: (assetId: string, accountId: string) =>
    request<AssetAccount>(`/api/v1/admin/assets/${assetId}/accounts/${accountId}/force-checkin`, {
      method: "POST",
      body: "{}",
    }),
  revealAccount: (assetId: string, accountId: string) =>
    request<{
      username: string;
      auth_method: string;
      secret: string;
      checkout_expires_at?: string;
    }>(`/api/v1/admin/assets/${assetId}/accounts/${accountId}/reveal`, {
      method: "POST",
      body: "{}",
    }),
  listSecretCheckouts: (pending = true) =>
    request<{ requests: SecretCheckoutRequest[] }>(
      `/api/v1/admin/secret-checkouts?pending=${pending ? "1" : "0"}`,
    ),
  approveSecretCheckout: (id: string) =>
    request<{ account: AssetAccount; status: string }>(
      `/api/v1/admin/secret-checkouts/${id}/approve`,
      { method: "POST", body: "{}" },
    ),
  denySecretCheckout: (id: string) =>
    request<{ status: string }>(`/api/v1/admin/secret-checkouts/${id}/deny`, {
      method: "POST",
      body: "{}",
    }),
  listACL: (assetId: string) =>
    request<{ bindings: AccessBinding[] }>(`/api/v1/admin/assets/${assetId}/acl`),
  createACL: (
    assetId: string,
    body: {
      user_id?: string;
      role_id?: string;
      time_start?: string;
      time_end?: string;
      days_of_week?: number;
      duration_minutes?: number;
      required_tags?: string[];
      require_ticket?: boolean;
      require_reason?: boolean;
      allowed_cidrs?: string[];
      command_policy_pack_id?: string;
      sql_policy_pack_id?: string;
    },
  ) =>
    request<AccessBinding>(`/api/v1/admin/assets/${assetId}/acl`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  deleteACL: (assetId: string, bindingId: string) =>
    request<{ status: string }>(`/api/v1/admin/assets/${assetId}/acl/${bindingId}`, {
      method: "DELETE",
    }),
  createAccessRequest: (
    assetId: string,
    body: { reason: string; duration_minutes: number; ticket_id?: string },
  ) =>
    request<AccessRequest>(`/api/v1/admin/assets/${assetId}/access-requests`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  listAccessRequests: (params?: { status?: string; limit?: number; offset?: number }) => {
    const qs = new URLSearchParams();
    if (params?.status) qs.set("status", params.status);
    if (params?.limit != null) qs.set("limit", String(params.limit));
    if (params?.offset != null) qs.set("offset", String(params.offset));
    const q = qs.toString();
    return request<{ requests: AccessRequest[]; total: number }>(
      `/api/v1/admin/access-requests${q ? `?${q}` : ""}`,
    );
  },
  accessRequestsSummary: () =>
    request<{
      pending_approve: number;
      my_pending: number;
      my_recent_decisions: AccessRequest[];
    }>("/api/v1/admin/access-requests/summary"),
  approveAccessRequest: (id: string) =>
    request<AccessRequest>(`/api/v1/admin/access-requests/${id}/approve`, { method: "POST" }),
  denyAccessRequest: (id: string) =>
    request<AccessRequest>(`/api/v1/admin/access-requests/${id}/deny`, { method: "POST" }),
  cancelAccessRequest: (id: string) =>
    request<AccessRequest>(`/api/v1/admin/access-requests/${id}/cancel`, { method: "POST" }),
  openBreakGlass: (assetId: string, body: { reason: string; duration_minutes?: number }) =>
    request<BreakGlassEvent>(`/api/v1/admin/assets/${assetId}/break-glass`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  listBreakGlass: (all = false) =>
    request<{ events: BreakGlassEvent[] }>(`/api/v1/admin/break-glass${all ? "?all=1" : ""}`),
  exportSessionMP4: (id: string) =>
    request<{ status: string; url: string }>(`/api/v1/admin/sessions/${id}/export-mp4`, {
      method: "POST",
    }),
  getRecordingMp4Url: (id: string) => `/api/v1/admin/sessions/${id}/recording.mp4`,
  createSession: (
    asset_id: string,
    account_id: string,
    opts?: { ticket_id?: string; reason?: string; db_privilege?: string },
  ) =>
    request<PamSession>("/api/v1/admin/sessions", {
      method: "POST",
      body: JSON.stringify({
        asset_id,
        account_id,
        ticket_id: opts?.ticket_id || undefined,
        reason: opts?.reason || undefined,
        db_privilege: opts?.db_privilege || undefined,
      }),
    }),
  endSession: (id: string) =>
    request<PamSession>(`/api/v1/admin/sessions/${id}/end`, { method: "POST" }),
  listSessions: (params?: {
    status?: string;
    protocol?: string;
    q?: string;
    limit?: number;
    offset?: number;
  }) => {
    const qs = new URLSearchParams();
    if (params?.status) qs.set("status", params.status);
    if (params?.protocol) qs.set("protocol", params.protocol);
    if (params?.q) qs.set("q", params.q);
    if (params?.limit != null) qs.set("limit", String(params.limit));
    if (params?.offset != null) qs.set("offset", String(params.offset));
    const q = qs.toString();
    return request<{ sessions: PamSession[]; total: number }>(
      `/api/v1/admin/sessions${q ? `?${q}` : ""}`,
    );
  },
  getSession: (id: string) => request<PamSession>(`/api/v1/admin/sessions/${id}`),
  getRecordingUrl: (id: string) => `/api/v1/admin/sessions/${id}/recording`,
  getAppIntegration: (assetId: string) =>
    request<AppIntegration>(`/api/v1/admin/assets/${assetId}/app`),
  putAppIntegration: (assetId: string, body: Partial<AppIntegration> & { oidc_client_secret?: string; clear_oidc_client_secret?: boolean }) =>
    request<AppIntegration>(`/api/v1/admin/assets/${assetId}/app`, {
      method: "PUT",
      body: JSON.stringify(body),
    }),
  requestAppAccess: (assetId: string, body: { account_id?: string; ticket_id?: string; reason?: string }) =>
    request<AppLease>(`/api/v1/admin/assets/${assetId}/app/access`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  requestK8sAccess: (assetId: string, body: { account_id: string; ticket_id?: string; reason?: string }) =>
    request<AppLease>(`/api/v1/admin/assets/${assetId}/k8s/access`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  consumeK8sLease: (leaseId: string) =>
    request<{ status: string }>(`/api/v1/admin/k8s/leases/${leaseId}/consume`, { method: "POST" }),
  getComplianceStatus: () => request<ComplianceStatus>("/api/v1/admin/compliance/status"),
  listCompliancePacks: () => request<{ packs: CompliancePack[] }>("/api/v1/admin/compliance/packs"),
  applyCompliancePack: (id: string) =>
    request<CompliancePack>(`/api/v1/admin/compliance/packs/${id}/apply`, { method: "POST" }),
  getRetention: () => request<RetentionPolicy>("/api/v1/admin/compliance/retention"),
  putRetention: (body: Partial<RetentionPolicy>) =>
    request<RetentionPolicy>("/api/v1/admin/compliance/retention", {
      method: "PUT",
      body: JSON.stringify(body),
    }),
  listLegalHolds: (activeOnly?: boolean) =>
    request<{ holds: LegalHold[] }>(
      `/api/v1/admin/compliance/legal-holds${activeOnly ? "?active=1" : ""}`,
    ),
  createLegalHold: (body: { resource_type: string; resource_id?: string; reason: string }) =>
    request<LegalHold>("/api/v1/admin/compliance/legal-holds", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  releaseLegalHold: (id: string) =>
    request<LegalHold>(`/api/v1/admin/compliance/legal-holds/${id}/release`, { method: "POST" }),
  runCompliancePurge: () =>
    request<{
      recordings_removed: number;
      sessions_purged: number;
      skipped_holds: number;
      audit_note: string;
    }>("/api/v1/admin/compliance/purge", { method: "POST" }),
  getDRStatus: () => request<DRStatus>("/api/v1/admin/dr/status"),
  getDRSettings: () => request<DRSettings>("/api/v1/admin/dr/settings"),
  putDRSettings: (body: Partial<DRSettings>) =>
    request<DRSettings>("/api/v1/admin/dr/settings", {
      method: "PUT",
      body: JSON.stringify(body),
    }),
  runDRBackup: () =>
    request<{ path: string; bytes: number; status: string; at: string }>("/api/v1/admin/dr/backup", {
      method: "POST",
    }),
  recordDRDrill: (body: { ok: boolean; notes: string }) =>
    request<DRSettings>("/api/v1/admin/dr/drill", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  listCommandPacks: () => request<{ packs: CommandPolicyPack[] }>("/api/v1/admin/jea/packs"),
  getCommandPack: (id: string) => request<CommandPolicyPack>(`/api/v1/admin/jea/packs/${id}`),
  createCommandPack: (body: CommandPolicyPackInput) =>
    request<CommandPolicyPack>("/api/v1/admin/jea/packs", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  updateCommandPack: (id: string, body: CommandPolicyPackInput) =>
    request<CommandPolicyPack>(`/api/v1/admin/jea/packs/${id}`, {
      method: "PUT",
      body: JSON.stringify(body),
    }),
  deleteCommandPack: (id: string) =>
    request<{ status: string }>(`/api/v1/admin/jea/packs/${id}`, { method: "DELETE" }),
  listSQLPacks: () => request<{ packs: SQLPolicyPack[] }>("/api/v1/admin/jea/sql-packs"),
  createSQLPack: (body: SQLPolicyPackInput) =>
    request<SQLPolicyPack>("/api/v1/admin/jea/sql-packs", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  updateSQLPack: (id: string, body: SQLPolicyPackInput) =>
    request<SQLPolicyPack>(`/api/v1/admin/jea/sql-packs/${id}`, {
      method: "PUT",
      body: JSON.stringify(body),
    }),
  deleteSQLPack: (id: string) =>
    request<{ status: string }>(`/api/v1/admin/jea/sql-packs/${id}`, { method: "DELETE" }),
  listAttackScenarios: () =>
    request<{ scenarios: AttackSimScenario[] }>("/api/v1/admin/attack-sim/scenarios"),
  listAttackRuns: () => request<{ runs: AttackSimRun[] }>("/api/v1/admin/attack-sim/runs"),
  getAttackRun: (id: string) => request<AttackSimRun>(`/api/v1/admin/attack-sim/runs/${id}`),
  startAttackRun: (body?: { notes?: string }) =>
    request<AttackSimRun>("/api/v1/admin/attack-sim/runs", {
      method: "POST",
      body: JSON.stringify(body || {}),
    }),
};

export type AttackSimScenario = {
  id: string;
  title: string;
  category: string;
  description: string;
};

export type AttackSimResult = {
  id: string;
  run_id: string;
  scenario_id: string;
  title: string;
  category: string;
  status: string;
  detail: string;
  duration_ms: number;
  created_at: string;
};

export type AttackSimRun = {
  id: string;
  started_by?: string;
  status: string;
  notes: string;
  summary: Record<string, unknown>;
  started_at: string;
  finished_at?: string;
  results?: AttackSimResult[];
};

export type CommandPolicyPack = {
  id: string;
  name: string;
  description: string;
  mode: "allowlist" | "denylist" | string;
  patterns: string[];
  created_at: string;
  updated_at: string;
};

export type CommandPolicyPackInput = {
  name: string;
  description?: string;
  mode: string;
  patterns: string[];
};

export type SQLPolicyPack = {
  id: string;
  name: string;
  description: string;
  mode: "allowlist" | "denylist" | string;
  statements: string[];
  tables: string[];
  mask_columns: string[];
  mask_replacement: string;
  created_at: string;
  updated_at: string;
};

export type SQLPolicyPackInput = {
  name: string;
  description?: string;
  mode: string;
  statements: string[];
  tables: string[];
  mask_columns: string[];
  mask_replacement?: string;
};

export type PamSession = {
  id: string;
  user_id: string;
  asset_id: string;
  account_id: string;
  protocol: string;
  status: string;
  client_ip: string;
  recording_path?: string;
  error_message?: string;
  started_at?: string;
  ended_at?: string;
  last_seen_at?: string;
  created_at: string;
  username?: string;
  asset_name?: string;
  account_username?: string;
  asset_address?: string;
  has_recording: boolean;
  isolated?: boolean;
  database_name?: string;
  wire_token?: string;
  wire_addr?: string;
  wire_user?: string;
  wire_hint?: string;
  db_privilege?: string;
  break_glass?: boolean;
};

export type AppIntegration = {
  asset_id: string;
  auth_mode: string;
  login_url: string;
  oidc_issuer: string;
  oidc_client_id: string;
  has_oidc_client_secret: boolean;
  recording_mode: string;
  header_name: string;
  updated_at?: string;
};

export type AppLease = {
  id: string;
  asset_id: string;
  account_id?: string;
  user_id: string;
  status: string;
  expires_at: string;
  created_at: string;
  secret?: string;
  username?: string;
  login_url?: string;
  auth_mode?: string;
  auth_method?: string;
  open_url?: string;
  kind?: string;
  cluster_address?: string;
  cluster_port?: number;
};

export type RetentionPolicy = {
  id: string;
  name: string;
  audit_retention_days: number;
  session_retention_days: number;
  recording_retention_days: number;
  purge_enabled: boolean;
  updated_at: string;
};

export type CompliancePack = {
  id: string;
  title: string;
  description: string;
  controls: string[];
  audit_days: number;
  session_days: number;
  recording_days: number;
  active: boolean;
};

export type LegalHold = {
  id: string;
  resource_type: string;
  resource_id: string;
  reason: string;
  active: boolean;
  created_at: string;
  released_at?: string;
};

export type ComplianceStatus = {
  active_pack_id?: string;
  applied_at?: string;
  retention: RetentionPolicy;
  controls: { id: string; title: string; status: string; detail: string }[];
  legal_hold_count: number;
  last_purge_at?: string;
  last_purge_stats?: Record<string, unknown>;
  generated_at: string;
};

export type DRSettings = {
  site_name: string;
  role: string;
  rpo_minutes: number;
  rto_minutes: number;
  replica_dsn_hint: string;
  backup_dir: string;
  last_backup_at?: string;
  last_backup_path?: string;
  last_backup_bytes: number;
  last_backup_status?: string;
  last_drill_at?: string;
  last_drill_notes?: string;
  last_drill_ok?: boolean;
  updated_at: string;
};

export type DRStatus = {
  settings: DRSettings;
  primary_ok: boolean;
  replica_ok?: boolean;
  replica_error?: string;
  backup_fresh: boolean;
  backup_age_minutes?: number;
  rpo_breached: boolean;
  recordings_dir: string;
  generated_at: string;
  runbook_hint: string;
};

export function hasPerm(user: User | null, perm: string): boolean {
  return !!user?.permissions?.includes(perm);
}
