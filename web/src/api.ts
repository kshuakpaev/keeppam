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
  x509_identity?: string;
  roles?: string[];
  groups?: string[];
  group_ids?: string[];
  permissions?: string[];
  tags?: string[];
};

export type Role = {
  id: string;
  name: string;
  description: string;
};

export type PamGroup = {
  id: string;
  name: string;
  description: string;
  parent_id?: string;
  parent_name?: string;
  member_count: number;
  created_at: string;
  updated_at: string;
  members?: { id: string; username: string; email: string; display_name: string; status: string }[];
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

export type AuditVerify = {
  ok: boolean;
  events: number;
  digest_ok: number;
  digest_mismatch: number;
  breaks: { index: number; id: string; reason: string }[];
  head_hash?: string;
  tail_hash?: string;
  unsealed: number;
  batches: number;
  batch_mac_ok: number;
  batch_mac_fail: number;
  batch_link_fail: number;
};

export type AuditBatch = {
  id: string;
  seq: number;
  from_ts: string;
  to_ts: string;
  first_id: string;
  last_id: string;
  event_count: number;
  first_hash: string;
  last_hash: string;
  prev_batch_mac: string;
  mac: string;
  created_at: string;
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
  token_request_enabled?: boolean;
  k8s_sa_namespace?: string;
  k8s_sa_name?: string;
  token_ttl_seconds?: number;
  k8s_impersonate?: boolean;
  k8s_impersonate_prefix?: string;
  k8s_bind_user?: boolean;
  ad_user_dn?: string;
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
  approval_stages?: string[];
  approval_mode?: string;
  quorum_n?: number;
  quorum_m?: number;
  approver_group_id?: string;
  approver_group_name?: string;
  require_supervisor?: boolean;
  supervisor_group_id?: string;
  supervisor_group_name?: string;
  ad_privileged_group_dn?: string;
  krb_spn?: string;
  terminal_charset?: string;
  rdp_remote_app?: string;
  rdp_remote_app_dir?: string;
  rdp_remote_app_args?: string;
  citrix_published_app?: string;
  citrix_storefront_url?: string;
  citrix_sta_urls?: string;
  citrix_transport?: string;
  tn3270_codepage?: string;
  tn3270_terminal_type?: string;
  host_key_algo?: string;
  host_key_fingerprint?: string;
  host_key_learned_at?: string;
  pam_only?: boolean;
  firewall_applied_at?: string;
  created_at: string;
  updated_at: string;
  accounts?: AssetAccount[];
};

export type PasswordSetMember = {
  account_id: string;
  asset_id: string;
  asset_name: string;
  protocol: string;
  username: string;
  auth_method: string;
  directory: boolean;
  sort_order: number;
};

export type PasswordSet = {
  id: string;
  name: string;
  description: string;
  sync_order: "directory_first" | "directory_last";
  created_at: string;
  updated_at: string;
  members?: PasswordSetMember[];
};

export type AccessBinding = {
  id: string;
  asset_id?: string;
  asset_match_tags?: string[];
  asset_match_mode?: string;
  asset_match_name?: string;
  asset_match_hostname?: string;
  asset_match_types?: string[];
  asset_match_cidrs?: string[];
  inherited?: boolean;
  user_id?: string;
  role_id?: string;
  group_id?: string;
  username?: string;
  role_name?: string;
  group_name?: string;
  time_start?: string;
  time_end?: string;
  days_of_week: number;
  expires_at?: string;
  required_tags: string[];
  require_ticket: boolean;
  require_reason?: boolean;
  allowed_cidrs?: string[];
  allowed_countries?: string[];
  allowed_devices?: string[];
  allowed_namespaces?: string[];
  allowed_egress?: string[];
  pii_action?: string;
  nlp_dlp_action?: string;
  file_transfer?: string;
  command_policy_pack_id?: string;
  command_policy_pack_name?: string;
  sql_policy_pack_id?: string;
  sql_policy_pack_name?: string;
  http_policy_pack_id?: string;
  http_policy_pack_name?: string;
  app_object_pack_id?: string;
  app_object_pack_name?: string;
  access_policy_id?: string;
  access_policy_name?: string;
  max_risk?: number;
  risk_action?: string;
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

export type OpApproval = {
  id: string;
  session_id: string;
  user_id: string;
  asset_id: string;
  method: string;
  path: string;
  object: string;
  pack_name: string;
  channel: string;
  status: string;
  approver_id?: string;
  created_at: string;
  decided_at?: string;
  expires_at: string;
  username?: string;
  asset_name?: string;
  approver_username?: string;
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
  risk_score?: number;
  risk_factors?: string[];
  approval_stages?: string[];
  approval_mode?: string;
  quorum_n?: number;
  quorum_m?: number;
  quorum_votes?: number;
  approver_group_id?: string;
  approver_group_name?: string;
  stage?: string;
  approvals?: { stage: string; actor_id: string; username: string; created_at: string }[];
};

export type AuthSettings = {
  mode: "local" | "oidc" | "ldap" | "saml" | string;
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
  radius_host: string;
  radius_nas_id: string;
  radius_timeout_sec: number;
  radius_secret?: string;
  has_radius_secret: boolean;
  radius_auto_provision: boolean;
  radius_skip_mfa: boolean;
  radius_default_role: string;
  radius_auth_method?: string;
  radius_eap_ca_pem?: string;
  radius_eap_anonymous_user?: string;
  radius_eap_insecure_tls?: boolean;
  radius_radsec?: boolean;
  radius_radsec_ca_pem?: string;
  radius_radsec_client_pem?: string;
  saml_idp_metadata_url: string;
  saml_idp_entity_id: string;
  saml_idp_sso_url: string;
  saml_idp_cert_pem: string;
  saml_sp_entity_id: string;
  has_saml_sp_key: boolean;
  rotate_saml_sp_key?: boolean;
  saml_attr_username: string;
  saml_attr_email: string;
  saml_attr_display_name: string;
  saml_auto_provision: boolean;
  saml_skip_mfa: boolean;
  saml_default_role: string;
  saml_group_attr?: string;
  saml_group_role_map?: Record<string, string>;
  saml_acs_url?: string;
  saml_metadata_url?: string;
  saml_slo_url?: string;
  scim_enabled: boolean;
  scim_token?: string;
  has_scim_token: boolean;
  scim_default_role: string;
  scim_base_url?: string;
  updated_at?: string;
};

export type SAMLIdP = {
  id: string;
  slug: string;
  name: string;
  enabled: boolean;
  sort_order?: number;
  metadata_url: string;
  entity_id: string;
  sso_url: string;
  cert_pem: string;
  attr_username: string;
  attr_email: string;
  attr_display_name: string;
  auto_provision: boolean;
  skip_mfa: boolean;
  default_role: string;
  group_attr: string;
  group_role_map?: Record<string, string>;
  acs_url?: string;
  sp_metadata_url?: string;
  slo_url?: string;
};

export type SSHSettings = {
  ssh_auth_mode: "vault_secret" | "ssh_cert" | "gssapi" | string;
  ssh_ca_public: string;
  ssh_cert_ttl_hours: number;
  krb5_realm?: string;
  krb5_config?: string;
  krb5_principal?: string;
  krb5_spn_template?: string;
  has_krb5_keytab?: boolean;
  krb5_keytab?: string;
  has_ssh_ca: boolean;
  rotate_ca?: boolean;
  updated_at?: string;
};

export type FirewallProbeAgent = {
  id: string;
  name: string;
  segment: string;
  probe_url: string;
  has_token?: boolean;
  enabled: boolean;
  last_health_at?: string;
  last_health_ok?: boolean;
  last_error?: string;
};

export type NACSettings = {
  mode?: string;
  api_url?: string;
  api_token?: string;
  has_api_token?: boolean;
  vendor?: string;
  timeout_ms?: number;
  last_check_at?: string;
  last_error?: string;
  updated_at?: string;
};

export type EIDASSettings = {
  mode?: string;
  profile?: string;
  require_b_lta?: boolean;
  pkcs11_enabled?: boolean;
  pkcs11_module?: string;
  pkcs11_label?: string;
  pkcs11_pin?: string;
  has_pkcs11_pin?: boolean;
  cert_cn?: string;
  cert_qualified?: boolean;
  pades_profile?: string;
  last_check_at?: string;
  last_error?: string;
  updated_at?: string;
};

export type UEBAMLSettings = {
  mode?: string;
  peer_group?: boolean;
  ml_threshold?: number;
  live_interval_s?: number;
  last_run_at?: string;
  last_error?: string;
  updated_at?: string;
};

export type FirewallSettings = {
  pam_gateway_cidrs: string[];
  probe_url?: string;
  probe_quorum?: number;
  probe_agents?: FirewallProbeAgent[];
  probe_interval_hours?: number;
  awx_launch_url?: string;
  awx_token?: string;
  has_awx_token?: boolean;
  awx_auto_push?: boolean;
  last_probe_at?: string;
  last_push_at?: string;
  last_push_error?: string;
  updated_at?: string;
};

export type FirewallAssetStatus = {
  id: string;
  name: string;
  address: string;
  port: number;
  protocol: string;
  pam_only: boolean;
  firewall_applied_at?: string;
  firewall_probe_at?: string;
  firewall_probe_reachable?: boolean;
  gaps?: string[];
};

export type FirewallStatus = {
  pam_only_count: number;
  gateway_cidrs_configured: boolean;
  gateway_cidrs: string[];
  unapplied_count: number;
  non_ip_count: number;
  probe_reachable_count: number;
  probe_quorum?: number;
  probe_agents_total?: number;
  probe_agents_healthy?: number;
  last_probe_at?: string;
  last_push_at?: string;
  last_push_error?: string;
  ready: boolean;
  assets: FirewallAssetStatus[];
};

export type FirewallProbeReport = {
  probed_at: string;
  reachable_count: number;
  probe_quorum?: number;
  probe_agents_total?: number;
  results: {
    asset_id: string;
    name: string;
    address: string;
    port: number;
    reachable: boolean;
    detail?: string;
    via: string;
    reachable_agents?: number;
    quorum?: number;
    agents?: {
      agent: string;
      segment?: string;
      reachable: boolean;
      detail?: string;
      error?: string;
      healthy: boolean;
    }[];
  }[];
};

export type SIEMSettings = {
  enabled: boolean;
  transport: "off" | "syslog_udp" | "syslog_tcp" | "webhook" | "kafka" | "nats" | "opensearch" | string;
  syslog_addr: string;
  syslog_tag: string;
  syslog_facility: number;
  webhook_url: string;
  webhook_auth_header?: string;
  has_webhook_auth_header: boolean;
  kafka_brokers?: string;
  kafka_topic?: string;
  kafka_username?: string;
  kafka_password?: string;
  has_kafka_password?: boolean;
  nats_url?: string;
  nats_subject?: string;
  nats_token?: string;
  has_nats_token?: boolean;
  opensearch_url?: string;
  opensearch_index?: string;
  format: "json" | "cef" | "ecs" | string;
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

export type NotifySettings = {
  enabled: boolean;
  webhook_url: string;
  auth_header?: string;
  has_auth_header: boolean;
  timeout_sec: number;
  last_error?: string;
  last_sent_at?: string;
  smtp_enabled?: boolean;
  smtp_host?: string;
  smtp_port?: number;
  smtp_tls?: string;
  smtp_tls_insecure?: boolean;
  smtp_username?: string;
  smtp_password?: string;
  has_smtp_password?: boolean;
  smtp_from?: string;
  smtp_last_error?: string;
  smtp_last_sent_at?: string;
  updated_at?: string;
};

export type InboxNotification = {
  id: string;
  kind: string;
  title: string;
  body: string;
  ref_type: string;
  ref_id: string;
  read_at?: string;
  created_at: string;
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
  geoip_db?: string;
  geoip_ready?: boolean;
  geoip_type?: string;
  geoip_nodes?: number;
  trusted_proxies?: string[];
  opa_policy?: string;
  opa_ready?: boolean;
  opa_package?: string;
  spiffe_trust_domain?: string;
  spiffe_id?: string;
  spiffe_svid?: boolean;
  spiffe_bundle?: boolean;
  pkcs11_token_file?: string;
  pkcs11_module?: string;
  pkcs11_helper?: boolean;
  pkcs11_label?: string;
  pkcs11_uri?: boolean;
  go_version?: string;
  cgo_enabled?: string;
  fips?: string;
  fips_required?: boolean;
  sbom_file?: boolean;
  sbom_components?: number;
  otel_endpoint?: string;
  otel_ready?: boolean;
  otel_via?: string;
  coredump?: string;
  dumpable?: boolean;
  data_key_mlock?: boolean;
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
  ueba?: {
    actor: string;
    baseline: number;
    recent_distinct: number;
    new_assets: number;
    new_names?: string[];
    spread: boolean;
  }[];
};

export type AnalyticsSLO = {
  generated_at: string;
  targets: {
    auth_p95_seconds: number;
    session_setup_p95_seconds: number;
    audit_lag_seconds: number;
  };
  auth_p95_seconds?: number | null;
  auth_samples: number;
  auth_burn?: number;
  session_setup_p95_seconds?: number | null;
  session_setup_samples: number;
  session_setup_burn?: number;
  active_sessions: number;
  audit_export_lag_seconds?: number | null;
  audit_pending: number;
  audit_lag_burn?: number;
  siem_enabled: boolean;
  siem_healthy: boolean;
  breached: boolean;
};

function csrfToken(): string {
  const match = document.cookie.match(/(?:^|; )kp_csrf=([^;]*)/);
  return match ? decodeURIComponent(match[1]) : "";
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (!headers.has("Content-Type") && init.body && !(init.body instanceof FormData)) {
    headers.set("Content-Type", "application/json");
  }
  if (!headers.has("Accept-Language")) {
    const lang = (document.cookie.match(/(?:^|; )kp_lang=([^;]*)/) || [])[1];
    headers.set("Accept-Language", decodeURIComponent(lang || "ru").startsWith("en") ? "en" : "ru");
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
    throw ApiError.fromResponse(res.status, data);
  }
  return data as T;
}

export class ApiError extends Error {
  status: number;
  code?: string;
  challenge_token?: string;
  totp?: boolean;
  webauthn?: boolean;
  risk_score?: number;
  max_risk?: number;
  risk_factors?: string[];
  risk_action?: string;
  operation?: string;

  constructor(message: string, status: number, extra?: Partial<ApiError>) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    Object.assign(this, extra);
  }

  static fromResponse(status: number, data: unknown): ApiError {
    const d = (data || {}) as {
      error?: string;
      code?: string;
      challenge_token?: string;
      totp?: boolean;
      webauthn?: boolean;
      risk_score?: number;
      max_risk?: number;
      risk_factors?: string[];
      risk_action?: string;
      operation?: string;
    };
    return new ApiError(d.error || "request failed", status, {
      code: d.code,
      challenge_token: d.challenge_token,
      totp: d.totp,
      webauthn: d.webauthn,
      risk_score: d.risk_score,
      max_risk: d.max_risk,
      risk_factors: d.risk_factors,
      risk_action: d.risk_action,
      operation: d.operation,
    });
  }

  static isStepUp(err: unknown): err is ApiError {
    return err instanceof ApiError && err.code === "mfa_required" && !!err.challenge_token;
  }
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
  loginCert: () =>
    request<{
      status: string;
      challenge_token?: string;
      user?: User;
    }>("/api/v1/auth/login/cert", { method: "POST", body: "{}" }),
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
  stepUpTotp: (challenge_token: string, code: string) =>
    request<{ step_up_token: string }>("/api/v1/auth/stepup/totp", {
      method: "POST",
      body: JSON.stringify({ challenge_token, code }),
    }),
  stepUpWebAuthnBegin: (challenge_token: string) =>
    request<unknown>("/api/v1/auth/stepup/webauthn/begin", {
      method: "POST",
      body: JSON.stringify({ challenge_token }),
    }),
  stepUpWebAuthnFinish: (challenge_token: string, credential: unknown) =>
    request<{ step_up_token: string }>("/api/v1/auth/stepup/webauthn/finish", {
      method: "POST",
      body: JSON.stringify({ challenge_token, credential }),
    }),
  getOpStepUp: (sessionId: string) =>
    request<{
      pending: boolean;
      granted?: boolean;
      code?: string;
      challenge_token?: string;
      totp?: boolean;
      webauthn?: boolean;
      risk_score?: number;
      max_risk?: number;
      risk_factors?: string[];
      operation?: string;
    }>(`/api/v1/admin/sessions/${sessionId}/op-stepup`),
  listUserWebAuthn: (userId: string) =>
    request<{ credentials: { id: string; name: string; created_at: string }[] }>(
      `/api/v1/admin/users/${userId}/webauthn`,
    ),
  logout: () => request<{ status: string }>("/api/v1/auth/logout", { method: "POST" }),
  me: () => request<User>("/api/v1/auth/me"),
  authMethods: () =>
    request<{
      mode: string;
      oidc_ready: boolean;
      ldap_ready: boolean;
      saml_ready: boolean;
      radius_ready?: boolean;
      cert_login?: boolean;
      cert_presented?: boolean;
      saml_idps?: { slug: string; name: string }[];
    }>("/api/v1/auth/methods"),
  listSAMLIdPs: () => request<{ idps: SAMLIdP[] }>("/api/v1/admin/settings/saml/idps"),
  createSAMLIdP: (body: Partial<SAMLIdP>) =>
    request<SAMLIdP>("/api/v1/admin/settings/saml/idps", { method: "POST", body: JSON.stringify(body) }),
  putSAMLIdP: (id: string, body: Partial<SAMLIdP>) =>
    request<SAMLIdP>(`/api/v1/admin/settings/saml/idps/${id}`, { method: "PUT", body: JSON.stringify(body) }),
  deleteSAMLIdP: (id: string) =>
    request<{ status: string }>(`/api/v1/admin/settings/saml/idps/${id}`, { method: "DELETE" }),
  getAuthSettings: () => request<AuthSettings>("/api/v1/admin/settings/auth"),
  getArchiveSettings: () => request<ArchiveSettings>("/api/v1/admin/settings/archive"),
  putArchiveSettings: (body: Partial<ArchiveSettings>) =>
    request<ArchiveSettings>("/api/v1/admin/settings/archive", {
      method: "PUT",
      body: JSON.stringify(body),
    }),
  runArchiveSync: () =>
    request<{ copied: number; skipped: number; failed: number }>("/api/v1/admin/settings/archive/sync", {
      method: "POST",
    }),
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
  downloadSIEMBulk: async (limit = 200) => {
    const res = await fetch(`/api/v1/admin/settings/siem/bulk?limit=${limit}`, { credentials: "include" });
    if (!res.ok) {
      const data = (await res.json().catch(() => ({}))) as { error?: string };
      throw new Error(data.error || res.statusText);
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "keeppam-audit.ndjson";
    a.click();
    URL.revokeObjectURL(url);
  },
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
  getFirewallSettings: () => request<FirewallSettings>("/api/v1/admin/settings/firewall"),
  putFirewallSettings: (body: Partial<FirewallSettings>) =>
    request<FirewallSettings>("/api/v1/admin/settings/firewall", {
      method: "PUT",
      body: JSON.stringify(body),
    }),
  getFirewallStatus: () => request<FirewallStatus>("/api/v1/admin/firewall/status"),
  markFirewallApplied: (assetId: string) =>
    request<Asset>(`/api/v1/admin/assets/${assetId}/firewall-applied`, { method: "POST" }),
  runFirewallProbe: () =>
    request<FirewallProbeReport>("/api/v1/admin/firewall/probe", { method: "POST" }),
  putFirewallProbeAgents: (body: {
    probe_quorum: number;
    agents: { name: string; segment?: string; probe_url: string; token?: string; enabled: boolean }[];
  }) =>
    request<{ probe_quorum: number; agents: FirewallProbeAgent[] }>(
      "/api/v1/admin/firewall/probe-agents",
      { method: "PUT", body: JSON.stringify(body) },
    ),
  pushFirewallAWX: () => request<FirewallSettings>("/api/v1/admin/firewall/push", { method: "POST" }),
  getNACSettings: () => request<NACSettings>("/api/v1/admin/settings/nac"),
  putNACSettings: (body: Partial<NACSettings>) =>
    request<NACSettings>("/api/v1/admin/settings/nac", {
      method: "PUT",
      body: JSON.stringify(body),
    }),
  testNACSettings: () =>
    request<{ result: { allowed: boolean; vlan?: string; policy?: string; reason?: string } }>(
      "/api/v1/admin/settings/nac/test",
      { method: "POST" },
    ),
  getEIDASSettings: () => request<EIDASSettings>("/api/v1/admin/settings/eidas"),
  putEIDASSettings: (body: Partial<EIDASSettings>) =>
    request<EIDASSettings>("/api/v1/admin/settings/eidas", {
      method: "PUT",
      body: JSON.stringify(body),
    }),
  testEIDASSettings: () =>
    request<{
      result: {
        mode: string;
        profile: string;
        cert_cn?: string;
        cert_qualified?: boolean;
        pades_profile?: string;
        pkcs11?: boolean;
        detail?: string;
        ready?: boolean;
      };
    }>("/api/v1/admin/settings/eidas/test", { method: "POST" }),
  getUEBAMLSettings: () => request<UEBAMLSettings>("/api/v1/admin/settings/ueba-ml"),
  putUEBAMLSettings: (body: Partial<UEBAMLSettings>) =>
    request<UEBAMLSettings>("/api/v1/admin/settings/ueba-ml", {
      method: "PUT",
      body: JSON.stringify(body),
    }),
  testUEBAMLSettings: (body?: { user_id?: string; asset_id?: string }) =>
    request<{ result: { risk_score: number; risk_factors?: string[]; connect?: Record<string, unknown> } }>(
      "/api/v1/admin/settings/ueba-ml/test",
      { method: "POST", body: JSON.stringify(body || {}) },
    ),
  downloadFirewallRules: async (format: "iptables" | "nft" | "ansible" = "iptables") => {
    const res = await fetch(`/api/v1/admin/firewall/export?format=${format}`, { credentials: "include" });
    if (!res.ok) throw new Error(await res.text());
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = format === "nft" ? "keeppam-firewall.nft" : format === "ansible" ? "keeppam-firewall.yml" : "keeppam-firewall.txt";
    a.click();
    URL.revokeObjectURL(url);
  },
  getNotifySettings: () => request<NotifySettings>("/api/v1/admin/settings/notify"),
  putNotifySettings: (body: Partial<NotifySettings>) =>
    request<NotifySettings>("/api/v1/admin/settings/notify", {
      method: "PUT",
      body: JSON.stringify(body),
    }),
  testNotifyEmail: () =>
    request<{ status: string }>("/api/v1/admin/settings/notify/test-email", { method: "POST" }),
  listNotifications: (limit = 20) =>
    request<{ notifications: InboxNotification[]; unread: number }>(
      `/api/v1/notifications?limit=${limit}`,
    ),
  unreadNotifications: () => request<{ unread: number }>("/api/v1/notifications/unread-count"),
  readNotification: (id: string) =>
    request<{ status: string }>(`/api/v1/notifications/${id}/read`, { method: "POST" }),
  readAllNotifications: () =>
    request<{ status: string }>("/api/v1/notifications/read-all", { method: "POST" }),
  getInfraStatus: () => request<InfraStatus>("/api/v1/admin/settings/infra"),
  getSBOM: () => request<Record<string, unknown>>("/api/v1/admin/settings/sbom"),
  downloadSBOM: async () => {
    const bom = await request<Record<string, unknown>>("/api/v1/admin/settings/sbom");
    const blob = new Blob([JSON.stringify(bom, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "keeppam-api.cdx.json";
    a.click();
    URL.revokeObjectURL(url);
  },
  getSSHSettings: () => request<SSHSettings>("/api/v1/admin/settings/ssh"),
  putSSHSettings: (body: Partial<SSHSettings>) =>
    request<SSHSettings>("/api/v1/admin/settings/ssh", {
      method: "PUT",
      body: JSON.stringify(body),
    }),
  listDiscoveryJobs: () => request<{ jobs: DiscoveryJob[] }>("/api/v1/admin/discovery/jobs"),
  createDiscoveryJob: (body: {
    kind?: string;
    cidr?: string;
    ports?: string;
    asset_ids?: string[];
    target_asset_id?: string;
    group_dns?: string[];
  }) =>
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
  getAnalyticsSLO: () => request<AnalyticsSLO>(`/api/v1/admin/analytics/slo`),
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
      group_ids?: string[];
      x509_identity?: string;
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
  listGroups: () => request<{ groups: PamGroup[] }>("/api/v1/admin/groups"),
  getGroup: (id: string) => request<PamGroup>(`/api/v1/admin/groups/${id}`),
  createGroup: (body: { name: string; description?: string; parent_id?: string; member_ids?: string[] }) =>
    request<PamGroup>("/api/v1/admin/groups", { method: "POST", body: JSON.stringify(body) }),
  updateGroup: (id: string, body: { name?: string; description?: string; parent_id?: string; member_ids?: string[] }) =>
    request<PamGroup>(`/api/v1/admin/groups/${id}`, { method: "PUT", body: JSON.stringify(body) }),
  deleteGroup: (id: string) =>
    request<{ status: string }>(`/api/v1/admin/groups/${id}`, { method: "DELETE" }),
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
  verifyAudit: () => request<AuditVerify>("/api/v1/admin/audit-events/verify"),
  sealAudit: () =>
    request<{ sealed: number }>("/api/v1/admin/audit-events/seal", { method: "POST" }),
  listAuditBatches: () => request<{ batches: AuditBatch[] }>("/api/v1/admin/audit-events/batches"),
  listAssets: () => request<{ assets: Asset[] }>("/api/v1/admin/assets"),
  getLicense: () =>
    request<{
      issued: string;
      customer?: string;
      max_assets: number;
      asset_count: number;
      soft_warn_at: number;
      ha: boolean;
      expires?: string;
      expired: boolean;
      soft_warn: boolean;
      hard_blocked: boolean;
      source: string;
      message?: string;
    }>("/api/v1/admin/license"),
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
    approval_stages?: string[];
    approval_mode?: string;
    quorum_n?: number;
    quorum_m?: number;
    approver_group_id?: string | null;
    require_supervisor?: boolean;
    supervisor_group_id?: string | null;
    pam_only?: boolean;
    ad_privileged_group_dn?: string;
  krb_spn?: string;
  terminal_charset?: string;
  rdp_remote_app?: string;
  rdp_remote_app_dir?: string;
  rdp_remote_app_args?: string;
  citrix_published_app?: string;
  citrix_storefront_url?: string;
  citrix_sta_urls?: string;
  citrix_transport?: string;
  tn3270_codepage?: string;
  tn3270_terminal_type?: string;
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
      approval_stages?: string[];
      approval_mode?: string;
      quorum_n?: number;
      quorum_m?: number;
      approver_group_id?: string | null;
      require_supervisor?: boolean;
      supervisor_group_id?: string | null;
      pam_only?: boolean;
      ad_privileged_group_dn?: string;
  krb_spn?: string;
  terminal_charset?: string;
  rdp_remote_app?: string;
  rdp_remote_app_dir?: string;
  rdp_remote_app_args?: string;
  citrix_published_app?: string;
  citrix_storefront_url?: string;
  citrix_sta_urls?: string;
  citrix_transport?: string;
  tn3270_codepage?: string;
  tn3270_terminal_type?: string;
    },
  ) =>
    request<Asset>(`/api/v1/admin/assets/${id}`, {
      method: "PATCH",
      body: JSON.stringify(body),
    }),
  citrixSFResources: (id: string, accountId?: string) =>
    request<{
      asset_id: string;
      storefront: string;
      count: number;
      resources: {
        id: string;
        name: string;
        path?: string;
        launch_url?: string;
        initial_program?: string;
      }[];
    }>(
      `/api/v1/admin/assets/${id}/citrix/resources${accountId ? `?account_id=${encodeURIComponent(accountId)}` : ""}`,
    ),
  citrixSFDiscovery: (id: string) =>
    request<{ asset_id: string; discovery: unknown }>(`/api/v1/admin/assets/${id}/citrix/discovery`),
  citrixSTAProbe: (id: string, ticket: string) =>
    request<{ ok: boolean; sta_url?: string; body_preview?: string }>(
      `/api/v1/admin/assets/${id}/citrix/sta/probe`,
      { method: "POST", body: JSON.stringify({ ticket }) },
    ),
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
      token_request_enabled?: boolean;
      k8s_sa_namespace?: string;
      k8s_sa_name?: string;
      token_ttl_seconds?: number;
      k8s_impersonate?: boolean;
      k8s_impersonate_prefix?: string;
      k8s_bind_user?: boolean;
      ad_user_dn?: string;
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
      token_request_enabled?: boolean;
      k8s_sa_namespace?: string;
      k8s_sa_name?: string;
      token_ttl_seconds?: number;
      k8s_impersonate?: boolean;
      k8s_impersonate_prefix?: string;
      k8s_bind_user?: boolean;
      ad_user_dn?: string;
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
  listPasswordSets: () => request<{ sets: PasswordSet[] }>("/api/v1/admin/password-sets"),
  getPasswordSet: (id: string) => request<PasswordSet>(`/api/v1/admin/password-sets/${id}`),
  createPasswordSet: (body: {
    name: string;
    description?: string;
    sync_order?: string;
    account_ids?: string[];
  }) =>
    request<PasswordSet>("/api/v1/admin/password-sets", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  updatePasswordSet: (
    id: string,
    body: {
      name?: string;
      description?: string;
      sync_order?: string;
      account_ids?: string[];
    },
  ) =>
    request<PasswordSet>(`/api/v1/admin/password-sets/${id}`, {
      method: "PATCH",
      body: JSON.stringify(body),
    }),
  deletePasswordSet: (id: string) =>
    request<{ status: string }>(`/api/v1/admin/password-sets/${id}`, { method: "DELETE" }),
  rotatePasswordSet: (id: string, body?: { apply_remote?: boolean; new_secret?: string }) =>
    request<{
      set_id: string;
      results: {
        account_id: string;
        asset_id: string;
        username: string;
        ok: boolean;
        remote_applied: boolean;
        error?: string;
      }[];
    }>(`/api/v1/admin/password-sets/${id}/rotate`, {
      method: "POST",
      body: JSON.stringify(body ?? {}),
    }),
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
  getACL: (assetId: string, bindingId: string) =>
    request<AccessBinding>(`/api/v1/admin/assets/${assetId}/acl/${bindingId}`),
  listTagACL: () => request<{ bindings: AccessBinding[] }>("/api/v1/admin/acl/tags"),
  createTagACL: (
    body: {
      user_id?: string;
      role_id?: string;
      group_id?: string;
      asset_match_tags?: string[];
      asset_match_mode?: string;
      asset_match_name?: string;
      asset_match_hostname?: string;
      asset_match_types?: string[];
      asset_match_cidrs?: string[];
      duration_minutes?: number;
      access_policy_id?: string;
      max_risk?: number;
      risk_action?: string;
    },
  ) =>
    request<AccessBinding>("/api/v1/admin/acl/tags", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  createACL: (
    assetId: string,
    body: {
      user_id?: string;
      role_id?: string;
      group_id?: string;
      time_start?: string;
      time_end?: string;
      days_of_week?: number;
      duration_minutes?: number;
      required_tags?: string[];
      require_ticket?: boolean;
      require_reason?: boolean;
      allowed_cidrs?: string[];
      allowed_countries?: string[];
      allowed_devices?: string[];
      allowed_namespaces?: string[];
  allowed_egress?: string[];
  pii_action?: string;
  nlp_dlp_action?: string;
  file_transfer?: string;
  command_policy_pack_id?: string | null;
      sql_policy_pack_id?: string | null;
      http_policy_pack_id?: string | null;
      app_object_pack_id?: string | null;
      access_policy_id?: string | null;
      max_risk?: number;
      risk_action?: string;
    },
  ) =>
    request<AccessBinding>(`/api/v1/admin/assets/${assetId}/acl`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  updateACL: (
    assetId: string,
    bindingId: string,
    body: {
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
  nlp_dlp_action?: string;
  file_transfer?: string;
  command_policy_pack_id?: string | null;
      sql_policy_pack_id?: string | null;
      http_policy_pack_id?: string | null;
      app_object_pack_id?: string | null;
      access_policy_id?: string | null;
      max_risk?: number;
      risk_action?: string;
      asset_match_tags?: string[];
      asset_match_mode?: string;
      asset_match_name?: string;
      asset_match_hostname?: string;
      asset_match_types?: string[];
      asset_match_cidrs?: string[];
    },
  ) =>
    request<AccessBinding>(`/api/v1/admin/assets/${assetId}/acl/${bindingId}`, {
      method: "PUT",
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
      pending_ops: number;
      pending_supervise?: number;
      my_pending: number;
      my_recent_decisions: AccessRequest[];
    }>("/api/v1/admin/access-requests/summary"),
  listOpApprovals: () =>
    request<{ approvals: OpApproval[] }>("/api/v1/admin/op-approvals"),
  approveOpApproval: (id: string) =>
    request<OpApproval>(`/api/v1/admin/op-approvals/${id}/approve`, { method: "POST" }),
  denyOpApproval: (id: string) =>
    request<OpApproval>(`/api/v1/admin/op-approvals/${id}/deny`, { method: "POST" }),
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
  downloadRdpUrl: (id: string) => `/api/v1/admin/sessions/${id}/rdp.rdp`,
  createSession: (
    asset_id: string,
    account_id: string,
    opts?: {
      ticket_id?: string;
      reason?: string;
      db_privilege?: string;
      step_up_token?: string;
      rdp_width?: number;
      rdp_height?: number;
    },
  ) =>
    request<PamSession>("/api/v1/admin/sessions", {
      method: "POST",
      body: JSON.stringify({
        asset_id,
        account_id,
        ticket_id: opts?.ticket_id || undefined,
        reason: opts?.reason || undefined,
        db_privilege: opts?.db_privilege || undefined,
        step_up_token: opts?.step_up_token || undefined,
        ...(opts?.rdp_width !== undefined ? { rdp_width: opts.rdp_width } : {}),
        ...(opts?.rdp_height !== undefined ? { rdp_height: opts.rdp_height } : {}),
      }),
    }),
  endSession: (id: string) =>
    request<PamSession>(`/api/v1/admin/sessions/${id}/end`, { method: "POST" }),
  listSessions: (params?: {
    status?: string;
    protocol?: string;
    q?: string;
    waiting_supervisor?: boolean;
    limit?: number;
    offset?: number;
  }) => {
    const qs = new URLSearchParams();
    if (params?.status) qs.set("status", params.status);
    if (params?.protocol) qs.set("protocol", params.protocol);
    if (params?.q) qs.set("q", params.q);
    if (params?.waiting_supervisor) qs.set("waiting_supervisor", "1");
    if (params?.limit != null) qs.set("limit", String(params.limit));
    if (params?.offset != null) qs.set("offset", String(params.offset));
    const q = qs.toString();
    return request<{ sessions: PamSession[]; total: number }>(
      `/api/v1/admin/sessions${q ? `?${q}` : ""}`,
    );
  },
  getSession: (id: string) => request<PamSession>(`/api/v1/admin/sessions/${id}`),
  approveSupervisor: (id: string) =>
    request<PamSession>(`/api/v1/admin/sessions/${id}/supervisor/approve`, { method: "POST" }),
  denySupervisor: (id: string) =>
    request<PamSession>(`/api/v1/admin/sessions/${id}/supervisor/deny`, { method: "POST" }),
  searchSessionEvents: (params?: {
    q?: string;
    type?: string;
    filename?: string;
    process?: string;
    protocol?: string;
    client_ip?: string;
    hours?: number;
    limit?: number;
    offset?: number;
  }) => {
    const qs = new URLSearchParams();
    if (params?.q) qs.set("q", params.q);
    if (params?.type) qs.set("type", params.type);
    if (params?.filename) qs.set("filename", params.filename);
    if (params?.process) qs.set("process", params.process);
    if (params?.protocol) qs.set("protocol", params.protocol);
    if (params?.client_ip) qs.set("client_ip", params.client_ip);
    if (params?.hours != null) qs.set("hours", String(params.hours));
    if (params?.limit != null) qs.set("limit", String(params.limit));
    if (params?.offset != null) qs.set("offset", String(params.offset));
    const q = qs.toString();
    return request<{ events: SessionEventHit[]; total: number }>(
      `/api/v1/admin/sessions/events${q ? `?${q}` : ""}`,
    );
  },
  getSessionTranscript: (id: string) =>
    request<{
      indexed: boolean;
      protocol: string;
      lines: TranscriptLine[];
      output?: TranscriptLine[];
      keystrokes?: TranscriptLine[];
      screen_text?: TranscriptLine[];
      files?: TranscriptLine[];
      window_titles?: TranscriptLine[];
      processes?: TranscriptLine[];
    }>(`/api/v1/admin/sessions/${id}/transcript`),
  indexSessionTranscript: (id: string, opts?: { force?: boolean; ocr?: boolean }) =>
    request<{
      result: {
        indexed: boolean;
        source: string;
        lines: number;
        output?: number;
        keystrokes?: number;
        skipped?: string;
      };
      ocr?: {
        indexed: boolean;
        source: string;
        screen_text: number;
        skipped?: string;
      };
      lines: TranscriptLine[];
      output?: TranscriptLine[];
      keystrokes?: TranscriptLine[];
      screen_text?: TranscriptLine[];
      files?: TranscriptLine[];
      window_titles?: TranscriptLine[];
      processes?: TranscriptLine[];
    }>(
      `/api/v1/admin/sessions/${id}/transcript`,
      { method: "POST", body: JSON.stringify({ force: !!opts?.force, ocr: !!opts?.ocr }) },
    ),
  searchTimeline: (params: {
    user_id?: string;
    username?: string;
    q?: string;
    filename?: string;
    process?: string;
    source?: string;
    hours?: number;
    from?: string;
    to?: string;
    limit?: number;
    offset?: number;
  }) => {
    const qs = new URLSearchParams();
    if (params.user_id) qs.set("user_id", params.user_id);
    if (params.username) qs.set("username", params.username);
    if (params.q) qs.set("q", params.q);
    if (params.filename) qs.set("filename", params.filename);
    if (params.process) qs.set("process", params.process);
    if (params.source) qs.set("source", params.source);
    if (params.hours != null) qs.set("hours", String(params.hours));
    if (params.from) qs.set("from", params.from);
    if (params.to) qs.set("to", params.to);
    if (params.limit != null) qs.set("limit", String(params.limit));
    if (params.offset != null) qs.set("offset", String(params.offset));
    const q = qs.toString();
    return request<TimelineResult>(`/api/v1/admin/sessions/timeline${q ? `?${q}` : ""}`);
  },
  downloadTimelineCsv: async (params: {
    user_id?: string;
    username?: string;
    q?: string;
    filename?: string;
    process?: string;
    source?: string;
    from?: string;
    to?: string;
    hours?: number;
    limit?: number;
  }) => {
    const qs = new URLSearchParams();
    if (params.user_id) qs.set("user_id", params.user_id);
    if (params.username) qs.set("username", params.username);
    if (params.q) qs.set("q", params.q);
    if (params.filename) qs.set("filename", params.filename);
    if (params.process) qs.set("process", params.process);
    if (params.source) qs.set("source", params.source);
    if (params.hours != null) qs.set("hours", String(params.hours));
    if (params.from) qs.set("from", params.from);
    if (params.to) qs.set("to", params.to);
    qs.set("limit", String(params.limit ?? 200));
    qs.set("format", "csv");
    const res = await fetch(`/api/v1/admin/sessions/timeline?${qs.toString()}`, {
      credentials: "include",
    });
    if (!res.ok) {
      const data = (await res.json().catch(() => ({}))) as { error?: string };
      throw new Error(data.error || res.statusText);
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "keeppam-timeline.csv";
    a.click();
    URL.revokeObjectURL(url);
  },
  getKubeconfig: (id: string) =>
    request<{ kubeconfig: string; k8s_addr: string; k8s_token: string }>(
      `/api/v1/admin/sessions/${id}/kubeconfig`,
    ),
  k8sCatalog: (id: string) =>
    request<{ resources: K8sResourceKind[] }>(`/api/v1/admin/sessions/${id}/k8s/catalog`),
  k8sNamespaces: (id: string) =>
    request<{ namespaces: string[]; acl: boolean }>(`/api/v1/admin/sessions/${id}/k8s/namespaces`),
  k8sList: (id: string, params: { resource: string; group?: string; namespace?: string }) => {
    const qs = new URLSearchParams();
    qs.set("resource", params.resource);
    if (params.group) qs.set("group", params.group);
    if (params.namespace) qs.set("namespace", params.namespace);
    return request<{ resource: string; group?: string; items: K8sBrowseItem[] }>(
      `/api/v1/admin/sessions/${id}/k8s/list?${qs}`,
    );
  },
  k8sGet: (id: string, params: { resource: string; group?: string; namespace?: string; name: string }) => {
    const qs = new URLSearchParams();
    qs.set("resource", params.resource);
    qs.set("name", params.name);
    if (params.group) qs.set("group", params.group);
    if (params.namespace) qs.set("namespace", params.namespace);
    return request<{ resource: string; group?: string; object: unknown }>(
      `/api/v1/admin/sessions/${id}/k8s/get?${qs}`,
    );
  },
  k8sApply: (id: string, body: { manifest: string; namespace?: string }) =>
    request<{ results: K8sApplyResult[] }>(`/api/v1/admin/sessions/${id}/k8s/apply`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  k8sReplace: (id: string, object: unknown) =>
    request<{ object: unknown; status: number }>(`/api/v1/admin/sessions/${id}/k8s/object`, {
      method: "PUT",
      body: JSON.stringify({ object }),
    }),
  k8sDelete: (id: string, params: { resource: string; group?: string; namespace?: string; name: string }) =>
    request<{ status: number }>(`/api/v1/admin/sessions/${id}/k8s/delete`, {
      method: "POST",
      body: JSON.stringify(params),
    }),
  k8sExecOnce: (
    id: string,
    body: { namespace: string; pod: string; container?: string; command: string | string[] },
  ) =>
    request<{ stdout: string; stderr: string; message?: string; exit_code?: number }>(
      `/api/v1/admin/sessions/${id}/k8s/exec`,
      { method: "POST", body: JSON.stringify(body) },
    ),
  k8sPortForwardHTTP: (
    id: string,
    body: { namespace: string; pod: string; port: number; method?: string; path?: string; body?: string },
  ) =>
    request<{ status: number; headers: Record<string, string>; body: string; truncated?: boolean }>(
      `/api/v1/admin/sessions/${id}/k8s/portforward`,
      { method: "POST", body: JSON.stringify(body) },
    ),
  getRecordingUrl: (id: string) => `/api/v1/admin/sessions/${id}/recording`,
  listSessionFiles: (id: string) =>
    request<{ files: SessionFile[] }>(`/api/v1/admin/sessions/${id}/files`),
  getSessionFileUrl: (sessionId: string, fileId: string) =>
    `/api/v1/admin/sessions/${sessionId}/files/${fileId}`,
  getAppIntegration: (assetId: string) =>
    request<AppIntegration>(`/api/v1/admin/assets/${assetId}/app`),
  putAppIntegration: (assetId: string, body: Partial<AppIntegration> & { oidc_client_secret?: string; clear_oidc_client_secret?: boolean }) =>
    request<AppIntegration>(`/api/v1/admin/assets/${assetId}/app`, {
      method: "PUT",
      body: JSON.stringify(body),
    }),
  requestAppAccess: (assetId: string, body: { account_id?: string; ticket_id?: string; reason?: string; step_up_token?: string }) =>
    request<AppLease>(`/api/v1/admin/assets/${assetId}/app/access`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  requestK8sAccess: (assetId: string, body: { account_id: string; ticket_id?: string; reason?: string; step_up_token?: string }) =>
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
  getComplianceReport: (params: {
    from?: string;
    to?: string;
    days?: number;
    framework?: string;
    limit?: number;
  }) => {
    const qs = new URLSearchParams();
    if (params.from) qs.set("from", params.from);
    if (params.to) qs.set("to", params.to);
    if (params.days != null) qs.set("days", String(params.days));
    if (params.framework) qs.set("framework", params.framework);
    if (params.limit != null) qs.set("limit", String(params.limit));
    const suffix = qs.toString() ? `?${qs.toString()}` : "";
    return request<ComplianceReport>(`/api/v1/admin/compliance/report${suffix}`);
  },
  downloadComplianceReportCsv: async (params: {
    from?: string;
    to?: string;
    days?: number;
    framework?: string;
    limit?: number;
  }) => {
    const qs = new URLSearchParams();
    if (params.from) qs.set("from", params.from);
    if (params.to) qs.set("to", params.to);
    if (params.days != null) qs.set("days", String(params.days));
    if (params.framework) qs.set("framework", params.framework);
    qs.set("limit", String(params.limit ?? 500));
    qs.set("format", "csv");
    const res = await fetch(`/api/v1/admin/compliance/report?${qs.toString()}`, {
      credentials: "include",
    });
    if (!res.ok) {
      const data = (await res.json().catch(() => ({}))) as { error?: string };
      throw new Error(data.error || res.statusText);
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "keeppam-compliance.csv";
    a.click();
    URL.revokeObjectURL(url);
  },
  downloadComplianceReportPdf: async (params: {
    from?: string;
    to?: string;
    days?: number;
    framework?: string;
    limit?: number;
  }) => {
    const qs = new URLSearchParams();
    if (params.from) qs.set("from", params.from);
    if (params.to) qs.set("to", params.to);
    if (params.days != null) qs.set("days", String(params.days));
    if (params.framework) qs.set("framework", params.framework);
    qs.set("limit", String(params.limit ?? 500));
    qs.set("format", "pdf");
    const res = await fetch(`/api/v1/admin/compliance/report?${qs.toString()}`, {
      credentials: "include",
    });
    if (!res.ok) {
      const data = (await res.json().catch(() => ({}))) as { error?: string };
      throw new Error(data.error || res.statusText);
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "keeppam-compliance.pdf";
    a.click();
    URL.revokeObjectURL(url);
  },
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
  importCommandPack: (id: string, file: File, merge = false) => {
    const fd = new FormData();
    fd.append("file", file);
    if (merge) fd.append("merge", "true");
    return request<{
      pack: CommandPolicyPack;
      added: number;
      total: number;
      merged: boolean;
    }>(`/api/v1/admin/jea/packs/${id}/import?merge=${merge ? "true" : "false"}`, {
      method: "POST",
      body: fd,
    });
  },
  deleteCommandPack: (id: string) =>
    request<{ status: string }>(`/api/v1/admin/jea/packs/${id}`, { method: "DELETE" }),
  previewCommand: (body: { command: string; pack_id?: string }) =>
    request<CommandPreview>("/api/v1/admin/jea/command-preview", {
      method: "POST",
      body: JSON.stringify(body),
    }),
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
  listHTTPPacks: () => request<{ packs: HTTPPolicyPack[] }>("/api/v1/admin/jea/http-packs"),
  createHTTPPack: (body: HTTPPolicyPackInput) =>
    request<HTTPPolicyPack>("/api/v1/admin/jea/http-packs", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  updateHTTPPack: (id: string, body: HTTPPolicyPackInput) =>
    request<HTTPPolicyPack>(`/api/v1/admin/jea/http-packs/${id}`, {
      method: "PUT",
      body: JSON.stringify(body),
    }),
  deleteHTTPPack: (id: string) =>
    request<{ status: string }>(`/api/v1/admin/jea/http-packs/${id}`, { method: "DELETE" }),
  listAppObjectPacks: () =>
    request<{ packs: AppObjectPack[] }>("/api/v1/admin/jea/app-object-packs"),
  createAppObjectPack: (body: AppObjectPackInput) =>
    request<AppObjectPack>("/api/v1/admin/jea/app-object-packs", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  updateAppObjectPack: (id: string, body: AppObjectPackInput) =>
    request<AppObjectPack>(`/api/v1/admin/jea/app-object-packs/${id}`, {
      method: "PUT",
      body: JSON.stringify(body),
    }),
  deleteAppObjectPack: (id: string) =>
    request<{ status: string }>(`/api/v1/admin/jea/app-object-packs/${id}`, { method: "DELETE" }),
  previewAppObject: (body: { method: string; path: string; pack_id?: string; query?: string }) =>
    request<AppObjectPreview>("/api/v1/admin/jea/app-object-preview", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  listAccessPolicies: () =>
    request<{ policies: AccessPolicy[] }>("/api/v1/admin/jea/access-policies"),
  getAccessPolicy: (id: string) =>
    request<AccessPolicy>(`/api/v1/admin/jea/access-policies/${id}`),
  createAccessPolicy: (body: AccessPolicyInput) =>
    request<AccessPolicy>("/api/v1/admin/jea/access-policies", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  updateAccessPolicy: (id: string, body: AccessPolicyInput) =>
    request<AccessPolicy>(`/api/v1/admin/jea/access-policies/${id}`, {
      method: "PUT",
      body: JSON.stringify(body),
    }),
  deleteAccessPolicy: (id: string) =>
    request<{ status: string }>(`/api/v1/admin/jea/access-policies/${id}`, { method: "DELETE" }),
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

export type CommandPreview = {
  command: string;
  parsed: {
    raw: string;
    inner: string;
    binary: string;
    args: string[];
    wrappers: string[];
    priv_shell: boolean;
  };
  dlp: boolean;
  jea_allowed?: boolean;
  pack?: string;
  operation: string;
  points: number;
  kind: string;
  note: string;
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
  max_rows: number;
  dlp_action: "truncate" | "deny" | string;
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
  max_rows?: number;
  dlp_action?: string;
};

export type HTTPPolicyPack = {
  id: string;
  name: string;
  description: string;
  mode: "allowlist" | "denylist" | string;
  rules: string[];
  created_at: string;
  updated_at: string;
};

export type HTTPPolicyPackInput = {
  name: string;
  description?: string;
  mode: string;
  rules: string[];
};

export type AppObjectPack = {
  id: string;
  name: string;
  description: string;
  unmatched: "allow" | "deny" | string;
  rules: string[];
  created_at: string;
  updated_at: string;
};

export type AppObjectPackInput = {
  name: string;
  description?: string;
  unmatched: string;
  rules: string[];
};

export type AppObjectPreview = {
  allowed: boolean;
  matched: boolean;
  object?: string;
  action: string;
  reason?: string;
  code?: string;
  pack_name?: string;
  graphql_fields?: string[];
};

export type DlpPattern = {
  name: string;
  pattern: string;
};

export type NlpClassifier = {
  name: string;
  keywords: string;
  min_hits?: number;
};

export type AccessPolicy = {
  id: string;
  name: string;
  description: string;
  time_start?: string;
  time_end?: string;
  days_of_week: number;
  required_tags: string[];
  require_ticket: boolean;
  require_reason: boolean;
  allowed_cidrs: string[];
  allowed_countries: string[];
  allowed_devices: string[];
  allowed_namespaces: string[];
  allowed_egress: string[];
  pii_action: string;
  nlp_dlp_action?: string;
  file_transfer: string;
  ocr_lang?: string;
  ocr_interval_sec?: number;
  ocr_max_frames?: number;
  rdp_clipboard?: boolean;
  rdp_drive?: boolean;
  rdp_printer?: boolean;
  rdp_native?: boolean;
  dlp_patterns?: DlpPattern[];
  dlp_classifiers?: NlpClassifier[];
  command_policy_pack_id?: string;
  command_policy_pack_name?: string;
  sql_policy_pack_id?: string;
  sql_policy_pack_name?: string;
  http_policy_pack_id?: string;
  http_policy_pack_name?: string;
  app_object_pack_id?: string;
  app_object_pack_name?: string;
  max_risk: number;
  risk_action: string;
  created_at: string;
  updated_at: string;
};

export type AccessPolicyInput = {
  name: string;
  description?: string;
  time_start?: string;
  time_end?: string;
  days_of_week?: number;
  required_tags?: string[];
  require_ticket?: boolean;
  require_reason?: boolean;
  allowed_cidrs?: string[];
  allowed_countries?: string[];
  allowed_devices?: string[];
  allowed_namespaces?: string[];
  allowed_egress?: string[];
  pii_action?: string;
  nlp_dlp_action?: string;
  file_transfer?: string;
  ocr_lang?: string;
  ocr_interval_sec?: number;
  ocr_max_frames?: number;
  rdp_clipboard?: boolean;
  rdp_drive?: boolean;
  rdp_printer?: boolean;
  rdp_native?: boolean;
  dlp_patterns?: DlpPattern[];
  dlp_classifiers?: NlpClassifier[];
  command_policy_pack_id?: string;
  sql_policy_pack_id?: string;
  http_policy_pack_id?: string;
  app_object_pack_id?: string;
  max_risk?: number;
  risk_action?: string;
};

export type TranscriptLine = {
  ts: string;
  type: string;
  command: string;
  source?: string;
  offset?: number;
  filename?: string;
  file_id?: string;
  path?: string;
  direction?: string;
  protocol?: string;
  captured?: boolean;
};

export type SessionEventHit = {
  id: string;
  session_id: string;
  ts: string;
  type: string;
  snippet: string;
  payload?: Record<string, unknown>;
  username?: string;
  asset_name?: string;
  asset_id: string;
  protocol: string;
  status: string;
  break_glass?: boolean;
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
  archived?: boolean;
  archive_backend?: string;
  isolated?: boolean;
  database_name?: string;
  wire_token?: string;
  wire_addr?: string;
  wire_user?: string;
  wire_hint?: string;
  citrix_ica?: string;
  citrix_filename?: string;
  rdp_token?: string;
  rdp_addr?: string;
  rdp_port?: number;
  rdp_user?: string;
  rdp_hint?: string;
  rdp_file?: string;
  rdp_proxy?: boolean;
  rdp_filename?: string;
  rdp_width?: number;
  rdp_height?: number;
  kubeconfig?: string;
  k8s_addr?: string;
  k8s_token?: string;
  db_privilege?: string;
  break_glass?: boolean;
  k8s_namespaces?: string[];
  risk_score?: number;
  risk_factors?: string[];
  labels?: string[];
  access_policy_id?: string;
  client_country?: string;
  policy_snapshot?: PolicySnapshot;
  require_supervisor?: boolean;
  waiting_supervisor?: boolean;
  supervisor_group_id?: string;
  supervisor_group_name?: string;
  supervisor_id?: string;
  supervisor_username?: string;
  supervisor_approved_at?: string;
};

export type ArchiveSettings = {
  enabled: boolean;
  backend: string;
  age_days: number;
  interval_minutes: number;
  delete_local: boolean;
  nfs_path: string;
  smb_host: string;
  smb_share: string;
  smb_user: string;
  smb_domain: string;
  smb_password?: string;
  has_smb_password: boolean;
  last_run_at?: string;
  last_error?: string;
  last_copied: number;
};

export type PolicySnapshot = {
  binding_id?: string;
  group_id?: string;
  access_policy_id?: string;
  access_policy_name?: string;
  max_risk?: number;
  risk_action?: string;
  command_policy_pack_id?: string;
  command_policy_pack_name?: string;
  sql_policy_pack_id?: string;
  sql_policy_pack_name?: string;
  http_policy_pack_id?: string;
  http_policy_pack_name?: string;
  app_object_pack_id?: string;
  app_object_pack_name?: string;
  allowed_namespaces?: string[];
  allowed_egress?: string[];
  pii_action?: string;
  nlp_dlp_action?: string;
  file_transfer?: string;
  ocr_lang?: string;
  ocr_interval_sec?: number;
  ocr_max_frames?: number;
  tag_acl?: boolean;
  match_tags?: string[];
  match_mode?: string;
  break_glass?: boolean;
  admin_bypass?: boolean;
};

export type SessionFile = {
  id: string;
  session_id: string;
  filename: string;
  remote_path: string;
  protocol: string;
  direction: string;
  size_bytes: number;
  sha256: string;
  captured: boolean;
  created_at: string;
};

export type TimelineEvent = {
  id: string;
  ts: string;
  source: "audit" | "session" | string;
  kind: string;
  snippet: string;
  session_id?: string;
  asset_id?: string;
  asset_name?: string;
  protocol?: string;
  ip?: string;
  labels?: string[];
  risk_score?: number;
  ticket_id?: string;
  payload?: Record<string, unknown>;
};

export type TimelineResult = {
  user_id: string;
  username: string;
  from: string;
  to: string;
  events: TimelineEvent[];
  total: number;
};

export type K8sResourceKind = {
  name: string;
  resource: string;
  group?: string;
  version: string;
  namespaced: boolean;
};

export type K8sBrowseItem = {
  name: string;
  namespace?: string;
  kind?: string;
  status?: string;
  created_at?: string;
};

export type K8sApplyResult = {
  verb: string;
  resource: string;
  group?: string;
  namespace?: string;
  name: string;
  status: number;
  error?: string;
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
  pdf_signed?: boolean;
  pdf_signer?: string;
  pdf_pades?: string;
  pdf_qualified?: boolean;
  pdf_eidas_mode?: string;
  pdf_eidas_profile?: string;
};

export type ComplianceReport = {
  generated_at: string;
  from: string;
  to: string;
  framework: string;
  controls: { id: string; title: string; categories: string[] }[];
  summary: {
    access: number;
    privileged: number;
    approvals: number;
    connections: number;
    commands: number;
    sql: number;
    downloads: number;
    changes: number;
    revoked: number;
  };
  snapshot: {
    acl_live: number;
    sessions_active: number;
    jit_pending: number;
    break_glass_active: number;
    legal_holds: number;
  };
  evidence: {
    id: string;
    ts: string;
    category: string;
    source: string;
    actor: string;
    action: string;
    resource_type: string;
    resource_id: string;
    detail: string;
    ip?: string;
  }[];
  evidence_total: number;
  truncated: boolean;
  notes: string[];
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
