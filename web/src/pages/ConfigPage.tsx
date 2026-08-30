import { useEffect, useState, type FormEvent } from "react";
import {
  api,
  hasPerm,
  type AuthSettings,
  type FirewallStatus,
  type FirewallProbeAgent,
  type InfraStatus,
  type ITSMSettings,
  type NotifySettings,
  type SIEMSettings,
  type SSHSettings,
  type SAMLIdP,
  type ArchiveSettings,
  type EIDASSettings,
  type LicenseStatus,
  type ResidencySettings,
  type UEBAMLSettings,
  type AISettings,
} from "../api";
import { useAuth } from "../auth";
import { useI18n } from "../i18n";
import { licenseCapText, licenseModelLabel, licenseStatusText } from "../licenseStatus";

const emptyEidas: EIDASSettings = { mode: "off", profile: "eidas", require_b_lta: true };
const emptyUebaMl: UEBAMLSettings = {
  mode: "off",
  peer_group: true,
  ml_threshold: 65,
  live_interval_s: 60,
};
const emptyAI: AISettings = {
  mode: "off",
  endpoint: "mock://local",
  model: "mock",
  embed_model: "mock",
  max_input_chars: 48000,
  timeout_s: 90,
  lang: "ru",
};

const emptyResidency: ResidencySettings = {
  region: "KZ",
  country_name: "Kazakhstan",
  on_prem: true,
  notes: "",
  compliant: true,
  risks: [],
};

const emptyArchive: ArchiveSettings = {
  enabled: false,
  backend: "nfs",
  age_days: 30,
  interval_minutes: 60,
  delete_local: false,
  nfs_path: "",
  smb_host: "",
  smb_share: "",
  smb_user: "",
  smb_domain: "",
  has_smb_password: false,
  last_copied: 0,
};

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
  oauth_authorize_url: "",
  oauth_token_url: "",
  oauth_userinfo_url: "",
  oauth_username_claim: "iin",
  oauth_email_claim: "email",
  oauth_name_claim: "name",
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
  radius_host: "",
  radius_nas_id: "keeppam",
  radius_timeout_sec: 5,
  has_radius_secret: false,
  radius_auto_provision: true,
  radius_skip_mfa: false,
  radius_default_role: "operator",
  radius_auth_method: "pap",
  radius_eap_ca_pem: "",
  radius_eap_anonymous_user: "anonymous",
  radius_eap_insecure_tls: false,
  radius_radsec: false,
  radius_radsec_ca_pem: "",
  radius_radsec_client_pem: "",
  saml_idp_metadata_url: "",
  saml_idp_entity_id: "",
  saml_idp_sso_url: "",
  saml_idp_cert_pem: "",
  saml_sp_entity_id: "",
  has_saml_sp_key: false,
  saml_attr_username: "uid",
  saml_attr_email: "email",
  saml_attr_display_name: "displayName",
  saml_auto_provision: true,
  saml_skip_mfa: true,
  saml_default_role: "operator",
  saml_group_attr: "groups",
  saml_group_role_map: {},
  scim_enabled: false,
  has_scim_token: false,
  scim_default_role: "operator",
};

const emptyExtraIdP: SAMLIdP = {
  id: "",
  slug: "",
  name: "",
  enabled: true,
  metadata_url: "",
  entity_id: "",
  sso_url: "",
  cert_pem: "",
  attr_username: "uid",
  attr_email: "email",
  attr_display_name: "displayName",
  auto_provision: true,
  skip_mfa: true,
  default_role: "operator",
  group_attr: "groups",
  group_role_map: {},
};

const emptySSH: SSHSettings = {
  ssh_auth_mode: "vault_secret",
  ssh_ca_public: "",
  ssh_cert_ttl_hours: 8,
  krb5_realm: "",
  krb5_config: "",
  krb5_principal: "",
  krb5_spn_template: "host/%h",
  has_krb5_keytab: false,
  krb5_keytab: "",
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
  kafka_brokers: "",
  kafka_topic: "keeppam.audit",
  kafka_username: "",
  has_kafka_password: false,
  nats_url: "",
  nats_subject: "keeppam.audit",
  has_nats_token: false,
  opensearch_url: "",
  opensearch_index: "keeppam-audit",
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

const emptyNotify: NotifySettings = {
  enabled: false,
  webhook_url: "",
  has_auth_header: false,
  timeout_sec: 5,
  smtp_enabled: false,
  smtp_host: "",
  smtp_port: 587,
  smtp_tls: "starttls",
  smtp_tls_insecure: false,
  smtp_username: "",
  has_smtp_password: false,
  smtp_from: "",
};

export function ConfigPage() {
  const { user } = useAuth();
  const { t, te } = useI18n();
  const [form, setForm] = useState<AuthSettings>(empty);
  const [siem, setSiem] = useState<SIEMSettings>(emptySIEM);
  const [itsm, setItsm] = useState<ITSMSettings>(emptyITSM);
  const [firewallCidrsText, setFirewallCidrsText] = useState("");
  const [firewallForm, setFirewallForm] = useState({
    probe_url: "",
    probe_interval_hours: 0,
    awx_launch_url: "",
    awx_auto_push: false,
  });
  const [firewallAwxToken, setFirewallAwxToken] = useState("");
  const [probeQuorum, setProbeQuorum] = useState(1);
  const [probeAgents, setProbeAgents] = useState<
    { name: string; segment: string; probe_url: string; enabled: boolean; token: string; has_token?: boolean }[]
  >([]);
  const [firewallStatus, setFirewallStatus] = useState<FirewallStatus | null>(null);
  const [nacForm, setNacForm] = useState({
    mode: "off",
    api_url: "",
    vendor: "generic",
    timeout_ms: 3000,
    has_api_token: false,
    last_error: "",
  });
  const [nacToken, setNacToken] = useState("");
  const [eidasForm, setEidasForm] = useState({
    mode: "off",
    profile: "eidas",
    require_b_lta: true,
    pkcs11_enabled: false,
    pkcs11_module: "",
    pkcs11_label: "",
    has_pkcs11_pin: false,
    cert_cn: "",
    cert_qualified: false,
    pades_profile: "",
    last_error: "",
  });
  const [eidasPin, setEidasPin] = useState("");
  const [uebaMlForm, setUebaMlForm] = useState({
    mode: "off",
    peer_group: true,
    ml_threshold: 65,
    live_interval_s: 60,
    last_error: "",
  });
  const [aiForm, setAiForm] = useState({
    mode: "off",
    endpoint: "mock://local",
    model: "mock",
    embed_model: "mock",
    max_input_chars: 48000,
    timeout_s: 90,
    lang: "ru",
    last_error: "",
    licensed: true,
    allow_external: false,
  });
  const [notify, setNotify] = useState<NotifySettings>(emptyNotify);
  const [notifyAuth, setNotifyAuth] = useState("");
  const [notifySmtpPass, setNotifySmtpPass] = useState("");
  const [ssh, setSsh] = useState<SSHSettings>(emptySSH);
  const [infra, setInfra] = useState<InfraStatus | null>(null);
  const [residency, setResidency] = useState<ResidencySettings>(emptyResidency);
  const [archive, setArchive] = useState<ArchiveSettings>(emptyArchive);
  const [smbPass, setSmbPass] = useState("");
  const [secret, setSecret] = useState("");
  const [didLab, setDidLab] = useState<{
    authorize_url: string;
    token_url: string;
    userinfo_url: string;
    client_id: string;
    client_secret: string;
    username_claim: string;
    email_claim: string;
    name_claim: string;
  } | null>(null);
  const [ldapPass, setLdapPass] = useState("");
  const [radiusSecret, setRadiusSecret] = useState("");
  const [scimToken, setScimToken] = useState("");
  const [webhookAuth, setWebhookAuth] = useState("");
  const [kafkaPassword, setKafkaPassword] = useState("");
  const [natsToken, setNatsToken] = useState("");
  const [itsmAuth, setItsmAuth] = useState("");
  const [itsmTicket, setItsmTicket] = useState("DEMO-100");
  const [itsmCheck, setItsmCheck] = useState("");
  const [error, setError] = useState("");
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState(false);
  const [groupMapText, setGroupMapText] = useState("");
  const [extraIdPs, setExtraIdPs] = useState<SAMLIdP[]>([]);
  const [extraForm, setExtraForm] = useState<SAMLIdP>(emptyExtraIdP);
  const [extraMapText, setExtraMapText] = useState("");
  const [licenseInfo, setLicenseInfo] = useState<LicenseStatus | null>(null);
  const [licenseFp, setLicenseFp] = useState("");
  const [licenseSkipHw, setLicenseSkipHw] = useState(false);
  const canWrite = hasPerm(user, "settings.write");
  const canReadLicense = hasPerm(user, "assets.read") || canWrite;

  async function loadLicense() {
    if (!canReadLicense) return;
    try {
      const [lic, fp] = await Promise.all([api.getLicense(), api.getLicenseFingerprint()]);
      setLicenseInfo(lic);
      setLicenseFp(fp.hardware_fingerprint);
      setLicenseSkipHw(fp.skip_hw);
    } catch {
      /* optional */
    }
  }

  async function onUploadLicense(file: File) {
    if (!canWrite) return;
    setBusy(true);
    setError("");
    setMsg("");
    try {
      const lic = await api.uploadLicenseFile(file);
      setLicenseInfo(lic);
      setMsg(t("config.licenseUploaded"));
      await loadLicense();
    } catch (err) {
      setError(err instanceof Error ? err.message : t("config.licenseLoadFailed"));
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    if (!canWrite) return;
    void (async () => {
      try {
        const [s, si, sh, inf, it, fw, fws, nac, eidas, uebaMl, aiSet, nt, idps, ar] = await Promise.all([
          api.getAuthSettings(),
          api.getSIEMSettings(),
          api.getSSHSettings(),
          api.getInfraStatus(),
          api.getITSMSettings(),
          api.getFirewallSettings(),
          api.getFirewallStatus().catch(() => null),
          api.getNACSettings().catch(() => ({
            mode: "off",
            api_url: "",
            vendor: "generic",
            timeout_ms: 3000,
            has_api_token: false,
            last_error: "",
          })),
          api.getEIDASSettings().catch(() => emptyEidas),
          api.getUEBAMLSettings().catch(() => emptyUebaMl),
          api.getAISettings().catch(() => emptyAI),
          api.getNotifySettings(),
          api.listSAMLIdPs().catch(() => ({ idps: [] as SAMLIdP[] })),
          api.getArchiveSettings().catch(() => emptyArchive),
        ]);
        void api.getDigitalIDLabPreset().then(setDidLab).catch(() => setDidLab(null));
        setForm({ ...empty, ...s });
        setGroupMapText(formatGroupRoleMap(s.saml_group_role_map));
        setSiem({ ...emptySIEM, ...si });
        setSsh({ ...emptySSH, ...sh });
        setInfra(inf);
        if (inf.residency) setResidency({ ...emptyResidency, ...inf.residency });
        setArchive({ ...emptyArchive, ...ar });
        setItsm({
          ...emptyITSM,
          ...it,
          ok_statuses: it.ok_statuses?.length ? it.ok_statuses : emptyITSM.ok_statuses,
        });
        setFirewallCidrsText((fw.pam_gateway_cidrs || []).join(", "));
        setFirewallForm({
          probe_url: fw.probe_url || "",
          probe_interval_hours: fw.probe_interval_hours || 0,
          awx_launch_url: fw.awx_launch_url || "",
          awx_auto_push: !!fw.awx_auto_push,
        });
        setProbeQuorum(fw.probe_quorum || 1);
        setProbeAgents(
          (fw.probe_agents || []).map((a: FirewallProbeAgent) => ({
            name: a.name,
            segment: a.segment || "",
            probe_url: a.probe_url,
            enabled: a.enabled,
            token: "",
            has_token: a.has_token,
          })),
        );
        setFirewallStatus(fws);
        setNacForm({
          mode: nac.mode || "off",
          api_url: nac.api_url || "",
          vendor: nac.vendor || "generic",
          timeout_ms: nac.timeout_ms || 3000,
          has_api_token: !!nac.has_api_token,
          last_error: nac.last_error || "",
        });
        setEidasForm({
          mode: eidas.mode || "off",
          profile: eidas.profile || "eidas",
          require_b_lta: eidas.require_b_lta !== false,
          pkcs11_enabled: !!eidas.pkcs11_enabled,
          pkcs11_module: eidas.pkcs11_module || "",
          pkcs11_label: eidas.pkcs11_label || "",
          has_pkcs11_pin: !!eidas.has_pkcs11_pin,
          cert_cn: eidas.cert_cn || "",
          cert_qualified: !!eidas.cert_qualified,
          pades_profile: eidas.pades_profile || "",
          last_error: eidas.last_error || "",
        });
        setUebaMlForm({
          mode: uebaMl.mode || "off",
          peer_group: uebaMl.peer_group !== false,
          ml_threshold: uebaMl.ml_threshold || 65,
          live_interval_s: uebaMl.live_interval_s || 60,
          last_error: uebaMl.last_error || "",
        });
        setAiForm({
          mode: aiSet.mode || "off",
          endpoint: aiSet.endpoint || "mock://local",
          model: aiSet.model || "mock",
          embed_model: aiSet.embed_model || "mock",
          max_input_chars: aiSet.max_input_chars || 48000,
          timeout_s: aiSet.timeout_s || 90,
          lang: aiSet.lang || "ru",
          last_error: aiSet.last_error || "",
          licensed: aiSet.licensed !== false,
          allow_external: !!aiSet.allow_external,
        });
        setNotify({ ...emptyNotify, ...nt });
        setExtraIdPs(idps.idps || []);
        await loadLicense();
      } catch (err) {
        setError(te(err, "config.loadFailed"));
      }
    })();
  }, [canWrite]);

  if (!canWrite) {
    return <p className="error">{t("common.forbidden")}</p>;
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
      if (radiusSecret.trim()) body.radius_secret = radiusSecret.trim();
      if (scimToken.trim()) body.scim_token = scimToken.trim();
      delete body.has_oidc_secret;
      delete body.has_ldap_bind_password;
      delete body.has_radius_secret;
      delete body.has_saml_sp_key;
      delete body.has_scim_token;
      delete body.saml_acs_url;
      delete body.saml_metadata_url;
      delete body.saml_slo_url;
      delete body.scim_base_url;
      body.saml_group_role_map = parseGroupRoleMap(groupMapText);
      const saved = await api.putAuthSettings(body);
      setForm({ ...empty, ...saved, rotate_saml_sp_key: false });
      setGroupMapText(formatGroupRoleMap(saved.saml_group_role_map));
      setSecret("");
      setLdapPass("");
      setRadiusSecret("");
      setScimToken("");
      setMsg(t("config.authSaved"));
    } catch (err) {
      setError(te(err, "config.saveFailed"));
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
      setMsg(t("config.itsmSaved"));
    } catch (err) {
      setError(err instanceof Error ? err.message : t("config.itsmSaveFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function onSaveFirewall(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    setMsg("");
    try {
      const cidrs = firewallCidrsText
        .split(/[,;\s]+/)
        .map((s) => s.trim())
        .filter(Boolean);
      const saved = await api.putFirewallSettings({
        pam_gateway_cidrs: cidrs,
        probe_url: firewallForm.probe_url.trim(),
        probe_quorum: probeQuorum,
        probe_interval_hours: Number(firewallForm.probe_interval_hours) || 0,
        awx_launch_url: firewallForm.awx_launch_url.trim(),
        awx_auto_push: firewallForm.awx_auto_push,
        ...(firewallAwxToken.trim() ? { awx_token: firewallAwxToken.trim() } : {}),
      });
      setFirewallCidrsText((saved.pam_gateway_cidrs || []).join(", "));
      setFirewallForm({
        probe_url: saved.probe_url || "",
        probe_interval_hours: saved.probe_interval_hours || 0,
        awx_launch_url: saved.awx_launch_url || "",
        awx_auto_push: !!saved.awx_auto_push,
      });
      setFirewallAwxToken("");
      setProbeQuorum(saved.probe_quorum || 1);
      setFirewallStatus(await api.getFirewallStatus().catch(() => null));
      setMsg(t("config.firewallSaved"));
    } catch (err) {
      setError(err instanceof Error ? err.message : t("config.firewallSaveFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function onSaveNAC(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    setMsg("");
    try {
      const saved = await api.putNACSettings({
        mode: nacForm.mode,
        api_url: nacForm.api_url.trim(),
        vendor: nacForm.vendor,
        timeout_ms: Number(nacForm.timeout_ms) || 3000,
        ...(nacToken.trim() ? { api_token: nacToken.trim() } : {}),
      });
      setNacForm({
        mode: saved.mode || "off",
        api_url: saved.api_url || "",
        vendor: saved.vendor || "generic",
        timeout_ms: saved.timeout_ms || 3000,
        has_api_token: !!saved.has_api_token,
        last_error: saved.last_error || "",
      });
      setNacToken("");
      setMsg(t("config.nacSaved"));
    } catch (err) {
      setError(err instanceof Error ? err.message : t("config.nacSaveFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function onSaveEIDAS(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    setMsg("");
    try {
      const saved = await api.putEIDASSettings({
        mode: eidasForm.mode,
        profile: eidasForm.profile,
        require_b_lta: eidasForm.require_b_lta,
        pkcs11_enabled: eidasForm.pkcs11_enabled,
        pkcs11_module: eidasForm.pkcs11_module.trim(),
        pkcs11_label: eidasForm.pkcs11_label.trim(),
        ...(eidasPin.trim() ? { pkcs11_pin: eidasPin.trim() } : {}),
      });
      setEidasForm({
        mode: saved.mode || "off",
        profile: saved.profile || "eidas",
        require_b_lta: saved.require_b_lta !== false,
        pkcs11_enabled: !!saved.pkcs11_enabled,
        pkcs11_module: saved.pkcs11_module || "",
        pkcs11_label: saved.pkcs11_label || "",
        has_pkcs11_pin: !!saved.has_pkcs11_pin,
        cert_cn: saved.cert_cn || "",
        cert_qualified: !!saved.cert_qualified,
        pades_profile: saved.pades_profile || "",
        last_error: saved.last_error || "",
      });
      setEidasPin("");
      setMsg(t("config.eidasSaved"));
    } catch (err) {
      setError(err instanceof Error ? err.message : t("config.eidasSaveFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function onSaveUEBAML(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    setMsg("");
    try {
      const saved = await api.putUEBAMLSettings({
        mode: uebaMlForm.mode,
        peer_group: uebaMlForm.peer_group,
        ml_threshold: Number(uebaMlForm.ml_threshold) || 65,
        live_interval_s: Number(uebaMlForm.live_interval_s) || 60,
      });
      setUebaMlForm({
        mode: saved.mode || "off",
        peer_group: saved.peer_group !== false,
        ml_threshold: saved.ml_threshold || 65,
        live_interval_s: saved.live_interval_s || 60,
        last_error: saved.last_error || "",
      });
      setMsg(t("config.uebaSaved"));
    } catch (err) {
      setError(err instanceof Error ? err.message : t("config.uebaSaveFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function onSaveAI(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    setMsg("");
    try {
      const saved = await api.putAISettings({
        mode: aiForm.mode,
        endpoint: aiForm.endpoint,
        model: aiForm.model,
        embed_model: aiForm.embed_model,
        max_input_chars: Number(aiForm.max_input_chars) || 48000,
        timeout_s: Number(aiForm.timeout_s) || 90,
        lang: aiForm.lang,
      });
      setAiForm({
        mode: saved.mode || "off",
        endpoint: saved.endpoint || "mock://local",
        model: saved.model || "mock",
        embed_model: saved.embed_model || "mock",
        max_input_chars: saved.max_input_chars || 48000,
        timeout_s: saved.timeout_s || 90,
        lang: saved.lang || "ru",
        last_error: saved.last_error || "",
        licensed: saved.licensed !== false,
        allow_external: !!saved.allow_external,
      });
      setMsg(t("config.aiSaved"));
    } catch (err) {
      setError(err instanceof Error ? err.message : t("config.aiSaveFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function onSaveProbeAgents(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    setMsg("");
    try {
      const res = await api.putFirewallProbeAgents({
        probe_quorum: probeQuorum,
        agents: probeAgents.map((a) => ({
          name: a.name.trim(),
          segment: a.segment.trim(),
          probe_url: a.probe_url.trim(),
          enabled: a.enabled,
          ...(a.token.trim() ? { token: a.token.trim() } : {}),
        })),
      });
      setProbeQuorum(res.probe_quorum);
      setProbeAgents(
        res.agents.map((a) => ({
          name: a.name,
          segment: a.segment || "",
          probe_url: a.probe_url,
          enabled: a.enabled,
          token: "",
          has_token: a.has_token,
        })),
      );
      setFirewallStatus(await api.getFirewallStatus().catch(() => null));
      setMsg(t("config.probeAgentsSaved"));
    } catch (err) {
      setError(err instanceof Error ? err.message : t("config.probeAgentsSaveFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function onSaveNotify(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    setMsg("");
    try {
      const body: Partial<NotifySettings> = { ...notify };
      if (notifyAuth.trim()) body.auth_header = notifyAuth.trim();
      if (notifySmtpPass) body.smtp_password = notifySmtpPass;
      delete body.has_auth_header;
      delete body.has_smtp_password;
      const saved = await api.putNotifySettings(body);
      setNotify({ ...emptyNotify, ...saved });
      setNotifyAuth("");
      setNotifySmtpPass("");
      setMsg(t("config.notifySaved"));
    } catch (err) {
      setError(err instanceof Error ? err.message : t("config.notifySaveFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function onTestNotifyEmail() {
    setBusy(true);
    setError("");
    setMsg("");
    try {
      await api.testNotifyEmail();
      setMsg(t("config.testEmailSent"));
      const nt = await api.getNotifySettings();
      setNotify({ ...emptyNotify, ...nt });
    } catch (err) {
      setError(err instanceof Error ? err.message : t("config.smtpError"));
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
      setError(err instanceof Error ? err.message : t("config.ticketCheckFailed"));
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
      if (kafkaPassword.trim()) body.kafka_password = kafkaPassword.trim();
      if (natsToken.trim()) body.nats_token = natsToken.trim();
      delete body.has_webhook_auth_header;
      delete body.has_kafka_password;
      delete body.has_nats_token;
      const saved = await api.putSIEMSettings(body);
      setSiem({ ...emptySIEM, ...saved });
      setWebhookAuth("");
      setKafkaPassword("");
      setNatsToken("");
      setMsg(t("config.siemSaved"));
    } catch (err) {
      setError(err instanceof Error ? err.message : t("config.siemSaveFailed"));
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
        krb5_realm: ssh.krb5_realm || "",
        krb5_config: ssh.krb5_config || "",
        krb5_principal: ssh.krb5_principal || "",
        krb5_spn_template: ssh.krb5_spn_template || "host/%h",
        ...(ssh.krb5_keytab ? { krb5_keytab: ssh.krb5_keytab } : {}),
      });
      setSsh({ ...emptySSH, ...saved, krb5_keytab: "" });
      setMsg(t("config.sshSaved"));
    } catch (err) {
      setError(err instanceof Error ? err.message : t("config.sshSaveFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function onRotateCA() {
    if (!confirm(t("config.rotateCaConfirm"))) return;
    setBusy(true);
    setError("");
    setMsg("");
    try {
      const saved = await api.putSSHSettings({
        ssh_auth_mode: ssh.ssh_auth_mode,
        ssh_cert_ttl_hours: ssh.ssh_cert_ttl_hours,
        krb5_realm: ssh.krb5_realm || "",
        krb5_config: ssh.krb5_config || "",
        krb5_principal: ssh.krb5_principal || "",
        krb5_spn_template: ssh.krb5_spn_template || "host/%h",
        ...(ssh.krb5_keytab ? { krb5_keytab: ssh.krb5_keytab } : {}),
        rotate_ca: true,
      });
      setSsh({ ...emptySSH, ...saved, krb5_keytab: "" });
      setMsg(t("config.caRotated"));
    } catch (err) {
      setError(err instanceof Error ? err.message : t("config.caRotateFailed"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <div className="toolbar">
        <div>
          <h1>{t("config.title")}</h1>
          <p className="muted">{t("config.lead")}</p>
          <p className="muted" style={{ marginTop: "0.35rem" }}>
            <a href="#ai">{t("config.aiTitle")}</a>
          </p>
        </div>
      </div>
      {error && <p className="error">{error}</p>}
      {msg && <p className="ok">{msg}</p>}

      {licenseInfo && canReadLicense && (
        <div className="card" style={{ maxWidth: 720, marginBottom: "1.25rem" }}>
          <h2>{t("config.licenseTitle")}</h2>
          <p className="muted">{t("config.licenseFormatHint")}</p>
          <table style={{ marginBottom: "0.75rem" }}>
            <tbody>
              <tr>
                <td className="muted">{t("config.licenseCustomer")}</td>
                <td>{licenseInfo.customer || "—"}</td>
              </tr>
              <tr>
                <td className="muted">{t("config.licenseModel")}</td>
                <td>{licenseModelLabel(licenseInfo.model, t)}</td>
              </tr>
              <tr>
                <td className="muted">{t("config.licenseAssets")}</td>
                <td>
                  {licenseCapText(licenseInfo.asset_count, licenseInfo.max_assets, licenseInfo.limits_assets)}
                  {licenseInfo.hard_blocked_assets ? t("config.licenseBlockedSuffix") : ""}
                </td>
              </tr>
              <tr>
                <td className="muted">{t("config.licenseUsers")}</td>
                <td>
                  {licenseCapText(licenseInfo.user_count, licenseInfo.max_users, licenseInfo.limits_users)}
                  {licenseInfo.hard_blocked_users ? t("config.licenseBlockedSuffix") : ""}
                </td>
              </tr>
              <tr>
                <td className="muted">{t("config.expires")}</td>
                <td>{licenseInfo.expires || "—"}</td>
              </tr>
              <tr>
                <td className="muted">HA</td>
                <td>{licenseInfo.ha ? t("common.yes") : t("common.no")}</td>
              </tr>
              <tr>
                <td className="muted">{t("config.licenseSource")}</td>
                <td className="mono">{licenseInfo.source}</td>
              </tr>
              {(licenseInfo.soft_warn || licenseInfo.hard_blocked || licenseInfo.expired) && (
                <tr>
                  <td className="muted">{t("common.status")}</td>
                  <td>
                    {licenseStatusText(licenseInfo, t)}
                    {licenseInfo.hard_blocked_assets ? ` ${t("license.createForbidden")}` : ""}
                    {licenseInfo.hard_blocked_users ? ` ${t("license.connectForbidden")}` : ""}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
          <label>{t("config.licenseHwFingerprint")}</label>
          <textarea
            readOnly
            rows={2}
            value={licenseFp}
            className="mono"
            style={{ width: "100%", marginBottom: "0.5rem" }}
          />
          <p className="muted" style={{ marginTop: 0 }}>
            {t("config.fingerprintHint1")}{" "}
            <span className="mono">*</span> {t("config.fingerprintHint2")} <span className="mono">KEEPPAM_LICENSE_SKIP_HW=true</span>.
            {licenseSkipHw ? t("config.fingerprintHwOff") : ""}
          </p>
          {canWrite && (
            <>
              <label>{t("config.licenseUploadLabel")}</label>
              <input
                type="file"
                accept=".lic,application/octet-stream"
                disabled={busy}
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  if (f) void onUploadLicense(f);
                  e.target.value = "";
                }}
              />
            </>
          )}
        </div>
      )}

      {infra && (
        <div className="card" style={{ maxWidth: 640, marginBottom: "1.25rem" }}>
          <h2>{t("config.residencyTitle")}</h2>
          <p className="muted" style={{ marginTop: 0 }}>
            {t("config.residencyLead")}{" "}
            <span className="mono">docs/data-residency.txt</span>
          </p>
          <p>
            {residency.compliant ? (
              t("config.residencyOk")
            ) : (
              <span className="error">
                {t("config.residencyBad")}
                {residency.risks && residency.risks.length
                  ? `: ${residency.risks.join(", ")}`
                  : ""}
              </span>
            )}
          </p>
          <label>{t("config.residencyRegion")}</label>
          <input
            className="mono"
            value={residency.region}
            disabled={!canWrite || busy}
            onChange={(e) => setResidency({ ...residency, region: e.target.value.toUpperCase() })}
          />
          <label className="row" style={{ gap: "0.5rem" }}>
            <input
              type="checkbox"
              checked={residency.on_prem}
              disabled={!canWrite || busy}
              onChange={(e) => setResidency({ ...residency, on_prem: e.target.checked })}
            />
            {t("config.residencyOnPrem")}
          </label>
          <label>{t("config.residencyNotes")}</label>
          <input
            value={residency.notes}
            disabled={!canWrite || busy}
            onChange={(e) => setResidency({ ...residency, notes: e.target.value })}
          />
          {residency.attested_at && (
            <p className="muted">
              {t("config.residencyAttested", {
                name: residency.attested_by_name || residency.attested_by || "—",
                at: new Date(residency.attested_at).toLocaleString(),
              })}
            </p>
          )}
          {canWrite && (
            <div className="row" style={{ gap: "0.5rem" }}>
              <button
                className="btn secondary"
                type="button"
                disabled={busy}
                onClick={() => {
                  void (async () => {
                    setBusy(true);
                    setError("");
                    try {
                      const saved = await api.putResidencySettings({
                        region: residency.region,
                        on_prem: residency.on_prem,
                        notes: residency.notes,
                      });
                      setResidency({ ...emptyResidency, ...saved });
                      setMsg(t("config.residencySaved"));
                    } catch (err) {
                      setError(err instanceof Error ? err.message : t("common.error"));
                    } finally {
                      setBusy(false);
                    }
                  })();
                }}
              >
                {t("common.save")}
              </button>
              <button
                className="btn"
                type="button"
                disabled={busy}
                onClick={() => {
                  void (async () => {
                    setBusy(true);
                    setError("");
                    try {
                      const saved = await api.putResidencySettings({
                        region: residency.region || "KZ",
                        on_prem: true,
                        notes: residency.notes,
                        attest: true,
                      });
                      setResidency({ ...emptyResidency, ...saved });
                      const inf = await api.getInfraStatus().catch(() => null);
                      if (inf) setInfra(inf);
                      setMsg(t("config.residencySaved"));
                    } catch (err) {
                      setError(err instanceof Error ? err.message : t("common.error"));
                    } finally {
                      setBusy(false);
                    }
                  })();
                }}
              >
                {t("config.residencyAttest")}
              </button>
            </div>
          )}
        </div>
      )}

      {infra && (
        <div className="card" style={{ maxWidth: 640, marginBottom: "1.25rem" }}>
          <h2>{t("config.infraTitle")}</h2>
          <p className="muted" style={{ marginTop: 0 }}>
            {t("config.infraReadOnly")}{" "}
            <span className="mono">docs/prod-infra.txt</span>).
          </p>
          {(infra.version || infra.build_time) && (
            <p>
              {t("config.versionLabel")}{" "}
              <span className="mono">
                {infra.version || "—"}
                {infra.build_time ? ` · built ${infra.build_time}` : ""}
              </span>
            </p>
          )}
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
                  ? t("config.infraS3NoObjectLock")
                  : "n/a (local)"}
            </span>
          </p>
          <p>
            Data key posture:{" "}
            <span className="mono">
              {infra.data_key_source === "vault"
                ? "vault (HSM-capable)"
                : infra.data_key_source === "pkcs11"
                  ? "pkcs11 (HSM)"
                  : ["aws", "gcp", "azure"].includes(infra.data_key_source)
                    ? `${infra.data_key_source} (KMS)`
                    : infra.data_key_source}
            </span>
          </p>
          {(infra.data_key_source === "pkcs11" ||
            infra.pkcs11_token_file ||
            infra.pkcs11_module ||
            infra.pkcs11_helper) && (
            <p>
              PKCS#11:{" "}
              <span className="mono">
                {infra.pkcs11_token_file
                  ? infra.pkcs11_token_file
                  : infra.pkcs11_helper
                    ? "helper"
                    : infra.pkcs11_module || "—"}
                {infra.pkcs11_label ? ` · ${infra.pkcs11_label}` : ""}
                {infra.pkcs11_uri ? " · uri" : ""}
              </span>
            </p>
          )}
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
          <p>
            GeoIP:{" "}
            <span className="mono">
              {infra.geoip_ready
                ? `${infra.geoip_type || infra.geoip_db || "ready"}${infra.geoip_nodes ? ` · ${infra.geoip_nodes} nodes` : ""}`
                : infra.geoip_db
                  ? `${infra.geoip_db} ${t("config.notLoaded")}`
                  : t("config.infraGeoipMissing")}
            </span>
          </p>
          {!!(infra.trusted_proxies && infra.trusted_proxies.length) && (
            <p>
              Trusted proxies:{" "}
              <span className="mono">{infra.trusted_proxies.join(", ")}</span>
            </p>
          )}
          <p>
            OPA:{" "}
            <span className="mono">
              {infra.opa_ready
                ? `${infra.opa_package || "keeppam.authz"} · ${infra.opa_policy || "ready"}`
                : infra.opa_policy
                  ? `${infra.opa_policy} ${t("config.notLoaded")}`
                  : "off"}
            </span>
          </p>
          <p>
            SPIFFE:{" "}
            <span className="mono">
              {infra.spiffe_id
                ? infra.spiffe_id
                : infra.spiffe_trust_domain
                  ? `domain ${infra.spiffe_trust_domain}`
                  : "off"}
              {infra.spiffe_svid ? " · svid" : ""}
              {infra.spiffe_bundle ? " · bundle" : ""}
              {infra.spiffe_id && infra.spiffe_trust_domain ? ` · ${infra.spiffe_trust_domain}` : ""}
            </span>
          </p>
          <p>
            FIPS:{" "}
            <span className="mono">
              {infra.fips || "go"}
              {infra.fips_required ? " · required" : ""}
              {infra.go_version ? ` · ${infra.go_version}` : ""}
              {infra.cgo_enabled ? ` · cgo=${infra.cgo_enabled}` : ""}
            </span>
          </p>
          <p>
            SBOM:{" "}
            <span className="mono">
              {infra.sbom_components ?? 0} components
              {infra.sbom_file ? " · file" : " · runtime"}
            </span>{" "}
            <button
              className="btn secondary"
              type="button"
              onClick={() => void api.downloadSBOM().catch((e) => setError(e instanceof Error ? e.message : "SBOM"))}
            >
              {t("config.infraDownloadCycloneDX")}
            </button>
          </p>
          <p>
            OTEL traces:{" "}
            <span className="mono">
              {infra.otel_ready
                ? `${infra.otel_via || "otlp"} · ${infra.otel_endpoint || "on"}`
                : infra.otel_endpoint
                  ? `${infra.otel_endpoint} ${t("config.notActive")}`
                  : "off"}
            </span>
          </p>
          <p>
            Memory:{" "}
            <span className="mono">
              coredump={infra.coredump || "?"}
              {infra.dumpable ? " · dumpable" : " · not dumpable"}
              {infra.data_key_mlock ? " · mlock" : " · no mlock"}
            </span>
          </p>
        </div>
      )}

      <form
        className="card"
        onSubmit={(e) => {
          e.preventDefault();
          void (async () => {
            setBusy(true);
            setError("");
            setMsg("");
            try {
              const body: Partial<ArchiveSettings> = { ...archive };
              if (smbPass.trim()) body.smb_password = smbPass.trim();
              delete body.has_smb_password;
              const saved = await api.putArchiveSettings(body);
              setArchive({ ...emptyArchive, ...saved });
              setSmbPass("");
              setMsg(t("config.archiveSaved"));
            } catch (err) {
              setError(err instanceof Error ? err.message : t("config.errorGeneric"));
            } finally {
              setBusy(false);
            }
          })();
        }}
        style={{ maxWidth: 640, marginBottom: "1.25rem" }}
      >
        <h2>{t("config.archiveTitle")}</h2>
        <p className="muted">
          {t("config.archiveHintJsx")}{" "}
          <span className="mono">docs/archive-smb-nfs.txt</span>
        </p>
        <button
          type="button"
          className="btn secondary"
          style={{ marginBottom: "0.75rem" }}
          onClick={() => setArchive({ ...archive, age_days: 30 })}
        >
          {t("config.archiveNitPreset")}
        </button>
        <label className="row" style={{ gap: "0.5rem", alignItems: "center" }}>
          <input
            type="checkbox"
            checked={archive.enabled}
            onChange={(e) => setArchive({ ...archive, enabled: e.target.checked })}
          />
          {t("config.enable")}
        </label>
        <label>Backend</label>
        <select
          value={archive.backend}
          onChange={(e) => setArchive({ ...archive, backend: e.target.value })}
        >
          <option value="nfs">{t("config.archiveProtocolNfs")}</option>
          <option value="smb">{t("config.archiveProtocolSmb")}</option>
        </select>
        <label>{t("config.archiveAgeDays")}</label>
        <input
          type="number"
          min={0}
          max={3650}
          value={archive.age_days}
          onChange={(e) => setArchive({ ...archive, age_days: Number(e.target.value) || 0 })}
        />
        <label>{t("config.jobIntervalMin")}</label>
        <input
          type="number"
          min={5}
          max={1440}
          value={archive.interval_minutes}
          onChange={(e) => setArchive({ ...archive, interval_minutes: Number(e.target.value) || 60 })}
        />
        {archive.backend === "nfs" && (
          <>
            <label>{t("config.archiveNfsPath")}</label>
            <input
              value={archive.nfs_path}
              onChange={(e) => setArchive({ ...archive, nfs_path: e.target.value })}
              placeholder="/var/lib/keeppam/archive"
            />
          </>
        )}
        {archive.backend === "smb" && (
          <>
            <label>Host[:port]</label>
            <input
              value={archive.smb_host}
              onChange={(e) => setArchive({ ...archive, smb_host: e.target.value })}
              placeholder="files.example:445"
            />
            <label>Share</label>
            <input
              value={archive.smb_share}
              onChange={(e) => setArchive({ ...archive, smb_share: e.target.value })}
              placeholder="keeppam-recordings"
            />
            <label>User / domain</label>
            <div className="row" style={{ gap: "0.5rem" }}>
              <input
                value={archive.smb_user}
                onChange={(e) => setArchive({ ...archive, smb_user: e.target.value })}
                placeholder="keeppam"
              />
              <input
                value={archive.smb_domain}
                onChange={(e) => setArchive({ ...archive, smb_domain: e.target.value })}
                placeholder="AD"
              />
            </div>
            <label>Password {archive.has_smb_password ? t("config.secretSet") : ""}</label>
            <input
              type="password"
              value={smbPass}
              onChange={(e) => setSmbPass(e.target.value)}
              autoComplete="off"
            />
          </>
        )}
        <label className="row" style={{ gap: "0.5rem", alignItems: "center" }}>
          <input
            type="checkbox"
            checked={archive.delete_local}
            onChange={(e) => setArchive({ ...archive, delete_local: e.target.checked })}
          />
          {t("config.deleteLocalAfterChecksum")}
        </label>
        {archive.last_run_at && (
          <p className="muted">
            Last run: {new Date(archive.last_run_at).toLocaleString()} · copied={archive.last_copied}
            {archive.last_error ? ` · ${archive.last_error}` : ""}
          </p>
        )}
        <div className="row" style={{ gap: "0.5rem" }}>
          <button className="btn" type="submit" disabled={busy}>
            {t("config.saveArchive")}
          </button>
          <button
            className="btn secondary"
            type="button"
            disabled={busy || !archive.enabled}
            onClick={() => {
              void (async () => {
                setBusy(true);
                setError("");
                try {
                  const st = await api.runArchiveSync();
                  setMsg(t("config.archiveStatusCopied", { copied: st.copied, failed: st.failed }));
                  const saved = await api.getArchiveSettings();
                  setArchive({ ...emptyArchive, ...saved });
                } catch (err) {
                  setError(err instanceof Error ? err.message : t("config.syncFailed"));
                } finally {
                  setBusy(false);
                }
              })();
            }}
          >
            {t("config.runJobNow")}
          </button>
        </div>
      </form>

      <form className="card" onSubmit={onSave} style={{ maxWidth: 640, marginBottom: "1.25rem" }}>
        <h2>{t("config.authTitle")}</h2>
        <label>{t("config.loginMode")}</label>
        <select
          value={form.mode}
          onChange={(e) => setForm({ ...form, mode: e.target.value })}
        >
          <option value="local">{t("config.loginModeLocal")}</option>
          <option value="oidc">OIDC / SSO</option>
          <option value="oauth">{t("config.loginModeOAuth")}</option>
          <option value="saml">SAML 2.0 / SSO</option>
          <option value="ldap">LDAP / Active Directory</option>
          <option value="radius">RADIUS (PAP/EAP/RadSec)</option>
        </select>

        <label>{t("config.publicBaseUrl")}</label>
        <input
          value={form.public_base_url}
          onChange={(e) => setForm({ ...form, public_base_url: e.target.value })}
          placeholder="http://localhost:5173"
        />
        <p className="muted" style={{ marginTop: 0 }}>
          OIDC callback:{" "}
          <span className="mono">{form.public_base_url || "…"}/api/v1/auth/oidc/callback</span>
          <br />
          OAuth callback:{" "}
          <span className="mono">{form.public_base_url || "…"}/api/v1/auth/oauth/callback</span>
          <br />
          SAML ACS: <span className="mono">{form.public_base_url || "…"}/api/v1/auth/saml/acs</span>
          <br />
          SCIM: <span className="mono">{form.scim_base_url || `${form.public_base_url || "…"}/scim/v2`}</span>
        </p>

        {form.mode === "oidc" && (
          <>
            <h2>{t("config.oidcTitle")}</h2>
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
            <label>Client Secret {form.has_oidc_secret ? t("config.secretSetLeaveEmpty") : ""}</label>
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
            <label>{t("config.defaultRoleAutoProvision")}</label>
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
              {t("config.autoCreateUsers")}
            </label>
            <label className="row" style={{ gap: "0.5rem", alignItems: "center" }}>
              <input
                type="checkbox"
                checked={form.oidc_skip_mfa}
                onChange={(e) => setForm({ ...form, oidc_skip_mfa: e.target.checked })}
              />
              {t("config.skipLocalMfaAfterSaml")}
            </label>
          </>
        )}

        {form.mode === "oauth" && (
          <>
            <h2>{t("config.oauthTitle")}</h2>
            <p className="muted">{t("config.oauthHint")}</p>
            <button
              type="button"
              className="btn secondary"
              style={{ marginBottom: "0.75rem" }}
              onClick={() =>
                setForm({
                  ...form,
                  mode: "oauth",
                  oidc_scopes: "",
                  oauth_username_claim: "iin",
                  oauth_email_claim: "email",
                  oauth_name_claim: "name",
                })
              }
            >
              {t("config.oauthDigitalIdPreset")}
            </button>
            {didLab ? (
              <button
                type="button"
                className="btn secondary"
                style={{ marginBottom: "0.75rem", marginLeft: "0.5rem" }}
                onClick={() => {
                  setForm({
                    ...form,
                    mode: "oauth",
                    oidc_client_id: didLab.client_id,
                    oidc_scopes: "",
                    oauth_authorize_url: didLab.authorize_url,
                    oauth_token_url: didLab.token_url,
                    oauth_userinfo_url: didLab.userinfo_url,
                    oauth_username_claim: didLab.username_claim,
                    oauth_email_claim: didLab.email_claim,
                    oauth_name_claim: didLab.name_claim,
                    oidc_auto_provision: true,
                    oidc_default_role: form.oidc_default_role || "operator",
                  });
                  setSecret(didLab.client_secret);
                }}
              >
                {t("config.oauthDigitalIdLab")}
              </button>
            ) : null}
            <label>Client ID</label>
            <input
              value={form.oidc_client_id}
              onChange={(e) => setForm({ ...form, oidc_client_id: e.target.value })}
              required={form.mode === "oauth"}
            />
            <label>Client Secret {form.has_oidc_secret ? t("config.secretSetLeaveEmpty") : ""}</label>
            <input
              type="password"
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
              autoComplete="off"
              placeholder={form.has_oidc_secret ? "••••••••" : ""}
            />
            <label>{t("config.oauthAuthorizeUrl")}</label>
            <input
              value={form.oauth_authorize_url || ""}
              onChange={(e) => setForm({ ...form, oauth_authorize_url: e.target.value })}
              placeholder="https://id.example/oauth/authorize"
              required={form.mode === "oauth"}
            />
            <label>{t("config.oauthTokenUrl")}</label>
            <input
              value={form.oauth_token_url || ""}
              onChange={(e) => setForm({ ...form, oauth_token_url: e.target.value })}
              placeholder="https://id.example/oauth/token"
              required={form.mode === "oauth"}
            />
            <label>{t("config.oauthUserinfoUrl")}</label>
            <input
              value={form.oauth_userinfo_url || ""}
              onChange={(e) => setForm({ ...form, oauth_userinfo_url: e.target.value })}
              placeholder="https://id.example/oauth/userinfo"
              required={form.mode === "oauth"}
            />
            <label>Scopes ({t("config.oauthScopesOptional")})</label>
            <input
              value={form.oidc_scopes}
              onChange={(e) => setForm({ ...form, oidc_scopes: e.target.value })}
              placeholder=""
            />
            <label>{t("config.oauthUsernameClaim")}</label>
            <input
              value={form.oauth_username_claim || "iin"}
              onChange={(e) => setForm({ ...form, oauth_username_claim: e.target.value })}
            />
            <label>{t("config.oauthEmailClaim")}</label>
            <input
              value={form.oauth_email_claim || "email"}
              onChange={(e) => setForm({ ...form, oauth_email_claim: e.target.value })}
            />
            <label>{t("config.oauthNameClaim")}</label>
            <input
              value={form.oauth_name_claim || "name"}
              onChange={(e) => setForm({ ...form, oauth_name_claim: e.target.value })}
            />
            <label>{t("config.defaultRoleAutoProvision")}</label>
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
              {t("config.autoCreateUsers")}
            </label>
            <label className="row" style={{ gap: "0.5rem", alignItems: "center" }}>
              <input
                type="checkbox"
                checked={form.oidc_skip_mfa}
                onChange={(e) => setForm({ ...form, oidc_skip_mfa: e.target.checked })}
              />
              {t("config.skipLocalMfaAfterSaml")}
            </label>
          </>
        )}

        {form.mode === "saml" && (
          <>
            <h2>{t("config.samlTitle")}</h2>
            <p className="muted">
              SP metadata:{" "}
              <a className="mono" href="/api/v1/auth/saml/metadata" target="_blank" rel="noreferrer">
                {form.saml_metadata_url || `${form.public_base_url || "…"}/api/v1/auth/saml/metadata`}
              </a>
              <br />
              ACS URL: <span className="mono">{form.saml_acs_url || `${form.public_base_url || "…"}/api/v1/auth/saml/acs`}</span>
              <br />
              SLO URL: <span className="mono">{form.saml_slo_url || `${form.public_base_url || "…"}/api/v1/auth/saml/slo`}</span>
              <br />
              SP key: {form.has_saml_sp_key ? t("config.spKeyGenerated") : t("config.spKeyWillCreate")}
              <br />
              {t("config.idpInitiatedHint")}
            </p>
            <label>{t("config.idpMetadataUrl")}</label>
            <input
              value={form.saml_idp_metadata_url}
              onChange={(e) => setForm({ ...form, saml_idp_metadata_url: e.target.value })}
              placeholder="https://idp.example/metadata"
            />
            <label>{t("config.idpEntityIdFallback")}</label>
            <input
              value={form.saml_idp_entity_id}
              onChange={(e) => setForm({ ...form, saml_idp_entity_id: e.target.value })}
            />
            <label>{t("config.idpSsoUrl")}</label>
            <input
              value={form.saml_idp_sso_url}
              onChange={(e) => setForm({ ...form, saml_idp_sso_url: e.target.value })}
              placeholder="https://idp.example/sso"
            />
            <label>{t("config.idpSigningCert")}</label>
            <textarea
              value={form.saml_idp_cert_pem}
              onChange={(e) => setForm({ ...form, saml_idp_cert_pem: e.target.value })}
              rows={4}
              placeholder="-----BEGIN CERTIFICATE-----"
            />
            <label>{t("config.spEntityId")}</label>
            <input
              value={form.saml_sp_entity_id}
              onChange={(e) => setForm({ ...form, saml_sp_entity_id: e.target.value })}
              placeholder={t("config.spEntityIdDefaultMetadata")}
            />
            <div className="row" style={{ gap: "0.75rem" }}>
              <div style={{ flex: 1 }}>
                <label>Attr username</label>
                <input
                  value={form.saml_attr_username}
                  onChange={(e) => setForm({ ...form, saml_attr_username: e.target.value })}
                />
              </div>
              <div style={{ flex: 1 }}>
                <label>Attr email</label>
                <input
                  value={form.saml_attr_email}
                  onChange={(e) => setForm({ ...form, saml_attr_email: e.target.value })}
                />
              </div>
              <div style={{ flex: 1 }}>
                <label>Attr display name</label>
                <input
                  value={form.saml_attr_display_name}
                  onChange={(e) => setForm({ ...form, saml_attr_display_name: e.target.value })}
                />
              </div>
            </div>
            <label>{t("config.defaultRoleAutoProvision")}</label>
            <input
              value={form.saml_default_role}
              onChange={(e) => setForm({ ...form, saml_default_role: e.target.value })}
            />
            <label>Attr groups</label>
            <input
              value={form.saml_group_attr || "groups"}
              onChange={(e) => setForm({ ...form, saml_group_attr: e.target.value })}
              placeholder="groups"
            />
            <label>{t("config.groupRoleMapLabel")}</label>
            <textarea
              value={groupMapText}
              onChange={(e) => setGroupMapText(e.target.value)}
              rows={4}
              placeholder={"keeppam-admins=admin\nops=operator"}
            />
            <label className="row" style={{ gap: "0.5rem", alignItems: "center" }}>
              <input
                type="checkbox"
                checked={form.saml_auto_provision}
                onChange={(e) => setForm({ ...form, saml_auto_provision: e.target.checked })}
              />
              {t("config.autoCreateUsers")}
            </label>
            <label className="row" style={{ gap: "0.5rem", alignItems: "center" }}>
              <input
                type="checkbox"
                checked={form.saml_skip_mfa}
                onChange={(e) => setForm({ ...form, saml_skip_mfa: e.target.checked })}
              />
              {t("config.skipLocalMfaAfterSaml")}
            </label>
            <label className="row" style={{ gap: "0.5rem", alignItems: "center" }}>
              <input
                type="checkbox"
                checked={!!form.rotate_saml_sp_key}
                onChange={(e) => setForm({ ...form, rotate_saml_sp_key: e.target.checked })}
              />
              {t("config.regenerateSpKey")}
            </label>

            <h2>{t("config.extraIdpTitle")}</h2>
            <p className="muted">{t("config.extraIdpHint")}</p>
            {extraIdPs.map((idp) => (
              <div key={idp.id} className="row" style={{ gap: "0.5rem", alignItems: "center", marginBottom: "0.35rem" }}>
                <span className="mono" style={{ flex: 1 }}>
                  {idp.name} ({idp.slug}){idp.enabled ? "" : t("config.idpDisabled")}
                </span>
                <button
                  className="btn secondary"
                  type="button"
                  onClick={() => {
                    setExtraForm({ ...emptyExtraIdP, ...idp });
                    setExtraMapText(formatGroupRoleMap(idp.group_role_map));
                  }}
                >
                  {t("config.edit")}
                </button>
                <button
                  className="btn secondary"
                  type="button"
                  onClick={() => {
                    void (async () => {
                      try {
                        await api.deleteSAMLIdP(idp.id);
                        setExtraIdPs((list) => list.filter((x) => x.id !== idp.id));
                        if (extraForm.id === idp.id) {
                          setExtraForm(emptyExtraIdP);
                          setExtraMapText("");
                        }
                        setMsg(t("config.idpDeleted"));
                      } catch (err) {
                        setError(err instanceof Error ? err.message : t("config.idpDeleteFailed"));
                      }
                    })();
                  }}
                >
                  {t("config.delete")}
                </button>
              </div>
            ))}
            <label>{t("config.idpSlug")}</label>
            <input
              value={extraForm.slug}
              onChange={(e) => setExtraForm({ ...extraForm, slug: e.target.value })}
              placeholder="okta"
              disabled={!!extraForm.id}
            />
            <label>{t("config.idpButtonLabel")}</label>
            <input
              value={extraForm.name}
              onChange={(e) => setExtraForm({ ...extraForm, name: e.target.value })}
              placeholder="Okta"
            />
            <label>IdP Metadata URL</label>
            <input
              value={extraForm.metadata_url}
              onChange={(e) => setExtraForm({ ...extraForm, metadata_url: e.target.value })}
            />
            <label>{t("config.idpManualFallback")}</label>
            <input
              value={extraForm.entity_id}
              onChange={(e) => setExtraForm({ ...extraForm, entity_id: e.target.value })}
              placeholder="Entity ID"
            />
            <input
              value={extraForm.sso_url}
              onChange={(e) => setExtraForm({ ...extraForm, sso_url: e.target.value })}
              placeholder="SSO URL"
            />
            <textarea
              value={extraForm.cert_pem}
              onChange={(e) => setExtraForm({ ...extraForm, cert_pem: e.target.value })}
              rows={3}
              placeholder="-----BEGIN CERTIFICATE-----"
            />
            <label>Group → role</label>
            <textarea
              value={extraMapText}
              onChange={(e) => setExtraMapText(e.target.value)}
              rows={3}
              placeholder={"keeppam-admins=admin"}
            />
            <label className="row" style={{ gap: "0.5rem", alignItems: "center" }}>
              <input
                type="checkbox"
                checked={extraForm.enabled}
                onChange={(e) => setExtraForm({ ...extraForm, enabled: e.target.checked })}
              />
              {t("config.enabled")}
            </label>
            {extraForm.sp_metadata_url && (
              <p className="muted">
                ACS: <span className="mono">{extraForm.acs_url}</span>
                <br />
                Metadata:{" "}
                <a className="mono" href={extraForm.sp_metadata_url.replace(/^https?:\/\/[^/]+/, "")} target="_blank" rel="noreferrer">
                  {extraForm.sp_metadata_url}
                </a>
              </p>
            )}
            <div className="row" style={{ gap: "0.5rem" }}>
              <button
                className="btn secondary"
                type="button"
                disabled={busy}
                onClick={() => {
                  void (async () => {
                    setBusy(true);
                    setError("");
                    setMsg("");
                    try {
                      const body = {
                        ...extraForm,
                        group_role_map: parseGroupRoleMap(extraMapText),
                      };
                      const saved = extraForm.id
                        ? await api.putSAMLIdP(extraForm.id, body)
                        : await api.createSAMLIdP(body);
                      const list = await api.listSAMLIdPs();
                      setExtraIdPs(list.idps || []);
                      setExtraForm({ ...emptyExtraIdP, ...saved });
                      setExtraMapText(formatGroupRoleMap(saved.group_role_map));
                      setMsg(t("config.idpSaved"));
                    } catch (err) {
                      setError(err instanceof Error ? err.message : t("config.idpSaveFailed"));
                    } finally {
                      setBusy(false);
                    }
                  })();
                }}
              >
                {extraForm.id ? t("config.saveIdP") : t("config.addIdP")}
              </button>
              {extraForm.id && (
                <button
                  className="btn secondary"
                  type="button"
                  onClick={() => {
                    setExtraForm(emptyExtraIdP);
                    setExtraMapText("");
                  }}
                >
                  {t("config.newIdP")}
                </button>
              )}
            </div>
          </>
        )}

        {form.mode === "ldap" && (
          <>
            <h2>{t("config.loginModeLdap")}</h2>
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
              Bind password {form.has_ldap_bind_password ? t("config.secretSet") : ""}
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
            <label>{t("config.defaultRole")}</label>
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
              {t("config.noTlsVerify")}
            </label>
            <label className="row" style={{ gap: "0.5rem", alignItems: "center" }}>
              <input
                type="checkbox"
                checked={form.ldap_auto_provision}
                onChange={(e) => setForm({ ...form, ldap_auto_provision: e.target.checked })}
              />
              {t("config.autoCreateUsers")}
            </label>
            <label className="row" style={{ gap: "0.5rem", alignItems: "center" }}>
              <input
                type="checkbox"
                checked={form.ldap_skip_mfa}
                onChange={(e) => setForm({ ...form, ldap_skip_mfa: e.target.checked })}
              />
              {t("config.skipLocalMfaAfterLdap")}
            </label>
          </>
        )}

        {form.mode === "radius" && (
          <>
            <h2>{t("config.radiusTitle")}</h2>
            <p className="muted">
              {t("config.radiusHint")}{" "}
              <span className="mono">docs/radius-auth.txt</span>,{" "}
              <span className="mono">docs/radius-eap.txt</span>.
            </p>
            <label>{t("config.ldapServer")}</label>
            <input
              value={form.radius_host}
              onChange={(e) => setForm({ ...form, radius_host: e.target.value })}
              placeholder="radius.example:1812"
              required={form.mode === "radius"}
            />
            <label>Shared secret {form.has_radius_secret ? t("config.secretSet") : ""}</label>
            <input
              type="password"
              value={radiusSecret}
              onChange={(e) => setRadiusSecret(e.target.value)}
              autoComplete="off"
            />
            <label>NAS-Identifier</label>
            <input
              value={form.radius_nas_id}
              onChange={(e) => setForm({ ...form, radius_nas_id: e.target.value })}
              placeholder="keeppam"
            />
            <label>{t("config.radiusTimeout")}</label>
            <input
              type="number"
              min={1}
              max={30}
              value={form.radius_timeout_sec}
              onChange={(e) => setForm({ ...form, radius_timeout_sec: Number(e.target.value) || 5 })}
            />
            <label>Auth method</label>
            <select
              value={form.radius_auth_method || "pap"}
              onChange={(e) => setForm({ ...form, radius_auth_method: e.target.value })}
            >
              <option value="pap">PAP (UDP)</option>
              <option value="eap-ttls">EAP-TTLS (inner PAP)</option>
              <option value="peap">PEAP (MSCHAPv2)</option>
            </select>
            {(form.radius_auth_method === "eap-ttls" || form.radius_auth_method === "peap") && (
              <>
                <label>EAP tunnel CA (PEM)</label>
                <textarea
                  rows={4}
                  value={form.radius_eap_ca_pem || ""}
                  onChange={(e) => setForm({ ...form, radius_eap_ca_pem: e.target.value })}
                  placeholder="-----BEGIN CERTIFICATE-----"
                  required
                />
                <label>EAP anonymous username</label>
                <input
                  value={form.radius_eap_anonymous_user || "anonymous"}
                  onChange={(e) => setForm({ ...form, radius_eap_anonymous_user: e.target.value })}
                />
                <label className="row" style={{ gap: "0.5rem", alignItems: "center" }}>
                  <input
                    type="checkbox"
                    checked={form.radius_eap_insecure_tls}
                    onChange={(e) => setForm({ ...form, radius_eap_insecure_tls: e.target.checked })}
                  />
                  {t("config.eapNoVerifyHostname")}
                </label>
              </>
            )}
            <label className="row" style={{ gap: "0.5rem", alignItems: "center" }}>
              <input
                type="checkbox"
                checked={form.radius_radsec}
                onChange={(e) => setForm({ ...form, radius_radsec: e.target.checked })}
              />
              {t("config.radsecOption")}
            </label>
            {form.radius_radsec && (
              <>
                <label>RadSec CA (PEM)</label>
                <textarea
                  rows={4}
                  value={form.radius_radsec_ca_pem || ""}
                  onChange={(e) => setForm({ ...form, radius_radsec_ca_pem: e.target.value })}
                />
                <label>RadSec client cert + key (PEM)</label>
                <textarea
                  rows={6}
                  value={form.radius_radsec_client_pem || ""}
                  onChange={(e) => setForm({ ...form, radius_radsec_client_pem: e.target.value })}
                />
              </>
            )}
            <label>{t("config.defaultRole")}</label>
            <input
              value={form.radius_default_role}
              onChange={(e) => setForm({ ...form, radius_default_role: e.target.value })}
            />
            <label className="row" style={{ gap: "0.5rem", alignItems: "center" }}>
              <input
                type="checkbox"
                checked={form.radius_auto_provision}
                onChange={(e) => setForm({ ...form, radius_auto_provision: e.target.checked })}
              />
              {t("config.autoCreateUsers")}
            </label>
            <label className="row" style={{ gap: "0.5rem", alignItems: "center" }}>
              <input
                type="checkbox"
                checked={form.radius_skip_mfa}
                onChange={(e) => setForm({ ...form, radius_skip_mfa: e.target.checked })}
              />
              {t("config.skipLocalMfaAfterRadius")}
            </label>
          </>
        )}

        <h2>{t("config.scimTitle")}</h2>
        <p className="muted">
          {t("config.scimLead")}
          Tenant URL:{" "}
          <span className="mono">{form.scim_base_url || `${form.public_base_url || "…"}/scim/v2`}</span>
        </p>
        <label className="row" style={{ gap: "0.5rem", alignItems: "center" }}>
          <input
            type="checkbox"
            checked={form.scim_enabled}
            onChange={(e) => setForm({ ...form, scim_enabled: e.target.checked })}
          />
          {t("config.scimEnableInbound")}
        </label>
        <label>
          {t("config.bearerTokenLabel")} {form.has_scim_token ? t("config.secretSetLeaveEmpty") : ""}
        </label>
        <input
          type="password"
          value={scimToken}
          onChange={(e) => setScimToken(e.target.value)}
          autoComplete="off"
          placeholder={form.has_scim_token ? "••••••••" : ""}
        />
        <button
          className="btn secondary"
          type="button"
          style={{ marginTop: "0.35rem" }}
          onClick={() => {
            const bytes = new Uint8Array(32);
            crypto.getRandomValues(bytes);
            const token = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
            setScimToken(token);
            void navigator.clipboard.writeText(token).then(
              () => setMsg(t("config.scimTokenCopied")),
              () => setMsg(t("config.scimTokenGenerated")),
            );
          }}
        >
          {t("config.genToken")}
        </button>
        <label>{t("config.defaultRoleNewUsers")}</label>
        <input
          value={form.scim_default_role}
          onChange={(e) => setForm({ ...form, scim_default_role: e.target.value })}
          placeholder="operator"
        />
        <p className="muted">{t("config.scimAdminClamp")}</p>

        <button className="btn" type="submit" disabled={busy} style={{ marginTop: "1rem" }}>
          {t("config.saveAuth")}
        </button>
      </form>

      <form className="card" onSubmit={onSaveSSH} style={{ maxWidth: 640, marginBottom: "1.25rem" }}>
        <h2>{t("config.sshTitle")}</h2>
        <p className="muted">{t("config.sshAuthLeadFull")}</p>
        <label>{t("config.mode")}</label>
        <select
          value={ssh.ssh_auth_mode}
          onChange={(e) => setSsh({ ...ssh, ssh_auth_mode: e.target.value })}
        >
          <option value="vault_secret">{t("config.sshModeVault")}</option>
          <option value="ssh_cert">{t("config.sshModeCert")}</option>
          <option value="gssapi">{t("config.sshModeKerberos")}</option>
        </select>
        <label>{t("config.certTtlHours")}</label>
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
              value={ssh.ssh_ca_public || (ssh.has_ssh_ca ? "" : t("config.sshSaveModeHint"))}
              className="mono"
              style={{ width: "100%", fontSize: "0.8rem" }}
            />
            {ssh.ssh_ca_public && (
              <button
                className="btn secondary"
                type="button"
                onClick={() => {
                  void navigator.clipboard.writeText(ssh.ssh_ca_public);
                  setMsg(t("config.caPubkeyCopied"));
                }}
              >
                {t("config.copyPubkey")}
              </button>
            )}
            <p className="muted" style={{ marginTop: "0.5rem" }}>{t("config.sshCaTargetHint")}</p>
            <button className="btn secondary" type="button" disabled={busy} onClick={() => void onRotateCA()}>
              {t("config.rotateCa")}
            </button>
          </>
        )}
        {ssh.ssh_auth_mode === "gssapi" && (
          <>
            <label>Kerberos realm</label>
            <input
              className="mono"
              value={ssh.krb5_realm || ""}
              onChange={(e) => setSsh({ ...ssh, krb5_realm: e.target.value })}
              placeholder="CORP.LOCAL"
            />
            <label>{t("config.krb5Conf")}</label>
            <textarea
              className="mono"
              rows={6}
              value={ssh.krb5_config || ""}
              onChange={(e) => setSsh({ ...ssh, krb5_config: e.target.value })}
              style={{ width: "100%", fontSize: "0.8rem" }}
            />
            <label>{t("config.spnTemplate")}</label>
            <input
              className="mono"
              value={ssh.krb5_spn_template || "host/%h"}
              onChange={(e) => setSsh({ ...ssh, krb5_spn_template: e.target.value })}
            />
            <p className="muted">{t("config.gssapiHint")}</p>
            <label>{t("config.keytabPrincipal")}</label>
            <input
              className="mono"
              value={ssh.krb5_principal || ""}
              onChange={(e) => setSsh({ ...ssh, krb5_principal: e.target.value })}
              placeholder="keeppam/gateway$@CORP.LOCAL"
            />
            <label>Keytab (base64, write-only){ssh.has_krb5_keytab ? t("config.keytabLoaded") : ""}</label>
            <textarea
              className="mono"
              rows={3}
              value={ssh.krb5_keytab || ""}
              onChange={(e) => setSsh({ ...ssh, krb5_keytab: e.target.value })}
              placeholder={t("config.leaveEmptyNoChange")}
              style={{ width: "100%", fontSize: "0.8rem" }}
            />
          </>
        )}
        <button className="btn" type="submit" disabled={busy} style={{ marginTop: "1rem" }}>
          {t("config.saveSsh")}
        </button>
      </form>

      <form className="card" onSubmit={onSaveFirewall} style={{ maxWidth: 640 }}>
        <h2>{t("config.firewallTitle")}</h2>
        <p className="muted">{t("config.firewallLead")}</p>
        <label>{t("config.pamGatewayCidr")}</label>
        <input
          value={firewallCidrsText}
          onChange={(e) => setFirewallCidrsText(e.target.value)}
          placeholder="10.0.1.0/24, 10.0.2.0/24"
        />
        <label>{t("config.probeAgents")}</label>
        {probeAgents.map((a, i) => (
          <div key={i} className="card" style={{ padding: "0.5rem", marginBottom: "0.5rem" }}>
            <div className="row" style={{ gap: "0.5rem", flexWrap: "wrap" }}>
              <input
                placeholder="name"
                value={a.name}
                onChange={(e) => {
                  const next = [...probeAgents];
                  next[i] = { ...next[i], name: e.target.value };
                  setProbeAgents(next);
                }}
                style={{ width: 100 }}
              />
              <input
                placeholder="segment"
                value={a.segment}
                onChange={(e) => {
                  const next = [...probeAgents];
                  next[i] = { ...next[i], segment: e.target.value };
                  setProbeAgents(next);
                }}
                style={{ width: 90 }}
              />
              <input
                placeholder="http://host:8100/probe"
                value={a.probe_url}
                onChange={(e) => {
                  const next = [...probeAgents];
                  next[i] = { ...next[i], probe_url: e.target.value };
                  setProbeAgents(next);
                }}
                style={{ flex: 1, minWidth: 200 }}
              />
              <label className="row" style={{ gap: 4, alignItems: "center" }}>
                <input
                  type="checkbox"
                  checked={a.enabled}
                  onChange={(e) => {
                    const next = [...probeAgents];
                    next[i] = { ...next[i], enabled: e.target.checked };
                    setProbeAgents(next);
                  }}
                />
                on
              </label>
              <button
                type="button"
                className="btn secondary"
                onClick={() => setProbeAgents(probeAgents.filter((_, j) => j !== i))}
              >
                ×
              </button>
            </div>
            <input
              type="password"
              placeholder={a.has_token ? t("config.probeAgentTokenSet") : t("config.probeAgentBearer")}
              value={a.token}
              onChange={(e) => {
                const next = [...probeAgents];
                next[i] = { ...next[i], token: e.target.value };
                setProbeAgents(next);
              }}
              style={{ width: "100%", marginTop: 4 }}
            />
          </div>
        ))}
        <div className="row" style={{ gap: "0.5rem", flexWrap: "wrap", marginBottom: "0.5rem" }}>
          <button
            type="button"
            className="btn secondary"
            onClick={() =>
              setProbeAgents([
                ...probeAgents,
                { name: "agent" + (probeAgents.length + 1), segment: "", probe_url: "", enabled: true, token: "" },
              ])
            }
          >
            {t("config.addAgent")}
          </button>
          <label>{t("config.probeQuorum")}</label>
          <input
            type="number"
            min={1}
            max={16}
            value={probeQuorum}
            onChange={(e) => setProbeQuorum(Number(e.target.value) || 1)}
            style={{ width: 64 }}
          />
          <button type="button" className="btn secondary" disabled={busy} onClick={(e) => void onSaveProbeAgents(e)}>
            {t("config.saveAgents")}
          </button>
        </div>
        <p className="muted" style={{ marginTop: 0 }}>
          {t("config.probeStandHint")}{" "}
          <span className="mono">http://firewall-probe:8100/probe</span>,{" "}
          <span className="mono">http://firewall-probe-b:8101/probe</span>. Legacy{" "}
          
        </p>
        <label>{t("config.legacyProbeUrl")}</label>
        <input
          value={firewallForm.probe_url}
          onChange={(e) => setFirewallForm({ ...firewallForm, probe_url: e.target.value })}
          placeholder="http://firewall-probe:8100/probe"
        />
        <label>{t("config.probeInterval")}</label>
        <input
          type="number"
          min={0}
          max={168}
          value={firewallForm.probe_interval_hours}
          onChange={(e) =>
            setFirewallForm({ ...firewallForm, probe_interval_hours: Number(e.target.value) })
          }
        />
        <label>AWX launch URL</label>
        <input
          value={firewallForm.awx_launch_url}
          onChange={(e) => setFirewallForm({ ...firewallForm, awx_launch_url: e.target.value })}
          placeholder="https://awx.example/api/v2/job_templates/7/launch/"
        />
        <label>AWX token {firewallStatus?.last_push_error ? "" : ""}</label>
        <input
          type="password"
          value={firewallAwxToken}
          onChange={(e) => setFirewallAwxToken(e.target.value)}
          placeholder={t("config.bearerLeaveEmpty")}
        />
        <label className="row" style={{ gap: 8, alignItems: "center" }}>
          <input
            type="checkbox"
            checked={firewallForm.awx_auto_push}
            onChange={(e) => setFirewallForm({ ...firewallForm, awx_auto_push: e.target.checked })}
          />
          {t("config.awxAutoPush")}
        </label>
        <div className="row" style={{ gap: "0.5rem", marginTop: "0.75rem", flexWrap: "wrap" }}>
          <button
            className="btn secondary"
            type="button"
            disabled={busy}
            onClick={() => void api.downloadFirewallRules("iptables").catch((err) => setError(String(err)))}
          >
            {t("config.downloadIptables")}
          </button>
          <button
            className="btn secondary"
            type="button"
            disabled={busy}
            onClick={() => void api.downloadFirewallRules("nft").catch((err) => setError(String(err)))}
          >
            {t("config.downloadNft")}
          </button>
          <button
            className="btn secondary"
            type="button"
            disabled={busy}
            onClick={() => void api.downloadFirewallRules("ansible").catch((err) => setError(String(err)))}
          >
            {t("config.downloadAnsible")}
          </button>
          <button
            className="btn secondary"
            type="button"
            disabled={busy}
            onClick={() =>
              void api
                .runFirewallProbe()
                .then(async () => {
                  setFirewallStatus(await api.getFirewallStatus());
                  setMsg(t("config.firewallProbeDone"));
                })
                .catch((err) => setError(String(err)))
            }
          >
            Drift probe
          </button>
          <button
            className="btn secondary"
            type="button"
            disabled={busy}
            onClick={() =>
              void api
                .pushFirewallAWX()
                .then(async () => {
                  setFirewallStatus(await api.getFirewallStatus());
                  setMsg(t("config.awxJobStarted"));
                })
                .catch((err) => setError(String(err)))
            }
          >
            Push AWX
          </button>
          <button className="btn" type="submit" disabled={busy}>
            {t("config.save")}
          </button>
        </div>
        {firewallStatus && (
          <div style={{ marginTop: "1rem" }}>
            <p className="muted">
              {t("config.fwPamOnlyStatus", { n: firewallStatus.pam_only_count, u: firewallStatus.unapplied_count })}
              {firewallStatus.non_ip_count > 0 ? t("config.fwHostnameInAddress", { n: firewallStatus.non_ip_count }) : ""}
              {firewallStatus.probe_reachable_count > 0
                ? ` · probe reachable: ${firewallStatus.probe_reachable_count}`
                : ""}
              {firewallStatus.probe_agents_total
                ? ` · agents: ${firewallStatus.probe_agents_healthy ?? 0}/${firewallStatus.probe_agents_total} healthy · quorum ${firewallStatus.probe_quorum ?? 1}`
                : ""}
              {firewallStatus.last_probe_at
                ? ` · probe: ${new Date(firewallStatus.last_probe_at).toLocaleString()}`
                : ""}
              {firewallStatus.last_push_at
                ? ` · push: ${new Date(firewallStatus.last_push_at).toLocaleString()}`
                : ""}
              {firewallStatus.last_push_error ? (
                <span className="error"> · push err: {firewallStatus.last_push_error}</span>
              ) : null}
              {firewallStatus.ready ? " · ready" : ""}
            </p>
            {firewallStatus.assets.length > 0 && (
              <table className="table compact">
                <thead>
                  <tr>
                    <th>{t("common.asset")}</th>
                    <th>Endpoint</th>
                    <th>{t("config.rules")}</th>
                    <th>Probe</th>
                    <th>Gaps</th>
                  </tr>
                </thead>
                <tbody>
                  {firewallStatus.assets.map((a) => (
                    <tr key={a.id}>
                      <td>{a.name}</td>
                      <td className="mono">
                        {a.address}:{a.port}
                      </td>
                      <td>
                        {a.firewall_applied_at
                          ? new Date(a.firewall_applied_at).toLocaleString()
                          : "—"}
                      </td>
                      <td>
                        {a.firewall_probe_at
                          ? `${a.firewall_probe_reachable ? "OPEN" : "closed"} ${new Date(a.firewall_probe_at).toLocaleDateString()}`
                          : "—"}
                      </td>
                      <td className="muted">{(a.gaps || []).join(", ") || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}
      </form>

      <form className="card" onSubmit={onSaveNAC} style={{ maxWidth: 640 }}>
        <h2>{t("config.nacTitle")}</h2>
        <p className="muted">
          {t("config.nacLead")} Mock:{" "}
          <span className="mono">cmd/nac-mock</span> (:8110), IP *.66 → deny.
        </p>
        <label>{t("config.mode")}</label>
        <select value={nacForm.mode} onChange={(e) => setNacForm({ ...nacForm, mode: e.target.value })}>
          <option value="off">{t("config.off")}</option>
          <option value="audit">audit</option>
          <option value="enforce">enforce</option>
        </select>
        <label>{t("config.nacApiUrl")}</label>
        <input
          value={nacForm.api_url}
          onChange={(e) => setNacForm({ ...nacForm, api_url: e.target.value })}
          placeholder="http://nac-mock:8110"
        />
        <label>Vendor</label>
        <select value={nacForm.vendor} onChange={(e) => setNacForm({ ...nacForm, vendor: e.target.value })}>
          <option value="generic">generic (/keeppam/posture)</option>
          <option value="cisco_ise">cisco_ise</option>
        </select>
        <label>Timeout (ms)</label>
        <input
          type="number"
          min={500}
          max={30000}
          value={nacForm.timeout_ms}
          onChange={(e) => setNacForm({ ...nacForm, timeout_ms: Number(e.target.value) })}
        />
        <label>API token {nacForm.has_api_token ? t("config.secretSet") : ""}</label>
        <input
          type="password"
          value={nacToken}
          onChange={(e) => setNacToken(e.target.value)}
          placeholder={t("config.nacBearerLeaveEmpty")}
        />
        {nacForm.last_error ? <p className="error">{t("config.lastError", { err: nacForm.last_error })}</p> : null}
        <div className="row" style={{ gap: "0.5rem", marginTop: "0.75rem" }}>
          <button
            className="btn secondary"
            type="button"
            disabled={busy}
            onClick={() =>
              void api.testNACSettings().then((r) => setMsg(`NAC test: allowed=${r.result.allowed}`)).catch((err) => setError(String(err)))
            }
          >
            Test posture
          </button>
          <button className="btn" type="submit" disabled={busy}>
            {t("config.save")}
          </button>
        </div>
      </form>

      <form className="card" onSubmit={onSaveEIDAS} style={{ maxWidth: 640 }}>
        <h2>{t("config.eidasTitle")}</h2>
        <p className="muted">{t("config.eidasLead")}</p>
        <label>{t("config.mode")}</label>
        <select value={eidasForm.mode} onChange={(e) => setEidasForm({ ...eidasForm, mode: e.target.value })}>
          <option value="off">{t("config.eidasModeOff")}</option>
          <option value="advanced">{t("config.eidasModeAdvanced")}</option>
          <option value="qualified">{t("config.eidasQualified")}</option>
        </select>
        <label>{t("config.profile")}</label>
        <select value={eidasForm.profile} onChange={(e) => setEidasForm({ ...eidasForm, profile: e.target.value })}>
          <option value="eidas">eIDAS (EU QES OID)</option>
          <option value="fstec">{t("config.eidasModeFstec")}</option>
        </select>
        <label>
          <input
            type="checkbox"
            checked={eidasForm.require_b_lta}
            onChange={(e) => setEidasForm({ ...eidasForm, require_b_lta: e.target.checked })}
          />{" "}
          {t("config.requirePades")}
        </label>
        <label>
          <input
            type="checkbox"
            checked={eidasForm.pkcs11_enabled}
            onChange={(e) => setEidasForm({ ...eidasForm, pkcs11_enabled: e.target.checked })}
          />{" "}
          {t("config.pkcs11ForPdf")}
        </label>
        {eidasForm.pkcs11_enabled ? (
          <>
            <label>PKCS#11 module (.so)</label>
            <input
              value={eidasForm.pkcs11_module}
              onChange={(e) => setEidasForm({ ...eidasForm, pkcs11_module: e.target.value })}
              placeholder="/usr/lib64/..."
            />
            <label>Object label</label>
            <input
              value={eidasForm.pkcs11_label}
              onChange={(e) => setEidasForm({ ...eidasForm, pkcs11_label: e.target.value })}
            />
            <label>PKCS#11 PIN {eidasForm.has_pkcs11_pin ? t("config.secretSet") : ""}</label>
            <input
              type="password"
              value={eidasPin}
              onChange={(e) => setEidasPin(e.target.value)}
              placeholder={t("config.emptyNoChange")}
            />
          </>
        ) : null}
        {eidasForm.cert_cn ? (
          <p className="muted">
            {t("config.certSummary", { cn: eidasForm.cert_cn, profile: eidasForm.pades_profile || "—" })}{" "}
            {eidasForm.cert_qualified ? t("common.yes") : t("common.no")}
          </p>
        ) : null}
        {eidasForm.last_error ? <p className="error">{t("config.lastCheck", { err: eidasForm.last_error })}</p> : null}
        <div className="row" style={{ gap: "0.5rem", marginTop: "0.75rem" }}>
          <button
            className="btn secondary"
            type="button"
            disabled={busy}
            onClick={() =>
              void api
                .testEIDASSettings()
                .then((r) =>
                  setMsg(
                    `eIDAS test: ready=${r.result.ready} qualified=${r.result.cert_qualified} ${r.result.detail || ""}`,
                  ),
                )
                .catch((err) => setError(String(err)))
            }
          >
            Test cert
          </button>
          <button className="btn" type="submit" disabled={busy}>
            {t("config.save")}
          </button>
        </div>
      </form>

      <form className="card" onSubmit={onSaveUEBAML} style={{ maxWidth: 640 }}>
        <h2>{t("config.uebaTitle")}</h2>
        <p className="muted">{t("config.uebaMlLead")}</p>
        <label>{t("config.mode")}</label>
        <select value={uebaMlForm.mode} onChange={(e) => setUebaMlForm({ ...uebaMlForm, mode: e.target.value })}>
          <option value="off">{t("config.off")}</option>
          <option value="audit">audit (connect + post-session)</option>
          <option value="live">live (+ mid-session scan)</option>
        </select>
        <label>
          <input
            type="checkbox"
            checked={uebaMlForm.peer_group}
            onChange={(e) => setUebaMlForm({ ...uebaMlForm, peer_group: e.target.checked })}
          />{" "}
          {t("config.peerGroupBaseline")}
        </label>
        <label>{t("config.mlThreshold")}</label>
        <input
          type="number"
          min={30}
          max={95}
          value={uebaMlForm.ml_threshold}
          onChange={(e) => setUebaMlForm({ ...uebaMlForm, ml_threshold: Number(e.target.value) })}
        />
        <label>{t("config.liveInterval")}</label>
        <input
          type="number"
          min={15}
          max={600}
          value={uebaMlForm.live_interval_s}
          onChange={(e) => setUebaMlForm({ ...uebaMlForm, live_interval_s: Number(e.target.value) })}
        />
        {uebaMlForm.last_error ? <p className="error">{t("config.lastLiveRun", { err: uebaMlForm.last_error })}</p> : null}
        <div className="row" style={{ gap: "0.5rem", marginTop: "0.75rem" }}>
          <button
            className="btn secondary"
            type="button"
            disabled={busy}
            onClick={() =>
              void api
                .testUEBAMLSettings()
                .then((r) =>
                  setMsg(
                    `UEBA-ML test: score=${r.result.risk_score} ml=${(r.result.connect as { ml_score?: number })?.ml_score ?? "—"}`,
                  ),
                )
                .catch((err) => setError(String(err)))
            }
          >
            Test score
          </button>
          <button className="btn" type="submit" disabled={busy}>
            {t("config.save")}
          </button>
        </div>
      </form>

      <form id="ai" className="card" onSubmit={onSaveAI} style={{ maxWidth: 640 }}>
        <h2>{t("config.aiTitle")}</h2>
        <p className="muted">{t("config.aiLead")}</p>
        <p className="muted">{aiForm.licensed ? t("config.aiLicensed") : t("config.aiUnlicensed")}</p>
        <label>{t("config.mode")}</label>
        <select value={aiForm.mode} onChange={(e) => setAiForm({ ...aiForm, mode: e.target.value })}>
          <option value="off">{t("config.off")}</option>
          <option value="on">on</option>
          {aiForm.allow_external ? <option value="external">external</option> : null}
        </select>
        <label>{t("config.aiEndpoint")}</label>
        <input value={aiForm.endpoint} onChange={(e) => setAiForm({ ...aiForm, endpoint: e.target.value })} />
        <label>{t("config.aiModel")}</label>
        <input value={aiForm.model} onChange={(e) => setAiForm({ ...aiForm, model: e.target.value })} />
        <label>{t("config.aiEmbed")}</label>
        <input value={aiForm.embed_model} onChange={(e) => setAiForm({ ...aiForm, embed_model: e.target.value })} />
        <label>Lang</label>
        <select value={aiForm.lang} onChange={(e) => setAiForm({ ...aiForm, lang: e.target.value })}>
          <option value="ru">ru</option>
          <option value="en">en</option>
        </select>
        {aiForm.last_error ? <p className="error">{aiForm.last_error}</p> : null}
        <div className="row" style={{ gap: "0.5rem", marginTop: "0.75rem" }}>
          <button
            className="btn secondary"
            type="button"
            disabled={busy}
            onClick={() =>
              void api
                .testAISettings()
                .then((r) => setMsg(`AI test: ok=${r.ok} model=${r.model || "—"}`))
                .catch((err) => setError(String(err)))
            }
          >
            Test
          </button>
          <button className="btn" type="submit" disabled={busy}>
            {t("config.save")}
          </button>
        </div>
      </form>

      <form className="card" onSubmit={onSaveITSM} style={{ maxWidth: 640 }}>
        <h2>{t("config.itsmTitle")}</h2>
        <p className="muted">{t("config.itsmLead")}</p>
        <label className="row" style={{ gap: "0.5rem", alignItems: "center" }}>
          <input
            type="checkbox"
            checked={itsm.enabled}
            onChange={(e) => setItsm({ ...itsm, enabled: e.target.checked })}
          />
          {t("config.itsmEnable")}
        </label>
        <label>Provider</label>
        <select
          value={itsm.provider}
          onChange={(e) => setItsm({ ...itsm, provider: e.target.value })}
        >
          <option value="mock">{t("config.itsmProviderMock")}</option>
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
        <label>{t("config.itsmOkStatuses")}</label>
        <input
          value={(itsm.ok_statuses || []).join(", ")}
          onChange={(e) =>
            setItsm({
              ...itsm,
              ok_statuses: e.target.value.split(",").map((x) => x.trim()).filter(Boolean),
            })
          }
        />
        <label>{t("config.authHeaderLeave", { set: itsm.has_auth_header ? t("config.secretSet") : "" })}</label>
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
            {t("config.onCreateRequest")}
          </label>
          <label className="row" style={{ gap: "0.4rem", alignItems: "center" }}>
            <input
              type="checkbox"
              checked={itsm.require_on_approve}
              onChange={(e) => setItsm({ ...itsm, require_on_approve: e.target.checked })}
            />
            {t("config.onApprove")}
          </label>
          <label className="row" style={{ gap: "0.4rem", alignItems: "center" }}>
            <input
              type="checkbox"
              checked={itsm.require_on_connect}
              onChange={(e) => setItsm({ ...itsm, require_on_connect: e.target.checked })}
            />
            {t("config.onConnect")}
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
            {t("config.checkAt", { at: itsm.last_check_at ? new Date(itsm.last_check_at).toLocaleString() : "—" })}
            {itsm.last_error ? (
              <>
                <br />
                <span className="error">{t("config.errorPrefix", { err: itsm.last_error })}</span>
              </>
            ) : null}
          </p>
        )}
        <div className="row" style={{ gap: "0.5rem", marginTop: "1rem", alignItems: "flex-end" }}>
          <div style={{ flex: 1 }}>
            <label>{t("config.checkTicket")}</label>
            <input value={itsmTicket} onChange={(e) => setItsmTicket(e.target.value)} />
          </div>
          <button className="btn secondary" type="button" disabled={busy} onClick={() => void onCheckTicket()}>
            Validate
          </button>
        </div>
        {itsmCheck && <p className="muted mono">{itsmCheck}</p>}
        <button className="btn" type="submit" disabled={busy} style={{ marginTop: "1rem" }}>
          {t("config.saveItsm")}
        </button>
      </form>

      <form className="card" onSubmit={onSaveNotify} style={{ maxWidth: 640 }}>
        <h2>{t("config.notifyTitle")}</h2>
        <p className="muted">{t("config.notifyLead")}</p>
        <h3>{t("config.jitWebhookTitle")}</h3>
        <label className="row" style={{ gap: "0.5rem", alignItems: "center" }}>
          <input
            type="checkbox"
            checked={notify.enabled}
            onChange={(e) => setNotify({ ...notify, enabled: e.target.checked })}
          />
          {t("config.enableWebhook")}
        </label>
        <label>URL</label>
        <input
          value={notify.webhook_url}
          onChange={(e) => setNotify({ ...notify, webhook_url: e.target.value })}
          placeholder="https://hooks.example.com/keeppam"
        />
        <label>{t("config.authHeaderLeave", { set: notify.has_auth_header ? t("config.secretSet") : "" })}</label>
        <input
          type="password"
          value={notifyAuth}
          onChange={(e) => setNotifyAuth(e.target.value)}
          placeholder="Bearer … / X-Token: …"
          autoComplete="new-password"
        />
        <label>Timeout (sec)</label>
        <input
          type="number"
          min={1}
          max={30}
          value={notify.timeout_sec}
          onChange={(e) => setNotify({ ...notify, timeout_sec: Number(e.target.value) })}
        />
        {(notify.last_sent_at || notify.last_error) && (
          <p className="muted" style={{ marginTop: "0.75rem" }}>
            Webhook: {notify.last_sent_at ? new Date(notify.last_sent_at).toLocaleString() : "—"}
            {notify.last_error ? (
              <>
                <br />
                <span className="error">{t("config.errorPrefix", { err: notify.last_error })}</span>
              </>
            ) : null}
          </p>
        )}
        <h3 style={{ marginTop: "1.25rem" }}>{t("config.smtpTitle")}</h3>
        <label className="row" style={{ gap: "0.5rem", alignItems: "center" }}>
          <input
            type="checkbox"
            checked={!!notify.smtp_enabled}
            onChange={(e) => setNotify({ ...notify, smtp_enabled: e.target.checked })}
          />
          {t("config.enableEmail")}
        </label>
        <label>Host</label>
        <input
          value={notify.smtp_host || ""}
          onChange={(e) => setNotify({ ...notify, smtp_host: e.target.value })}
          placeholder="smtp.example.com"
        />
        <label>Port</label>
        <input
          type="number"
          min={1}
          max={65535}
          value={notify.smtp_port ?? 587}
          onChange={(e) => setNotify({ ...notify, smtp_port: Number(e.target.value) })}
        />
        <label>TLS</label>
        <select
          value={notify.smtp_tls || "starttls"}
          onChange={(e) => setNotify({ ...notify, smtp_tls: e.target.value })}
        >
          <option value="starttls">STARTTLS (587)</option>
          <option value="tls">TLS (465)</option>
          <option value="none">{t("config.smtpRelayNone")}</option>
        </select>
        <label className="row" style={{ gap: "0.5rem", alignItems: "center" }}>
          <input
            type="checkbox"
            checked={!!notify.smtp_tls_insecure}
            onChange={(e) => setNotify({ ...notify, smtp_tls_insecure: e.target.checked })}
          />
          {t("config.noCertVerify")}
        </label>
        <label>From</label>
        <input
          value={notify.smtp_from || ""}
          onChange={(e) => setNotify({ ...notify, smtp_from: e.target.value })}
          placeholder="keeppam@example.com"
        />
        <label>{t("config.smtpUsername")}</label>
        <input
          value={notify.smtp_username || ""}
          onChange={(e) => setNotify({ ...notify, smtp_username: e.target.value })}
          autoComplete="off"
        />
        <label>{t("config.passwordLeave", { set: notify.has_smtp_password ? t("config.secretSet") : "" })}</label>
        <input
          type="password"
          value={notifySmtpPass}
          onChange={(e) => setNotifySmtpPass(e.target.value)}
          autoComplete="new-password"
        />
        {(notify.smtp_last_sent_at || notify.smtp_last_error) && (
          <p className="muted" style={{ marginTop: "0.75rem" }}>
            SMTP: {notify.smtp_last_sent_at ? new Date(notify.smtp_last_sent_at).toLocaleString() : "—"}
            {notify.smtp_last_error ? (
              <>
                <br />
                <span className="error">{t("config.errorPrefix", { err: notify.smtp_last_error })}</span>
              </>
            ) : null}
          </p>
        )}
        <div className="row" style={{ gap: "0.5rem", marginTop: "1rem" }}>
          <button className="btn" type="submit" disabled={busy}>
            {t("config.saveNotify")}
          </button>
          <button
            className="btn secondary"
            type="button"
            disabled={busy}
            onClick={() => void onTestNotifyEmail()}
          >
            {t("config.testEmail")}
          </button>
        </div>
      </form>

      <form className="card" onSubmit={onSaveSIEM} style={{ maxWidth: 640 }}>
        <h2>{t("config.siemTitle")}</h2>
        <p className="muted">{t("config.siemLead")}</p>
        <label className="row" style={{ gap: "0.5rem", alignItems: "center" }}>
          <input
            type="checkbox"
            checked={siem.enabled}
            onChange={(e) => setSiem({ ...siem, enabled: e.target.checked })}
          />
          {t("config.siemEnable")}
        </label>
        <label>{t("config.siemTransport")}</label>
        <select
          value={siem.transport}
          onChange={(e) => setSiem({ ...siem, transport: e.target.value })}
        >
          <option value="off">{t("config.disabled")}</option>
          <option value="syslog_udp">Syslog UDP</option>
          <option value="syslog_tcp">Syslog TCP</option>
          <option value="webhook">HTTPS Webhook</option>
          <option value="kafka">Kafka</option>
          <option value="nats">NATS</option>
          <option value="opensearch">OpenSearch (_bulk)</option>
        </select>
        <label>{t("config.format")}</label>
        <select value={siem.format} onChange={(e) => setSiem({ ...siem, format: e.target.value })}>
          <option value="json">JSON</option>
          <option value="cef">CEF</option>
          <option value="ecs">ECS (OpenSearch)</option>
          <option value="leef">LEEF 2.0 (QRadar)</option>
        </select>
        {(siem.transport === "syslog_udp" || siem.transport === "syslog_tcp") && (
          <>
            <label>{t("config.siemSyslog")}</label>
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
              {t("config.authHeaderPlain", { set: siem.has_webhook_auth_header ? t("config.secretSet") : "" })}
            </label>
            <input
              type="password"
              value={webhookAuth}
              onChange={(e) => setWebhookAuth(e.target.value)}
              placeholder={t("config.siemAuthBearer")}
              autoComplete="off"
            />
          </>
        )}
        {siem.transport === "kafka" && (
          <>
            <label>{t("config.kafkaBrokers")}</label>
            <input
              value={siem.kafka_brokers || ""}
              onChange={(e) => setSiem({ ...siem, kafka_brokers: e.target.value })}
              placeholder="kafka:9092"
            />
            <label>Topic</label>
            <input
              value={siem.kafka_topic || "keeppam.audit"}
              onChange={(e) => setSiem({ ...siem, kafka_topic: e.target.value })}
            />
            <label>{t("config.kafkaSaslUser")}</label>
            <input
              value={siem.kafka_username || ""}
              onChange={(e) => setSiem({ ...siem, kafka_username: e.target.value })}
              autoComplete="off"
            />
            <label>
              {t("config.saslPasswordLeave", { set: siem.has_kafka_password ? t("config.secretSet") : "" })}
            </label>
            <input
              type="password"
              value={kafkaPassword}
              onChange={(e) => setKafkaPassword(e.target.value)}
              autoComplete="off"
            />
          </>
        )}
        {siem.transport === "nats" && (
          <>
            <label>NATS URL</label>
            <input
              value={siem.nats_url || ""}
              onChange={(e) => setSiem({ ...siem, nats_url: e.target.value })}
              placeholder="nats://nats:4222"
            />
            <label>Subject</label>
            <input
              value={siem.nats_subject || "keeppam.audit"}
              onChange={(e) => setSiem({ ...siem, nats_subject: e.target.value })}
            />
            <label>{t("config.tokenLeave", { set: siem.has_nats_token ? t("config.secretSet") : "" })}</label>
            <input
              type="password"
              value={natsToken}
              onChange={(e) => setNatsToken(e.target.value)}
              autoComplete="off"
            />
          </>
        )}
        {siem.transport === "opensearch" && (
          <>
            <label>OpenSearch URL (https://host:9200)</label>
            <input
              value={siem.opensearch_url || ""}
              onChange={(e) => setSiem({ ...siem, opensearch_url: e.target.value })}
              placeholder="https://opensearch.example.com:9200"
            />
            <label>Index</label>
            <input
              value={siem.opensearch_index || "keeppam-audit"}
              onChange={(e) => setSiem({ ...siem, opensearch_index: e.target.value })}
              placeholder="keeppam-audit"
            />
            <label>
              {t("config.authHeaderPlain", { set: siem.has_webhook_auth_header ? t("config.secretSet") : "" })}
            </label>
            <input
              type="password"
              value={webhookAuth}
              onChange={(e) => setWebhookAuth(e.target.value)}
              placeholder={t("config.siemAuthApiKey")}
              autoComplete="off"
            />
            <p className="muted">{t("config.opensearchStand")}</p>
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
            <label>{t("config.scimPollInterval")}</label>
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
            {t("config.cursorLabel", { ts: siem.cursor_ts ? new Date(siem.cursor_ts).toLocaleString() : "—" })}
            {siem.last_export_at
              ? t("config.lastExport", { ts: new Date(siem.last_export_at).toLocaleString() })
              : ""}
            {siem.last_error ? (
              <>
                <br />
                <span className="error">{t("config.errorPrefix", { err: siem.last_error })}</span>
              </>
            ) : null}
          </p>
        )}
        <div className="row" style={{ gap: "0.75rem", marginTop: "1rem" }}>
          <button className="btn" type="submit" disabled={busy}>
            {t("config.saveSiem")}
          </button>
          <button
            className="btn secondary"
            type="button"
            disabled={busy}
            onClick={() =>
              void api.downloadSIEMBulk(200).catch((err) =>
                setError(err instanceof Error ? err.message : t("config.ecsBulkFailed")),
              )
            }
          >
            {t("config.downloadEcsBulk")}
          </button>
        </div>
      </form>
    </div>
  );
}

function formatGroupRoleMap(m?: Record<string, string>) {
  return Object.entries(m || {})
    .map(([k, v]) => `${k}=${v}`)
    .join("\n");
}

function parseGroupRoleMap(text: string) {
  const out: Record<string, string> = {};
  for (const line of text.split("\n")) {
    const t = line.trim();
    if (!t || t.startsWith("#")) continue;
    const i = t.indexOf("=");
    if (i <= 0) continue;
    const k = t.slice(0, i).trim();
    const v = t.slice(i + 1).trim();
    if (k && v) out[k] = v;
  }
  return out;
}
