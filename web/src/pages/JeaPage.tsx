import { useEffect, useMemo, useState, type FormEvent } from "react";
import { api, hasPerm, type AccessBinding, type AccessPolicy, type AppObjectPack, type AppObjectPreview, type CommandPolicyPack, type CommandPreview, type HTTPPolicyPack, type PamGroup, type Role, type SQLPolicyPack, type User } from "../api";
import { useAuth } from "../auth";
import { useI18n } from "../i18n";

const emptyPolicyForm = {
  name: "",
  description: "",
  time_start: "",
  time_end: "",
  days_of_week: 127,
  required_tags: "",
  require_ticket: false,
  require_reason: false,
  allowed_cidrs: "",
  allowed_countries: "",
  allowed_devices: "",
  allowed_namespaces: "",
  allowed_egress: "",
  pii_action: "",
  nlp_dlp_action: "",
  file_transfer: "deny",
	ocr_lang: "rus+eng",
  ocr_interval_sec: "15",
  ocr_max_frames: "60",
  ocr_every_frame: false,
  ocr_live: true,
  ocr_ssh_stdout: true,
  rdp_clipboard: false,
  rdp_drive: false,
  rdp_printer: false,
  rdp_native: true,
  dlp_patterns: "",
  dlp_classifiers: "",
  command_policy_pack_id: "",
  sql_policy_pack_id: "",
  http_policy_pack_id: "",
  app_object_pack_id: "",
  max_risk: "0",
  risk_action: "deny",
};

function formatDlpClassifiers(classifiers?: { name: string; keywords: string; min_hits?: number }[]): string {
  if (!classifiers?.length) return "";
  return classifiers
    .map((c) => {
      const hits = c.min_hits && c.min_hits > 1 ? ` min=${c.min_hits}` : "";
      return `${c.name}${hits} ${c.keywords.replace(/\n/g, " | ")}`;
    })
    .join("\n");
}

function parseDlpClassifiers(text: string): { name: string; keywords: string; min_hits?: number }[] {
  const out: { name: string; keywords: string; min_hits?: number }[] = [];
  for (const line of text.split("\n")) {
    const t = line.trim();
    if (!t || t.startsWith("#")) continue;
    let rest = t;
    let minHits = 1;
    const minIdx = rest.indexOf(" min=");
    if (minIdx > 0) {
      const tail = rest.slice(minIdx + 5).trim();
      const sp = tail.indexOf(" ");
      const num = sp > 0 ? tail.slice(0, sp) : tail;
      minHits = Number(num) || 1;
      rest = rest.slice(0, minIdx) + (sp > 0 ? " " + tail.slice(sp + 1) : "");
    }
    const sp = rest.indexOf(" ");
    if (sp <= 0) continue;
    out.push({
      name: rest.slice(0, sp).trim(),
      keywords: rest.slice(sp + 1).trim().replace(/\s*\|\s*/g, "\n"),
      min_hits: minHits,
    });
  }
  return out;
}

function parseDlpPatterns(text: string): { name: string; pattern: string }[] {
  const out: { name: string; pattern: string }[] = [];
  for (const line of text.split("\n")) {
    const t = line.trim();
    if (!t || t.startsWith("#")) continue;
    const sp = t.indexOf(" ");
    if (sp <= 0) continue;
    out.push({ name: t.slice(0, sp).trim(), pattern: t.slice(sp + 1).trim() });
  }
  return out;
}

function formatDlpPatterns(patterns?: { name: string; pattern: string }[]): string {
  return (patterns || []).map((p) => `${p.name} ${p.pattern}`).join("\n");
}

/** Client-side parse for new packs (server ParsePatternList for existing). */
function parseJeaImportText(text: string, filename: string): string[] {
  const name = filename.toLowerCase();
  const trim = text.trim();
  if (!trim) return [];
  if (name.endsWith(".json") || trim.startsWith("{") || trim.startsWith("[")) {
    try {
      const j = JSON.parse(trim);
      const arr: string[] = Array.isArray(j)
        ? j
        : j.patterns || j.commands || j.list || [];
      return [...new Set(arr.map((x) => String(x).trim()).filter(Boolean))];
    } catch {
      return [];
    }
  }
  const lines = trim.split(/\r?\n/);
  const out: string[] = [];
  let start = 0;
  if (name.endsWith(".csv") || (lines[0]?.includes(",") && /pattern|command|glob/i.test(lines[0] || ""))) {
    const header = (lines[0] || "").split(",").map((x) => x.trim().toLowerCase());
    let col = 0;
    const idx = header.findIndex((h) => h === "pattern" || h === "command" || h === "cmd" || h === "glob");
    if (idx >= 0) {
      col = idx;
      start = 1;
    }
    for (const line of lines.slice(start)) {
      if (!line.trim() || line.trim().startsWith("#")) continue;
      const cells = line.split(",");
      const p = (cells[col] || "").trim();
      if (p) out.push(p);
    }
    return [...new Set(out)];
  }
  for (const line of lines) {
    const p = line.trim();
    if (!p || p.startsWith("#")) continue;
    out.push(p);
  }
  return [...new Set(out)];
}

function splitCSV(s: string): string[] {
  return s
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean);
}

const emptyTagForm = {
  who: "group" as "user" | "role" | "group",
  user_id: "",
  role_id: "",
  group_id: "",
  asset_match_tags: "",
  asset_match_mode: "all" as "all" | "any",
  asset_match_name: "",
  asset_match_hostname: "",
  asset_match_types: "",
  asset_match_cidrs: "",
  access_policy_id: "",
  duration_minutes: "",
};

export function JeaPage() {
  const { user } = useAuth();
  const { t, te } = useI18n();
  const dayLabels = useMemo(
    () => [t("cal.0"), t("cal.1"), t("cal.2"), t("cal.3"), t("cal.4"), t("cal.5"), t("cal.6")],
    [t],
  );
  const canWrite = hasPerm(user, "jea.write");
  const canACL = hasPerm(user, "assets.acl");
  const canSeeACL = hasPerm(user, "assets.read");
  const [tab, setTab] = useState<"ssh" | "sql" | "http" | "objects" | "policy" | "tags">("ssh");
  const [packs, setPacks] = useState<CommandPolicyPack[]>([]);
  const [sqlPacks, setSqlPacks] = useState<SQLPolicyPack[]>([]);
  const [httpPacks, setHttpPacks] = useState<HTTPPolicyPack[]>([]);
  const [appPacks, setAppPacks] = useState<AppObjectPack[]>([]);
  const [policies, setPolicies] = useState<AccessPolicy[]>([]);
  const [error, setError] = useState("");
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState(false);
  const [editId, setEditId] = useState<string | null>(null);
  const [form, setForm] = useState({
    name: "",
    description: "",
    mode: "allowlist",
    patterns: "",
  });
  const [sqlEditId, setSqlEditId] = useState<string | null>(null);
  const [sqlForm, setSqlForm] = useState({
    name: "",
    description: "",
    mode: "allowlist",
    statements: "SELECT",
    tables: "",
    mask_columns: "",
    mask_replacement: "***",
    max_rows: "500",
    dlp_action: "truncate",
  });
  const [httpEditId, setHttpEditId] = useState<string | null>(null);
  const [httpForm, setHttpForm] = useState({
    name: "",
    description: "",
    mode: "allowlist",
    rules: "GET *\nHEAD *\nOPTIONS *",
  });
  const defaultAppRules =
    "GET /api/customers/export customer.export approval\nGET /api/customers* customer.view allow\nPOST /api/customers customer.create allow\nPUT /api/customers/* customer.update allow\nPATCH /api/customers/* customer.update allow\nDELETE /api/customers/* customer.delete deny\n* /admin* admin.panel deny";
  const [appEditId, setAppEditId] = useState<string | null>(null);
  const [appForm, setAppForm] = useState({
    name: "",
    description: "",
    unmatched: "deny",
    rules: defaultAppRules,
  });
  const [tryAppMethod, setTryAppMethod] = useState("GET");
  const [tryAppPath, setTryAppPath] = useState("/api/customers/1");
  const [tryAppPack, setTryAppPack] = useState("");
  const [tryAppQuery, setTryAppQuery] = useState("");
  const [tryAppOut, setTryAppOut] = useState<AppObjectPreview | null>(null);
  const [policyEditId, setPolicyEditId] = useState<string | null>(null);
  const [policyForm, setPolicyForm] = useState({ ...emptyPolicyForm });
  const [tryCmd, setTryCmd] = useState("sudo ls -la");
  const [tryPack, setTryPack] = useState("");
  const [tryOut, setTryOut] = useState<CommandPreview | null>(null);
  const [aiPrompt, setAiPrompt] = useState("DBA SSH на *db* пн–пт 9-18, без rm/dd");
  const [aiDraft, setAiDraft] = useState<string>("");
  const [tagBindings, setTagBindings] = useState<AccessBinding[]>([]);
  const [tagUsers, setTagUsers] = useState<User[]>([]);
  const [tagRoles, setTagRoles] = useState<Role[]>([]);
  const [tagGroups, setTagGroups] = useState<PamGroup[]>([]);
  const [tagForm, setTagForm] = useState({ ...emptyTagForm });
  const [tagEditId, setTagEditId] = useState<string | null>(null);
  const [tagRaw, setTagRaw] = useState<AccessBinding | null>(null);
  const [tagPermanent, setTagPermanent] = useState(false);

  async function load() {
    setError("");
    try {
      const [cmd, sql, http, app, pol] = await Promise.all([
        api.listCommandPacks(),
        api.listSQLPacks(),
        api.listHTTPPacks(),
        api.listAppObjectPacks(),
        api.listAccessPolicies(),
      ]);
      setPacks(cmd.packs || []);
      setSqlPacks(sql.packs || []);
      setHttpPacks(http.packs || []);
      setAppPacks(app.packs || []);
      setPolicies(pol.policies || []);
      if (canSeeACL) {
        try {
          const tb = await api.listTagACL();
          setTagBindings(tb.bindings || []);
        } catch {
          setTagBindings([]);
        }
        try {
          const [u, r, g] = await Promise.all([api.listUsers(), api.listRoles(), api.listGroups()]);
          setTagUsers(u.users || []);
          setTagRoles(r.roles || []);
          setTagGroups(g.groups || []);
        } catch {
          /* form without directory lookups */
        }
      }
    } catch (err) {
      setError(te(err, "jea.loadFailed"));
    }
  }

  useEffect(() => {
    if (!canWrite) return;
    void load();
  }, [canWrite]);

  if (!canWrite) {
    return <p className="error">{t("jea.forbidden")}</p>;
  }

  function startEdit(p: CommandPolicyPack) {
    setEditId(p.id);
    setForm({
      name: p.name,
      description: p.description || "",
      mode: p.mode || "allowlist",
      patterns: (p.patterns || []).join("\n"),
    });
    setMsg("");
  }

  function resetForm() {
    setEditId(null);
    setForm({ name: "", description: "", mode: "allowlist", patterns: "" });
  }

  async function tryCommand(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      const out = await api.previewCommand({
        command: tryCmd,
        pack_id: tryPack || undefined,
      });
      setTryOut(out);
    } catch (err) {
      setError(te(err, "jea.previewFailed"));
    } finally {
      setBusy(false);
    }
  }

  function startSqlEdit(p: SQLPolicyPack) {
    setSqlEditId(p.id);
    setSqlForm({
      name: p.name,
      description: p.description || "",
      mode: p.mode || "allowlist",
      statements: (p.statements || []).join("\n"),
      tables: (p.tables || []).join("\n"),
      mask_columns: (p.mask_columns || []).join("\n"),
      mask_replacement: p.mask_replacement || "***",
      max_rows: String(p.max_rows || 500),
      dlp_action: p.dlp_action || "truncate",
    });
    setMsg("");
  }

  function resetSqlForm() {
    setSqlEditId(null);
    setSqlForm({
      name: "",
      description: "",
      mode: "allowlist",
      statements: "SELECT",
      tables: "",
      mask_columns: "",
      mask_replacement: "***",
      max_rows: "500",
      dlp_action: "truncate",
    });
  }

  function startHttpEdit(p: HTTPPolicyPack) {
    setHttpEditId(p.id);
    setHttpForm({
      name: p.name,
      description: p.description || "",
      mode: p.mode || "allowlist",
      rules: (p.rules || []).join("\n"),
    });
    setMsg("");
  }

  function resetHttpForm() {
    setHttpEditId(null);
    setHttpForm({
      name: "",
      description: "",
      mode: "allowlist",
      rules: "GET *\nHEAD *\nOPTIONS *",
    });
  }

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    if (!canWrite) return;
    setBusy(true);
    setError("");
    setMsg("");
    try {
      const patterns = form.patterns
        .split(/[\n,]/)
        .map((x) => x.trim())
        .filter(Boolean);
      const body = {
        name: form.name.trim(),
        description: form.description.trim(),
        mode: form.mode,
        patterns,
      };
      if (editId) {
        await api.updateCommandPack(editId, body);
        setMsg(t("jea.sshPackUpdated"));
      } else {
        await api.createCommandPack(body);
        setMsg(t("jea.sshPackCreated"));
      }
      resetForm();
      await load();
    } catch (err) {
      setError(te(err, "jea.saveFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function onSqlSubmit(e: FormEvent) {
    e.preventDefault();
    if (!canWrite) return;
    setBusy(true);
    setError("");
    setMsg("");
    try {
      const body = {
        name: sqlForm.name.trim(),
        description: sqlForm.description.trim(),
        mode: sqlForm.mode,
        statements: sqlForm.statements
          .split(/[\n,]/)
          .map((x) => x.trim().toUpperCase())
          .filter(Boolean),
        tables: sqlForm.tables
          .split(/[\n,]/)
          .map((x) => x.trim())
          .filter(Boolean),
        mask_columns: sqlForm.mask_columns
          .split(/[\n,]/)
          .map((x) => x.trim())
          .filter(Boolean),
        mask_replacement: sqlForm.mask_replacement.trim() || "***",
        max_rows: Number(sqlForm.max_rows) || 500,
        dlp_action: sqlForm.dlp_action,
      };
      if (sqlEditId) {
        await api.updateSQLPack(sqlEditId, body);
        setMsg(t("jea.sqlPackUpdated"));
      } else {
        await api.createSQLPack(body);
        setMsg(t("jea.sqlPackCreated"));
      }
      resetSqlForm();
      await load();
    } catch (err) {
      setError(te(err, "jea.saveFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function onDelete(p: CommandPolicyPack) {
    if (!canWrite) return;
    if (!confirm(t("jea.deleteSshPackConfirm", { name: p.name }))) return;
    setBusy(true);
    try {
      await api.deleteCommandPack(p.id);
      setMsg(t("jea.deleted"));
      if (editId === p.id) resetForm();
      await load();
    } catch (err) {
      setError(te(err, "jea.deleteFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function onSqlDelete(p: SQLPolicyPack) {
    if (!canWrite) return;
    if (!confirm(t("jea.deleteSqlPackConfirm", { name: p.name }))) return;
    setBusy(true);
    try {
      await api.deleteSQLPack(p.id);
      setMsg(t("jea.deleted"));
      if (sqlEditId === p.id) resetSqlForm();
      await load();
    } catch (err) {
      setError(te(err, "jea.deleteFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function onHttpSubmit(e: FormEvent) {
    e.preventDefault();
    if (!canWrite) return;
    setBusy(true);
    setError("");
    setMsg("");
    try {
      const body = {
        name: httpForm.name.trim(),
        description: httpForm.description.trim(),
        mode: httpForm.mode,
        rules: httpForm.rules
          .split(/[\n,]/)
          .map((x) => x.trim())
          .filter(Boolean),
      };
      if (httpEditId) {
        await api.updateHTTPPack(httpEditId, body);
        setMsg(t("jea.httpPackUpdated"));
      } else {
        await api.createHTTPPack(body);
        setMsg(t("jea.httpPackCreated"));
      }
      resetHttpForm();
      await load();
    } catch (err) {
      setError(te(err, "jea.saveFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function onHttpDelete(p: HTTPPolicyPack) {
    if (!canWrite) return;
    if (!confirm(t("jea.deleteHttpPackConfirm", { name: p.name }))) return;
    setBusy(true);
    try {
      await api.deleteHTTPPack(p.id);
      setMsg(t("jea.deleted"));
      if (httpEditId === p.id) resetHttpForm();
      await load();
    } catch (err) {
      setError(te(err, "jea.deleteFailed"));
    } finally {
      setBusy(false);
    }
  }

  function startAppEdit(p: AppObjectPack) {
    setAppEditId(p.id);
    setAppForm({
      name: p.name,
      description: p.description || "",
      unmatched: p.unmatched || "allow",
      rules: (p.rules || []).join("\n"),
    });
    setMsg("");
  }

  function resetAppForm() {
    setAppEditId(null);
    setAppForm({
      name: "",
      description: "",
      unmatched: "deny",
      rules: defaultAppRules,
    });
  }

  async function onAppSubmit(e: FormEvent) {
    e.preventDefault();
    if (!canWrite) return;
    setBusy(true);
    setError("");
    setMsg("");
    try {
      const body = {
        name: appForm.name.trim(),
        description: appForm.description.trim(),
        unmatched: appForm.unmatched,
        rules: appForm.rules
          .split("\n")
          .map((x) => x.trim())
          .filter(Boolean),
      };
      if (appEditId) {
        await api.updateAppObjectPack(appEditId, body);
        setMsg(t("jea.appPackUpdated"));
      } else {
        await api.createAppObjectPack(body);
        setMsg(t("jea.appPackCreated"));
      }
      resetAppForm();
      await load();
    } catch (err) {
      setError(te(err, "jea.saveFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function onAppDelete(p: AppObjectPack) {
    if (!canWrite) return;
    if (!confirm(t("jea.deleteAppPackConfirm", { name: p.name }))) return;
    setBusy(true);
    try {
      await api.deleteAppObjectPack(p.id);
      setMsg(t("jea.deleted"));
      if (appEditId === p.id) resetAppForm();
      await load();
    } catch (err) {
      setError(te(err, "jea.deleteFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function tryAppObject(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      const out = await api.previewAppObject({
        method: tryAppMethod,
        path: tryAppPath,
        pack_id: tryAppPack || undefined,
        query: tryAppQuery.trim() || undefined,
      });
      setTryAppOut(out);
    } catch (err) {
      setError(te(err, "jea.previewFailed"));
    } finally {
      setBusy(false);
    }
  }

  function startPolicyEdit(p: AccessPolicy) {
    setPolicyEditId(p.id);
    setPolicyForm({
      name: p.name,
      description: p.description || "",
      time_start: p.time_start || "",
      time_end: p.time_end || "",
      days_of_week: p.days_of_week ?? 127,
      required_tags: (p.required_tags || []).join(", "),
      require_ticket: !!p.require_ticket,
      require_reason: !!p.require_reason,
      allowed_cidrs: (p.allowed_cidrs || []).join(", "),
      allowed_countries: (p.allowed_countries || []).join(", "),
      allowed_devices: (p.allowed_devices || []).join(", "),
      allowed_namespaces: (p.allowed_namespaces || []).join(", "),
      allowed_egress: (p.allowed_egress || []).join(", "),
      pii_action: p.pii_action || "",
      nlp_dlp_action: p.nlp_dlp_action || "",
      file_transfer: p.file_transfer || "deny",
      ocr_lang: p.ocr_lang || "rus+eng",
      ocr_interval_sec: String(p.ocr_interval_sec || 15),
      ocr_max_frames: String(p.ocr_max_frames || 60),
      ocr_every_frame: !!p.ocr_every_frame,
      ocr_live: !!p.ocr_live,
      ocr_ssh_stdout: p.ocr_ssh_stdout !== false,
      rdp_clipboard: !!p.rdp_clipboard,
      rdp_drive: !!p.rdp_drive,
      rdp_printer: !!p.rdp_printer,
      rdp_native: !!p.rdp_native,
      dlp_patterns: formatDlpPatterns(p.dlp_patterns),
      dlp_classifiers: formatDlpClassifiers(p.dlp_classifiers),
      command_policy_pack_id: p.command_policy_pack_id || "",
      sql_policy_pack_id: p.sql_policy_pack_id || "",
      http_policy_pack_id: p.http_policy_pack_id || "",
      app_object_pack_id: p.app_object_pack_id || "",
      max_risk: String(p.max_risk ?? 0),
      risk_action: p.risk_action || "deny",
    });
    setMsg("");
  }

  function resetPolicyForm() {
    setPolicyEditId(null);
    setPolicyForm({ ...emptyPolicyForm });
  }

  function togglePolicyDay(bit: number) {
    setPolicyForm((f) => ({
      ...f,
      days_of_week: f.days_of_week & bit ? f.days_of_week & ~bit : f.days_of_week | bit,
    }));
  }

  function formatDays(mask: number): string {
    if (mask === 127) return t("cal.allDays");
    return dayLabels.filter((_, i) => mask & (1 << i)).join(", ") || t("config.dash");
  }

  function policySummary(p: AccessPolicy): string {
    const bits: string[] = [];
    if (p.time_start || p.time_end) bits.push(`${p.time_start || "00:00"}–${p.time_end || "24:00"}`);
    if (p.days_of_week !== 127) bits.push(formatDays(p.days_of_week));
    if ((p.allowed_cidrs || []).length) bits.push(p.allowed_cidrs.join(","));
    if ((p.allowed_countries || []).length) bits.push(p.allowed_countries.join(","));
    if ((p.allowed_devices || []).length) bits.push(p.allowed_devices.join(","));
    if ((p.allowed_namespaces || []).length) bits.push("ns:" + p.allowed_namespaces.join(","));
    if ((p.allowed_egress || []).length) bits.push("egress:" + p.allowed_egress.join(","));
    if (p.pii_action) bits.push("pii:" + p.pii_action);
    if (p.nlp_dlp_action) bits.push("nlp:" + p.nlp_dlp_action);
    if (p.file_transfer && p.file_transfer !== "deny") bits.push("files:" + p.file_transfer);
    if (p.ocr_lang) {
      bits.push(
        "ocr:" +
          p.ocr_lang +
          (p.ocr_every_frame ? "/every" : "/" + (p.ocr_interval_sec || 15) + "s") +
          (p.ocr_live ? "+live" : "") +
          (p.ocr_ssh_stdout !== false ? "+ssh" : ""),
      );
    }
    if (p.rdp_clipboard || p.rdp_drive || p.rdp_printer) {
      const r: string[] = [];
      if (p.rdp_clipboard) r.push("clip");
      if (p.rdp_drive) r.push("drive");
      if (p.rdp_printer) r.push("print");
      bits.push("rdp:" + r.join("+"));
    }
    if (p.rdp_native) bits.push("mstsc");
    if ((p.dlp_patterns || []).length) bits.push(`dlp:${(p.dlp_patterns || []).length}`);
    if ((p.dlp_classifiers || []).length) bits.push(`nlp+:${(p.dlp_classifiers || []).length}`);
    if (p.require_ticket) bits.push("ticket");
    if (p.require_reason) bits.push("reason");
    if (p.command_policy_pack_name) bits.push(`ssh:${p.command_policy_pack_name}`);
    if (p.sql_policy_pack_name) bits.push(`sql:${p.sql_policy_pack_name}`);
    if (p.http_policy_pack_name) bits.push(`http:${p.http_policy_pack_name}`);
    if (p.app_object_pack_name) bits.push(`obj:${p.app_object_pack_name}`);
    if (p.max_risk) bits.push(`risk≤${p.max_risk}`);
    return bits.length ? bits.join(" · ") : t("jea.noRestrictionsTemplate");
  }

  async function onPolicySubmit(e: FormEvent) {
    e.preventDefault();
    if (!canWrite) return;
    setBusy(true);
    setError("");
    setMsg("");
    try {
      const body: Parameters<typeof api.createAccessPolicy>[0] = {
        name: policyForm.name.trim(),
        description: policyForm.description.trim(),
        days_of_week: policyForm.days_of_week,
        require_ticket: policyForm.require_ticket,
        require_reason: policyForm.require_reason,
        required_tags: splitCSV(policyForm.required_tags),
        allowed_cidrs: splitCSV(policyForm.allowed_cidrs),
        allowed_countries: splitCSV(policyForm.allowed_countries),
        allowed_devices: splitCSV(policyForm.allowed_devices),
        allowed_namespaces: splitCSV(policyForm.allowed_namespaces),
        allowed_egress: splitCSV(policyForm.allowed_egress),
        pii_action: policyForm.pii_action || "",
        nlp_dlp_action: policyForm.nlp_dlp_action || "",
        file_transfer: policyForm.file_transfer || "deny",
        ocr_lang: policyForm.ocr_lang || "rus+eng",
        ocr_interval_sec: Number(policyForm.ocr_interval_sec) || 15,
        ocr_max_frames: Number(policyForm.ocr_max_frames) || 60,
        ocr_every_frame: !!policyForm.ocr_every_frame,
        ocr_live: !!policyForm.ocr_live,
        ocr_ssh_stdout: !!policyForm.ocr_ssh_stdout,
        rdp_clipboard: !!policyForm.rdp_clipboard,
        rdp_drive: !!policyForm.rdp_drive,
        rdp_printer: !!policyForm.rdp_printer,
        rdp_native: !!policyForm.rdp_native,
        dlp_patterns: parseDlpPatterns(policyForm.dlp_patterns),
        dlp_classifiers: parseDlpClassifiers(policyForm.dlp_classifiers),
        max_risk: Number(policyForm.max_risk) || 0,
        risk_action: policyForm.risk_action,
      };
      if (policyForm.time_start) body.time_start = policyForm.time_start;
      else if (policyEditId) body.time_start = "";
      if (policyForm.time_end) body.time_end = policyForm.time_end;
      else if (policyEditId) body.time_end = "";
      if (policyForm.command_policy_pack_id) body.command_policy_pack_id = policyForm.command_policy_pack_id;
      if (policyForm.sql_policy_pack_id) body.sql_policy_pack_id = policyForm.sql_policy_pack_id;
      if (policyForm.http_policy_pack_id) body.http_policy_pack_id = policyForm.http_policy_pack_id;
      if (policyForm.app_object_pack_id) body.app_object_pack_id = policyForm.app_object_pack_id;
      if (policyEditId) {
        await api.updateAccessPolicy(policyEditId, body);
        setMsg(t("jea.policyUpdated"));
      } else {
        await api.createAccessPolicy(body);
        setMsg(t("jea.policyCreated"));
      }
      resetPolicyForm();
      await load();
    } catch (err) {
      setError(te(err, "jea.saveFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function onPolicyDelete(p: AccessPolicy) {
    if (!canWrite) return;
    if (!confirm(t("jea.deletePolicyConfirm", { name: p.name }))) return;
    setBusy(true);
    try {
      await api.deleteAccessPolicy(p.id);
      setMsg(t("jea.deletedShort"));
      if (policyEditId === p.id) resetPolicyForm();
      await load();
    } catch (err) {
      setError(te(err, "jea.deleteFailed"));
    } finally {
      setBusy(false);
    }
  }

  function resetTagForm() {
    setTagEditId(null);
    setTagRaw(null);
    setTagPermanent(false);
    setTagForm({
      ...emptyTagForm,
      who: tagForm.who,
      asset_match_tags: tagForm.asset_match_tags,
      asset_match_mode: tagForm.asset_match_mode,
      asset_match_name: tagForm.asset_match_name,
      asset_match_hostname: tagForm.asset_match_hostname,
      asset_match_types: tagForm.asset_match_types,
      asset_match_cidrs: tagForm.asset_match_cidrs,
    });
  }

  async function startTagEdit(b: AccessBinding) {
    if (!canACL) return;
    setError("");
    try {
      const raw = await api.getACL("_", b.id);
      setTagEditId(raw.id);
      setTagRaw(raw);
      setTagPermanent(!raw.expires_at);
      setTagForm({
        who: raw.user_id ? "user" : raw.group_id ? "group" : "role",
        user_id: raw.user_id || "",
        role_id: raw.role_id || "",
        group_id: raw.group_id || "",
        asset_match_tags: (raw.asset_match_tags || []).join(", "),
        asset_match_mode: raw.asset_match_mode === "any" ? "any" : "all",
        asset_match_name: raw.asset_match_name || "",
        asset_match_hostname: raw.asset_match_hostname || "",
        asset_match_types: (raw.asset_match_types || []).join(", "),
        asset_match_cidrs: (raw.asset_match_cidrs || []).join(", "),
        access_policy_id: raw.access_policy_id || "",
        duration_minutes: "",
      });
      setMsg("");
    } catch (err) {
      setError(err instanceof Error ? err.message : t("jea.tagAclLoadFailed"));
    }
  }

  async function onTagSubmit(e: FormEvent) {
    e.preventDefault();
    if (!canACL) return;
    const tags = splitCSV(tagForm.asset_match_tags);
    const types = splitCSV(tagForm.asset_match_types);
    const matchCidrs = splitCSV(tagForm.asset_match_cidrs);
    if (
      !tags.length &&
      !tagForm.asset_match_name.trim() &&
      !tagForm.asset_match_hostname.trim() &&
      !types.length &&
      !matchCidrs.length
    ) {
      setError(t("jea.tagAclValidation"));
      return;
    }
    setBusy(true);
    setError("");
    setMsg("");
    try {
      if (tagEditId && tagRaw) {
        const body: Parameters<typeof api.updateACL>[2] = {
          time_start: tagRaw.time_start || "",
          time_end: tagRaw.time_end || "",
          days_of_week: tagRaw.days_of_week,
          required_tags: tagRaw.required_tags || [],
          require_ticket: !!tagRaw.require_ticket,
          require_reason: !!tagRaw.require_reason,
          allowed_cidrs: tagRaw.allowed_cidrs || [],
          allowed_countries: tagRaw.allowed_countries || [],
          allowed_devices: tagRaw.allowed_devices || [],
          allowed_namespaces: tagRaw.allowed_namespaces || [],
          allowed_egress: tagRaw.allowed_egress || [],
          pii_action: tagRaw.pii_action || "",
          file_transfer: tagRaw.file_transfer || "",
          command_policy_pack_id: tagRaw.command_policy_pack_id || null,
          sql_policy_pack_id: tagRaw.sql_policy_pack_id || null,
          http_policy_pack_id: tagRaw.http_policy_pack_id || null,
          app_object_pack_id: tagRaw.app_object_pack_id || null,
          max_risk: tagRaw.max_risk || 0,
          risk_action: tagRaw.risk_action || "deny",
          asset_match_tags: tags,
          asset_match_mode: tagForm.asset_match_mode,
          asset_match_name: tagForm.asset_match_name.trim(),
          asset_match_hostname: tagForm.asset_match_hostname.trim(),
          asset_match_types: types,
          asset_match_cidrs: matchCidrs,
          access_policy_id: tagForm.access_policy_id || null,
        };
        if (tagPermanent) body.permanent = true;
        else if (tagForm.duration_minutes) body.duration_minutes = Number(tagForm.duration_minutes);
        await api.updateACL("_", tagEditId, body);
        setMsg(t("jea.tagAclUpdated"));
        resetTagForm();
      } else {
        const body: Parameters<typeof api.createTagACL>[0] = {
          asset_match_tags: tags,
          asset_match_mode: tagForm.asset_match_mode,
          asset_match_name: tagForm.asset_match_name.trim() || undefined,
          asset_match_hostname: tagForm.asset_match_hostname.trim() || undefined,
          asset_match_types: types.length ? types : undefined,
          asset_match_cidrs: matchCidrs.length ? matchCidrs : undefined,
        };
        if (tagForm.who === "user" && tagForm.user_id) body.user_id = tagForm.user_id;
        else if (tagForm.who === "role" && tagForm.role_id) body.role_id = tagForm.role_id;
        else if (tagForm.who === "group" && tagForm.group_id) body.group_id = tagForm.group_id;
        else {
          setError(t("jea.selectSubject"));
          setBusy(false);
          return;
        }
        if (tagForm.access_policy_id) body.access_policy_id = tagForm.access_policy_id;
        if (tagForm.duration_minutes) body.duration_minutes = Number(tagForm.duration_minutes);
        await api.createTagACL(body);
        setMsg(t("jea.tagAclDynamicCreated"));
        setTagForm({
          who: tagForm.who,
          user_id: "",
          role_id: "",
          group_id: "",
          asset_match_tags: tagForm.asset_match_tags,
          asset_match_mode: tagForm.asset_match_mode,
          asset_match_name: tagForm.asset_match_name,
          asset_match_hostname: tagForm.asset_match_hostname,
          asset_match_types: tagForm.asset_match_types,
          asset_match_cidrs: tagForm.asset_match_cidrs,
          access_policy_id: "",
          duration_minutes: "",
        });
      }
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : t("jea.tagAclError"));
    } finally {
      setBusy(false);
    }
  }

  async function onDeleteTagACL(b: AccessBinding) {
    if (!canACL) return;
    if (!confirm(t("jea.revokeTagAclConfirm"))) return;
    setBusy(true);
    try {
      await api.deleteACL("_", b.id);
      setMsg(t("jea.revoked"));
      if (tagEditId === b.id) resetTagForm();
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : t("jea.revokeFailed"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <h1>{t("jea.title")}</h1>
      <p className="muted">
        {t("jea.lead")}
      </p>
      <div className="row" style={{ gap: "0.5rem", marginBottom: "1rem" }}>
        <button
          className={`btn ${tab === "ssh" ? "" : "secondary"}`}
          type="button"
          onClick={() => setTab("ssh")}
        >
          {t("jea.tabSsh")}
        </button>
        <button
          className={`btn ${tab === "sql" ? "" : "secondary"}`}
          type="button"
          onClick={() => setTab("sql")}
        >
          {t("jea.tabSql")}
        </button>
        <button
          className={`btn ${tab === "http" ? "" : "secondary"}`}
          type="button"
          onClick={() => setTab("http")}
        >
          {t("jea.tabHttp")}
        </button>
        <button
          className={`btn ${tab === "objects" ? "" : "secondary"}`}
          type="button"
          onClick={() => setTab("objects")}
        >
          {t("jea.tabObjects")}
        </button>
        <button
          className={`btn ${tab === "policy" ? "" : "secondary"}`}
          type="button"
          onClick={() => setTab("policy")}
        >
          Policy
        </button>
        <button
          className={`btn ${tab === "tags" ? "" : "secondary"}`}
          type="button"
          onClick={() => setTab("tags")}
        >
          {t("jea.tabTags")}
        </button>
      </div>
      {error && <p className="error">{error}</p>}
      {msg && <p className="ok">{msg}</p>}

      {tab === "ssh" && (
        <>
          <div className="card" style={{ marginBottom: "1.25rem" }}>
            <h2>{t("jea.sshPacksTitle")}</h2>
            <table>
              <thead>
                <tr>
                  <th>{t("common.name")}</th>
                  <th>{t("config.mode")}</th>
                  <th>{t("jea.patterns")}</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {packs.map((p) => (
                  <tr key={p.id}>
                    <td>
                      <span className="mono">{p.name}</span>
                      {p.description ? (
                        <div className="muted" style={{ fontSize: "0.85rem" }}>
                          {p.description}
                        </div>
                      ) : null}
                    </td>
                    <td className="mono">{p.mode}</td>
                    <td className="mono" style={{ fontSize: "0.8rem", maxWidth: 360 }}>
                      {(p.patterns || []).slice(0, 8).join(", ")}
                      {(p.patterns || []).length > 8 ? ` (+${(p.patterns || []).length - 8})` : ""}
                    </td>
                    <td>
                      {canWrite && (
                        <div className="row" style={{ gap: "0.4rem" }}>
                          <button className="btn secondary" type="button" onClick={() => startEdit(p)}>
                            {t("jea.edit")}
                          </button>
                          <button className="btn danger" type="button" disabled={busy} onClick={() => void onDelete(p)}>
                            {t("common.delete")}
                          </button>
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <form className="card" style={{ marginBottom: "1.25rem" }} onSubmit={(e) => void tryCommand(e)}>
            <h2>{t("jea.tryCommandTitle")}</h2>
            <p className="muted">
              {t("jea.tryCommandHint")}
            </p>
            <label>{t("jea.command")}</label>
            <input
              value={tryCmd}
              onChange={(e) => setTryCmd(e.target.value)}
              placeholder="sudo rm -rf /tmp/x"
              style={{ fontFamily: "ui-monospace, monospace", width: "100%" }}
            />
            <label>{t("jea.sshPackOptional")}</label>
            <select value={tryPack} onChange={(e) => setTryPack(e.target.value)}>
              <option value="">{t("jea.noPack")}</option>
              {packs.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name} ({p.mode})
                </option>
              ))}
            </select>
            <button className="btn" type="submit" disabled={busy || !tryCmd.trim()} style={{ marginTop: "0.75rem" }}>
              {t("jea.parse")}
            </button>
            {tryOut && (
              <div className="muted" style={{ marginTop: "0.75rem", fontSize: "0.9rem" }}>
                <p>
                  binary <span className="mono">{tryOut.parsed.binary || "—"}</span>
                  {tryOut.parsed.wrappers?.length ? (
                    <>
                      {" "}
                      · wrappers <span className="mono">{tryOut.parsed.wrappers.join(" → ")}</span>
                    </>
                  ) : null}
                  {tryOut.parsed.priv_shell ? " · priv shell" : null}
                  {tryOut.parsed.inner && tryOut.parsed.inner !== tryOut.parsed.raw ? (
                    <>
                      {" "}
                      · inner <span className="mono">{tryOut.parsed.inner}</span>
                    </>
                  ) : null}
                </p>
                <p>
                  {tryOut.dlp ? <span className="badge">DLP deny</span> : null}{" "}
                  {tryOut.jea_allowed == null ? null : tryOut.jea_allowed ? (
                    <span className="badge">JEA allow</span>
                  ) : (
                    <span className="badge">JEA deny</span>
                  )}{" "}
                  {tryOut.operation ? (
                    <>
                      {tryOut.operation} · {tryOut.points} pts
                    </>
                  ) : (
                    t("jea.noExtraRisk")
                  )}
                </p>
                <p>{tryOut.note}</p>
              </div>
            )}
          </form>
          <form
            className="card"
            style={{ marginBottom: "1.25rem" }}
            onSubmit={(e) => {
              e.preventDefault();
              setBusy(true);
              void api
                .jeaAIDraft(aiPrompt)
                .then((d) => setAiDraft(JSON.stringify(d, null, 2)))
                .catch((err) => setError(te(err, "jea.previewFailed")))
                .finally(() => setBusy(false));
            }}
          >
            <h2>{t("jea.aiDraft")}</h2>
            <p className="muted">{t("jea.aiDraftHint")}</p>
            <label>{t("jea.aiPrompt")}</label>
            <textarea value={aiPrompt} onChange={(e) => setAiPrompt(e.target.value)} rows={3} style={{ width: "100%" }} />
            <button className="btn" type="submit" disabled={busy || !aiPrompt.trim()} style={{ marginTop: "0.75rem" }}>
              {t("jea.aiDraftRun")}
            </button>
            {aiDraft ? (
              <pre className="mono" style={{ whiteSpace: "pre-wrap", fontSize: "0.8rem" }}>
                {aiDraft}
              </pre>
            ) : null}
          </form>
          {canWrite && (
            <form className="card" onSubmit={onSubmit} style={{ maxWidth: 560 }}>
              <h2>{editId ? t("jea.editSshPack") : t("jea.newSshPack")}</h2>
              <label>{t("common.name")}</label>
              <input
                required
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                disabled={!!editId}
              />
              <label>{t("common.description")}</label>
              <input
                value={form.description}
                onChange={(e) => setForm({ ...form, description: e.target.value })}
              />
              <label>{t("config.mode")}</label>
              <select value={form.mode} onChange={(e) => setForm({ ...form, mode: e.target.value })}>
                <option value="allowlist">allowlist</option>
                <option value="denylist">denylist</option>
              </select>
              <label>{t("jea.patterns")}</label>
              <textarea
                rows={8}
                value={form.patterns}
                onChange={(e) => setForm({ ...form, patterns: e.target.value })}
                style={{ fontFamily: "ui-monospace, monospace", width: "100%" }}
              />
              <label>{t("jea.importList")}</label>
              <input
                type="file"
                accept=".txt,.csv,.json,text/plain,text/csv,application/json"
                disabled={busy}
                onChange={async (e) => {
                  const file = e.target.files?.[0];
                  e.target.value = "";
                  if (!file || !canWrite) return;
                  setBusy(true);
                  setError("");
                  setMsg("");
                  try {
                    if (editId) {
                      const merge = confirm(
                        t("jea.mergePatternsConfirm")
                      );
                      const out = await api.importCommandPack(editId, file, merge);
                      setForm({
                        ...form,
                        patterns: (out.pack.patterns || []).join("\n"),
                        mode: out.pack.mode || form.mode,
                        name: out.pack.name || form.name,
                        description: out.pack.description || form.description,
                      });
                      setMsg(t("jea.importAdded", { added: out.added, total: out.total }));
                      await load();
                    } else {
                      const text = await file.text();
                      const parsed = parseJeaImportText(text, file.name);
                      if (!parsed.length) {
                        setError(t("jea.importNoPatterns"));
                        return;
                      }
                      const merge = form.patterns.trim()
                        ? confirm(t("jea.importMergeConfirm"))
                        : false;
                      const next = merge
                        ? `${form.patterns.trim()}\n${parsed.join("\n")}`.trim()
                        : parsed.join("\n");
                      setForm({ ...form, patterns: next });
                      setMsg(t("jea.loadedIntoForm", { n: parsed.length }));
                    }
                  } catch (err) {
                    setError(err instanceof Error ? err.message : t("jea.importFailed"));
                  } finally {
                    setBusy(false);
                  }
                }}
              />
              <p className="muted" style={{ marginTop: 0 }}>
                {t("jea.importHint")}
              </p>
              <div className="row" style={{ gap: "0.5rem" }}>
                <button className="btn" type="submit" disabled={busy}>
                  {editId ? t("common.save") : t("common.create")}
                </button>
                {editId && (
                  <button className="btn secondary" type="button" onClick={resetForm}>
                    {t("common.cancel")}
                  </button>
                )}
              </div>
            </form>
          )}
        </>
      )}

      {tab === "sql" && (
        <>
          <div className="card" style={{ marginBottom: "1.25rem" }}>
            <h2>{t("jea.sqlPacksTitle")}</h2>
            <p className="muted">{t("jea.sqlPackHint")}</p>
            <table>
              <thead>
                <tr>
                  <th>{t("common.name")}</th>
                  <th>{t("config.mode")}</th>
                  <th>Statements</th>
                  <th>Tables</th>
                  <th>Mask</th>
                  <th>DLP</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {sqlPacks.map((p) => (
                  <tr key={p.id}>
                    <td>
                      <span className="mono">{p.name}</span>
                      {p.description ? (
                        <div className="muted" style={{ fontSize: "0.85rem" }}>
                          {p.description}
                        </div>
                      ) : null}
                    </td>
                    <td className="mono">{p.mode}</td>
                    <td className="mono">{(p.statements || []).join(", ") || "—"}</td>
                    <td className="mono">{(p.tables || []).slice(0, 6).join(", ")}</td>
                    <td className="mono">{(p.mask_columns || []).join(", ") || "—"}</td>
                    <td className="mono">
                      {p.max_rows || 500}/{p.dlp_action || "truncate"}
                    </td>
                    <td>
                      {canWrite && (
                        <div className="row" style={{ gap: "0.4rem" }}>
                          <button className="btn secondary" type="button" onClick={() => startSqlEdit(p)}>
                            {t("jea.edit")}
                          </button>
                          <button
                            className="btn danger"
                            type="button"
                            disabled={busy}
                            onClick={() => void onSqlDelete(p)}
                          >
                            {t("common.delete")}
                          </button>
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {canWrite && (
            <form className="card" onSubmit={onSqlSubmit} style={{ maxWidth: 560 }}>
              <h2>{sqlEditId ? t("jea.editSqlPack") : t("jea.newSqlPack")}</h2>
              <label>{t("common.name")}</label>
              <input
                required
                value={sqlForm.name}
                onChange={(e) => setSqlForm({ ...sqlForm, name: e.target.value })}
                disabled={!!sqlEditId}
              />
              <label>{t("common.description")}</label>
              <input
                value={sqlForm.description}
                onChange={(e) => setSqlForm({ ...sqlForm, description: e.target.value })}
              />
              <label>{t("config.mode")}</label>
              <select value={sqlForm.mode} onChange={(e) => setSqlForm({ ...sqlForm, mode: e.target.value })}>
                <option value="allowlist">allowlist</option>
                <option value="denylist">denylist</option>
              </select>
              <label>Statements (SELECT, INSERT, DDL…)</label>
              <textarea
                rows={3}
                value={sqlForm.statements}
                onChange={(e) => setSqlForm({ ...sqlForm, statements: e.target.value })}
                style={{ fontFamily: "ui-monospace, monospace", width: "100%" }}
              />
              <label>{t("jea.tablesGlob")}</label>
              <textarea
                rows={4}
                value={sqlForm.tables}
                onChange={(e) => setSqlForm({ ...sqlForm, tables: e.target.value })}
                placeholder={"tickets\npublic.tickets"}
                style={{ fontFamily: "ui-monospace, monospace", width: "100%" }}
              />
              <label>Mask columns</label>
              <textarea
                rows={3}
                value={sqlForm.mask_columns}
                onChange={(e) => setSqlForm({ ...sqlForm, mask_columns: e.target.value })}
                placeholder={"amount\nssn"}
                style={{ fontFamily: "ui-monospace, monospace", width: "100%" }}
              />
              <label>Mask replacement</label>
              <input
                value={sqlForm.mask_replacement}
                onChange={(e) => setSqlForm({ ...sqlForm, mask_replacement: e.target.value })}
              />
              <label>Max rows (DLP)</label>
              <input
                type="number"
                min={1}
                max={100000}
                value={sqlForm.max_rows}
                onChange={(e) => setSqlForm({ ...sqlForm, max_rows: e.target.value })}
              />
              <label>{t("jea.maxRowsExceeded")}</label>
              <select
                value={sqlForm.dlp_action}
                onChange={(e) => setSqlForm({ ...sqlForm, dlp_action: e.target.value })}
              >
                <option value="truncate">{t("jea.onMaxRowsTruncate")}</option>
                <option value="deny">{t("jea.onMaxRowsDeny")}</option>
              </select>
              <div className="row" style={{ gap: "0.5rem" }}>
                <button className="btn" type="submit" disabled={busy}>
                  {sqlEditId ? t("common.save") : t("common.create")}
                </button>
                {sqlEditId && (
                  <button className="btn secondary" type="button" onClick={resetSqlForm}>
                    {t("common.cancel")}
                  </button>
                )}
              </div>
            </form>
          )}
        </>
      )}

      {tab === "http" && (
        <>
          <div className="card" style={{ marginBottom: "1.25rem" }}>
            <h2>{t("jea.httpPacksTitle")}</h2>
            <p className="muted">{t("jea.httpPackHint")}</p>
            <table>
              <thead>
                <tr>
                  <th>{t("common.name")}</th>
                  <th>{t("config.mode")}</th>
                  <th>{t("jea.rules")}</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {httpPacks.map((p) => (
                  <tr key={p.id}>
                    <td>
                      <span className="mono">{p.name}</span>
                      {p.description ? (
                        <div className="muted" style={{ fontSize: "0.85rem" }}>
                          {p.description}
                        </div>
                      ) : null}
                    </td>
                    <td className="mono">{p.mode}</td>
                    <td className="mono" style={{ fontSize: "0.8rem", maxWidth: 420 }}>
                      {(p.rules || []).slice(0, 8).join(", ")}
                      {(p.rules || []).length > 8 ? ` (+${(p.rules || []).length - 8})` : ""}
                    </td>
                    <td>
                      {canWrite && (
                        <div className="row" style={{ gap: "0.4rem" }}>
                          <button className="btn secondary" type="button" onClick={() => startHttpEdit(p)}>
                            {t("jea.edit")}
                          </button>
                          <button
                            className="btn danger"
                            type="button"
                            disabled={busy}
                            onClick={() => void onHttpDelete(p)}
                          >
                            {t("common.delete")}
                          </button>
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {canWrite && (
            <form className="card" onSubmit={onHttpSubmit} style={{ maxWidth: 560 }}>
              <h2>{httpEditId ? t("jea.editHttpPack") : t("jea.newHttpPack")}</h2>
              <label>{t("common.name")}</label>
              <input
                required
                value={httpForm.name}
                onChange={(e) => setHttpForm({ ...httpForm, name: e.target.value })}
                disabled={!!httpEditId}
              />
              <label>{t("common.description")}</label>
              <input
                value={httpForm.description}
                onChange={(e) => setHttpForm({ ...httpForm, description: e.target.value })}
              />
              <label>{t("config.mode")}</label>
              <select value={httpForm.mode} onChange={(e) => setHttpForm({ ...httpForm, mode: e.target.value })}>
                <option value="allowlist">allowlist</option>
                <option value="denylist">denylist</option>
              </select>
              <label>{t("jea.rulesPerLine")}</label>
              <textarea
                rows={8}
                value={httpForm.rules}
                onChange={(e) => setHttpForm({ ...httpForm, rules: e.target.value })}
                placeholder={"GET *\nPOST /api/tickets\nDELETE *"}
                style={{ fontFamily: "ui-monospace, monospace", width: "100%" }}
              />
              <div className="row" style={{ gap: "0.5rem" }}>
                <button className="btn" type="submit" disabled={busy}>
                  {httpEditId ? t("common.save") : t("common.create")}
                </button>
                {httpEditId && (
                  <button className="btn secondary" type="button" onClick={resetHttpForm}>
                    {t("common.cancel")}
                  </button>
                )}
              </div>
            </form>
          )}
        </>
      )}

      {tab === "objects" && (
        <>
          <div className="card" style={{ marginBottom: "1.25rem" }}>
            <h2>{t("jea.appObjectsTitle")}</h2>
            <p className="muted">{t("jea.appPackHint")}</p>
            <table>
              <thead>
                <tr>
                  <th>{t("common.name")}</th>
                  <th>unmatched</th>
                  <th>{t("jea.rules")}</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {appPacks.map((p) => (
                  <tr key={p.id}>
                    <td>
                      <span className="mono">{p.name}</span>
                      {p.description ? (
                        <div className="muted" style={{ fontSize: "0.85rem" }}>
                          {p.description}
                        </div>
                      ) : null}
                    </td>
                    <td className="mono">{p.unmatched}</td>
                    <td className="mono" style={{ fontSize: "0.8rem", maxWidth: 420 }}>
                      {(p.rules || []).slice(0, 6).join(", ")}
                      {(p.rules || []).length > 6 ? ` (+${(p.rules || []).length - 6})` : ""}
                    </td>
                    <td>
                      {canWrite && (
                        <div className="row" style={{ gap: "0.4rem" }}>
                          <button className="btn secondary" type="button" onClick={() => startAppEdit(p)}>
                            {t("jea.edit")}
                          </button>
                          <button
                            className="btn danger"
                            type="button"
                            disabled={busy}
                            onClick={() => void onAppDelete(p)}
                          >
                            {t("common.delete")}
                          </button>
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <form className="card" onSubmit={tryAppObject} style={{ maxWidth: 560, marginBottom: "1.25rem" }}>
            <h2>{t("jea.tryRequestTitle")}</h2>
            <label>{t("jea.pack")}</label>
            <select value={tryAppPack} onChange={(e) => setTryAppPack(e.target.value)}>
              <option value="">{t("jea.selectPlaceholder")}</option>
              {appPacks.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
            <div className="row" style={{ gap: "0.5rem" }}>
              <div style={{ flex: "0 0 8rem" }}>
                <label>{t("jea.method")}</label>
                <input
                  value={tryAppMethod}
                  onChange={(e) => setTryAppMethod(e.target.value)}
                  className="mono"
                />
              </div>
              <div style={{ flex: 1 }}>
                <label>{t("jea.path")}</label>
                <input
                  value={tryAppPath}
                  onChange={(e) => setTryAppPath(e.target.value)}
                  className="mono"
                />
              </div>
            </div>
            <label>{t("jea.graphqlQuery")}</label>
            <textarea
              rows={4}
              value={tryAppQuery}
              onChange={(e) => setTryAppQuery(e.target.value)}
              placeholder={'mutation { deleteCustomer(id: "1") { id } }'}
              className="mono"
              style={{ width: "100%" }}
            />
            <button className="btn" type="submit" disabled={busy || !tryAppPath.trim()} style={{ marginTop: "0.75rem" }}>
              {t("jea.check")}
            </button>
            {tryAppOut && (
              <p className="mono" style={{ marginTop: "0.75rem" }}>
                {tryAppOut.allowed ? "ALLOW" : "DENY"} · {tryAppOut.action}
                {tryAppOut.object ? ` · ${tryAppOut.object}` : ""}
                {tryAppOut.code ? ` · ${tryAppOut.code}` : ""}
                {tryAppOut.reason ? ` — ${tryAppOut.reason}` : ""}
                {tryAppOut.graphql_fields?.length
                  ? ` · gql:${tryAppOut.graphql_fields.join(",")}`
                  : ""}
              </p>
            )}
          </form>
          {canWrite && (
            <form className="card" onSubmit={onAppSubmit} style={{ maxWidth: 560 }}>
              <h2>{appEditId ? t("jea.editAppPack") : t("jea.newAppPack")}</h2>
              <label>{t("common.name")}</label>
              <input
                required
                value={appForm.name}
                onChange={(e) => setAppForm({ ...appForm, name: e.target.value })}
                disabled={!!appEditId}
              />
              <label>{t("common.description")}</label>
              <input
                value={appForm.description}
                onChange={(e) => setAppForm({ ...appForm, description: e.target.value })}
              />
              <label>{t("jea.unmatched")}</label>
              <select
                value={appForm.unmatched}
                onChange={(e) => setAppForm({ ...appForm, unmatched: e.target.value })}
              >
                <option value="allow">{t("jea.appModeAllow")}</option>
                <option value="deny">{t("jea.appModeDeny")}</option>
              </select>
              <label>{t("jea.appRulesLabelFull")}</label>
              <textarea
                rows={9}
                value={appForm.rules}
                onChange={(e) => setAppForm({ ...appForm, rules: e.target.value })}
                placeholder={defaultAppRules}
                style={{ fontFamily: "ui-monospace, monospace", width: "100%" }}
              />
              <div className="row" style={{ gap: "0.5rem" }}>
                <button className="btn" type="submit" disabled={busy}>
                  {appEditId ? t("common.save") : t("common.create")}
                </button>
                {appEditId && (
                  <button className="btn secondary" type="button" onClick={resetAppForm}>
                    {t("common.cancel")}
                  </button>
                )}
              </div>
            </form>
          )}
        </>
      )}

      {tab === "policy" && (
        <>
          <div className="card" style={{ marginBottom: "1.25rem" }}>
            <h2>{t("jea.policyTitle")}</h2>
            <p className="muted" style={{ fontSize: "0.9rem" }}>{t("jea.policyLead")}</p>
            <table>
              <thead>
                <tr>
                  <th>{t("common.name")}</th>
                  <th>{t("jea.restrictions")}</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {policies.map((p) => (
                  <tr key={p.id}>
                    <td>
                      <span className="mono">{p.name}</span>
                      {p.description ? (
                        <div className="muted" style={{ fontSize: "0.85rem" }}>
                          {p.description}
                        </div>
                      ) : null}
                    </td>
                    <td className="mono" style={{ fontSize: "0.8rem", maxWidth: 480 }}>
                      {policySummary(p)}
                    </td>
                    <td>
                      {canWrite && (
                        <div className="row" style={{ gap: "0.4rem" }}>
                          <button className="btn secondary" type="button" onClick={() => startPolicyEdit(p)}>
                            {t("jea.edit")}
                          </button>
                          <button
                            className="btn danger"
                            type="button"
                            disabled={busy}
                            onClick={() => void onPolicyDelete(p)}
                          >
                            {t("common.delete")}
                          </button>
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
                {policies.length === 0 && (
                  <tr>
                    <td colSpan={3} className="muted">
                      {t("jea.noPolicies")}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          {canWrite && (
            <form className="card" onSubmit={onPolicySubmit} style={{ maxWidth: 560 }}>
              <h2>{policyEditId ? t("jea.editPolicy") : t("jea.newPolicy")}</h2>
              <label>{t("common.name")}</label>
              <input
                required
                value={policyForm.name}
                onChange={(e) => setPolicyForm({ ...policyForm, name: e.target.value })}
                disabled={!!policyEditId}
              />
              <label>{t("common.description")}</label>
              <input
                value={policyForm.description}
                onChange={(e) => setPolicyForm({ ...policyForm, description: e.target.value })}
              />
              <div className="row" style={{ alignItems: "flex-end" }}>
                <div style={{ flex: 1 }}>
                  <label>{t("jea.timeFrom")}</label>
                  <input
                    placeholder="09:00"
                    value={policyForm.time_start}
                    onChange={(e) => setPolicyForm({ ...policyForm, time_start: e.target.value })}
                  />
                </div>
                <div style={{ flex: 1 }}>
                  <label>{t("jea.timeTo")}</label>
                  <input
                    placeholder="18:00"
                    value={policyForm.time_end}
                    onChange={(e) => setPolicyForm({ ...policyForm, time_end: e.target.value })}
                  />
                </div>
              </div>
              <label>{t("jea.daysOfWeek")}</label>
              <div className="row" style={{ marginBottom: "0.9rem" }}>
                {dayLabels.map((label, i) => {
                  const bit = 1 << i;
                  const on = (policyForm.days_of_week & bit) !== 0;
                  return (
                    <button
                      key={label}
                      type="button"
                      className={on ? "btn" : "btn secondary"}
                      onClick={() => togglePolicyDay(bit)}
                    >
                      {label}
                    </button>
                  );
                })}
              </div>
              <label>Required tags</label>
              <input
                value={policyForm.required_tags}
                onChange={(e) => setPolicyForm({ ...policyForm, required_tags: e.target.value })}
                placeholder="pci, prod/sre"
              />
              <label className="row" style={{ gap: "0.5rem", alignItems: "center" }}>
                <input
                  type="checkbox"
                  checked={policyForm.require_ticket}
                  onChange={(e) => setPolicyForm({ ...policyForm, require_ticket: e.target.checked })}
                />
                {t("jea.requireTicket")}
              </label>
              <label className="row" style={{ gap: "0.5rem", alignItems: "center" }}>
                <input
                  type="checkbox"
                  checked={policyForm.require_reason}
                  onChange={(e) => setPolicyForm({ ...policyForm, require_reason: e.target.checked })}
                />
                {t("jea.requireReason")}
              </label>
              <label>Allowed CIDR</label>
              <input
                value={policyForm.allowed_cidrs}
                onChange={(e) => setPolicyForm({ ...policyForm, allowed_cidrs: e.target.value })}
                placeholder="10.0.0.0/8, 192.168.0.0/16"
              />
              <label>Allowed countries</label>
              <input
                value={policyForm.allowed_countries}
                onChange={(e) => setPolicyForm({ ...policyForm, allowed_countries: e.target.value })}
                placeholder="LAN, RU"
              />
              <label>Allowed devices</label>
              <input
                value={policyForm.allowed_devices}
                onChange={(e) => setPolicyForm({ ...policyForm, allowed_devices: e.target.value })}
                placeholder="WEBAUTHN, TLS, SPIFFE"
              />
              <label>Allowed namespaces</label>
              <input
                value={policyForm.allowed_namespaces}
                onChange={(e) => setPolicyForm({ ...policyForm, allowed_namespaces: e.target.value })}
              />
              <label>{t("jea.allowedEgress")}</label>
              <input
                value={policyForm.allowed_egress}
                onChange={(e) => setPolicyForm({ ...policyForm, allowed_egress: e.target.value })}
                placeholder="10.1.2.0/24:5432, db.prod.local:5432"
              />
              <label>{t("jea.piiInResponse")}</label>
              <select
                value={policyForm.pii_action}
                onChange={(e) => setPolicyForm({ ...policyForm, pii_action: e.target.value })}
              >
                <option value="">{t("assets.off")}</option>
                <option value="mask">mask</option>
                <option value="deny">deny</option>
              </select>
              <label>{t("jea.nlpDlpClassifier")}</label>
              <select
                value={policyForm.nlp_dlp_action}
                onChange={(e) => setPolicyForm({ ...policyForm, nlp_dlp_action: e.target.value })}
              >
                <option value="">{t("assets.off")}</option>
                <option value="audit">audit</option>
                <option value="mask">mask</option>
                <option value="deny">deny</option>
              </select>
              <label>SCP/SFTP</label>
              <select
                value={policyForm.file_transfer}
                onChange={(e) => setPolicyForm({ ...policyForm, file_transfer: e.target.value })}
              >
                <option value="deny">deny</option>
                <option value="audit">audit</option>
                <option value="capture">capture</option>
              </select>
              <label>{t("jea.ocrLang")}</label>
              <select
                value={policyForm.ocr_lang}
                onChange={(e) => setPolicyForm({ ...policyForm, ocr_lang: e.target.value })}
              >
                <option value="rus+eng">rus+eng</option>
                <option value="eng">eng</option>
                <option value="rus">rus</option>
              </select>
              <label>{t("jea.ocrInterval")}</label>
              <input
                type="number"
                min={5}
                max={120}
                value={policyForm.ocr_interval_sec}
                onChange={(e) => setPolicyForm({ ...policyForm, ocr_interval_sec: e.target.value })}
                disabled={!!policyForm.ocr_every_frame}
              />
              <label>{t("jea.ocrMaxFrames")}</label>
              <input
                type="number"
                min={1}
                max={3600}
                value={policyForm.ocr_max_frames}
                onChange={(e) => setPolicyForm({ ...policyForm, ocr_max_frames: e.target.value })}
              />
              <label style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
                <input
                  type="checkbox"
                  checked={!!policyForm.ocr_every_frame}
                  onChange={(e) => {
                    const on = e.target.checked;
                    setPolicyForm({
                      ...policyForm,
                      ocr_every_frame: on,
                      ocr_max_frames: on && Number(policyForm.ocr_max_frames) < 300 ? "3600" : policyForm.ocr_max_frames,
                    });
                  }}
                />
                {t("jea.ocrEveryFrame")}
              </label>
              <label style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
                <input
                  type="checkbox"
                  checked={!!policyForm.ocr_live}
                  onChange={(e) => setPolicyForm({ ...policyForm, ocr_live: e.target.checked })}
                />
                {t("jea.ocrLive")}
              </label>
              <label style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
                <input
                  type="checkbox"
                  checked={!!policyForm.ocr_ssh_stdout}
                  onChange={(e) => setPolicyForm({ ...policyForm, ocr_ssh_stdout: e.target.checked })}
                />
                {t("jea.ocrSshStdout")}
              </label>
              <p className="muted" style={{ marginTop: "-0.5rem" }}>
                {t("jea.ocrHint")}
              </p>
              <label style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
                <input
                  type="checkbox"
                  checked={!!policyForm.rdp_clipboard}
                  onChange={(e) => setPolicyForm({ ...policyForm, rdp_clipboard: e.target.checked })}
                />
                RDP clipboard (default off — DLP)
              </label>
              <label style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
                <input
                  type="checkbox"
                  checked={!!policyForm.rdp_drive}
                  onChange={(e) => setPolicyForm({ ...policyForm, rdp_drive: e.target.checked })}
                />
                RDP drive mapping
              </label>
              <label style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
                <input
                  type="checkbox"
                  checked={!!policyForm.rdp_printer}
                  onChange={(e) => setPolicyForm({ ...policyForm, rdp_printer: e.target.checked })}
                />
                RDP printers
              </label>
              <label style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
                <input
                  type="checkbox"
                  checked={!!policyForm.rdp_native}
                  onChange={(e) => setPolicyForm({ ...policyForm, rdp_native: e.target.checked })}
                />
                {t("jea.nativeMstsc")}
              </label>
              <label>{t("jea.dlpRegex")}</label>
              <textarea
                rows={4}
                value={policyForm.dlp_patterns}
                onChange={(e) => setPolicyForm({ ...policyForm, dlp_patterns: e.target.value })}
                placeholder={"passport \\b[A-Z]{2}\\d{7}\\b\ninternal_id INTERNAL-\\d+"}
                spellCheck={false}
              />
              <p className="muted" style={{ marginTop: "-0.5rem" }}>
                {t("jea.piiBuiltinHint")}
              </p>
              <label>{t("jea.nlpClassifiers")}</label>
              <textarea
                rows={4}
                value={policyForm.dlp_classifiers}
                onChange={(e) => setPolicyForm({ ...policyForm, dlp_classifiers: e.target.value })}
                placeholder={"trade_secret min=2 alpha|beta|roadmap\nhr_data salary bonus termination"}
                spellCheck={false}
              />
              <p className="muted" style={{ marginTop: "-0.5rem" }}>{t("jea.nlpBuiltins")}</p>
              <label>SSH JEA pack</label>
              <select
                value={policyForm.command_policy_pack_id}
                onChange={(e) => setPolicyForm({ ...policyForm, command_policy_pack_id: e.target.value })}
              >
                <option value="">—</option>
                {packs.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name}
                  </option>
                ))}
              </select>
              <label>SQL JEA pack</label>
              <select
                value={policyForm.sql_policy_pack_id}
                onChange={(e) => setPolicyForm({ ...policyForm, sql_policy_pack_id: e.target.value })}
              >
                <option value="">—</option>
                {sqlPacks.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name}
                  </option>
                ))}
              </select>
              <label>HTTP ACL pack</label>
              <select
                value={policyForm.http_policy_pack_id}
                onChange={(e) => setPolicyForm({ ...policyForm, http_policy_pack_id: e.target.value })}
              >
                <option value="">—</option>
                {httpPacks.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name}
                  </option>
                ))}
              </select>
              <label>Object ACL pack</label>
              <select
                value={policyForm.app_object_pack_id}
                onChange={(e) => setPolicyForm({ ...policyForm, app_object_pack_id: e.target.value })}
              >
                <option value="">—</option>
                {appPacks.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name}
                  </option>
                ))}
              </select>
              <div className="row" style={{ alignItems: "flex-end" }}>
                <div style={{ flex: 1 }}>
                  <label>Max risk</label>
                  <input
                    type="number"
                    min={0}
                    max={100}
                    value={policyForm.max_risk}
                    onChange={(e) => setPolicyForm({ ...policyForm, max_risk: e.target.value })}
                  />
                </div>
                <div style={{ flex: 1 }}>
                  <label>{t("jea.ifAboveThreshold")}</label>
                  <select
                    value={policyForm.risk_action}
                    onChange={(e) => setPolicyForm({ ...policyForm, risk_action: e.target.value })}
                  >
                    <option value="deny">deny</option>
                    <option value="require_approval">require_approval</option>
                    <option value="require_mfa">require_mfa</option>
                    <option value="terminate">terminate</option>
                    <option value="lock_account">lock_account</option>
                  </select>
                </div>
              </div>
              <div className="row" style={{ gap: "0.5rem" }}>
                <button className="btn" type="submit" disabled={busy}>
                  {policyEditId ? t("common.save") : t("common.create")}
                </button>
                {policyEditId && (
                  <button className="btn secondary" type="button" onClick={resetPolicyForm}>
                    {t("common.cancel")}
                  </button>
                )}
              </div>
            </form>
          )}
        </>
      )}

      {tab === "tags" && (
        <>
          <div className="card" style={{ marginBottom: "1.25rem" }}>
            <h2>{t("jea.tagAclTitle")}</h2>
            <p className="muted">{t("jea.tagAclLeadFull")} {t("jea.needAssetsRead")}</p>
            {!canSeeACL && <p className="error">{t("jea.needAssetsRead")}</p>}
            {canSeeACL && (
              <table>
                <thead>
                  <tr>
                    <th>{t("jea.subject")}</th>
                    <th>{t("jea.tabTags")}</th>
                    <th>{t("jea.matchMode")}</th>
                    <th>Policy</th>
                    <th>{t("jea.expires")}</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {tagBindings.map((b) => (
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
                      </td>
                      <td className="mono">
                        {[
                          (b.asset_match_tags || []).length ? `tags:${(b.asset_match_tags || []).join(",")}` : "",
                          b.asset_match_name ? `name:${b.asset_match_name}` : "",
                          b.asset_match_hostname ? `host:${b.asset_match_hostname}` : "",
                          (b.asset_match_types || []).length ? `type:${(b.asset_match_types || []).join(",")}` : "",
                          (b.asset_match_cidrs || []).length ? `cidr:${(b.asset_match_cidrs || []).join(",")}` : "",
                        ]
                          .filter(Boolean)
                          .join(" · ") || "—"}
                      </td>
                      <td>{b.asset_match_mode === "any" ? t("jea.any") : t("common.all")}</td>
                      <td className="mono">{b.access_policy_name || "—"}</td>
                      <td className="mono">
                        {b.expires_at ? new Date(b.expires_at).toLocaleString() : t("jea.permanent")}
                      </td>
                      <td>
                        {canACL && (
                          <div className="row" style={{ gap: "0.35rem", flexWrap: "wrap" }}>
                            <button
                              className="btn secondary"
                              type="button"
                              disabled={busy}
                              onClick={() => void startTagEdit(b)}
                            >
                              {t("jea.edit")}
                            </button>
                            <button
                              className="btn danger"
                              type="button"
                              disabled={busy}
                              onClick={() => void onDeleteTagACL(b)}
                            >
                              {t("jea.revoke")}
                            </button>
                          </div>
                        )}
                      </td>
                    </tr>
                  ))}
                  {tagBindings.length === 0 && (
                    <tr>
                      <td colSpan={6} className="muted">
                        {t("jea.noTagAcl")}
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            )}
          </div>
          {canACL && (
            <form className="card" style={{ maxWidth: 560 }} onSubmit={(e) => void onTagSubmit(e)}>
              <h2>{tagEditId ? t("jea.editTagAcl") : t("jea.newTagAcl")}</h2>
              {tagEditId && (
                <p className="muted">
                  {t("jea.tagAclEditLead")}
                  {tagRaw?.expires_at
                    ? t("jea.expiresNow", { at: new Date(tagRaw.expires_at).toLocaleString() })
                    : t("jea.tagAclNoTtl")}
                </p>
              )}
              <label>{t("jea.who")}</label>
              <select
                value={tagForm.who}
                disabled={!!tagEditId}
                onChange={(e) => setTagForm({ ...tagForm, who: e.target.value as typeof tagForm.who })}
              >
                <option value="group">{t("common.group")}</option>
                <option value="role">{t("jea.role")}</option>
                <option value="user">{t("common.user")}</option>
              </select>
              {tagForm.who === "group" && (
                <select
                  value={tagForm.group_id}
                  disabled={!!tagEditId}
                  onChange={(e) => setTagForm({ ...tagForm, group_id: e.target.value })}
                >
                  <option value="">{t("jea.selectGroup")}</option>
                  {tagGroups.map((g) => (
                    <option key={g.id} value={g.id}>
                      {g.parent_name ? `${g.parent_name} / ${g.name}` : g.name}
                    </option>
                  ))}
                </select>
              )}
              {tagForm.who === "role" && (
                <select
                  value={tagForm.role_id}
                  disabled={!!tagEditId}
                  onChange={(e) => setTagForm({ ...tagForm, role_id: e.target.value })}
                >
                  <option value="">{t("jea.selectRole")}</option>
                  {tagRoles.map((r) => (
                    <option key={r.id} value={r.id}>
                      {r.name}
                    </option>
                  ))}
                </select>
              )}
              {tagForm.who === "user" && (
                <select
                  value={tagForm.user_id}
                  disabled={!!tagEditId}
                  onChange={(e) => setTagForm({ ...tagForm, user_id: e.target.value })}
                >
                  <option value="">{t("jea.selectUser")}</option>
                  {tagUsers.map((u) => (
                    <option key={u.id} value={u.id}>
                      {u.username}
                    </option>
                  ))}
                </select>
              )}
              <label>{t("jea.assetTags")}</label>
              <input
                required
                value={tagForm.asset_match_tags}
                onChange={(e) => setTagForm({ ...tagForm, asset_match_tags: e.target.value })}
                placeholder="prod/linux, pci"
              />
              <label>{t("jea.matchMode")}</label>
              <select
                value={tagForm.asset_match_mode}
                onChange={(e) =>
                  setTagForm({ ...tagForm, asset_match_mode: e.target.value as "all" | "any" })
                }
              >
                <option value="all">{t("jea.matchAllAnd")}</option>
                <option value="any">{t("jea.matchAnyOr")}</option>
              </select>
              <label>{t("jea.assetNameGlob")}</label>
              <input
                value={tagForm.asset_match_name}
                onChange={(e) => setTagForm({ ...tagForm, asset_match_name: e.target.value })}
                placeholder="prod-*"
              />
              <label>{t("jea.hostnameGlob")}</label>
              <input
                value={tagForm.asset_match_hostname}
                onChange={(e) => setTagForm({ ...tagForm, asset_match_hostname: e.target.value })}
                placeholder="*.corp.local"
              />
              <label>{t("jea.assetTypes")}</label>
              <input
                value={tagForm.asset_match_types}
                onChange={(e) => setTagForm({ ...tagForm, asset_match_types: e.target.value })}
                placeholder="ssh, rdp"
              />
              <label>{t("jea.cidrAddresses")}</label>
              <input
                value={tagForm.asset_match_cidrs}
                onChange={(e) => setTagForm({ ...tagForm, asset_match_cidrs: e.target.value })}
                placeholder="10.1.0.0/16"
              />
              <p className="muted" style={{ marginTop: "-0.5rem" }}>{t("jea.whatFieldsHint")}</p>
              <label>{t("jea.policyOptional")}</label>
              <select
                value={tagForm.access_policy_id}
                onChange={(e) => setTagForm({ ...tagForm, access_policy_id: e.target.value })}
              >
                <option value="">—</option>
                {policies.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name}
                  </option>
                ))}
              </select>
              <label>{t("jea.ttlMinutesLabel", { mode: tagEditId ? t("jea.leaveTtl") : t("jea.permanent") })}</label>
              <input
                type="number"
                min={1}
                max={1440}
                value={tagForm.duration_minutes}
                onChange={(e) => {
                  setTagPermanent(false);
                  setTagForm({ ...tagForm, duration_minutes: e.target.value });
                }}
              />
              {tagEditId && (
                <label className="row" style={{ gap: "0.5rem", alignItems: "center" }}>
                  <input
                    type="checkbox"
                    checked={tagPermanent}
                    onChange={(e) => {
                      setTagPermanent(e.target.checked);
                      if (e.target.checked) setTagForm({ ...tagForm, duration_minutes: "" });
                    }}
                  />
                  {t("jea.permanentRemoveTtl")}
                </label>
              )}
              <div className="row" style={{ gap: "0.5rem", marginTop: "0.75rem" }}>
                <button className="btn" type="submit" disabled={busy}>
                  {tagEditId ? t("common.save") : t("common.create")}
                </button>
                {tagEditId && (
                  <button className="btn secondary" type="button" disabled={busy} onClick={resetTagForm}>
                    {t("common.cancel")}
                  </button>
                )}
              </div>
            </form>
          )}
        </>
      )}
    </div>
  );
}
