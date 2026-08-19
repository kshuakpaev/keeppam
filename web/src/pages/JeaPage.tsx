import { useEffect, useState, type FormEvent } from "react";
import { api, hasPerm, type AccessBinding, type AccessPolicy, type AppObjectPack, type AppObjectPreview, type CommandPolicyPack, type CommandPreview, type HTTPPolicyPack, type PamGroup, type Role, type SQLPolicyPack, type User } from "../api";
import { useAuth } from "../auth";

const DAY_LABELS = ["Вс", "Пн", "Вт", "Ср", "Чт", "Пт", "Сб"];

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
  file_transfer: "deny",
  dlp_patterns: "",
  command_policy_pack_id: "",
  sql_policy_pack_id: "",
  http_policy_pack_id: "",
  app_object_pack_id: "",
  max_risk: "0",
  risk_action: "deny",
};

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
  access_policy_id: "",
  duration_minutes: "",
};

export function JeaPage() {
  const { user } = useAuth();
  const canRead = hasPerm(user, "jea.read");
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
          /* форма без справочников */
        }
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка загрузки");
    }
  }

  useEffect(() => {
    if (!canRead) return;
    void load();
  }, [canRead]);

  if (!canRead) {
    return <p className="error">Недостаточно прав (jea.read)</p>;
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
      setError(err instanceof Error ? err.message : "Ошибка preview");
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
        setMsg("SSH-пакет обновлён");
      } else {
        await api.createCommandPack(body);
        setMsg("SSH-пакет создан");
      }
      resetForm();
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка сохранения");
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
        setMsg("SQL-пакет обновлён");
      } else {
        await api.createSQLPack(body);
        setMsg("SQL-пакет создан");
      }
      resetSqlForm();
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка сохранения");
    } finally {
      setBusy(false);
    }
  }

  async function onDelete(p: CommandPolicyPack) {
    if (!canWrite) return;
    if (!confirm(`Удалить пакет «${p.name}»?`)) return;
    setBusy(true);
    try {
      await api.deleteCommandPack(p.id);
      setMsg("Удалён");
      if (editId === p.id) resetForm();
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка удаления");
    } finally {
      setBusy(false);
    }
  }

  async function onSqlDelete(p: SQLPolicyPack) {
    if (!canWrite) return;
    if (!confirm(`Удалить SQL-пакет «${p.name}»?`)) return;
    setBusy(true);
    try {
      await api.deleteSQLPack(p.id);
      setMsg("Удалён");
      if (sqlEditId === p.id) resetSqlForm();
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка удаления");
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
        setMsg("HTTP-пакет обновлён");
      } else {
        await api.createHTTPPack(body);
        setMsg("HTTP-пакет создан");
      }
      resetHttpForm();
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка сохранения");
    } finally {
      setBusy(false);
    }
  }

  async function onHttpDelete(p: HTTPPolicyPack) {
    if (!canWrite) return;
    if (!confirm(`Удалить HTTP-пакет «${p.name}»?`)) return;
    setBusy(true);
    try {
      await api.deleteHTTPPack(p.id);
      setMsg("Удалён");
      if (httpEditId === p.id) resetHttpForm();
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка удаления");
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
        setMsg("Пакет объектов обновлён");
      } else {
        await api.createAppObjectPack(body);
        setMsg("Пакет объектов создан");
      }
      resetAppForm();
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка сохранения");
    } finally {
      setBusy(false);
    }
  }

  async function onAppDelete(p: AppObjectPack) {
    if (!canWrite) return;
    if (!confirm(`Удалить пакет объектов «${p.name}»?`)) return;
    setBusy(true);
    try {
      await api.deleteAppObjectPack(p.id);
      setMsg("Удалён");
      if (appEditId === p.id) resetAppForm();
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка удаления");
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
      setError(err instanceof Error ? err.message : "Ошибка preview");
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
      file_transfer: p.file_transfer || "deny",
      dlp_patterns: formatDlpPatterns(p.dlp_patterns),
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
    if (mask === 127) return "все дни";
    return DAY_LABELS.filter((_, i) => mask & (1 << i)).join(", ") || "—";
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
    if (p.file_transfer && p.file_transfer !== "deny") bits.push("files:" + p.file_transfer);
    if ((p.dlp_patterns || []).length) bits.push(`dlp:${(p.dlp_patterns || []).length}`);
    if (p.require_ticket) bits.push("ticket");
    if (p.require_reason) bits.push("reason");
    if (p.command_policy_pack_name) bits.push(`ssh:${p.command_policy_pack_name}`);
    if (p.sql_policy_pack_name) bits.push(`sql:${p.sql_policy_pack_name}`);
    if (p.http_policy_pack_name) bits.push(`http:${p.http_policy_pack_name}`);
    if (p.app_object_pack_name) bits.push(`obj:${p.app_object_pack_name}`);
    if (p.max_risk) bits.push(`risk≤${p.max_risk}`);
    return bits.length ? bits.join(" · ") : "без ограничений (шаблон)";
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
        file_transfer: policyForm.file_transfer || "deny",
        dlp_patterns: parseDlpPatterns(policyForm.dlp_patterns),
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
        setMsg("Политика обновлена");
      } else {
        await api.createAccessPolicy(body);
        setMsg("Политика создана");
      }
      resetPolicyForm();
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка сохранения");
    } finally {
      setBusy(false);
    }
  }

  async function onPolicyDelete(p: AccessPolicy) {
    if (!canWrite) return;
    if (!confirm(`Удалить политику «${p.name}»? Привязки ACL останутся, ссылка сбросится.`)) return;
    setBusy(true);
    try {
      await api.deleteAccessPolicy(p.id);
      setMsg("Удалена");
      if (policyEditId === p.id) resetPolicyForm();
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка удаления");
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
        access_policy_id: raw.access_policy_id || "",
        duration_minutes: "",
      });
      setMsg("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка загрузки tag ACL");
    }
  }

  async function onTagSubmit(e: FormEvent) {
    e.preventDefault();
    if (!canACL) return;
    const tags = splitCSV(tagForm.asset_match_tags);
    if (!tags.length) {
      setError("укажите теги активов");
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
          access_policy_id: tagForm.access_policy_id || null,
        };
        if (tagPermanent) body.permanent = true;
        else if (tagForm.duration_minutes) body.duration_minutes = Number(tagForm.duration_minutes);
        await api.updateACL("_", tagEditId, body);
        setMsg("Tag ACL обновлён");
        resetTagForm();
      } else {
        const body: Parameters<typeof api.createTagACL>[0] = {
          asset_match_tags: tags,
          asset_match_mode: tagForm.asset_match_mode,
        };
        if (tagForm.who === "user" && tagForm.user_id) body.user_id = tagForm.user_id;
        else if (tagForm.who === "role" && tagForm.role_id) body.role_id = tagForm.role_id;
        else if (tagForm.who === "group" && tagForm.group_id) body.group_id = tagForm.group_id;
        else {
          setError("выберите субъекта");
          setBusy(false);
          return;
        }
        if (tagForm.access_policy_id) body.access_policy_id = tagForm.access_policy_id;
        if (tagForm.duration_minutes) body.duration_minutes = Number(tagForm.duration_minutes);
        await api.createTagACL(body);
        setMsg("Tag ACL создан");
        setTagForm({
          who: tagForm.who,
          user_id: "",
          role_id: "",
          group_id: "",
          asset_match_tags: tagForm.asset_match_tags,
          asset_match_mode: tagForm.asset_match_mode,
          access_policy_id: "",
          duration_minutes: "",
        });
      }
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка tag ACL");
    } finally {
      setBusy(false);
    }
  }

  async function onDeleteTagACL(b: AccessBinding) {
    if (!canACL) return;
    if (!confirm("Отозвать tag ACL? Пропадёт доступ ко всем подходящим активам.")) return;
    setBusy(true);
    try {
      await api.deleteACL("_", b.id);
      setMsg("Отозван");
      if (tagEditId === b.id) resetTagForm();
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка отзыва");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <h1>JEA</h1>
      <p className="muted">
        SSH / SQL / HTTP-пакеты, Policy, Command Risk и ACL на теги активов (путь prod/linux, без строки на каждый хост).
      </p>
      <div className="row" style={{ gap: "0.5rem", marginBottom: "1rem" }}>
        <button
          className={`btn ${tab === "ssh" ? "" : "secondary"}`}
          type="button"
          onClick={() => setTab("ssh")}
        >
          SSH commands
        </button>
        <button
          className={`btn ${tab === "sql" ? "" : "secondary"}`}
          type="button"
          onClick={() => setTab("sql")}
        >
          SQL tables / masking
        </button>
        <button
          className={`btn ${tab === "http" ? "" : "secondary"}`}
          type="button"
          onClick={() => setTab("http")}
        >
          HTTP / URL ACL
        </button>
        <button
          className={`btn ${tab === "objects" ? "" : "secondary"}`}
          type="button"
          onClick={() => setTab("objects")}
        >
          Объекты
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
          Теги активов
        </button>
      </div>
      {error && <p className="error">{error}</p>}
      {msg && <p className="ok">{msg}</p>}

      {tab === "ssh" && (
        <>
          <div className="card" style={{ marginBottom: "1.25rem" }}>
            <h2>SSH-пакеты</h2>
            <table>
              <thead>
                <tr>
                  <th>Имя</th>
                  <th>Режим</th>
                  <th>Паттерны</th>
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
                            Изменить
                          </button>
                          <button className="btn danger" type="button" disabled={busy} onClick={() => void onDelete(p)}>
                            Удалить
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
            <h2>Проверить команду</h2>
            <p className="muted">
              Парсер снимает sudo/su/env. JEA смотрит на inner binary. Баллы — класс команды (без connect-риска).
            </p>
            <label>Команда</label>
            <input
              value={tryCmd}
              onChange={(e) => setTryCmd(e.target.value)}
              placeholder="sudo rm -rf /tmp/x"
              style={{ fontFamily: "ui-monospace, monospace", width: "100%" }}
            />
            <label>SSH-пакет (опц.)</label>
            <select value={tryPack} onChange={(e) => setTryPack(e.target.value)}>
              <option value="">без пакета</option>
              {packs.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name} ({p.mode})
                </option>
              ))}
            </select>
            <button className="btn" type="submit" disabled={busy || !tryCmd.trim()} style={{ marginTop: "0.75rem" }}>
              Разобрать
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
                    "без extra-risk"
                  )}
                </p>
                <p>{tryOut.note}</p>
              </div>
            )}
          </form>
          {canWrite && (
            <form className="card" onSubmit={onSubmit} style={{ maxWidth: 560 }}>
              <h2>{editId ? "Редактировать SSH-пакет" : "Новый SSH-пакет"}</h2>
              <label>Имя</label>
              <input
                required
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                disabled={!!editId}
              />
              <label>Описание</label>
              <input
                value={form.description}
                onChange={(e) => setForm({ ...form, description: e.target.value })}
              />
              <label>Режим</label>
              <select value={form.mode} onChange={(e) => setForm({ ...form, mode: e.target.value })}>
                <option value="allowlist">allowlist</option>
                <option value="denylist">denylist</option>
              </select>
              <label>Паттерны</label>
              <textarea
                rows={8}
                value={form.patterns}
                onChange={(e) => setForm({ ...form, patterns: e.target.value })}
                style={{ fontFamily: "ui-monospace, monospace", width: "100%" }}
              />
              <div className="row" style={{ gap: "0.5rem" }}>
                <button className="btn" type="submit" disabled={busy}>
                  {editId ? "Сохранить" : "Создать"}
                </button>
                {editId && (
                  <button className="btn secondary" type="button" onClick={resetForm}>
                    Отмена
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
            <h2>SQL-пакеты</h2>
            <p className="muted">
              statements: SELECT/INSERT/UPDATE/DELETE/DDL · tables: glob · mask_columns: колонки → ***
              · DLP: COPY/OUTFILE всегда запрещены; max_rows / dlp_action — лимит выгрузки
            </p>
            <table>
              <thead>
                <tr>
                  <th>Имя</th>
                  <th>Режим</th>
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
                            Изменить
                          </button>
                          <button
                            className="btn danger"
                            type="button"
                            disabled={busy}
                            onClick={() => void onSqlDelete(p)}
                          >
                            Удалить
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
              <h2>{sqlEditId ? "Редактировать SQL-пакет" : "Новый SQL-пакет"}</h2>
              <label>Имя</label>
              <input
                required
                value={sqlForm.name}
                onChange={(e) => setSqlForm({ ...sqlForm, name: e.target.value })}
                disabled={!!sqlEditId}
              />
              <label>Описание</label>
              <input
                value={sqlForm.description}
                onChange={(e) => setSqlForm({ ...sqlForm, description: e.target.value })}
              />
              <label>Режим</label>
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
              <label>Tables (glob, по одному в строке)</label>
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
              <label>При превышении max_rows</label>
              <select
                value={sqlForm.dlp_action}
                onChange={(e) => setSqlForm({ ...sqlForm, dlp_action: e.target.value })}
              >
                <option value="truncate">truncate — обрезать результат</option>
                <option value="deny">deny — запретить запрос</option>
              </select>
              <div className="row" style={{ gap: "0.5rem" }}>
                <button className="btn" type="submit" disabled={busy}>
                  {sqlEditId ? "Сохранить" : "Создать"}
                </button>
                {sqlEditId && (
                  <button className="btn secondary" type="button" onClick={resetSqlForm}>
                    Отмена
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
            <h2>HTTP / URL-пакеты</h2>
            <p className="muted">
              Правило: METHOD PATH. METHOD = GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS/*. PATH glob, * совпадает с /.
              Allowlist — только совпавшие; denylist — запрет совпавших. Без пакета на ACL URL не режется.
              Isolated browser ходит через reverse-proxy KeepPAM — тот же HTTP ACL, что у recording_mode=full.
            </p>
            <table>
              <thead>
                <tr>
                  <th>Имя</th>
                  <th>Режим</th>
                  <th>Правила</th>
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
                            Изменить
                          </button>
                          <button
                            className="btn danger"
                            type="button"
                            disabled={busy}
                            onClick={() => void onHttpDelete(p)}
                          >
                            Удалить
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
              <h2>{httpEditId ? "Редактировать HTTP-пакет" : "Новый HTTP-пакет"}</h2>
              <label>Имя</label>
              <input
                required
                value={httpForm.name}
                onChange={(e) => setHttpForm({ ...httpForm, name: e.target.value })}
                disabled={!!httpEditId}
              />
              <label>Описание</label>
              <input
                value={httpForm.description}
                onChange={(e) => setHttpForm({ ...httpForm, description: e.target.value })}
              />
              <label>Режим</label>
              <select value={httpForm.mode} onChange={(e) => setHttpForm({ ...httpForm, mode: e.target.value })}>
                <option value="allowlist">allowlist</option>
                <option value="denylist">denylist</option>
              </select>
              <label>Правила (по одному в строке)</label>
              <textarea
                rows={8}
                value={httpForm.rules}
                onChange={(e) => setHttpForm({ ...httpForm, rules: e.target.value })}
                placeholder={"GET *\nPOST /api/tickets\nDELETE *"}
                style={{ fontFamily: "ui-monospace, monospace", width: "100%" }}
              />
              <div className="row" style={{ gap: "0.5rem" }}>
                <button className="btn" type="submit" disabled={busy}>
                  {httpEditId ? "Сохранить" : "Создать"}
                </button>
                {httpEditId && (
                  <button className="btn secondary" type="button" onClick={resetHttpForm}>
                    Отмена
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
            <h2>Объекты приложения</h2>
            <p className="muted">
              Правило: METHOD PATH OBJECT ACTION. ACTION = allow / deny / approval. Первое совпадение побеждает.
              unmatched=deny — allowlist функций (как CRM). APPROVAL держит HTTPS/isolated/kubectl до 60 с. Isolated
              browser ходит через тот же reverse-proxy.
            </p>
            <table>
              <thead>
                <tr>
                  <th>Имя</th>
                  <th>unmatched</th>
                  <th>Правила</th>
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
                            Изменить
                          </button>
                          <button
                            className="btn danger"
                            type="button"
                            disabled={busy}
                            onClick={() => void onAppDelete(p)}
                          >
                            Удалить
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
            <h2>Проверить запрос</h2>
            <label>Пакет</label>
            <select value={tryAppPack} onChange={(e) => setTryAppPack(e.target.value)}>
              <option value="">— выбрать —</option>
              {appPacks.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
            <div className="row" style={{ gap: "0.5rem" }}>
              <div style={{ flex: "0 0 8rem" }}>
                <label>Метод</label>
                <input
                  value={tryAppMethod}
                  onChange={(e) => setTryAppMethod(e.target.value)}
                  className="mono"
                />
              </div>
              <div style={{ flex: 1 }}>
                <label>Путь</label>
                <input
                  value={tryAppPath}
                  onChange={(e) => setTryAppPath(e.target.value)}
                  className="mono"
                />
              </div>
            </div>
            <label>GraphQL query (опц. — верхнеуровневые поля)</label>
            <textarea
              rows={4}
              value={tryAppQuery}
              onChange={(e) => setTryAppQuery(e.target.value)}
              placeholder={'mutation { deleteCustomer(id: "1") { id } }'}
              className="mono"
              style={{ width: "100%" }}
            />
            <button className="btn" type="submit" disabled={busy || !tryAppPath.trim()} style={{ marginTop: "0.75rem" }}>
              Проверить
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
              <h2>{appEditId ? "Редактировать пакет объектов" : "Новый пакет объектов"}</h2>
              <label>Имя</label>
              <input
                required
                value={appForm.name}
                onChange={(e) => setAppForm({ ...appForm, name: e.target.value })}
                disabled={!!appEditId}
              />
              <label>Описание</label>
              <input
                value={appForm.description}
                onChange={(e) => setAppForm({ ...appForm, description: e.target.value })}
              />
              <label>Несовпавшее</label>
              <select
                value={appForm.unmatched}
                onChange={(e) => setAppForm({ ...appForm, unmatched: e.target.value })}
              >
                <option value="allow">allow — overlay, остальное не режется</option>
                <option value="deny">deny — allowlist функций</option>
              </select>
              <label>Правила (METHOD PATH OBJECT ACTION). GraphQL: OBJECT — glob полей (`delete*`, `*`)</label>
              <textarea
                rows={9}
                value={appForm.rules}
                onChange={(e) => setAppForm({ ...appForm, rules: e.target.value })}
                placeholder={defaultAppRules}
                style={{ fontFamily: "ui-monospace, monospace", width: "100%" }}
              />
              <div className="row" style={{ gap: "0.5rem" }}>
                <button className="btn" type="submit" disabled={busy}>
                  {appEditId ? "Сохранить" : "Создать"}
                </button>
                {appEditId && (
                  <button className="btn secondary" type="button" onClick={resetAppForm}>
                    Отмена
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
            <h2>Access Policy</h2>
            <p className="muted" style={{ fontSize: "0.9rem" }}>
              Именованный набор ограничений. На ACL актива выбираете политику + пользователя/роль. Пустые поля ACL
              берутся из политики; ticket/reason политика может только ужесточить.
            </p>
            <table>
              <thead>
                <tr>
                  <th>Имя</th>
                  <th>Ограничения</th>
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
                            Изменить
                          </button>
                          <button
                            className="btn danger"
                            type="button"
                            disabled={busy}
                            onClick={() => void onPolicyDelete(p)}
                          >
                            Удалить
                          </button>
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
                {policies.length === 0 && (
                  <tr>
                    <td colSpan={3} className="muted">
                      Политик нет
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          {canWrite && (
            <form className="card" onSubmit={onPolicySubmit} style={{ maxWidth: 560 }}>
              <h2>{policyEditId ? "Редактировать политику" : "Новая политика"}</h2>
              <label>Имя</label>
              <input
                required
                value={policyForm.name}
                onChange={(e) => setPolicyForm({ ...policyForm, name: e.target.value })}
                disabled={!!policyEditId}
              />
              <label>Описание</label>
              <input
                value={policyForm.description}
                onChange={(e) => setPolicyForm({ ...policyForm, description: e.target.value })}
              />
              <div className="row" style={{ alignItems: "flex-end" }}>
                <div style={{ flex: 1 }}>
                  <label>С (HH:MM)</label>
                  <input
                    placeholder="09:00"
                    value={policyForm.time_start}
                    onChange={(e) => setPolicyForm({ ...policyForm, time_start: e.target.value })}
                  />
                </div>
                <div style={{ flex: 1 }}>
                  <label>До (HH:MM)</label>
                  <input
                    placeholder="18:00"
                    value={policyForm.time_end}
                    onChange={(e) => setPolicyForm({ ...policyForm, time_end: e.target.value })}
                  />
                </div>
              </div>
              <label>Дни недели</label>
              <div className="row" style={{ marginBottom: "0.9rem" }}>
                {DAY_LABELS.map((label, i) => {
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
                Требовать ticket_id
              </label>
              <label className="row" style={{ gap: "0.5rem", alignItems: "center" }}>
                <input
                  type="checkbox"
                  checked={policyForm.require_reason}
                  onChange={(e) => setPolicyForm({ ...policyForm, require_reason: e.target.checked })}
                />
                Требовать reason
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
              <label>Allowed egress (SSH -L; пусто = туннели запрещены)</label>
              <input
                value={policyForm.allowed_egress}
                onChange={(e) => setPolicyForm({ ...policyForm, allowed_egress: e.target.value })}
                placeholder="10.1.2.0/24:5432, db.prod.local:5432"
              />
              <label>PII в ответе SQL/HTTP</label>
              <select
                value={policyForm.pii_action}
                onChange={(e) => setPolicyForm({ ...policyForm, pii_action: e.target.value })}
              >
                <option value="">выкл.</option>
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
              <label>DLP regex (имя и паттерн на строку, до 16)</label>
              <textarea
                rows={4}
                value={policyForm.dlp_patterns}
                onChange={(e) => setPolicyForm({ ...policyForm, dlp_patterns: e.target.value })}
                placeholder={"passport \\b[A-Z]{2}\\d{7}\\b\ninternal_id INTERNAL-\\d+"}
                spellCheck={false}
              />
              <p className="muted" style={{ marginTop: "-0.5rem" }}>
                Встроенные kind: email, pan, phone, snils. Свои regex + PII в SSH stdout, keystroke, OCR screen_text.
              </p>
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
                  <label>Если выше порога</label>
                  <select
                    value={policyForm.risk_action}
                    onChange={(e) => setPolicyForm({ ...policyForm, risk_action: e.target.value })}
                  >
                    <option value="deny">deny</option>
                    <option value="require_approval">require_approval</option>
                    <option value="require_mfa">require_mfa</option>
                  </select>
                </div>
              </div>
              <div className="row" style={{ gap: "0.5rem" }}>
                <button className="btn" type="submit" disabled={busy}>
                  {policyEditId ? "Сохранить" : "Создать"}
                </button>
                {policyEditId && (
                  <button className="btn secondary" type="button" onClick={resetPolicyForm}>
                    Отмена
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
            <h2>ACL на теги активов</h2>
            <p className="muted">
              WHO (пользователь / роль / группа) + теги WHAT. Путь <span className="mono">prod/linux</span> —
              потомок покрывает предка (ACL на <span className="mono">prod</span> видит хост с{" "}
              <span className="mono">prod/linux</span>). Режим <strong>все</strong> — каждый тег селектора;
              <strong> любой</strong> — достаточно одного. Прямой ACL на карточке актива побеждает. Нужны права
              assets.read / assets.acl.
            </p>
            {!canSeeACL && <p className="error">Нужно право assets.read</p>}
            {canSeeACL && (
              <table>
                <thead>
                  <tr>
                    <th>Субъект</th>
                    <th>Теги активов</th>
                    <th>Совпадение</th>
                    <th>Policy</th>
                    <th>Истекает</th>
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
                      <td className="mono">{(b.asset_match_tags || []).join(", ") || "—"}</td>
                      <td>{b.asset_match_mode === "any" ? "любой" : "все"}</td>
                      <td className="mono">{b.access_policy_name || "—"}</td>
                      <td className="mono">
                        {b.expires_at ? new Date(b.expires_at).toLocaleString() : "постоянно"}
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
                              Изменить
                            </button>
                            <button
                              className="btn danger"
                              type="button"
                              disabled={busy}
                              onClick={() => void onDeleteTagACL(b)}
                            >
                              Отозвать
                            </button>
                          </div>
                        )}
                      </td>
                    </tr>
                  ))}
                  {tagBindings.length === 0 && (
                    <tr>
                      <td colSpan={6} className="muted">
                        Нет tag ACL
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            )}
          </div>
          {canACL && (
            <form className="card" style={{ maxWidth: 560 }} onSubmit={(e) => void onTagSubmit(e)}>
              <h2>{tagEditId ? "Изменить tag ACL" : "Новый tag ACL"}</h2>
              {tagEditId && (
                <p className="muted">
                  WHO нельзя сменить. Остальные ограничения (время, JEA, ABAC) сохраняются; меняются теги, Policy и TTL.
                  {tagRaw?.expires_at
                    ? ` Сейчас истекает ${new Date(tagRaw.expires_at).toLocaleString()}.`
                    : " Сейчас без TTL."}
                </p>
              )}
              <label>WHO</label>
              <select
                value={tagForm.who}
                disabled={!!tagEditId}
                onChange={(e) => setTagForm({ ...tagForm, who: e.target.value as typeof tagForm.who })}
              >
                <option value="group">Группа</option>
                <option value="role">Роль</option>
                <option value="user">Пользователь</option>
              </select>
              {tagForm.who === "group" && (
                <select
                  value={tagForm.group_id}
                  disabled={!!tagEditId}
                  onChange={(e) => setTagForm({ ...tagForm, group_id: e.target.value })}
                >
                  <option value="">выберите группу</option>
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
                  <option value="">выберите роль</option>
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
                  <option value="">выберите пользователя</option>
                  {tagUsers.map((u) => (
                    <option key={u.id} value={u.id}>
                      {u.username}
                    </option>
                  ))}
                </select>
              )}
              <label>Теги активов (через запятую)</label>
              <input
                required
                value={tagForm.asset_match_tags}
                onChange={(e) => setTagForm({ ...tagForm, asset_match_tags: e.target.value })}
                placeholder="prod/linux, pci"
              />
              <label>Совпадение</label>
              <select
                value={tagForm.asset_match_mode}
                onChange={(e) =>
                  setTagForm({ ...tagForm, asset_match_mode: e.target.value as "all" | "any" })
                }
              >
                <option value="all">Все перечисленные (AND)</option>
                <option value="any">Любой из перечисленных (OR)</option>
              </select>
              <label>Policy (опц.)</label>
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
              <label>TTL минут (опц., пусто = {tagEditId ? "оставить" : "постоянно"})</label>
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
                  Постоянно (снять TTL)
                </label>
              )}
              <div className="row" style={{ gap: "0.5rem", marginTop: "0.75rem" }}>
                <button className="btn" type="submit" disabled={busy}>
                  {tagEditId ? "Сохранить" : "Создать"}
                </button>
                {tagEditId && (
                  <button className="btn secondary" type="button" disabled={busy} onClick={resetTagForm}>
                    Отмена
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
