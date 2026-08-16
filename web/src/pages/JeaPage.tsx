import { useEffect, useState, type FormEvent } from "react";
import { api, hasPerm, type CommandPolicyPack, type HTTPPolicyPack, type SQLPolicyPack } from "../api";
import { useAuth } from "../auth";

export function JeaPage() {
  const { user } = useAuth();
  const canRead = hasPerm(user, "jea.read");
  const canWrite = hasPerm(user, "jea.write");
  const [tab, setTab] = useState<"ssh" | "sql" | "http">("ssh");
  const [packs, setPacks] = useState<CommandPolicyPack[]>([]);
  const [sqlPacks, setSqlPacks] = useState<SQLPolicyPack[]>([]);
  const [httpPacks, setHttpPacks] = useState<HTTPPolicyPack[]>([]);
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

  async function load() {
    setError("");
    try {
      const [cmd, sql, http] = await Promise.all([
        api.listCommandPacks(),
        api.listSQLPacks(),
        api.listHTTPPacks(),
      ]);
      setPacks(cmd.packs || []);
      setSqlPacks(sql.packs || []);
      setHttpPacks(http.packs || []);
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

  return (
    <div>
      <h1>JEA</h1>
      <p className="muted">
        SSH command packs, SQL table/mask packs и HTTP/URL ACL. Привязка — в ACL на карточке актива.
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
              Isolated browser (VNC) не видит HTTP ACL.
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
    </div>
  );
}
