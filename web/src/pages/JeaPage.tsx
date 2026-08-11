import { useEffect, useState, type FormEvent } from "react";
import { api, hasPerm, type CommandPolicyPack } from "../api";
import { useAuth } from "../auth";

export function JeaPage() {
  const { user } = useAuth();
  const canRead = hasPerm(user, "jea.read");
  const canWrite = hasPerm(user, "jea.write");
  const [packs, setPacks] = useState<CommandPolicyPack[]>([]);
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

  async function load() {
    setError("");
    try {
      const res = await api.listCommandPacks();
      setPacks(res.packs || []);
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
        setMsg("Пакет обновлён");
      } else {
        await api.createCommandPack(body);
        setMsg("Пакет создан");
      }
      resetForm();
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
    setError("");
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

  return (
    <div>
      <h1>JEA / Command policy</h1>
      <p className="muted">
        Пакеты allowlist/denylist для SSH-сессий. Привяжите пакет к ACL на карточке актива — фильтрация
        команд работает в браузерном терминале и на SSH gateway :2222.
      </p>
      {error && <p className="error">{error}</p>}
      {msg && <p className="ok">{msg}</p>}

      <div className="card" style={{ marginBottom: "1.25rem" }}>
        <h2>Пакеты</h2>
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
            {packs.length === 0 && (
              <tr>
                <td colSpan={4} className="muted">
                  Пакетов нет
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {canWrite && (
        <form className="card" onSubmit={onSubmit} style={{ maxWidth: 560 }}>
          <h2>{editId ? "Редактировать пакет" : "Новый пакет"}</h2>
          <label>Имя</label>
          <input
            required
            value={form.name}
            onChange={(e) => setForm({ ...form, name: e.target.value })}
            placeholder="readonly-linux"
            disabled={!!editId}
          />
          <label>Описание</label>
          <input
            value={form.description}
            onChange={(e) => setForm({ ...form, description: e.target.value })}
          />
          <label>Режим</label>
          <select value={form.mode} onChange={(e) => setForm({ ...form, mode: e.target.value })}>
            <option value="allowlist">allowlist — только совпадения</option>
            <option value="denylist">denylist — запрет совпадений</option>
          </select>
          <label>Паттерны (по одному в строке, glob)</label>
          <textarea
            rows={10}
            value={form.patterns}
            onChange={(e) => setForm({ ...form, patterns: e.target.value })}
            placeholder={"ls\ncat *\nrm *"}
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
    </div>
  );
}
