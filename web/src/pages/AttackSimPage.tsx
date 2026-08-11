import { useEffect, useState } from "react";
import { api, hasPerm, type AttackSimRun, type AttackSimScenario } from "../api";
import { useAuth } from "../auth";

export function AttackSimPage() {
  const { user } = useAuth();
  const canRead = hasPerm(user, "attacksim.read");
  const canWrite = hasPerm(user, "attacksim.write");
  const [scenarios, setScenarios] = useState<AttackSimScenario[]>([]);
  const [runs, setRuns] = useState<AttackSimRun[]>([]);
  const [selected, setSelected] = useState<AttackSimRun | null>(null);
  const [notes, setNotes] = useState("");
  const [error, setError] = useState("");
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState(false);

  async function load() {
    setError("");
    try {
      const [sc, rn] = await Promise.all([api.listAttackScenarios(), api.listAttackRuns()]);
      setScenarios(sc.scenarios || []);
      setRuns(rn.runs || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка загрузки");
    }
  }

  useEffect(() => {
    if (!canRead) return;
    void load();
  }, [canRead]);

  if (!canRead) {
    return <p className="error">Недостаточно прав (attacksim.read)</p>;
  }

  async function startRun() {
    if (!canWrite) return;
    setBusy(true);
    setError("");
    setMsg("");
    try {
      const run = await api.startAttackRun({ notes });
      setSelected(run);
      setMsg(`Прогон ${run.status}: pass=${run.summary?.pass ?? "?"} fail=${run.summary?.fail ?? "?"}`);
      setNotes("");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка запуска");
    } finally {
      setBusy(false);
    }
  }

  async function openRun(id: string) {
    setError("");
    try {
      const run = await api.getAttackRun(id);
      setSelected(run);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка");
    }
  }

  return (
    <div>
      <h1>Attack simulation</h1>
      <p className="muted">
        Безопасные проверки контролей KeepPAM (auth deny, JEA packs, ACL deny-by-default, schema). Не атакует
        целевые хосты.
      </p>
      {error && <p className="error">{error}</p>}
      {msg && <p className="ok">{msg}</p>}

      <div className="card" style={{ marginBottom: "1.25rem" }}>
        <h2>Сценарии ({scenarios.length})</h2>
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Категория</th>
              <th>Название</th>
            </tr>
          </thead>
          <tbody>
            {scenarios.map((s) => (
              <tr key={s.id}>
                <td className="mono" style={{ fontSize: "0.8rem" }}>
                  {s.id}
                </td>
                <td>{s.category}</td>
                <td>
                  {s.title}
                  <div className="muted" style={{ fontSize: "0.85rem" }}>
                    {s.description}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {canWrite && (
          <div className="row" style={{ gap: "0.5rem", marginTop: "1rem", alignItems: "flex-end" }}>
            <div style={{ flex: 1 }}>
              <label>Заметки к прогону</label>
              <input value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="квартальный drill" />
            </div>
            <button className="btn" type="button" disabled={busy} onClick={() => void startRun()}>
              Запустить suite
            </button>
          </div>
        )}
      </div>

      <div className="card" style={{ marginBottom: "1.25rem" }}>
        <h2>История прогонов</h2>
        <table>
          <thead>
            <tr>
              <th>Когда</th>
              <th>Статус</th>
              <th>Summary</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {runs.map((r) => (
              <tr key={r.id}>
                <td className="mono">{new Date(r.started_at).toLocaleString()}</td>
                <td>{r.status}</td>
                <td className="mono" style={{ fontSize: "0.85rem" }}>
                  pass={String(r.summary?.pass ?? "—")} fail={String(r.summary?.fail ?? "—")} skip=
                  {String(r.summary?.skip ?? "—")}
                </td>
                <td>
                  <button className="btn secondary" type="button" onClick={() => void openRun(r.id)}>
                    Открыть
                  </button>
                </td>
              </tr>
            ))}
            {runs.length === 0 && (
              <tr>
                <td colSpan={4} className="muted">
                  Прогонов ещё не было
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {selected && (
        <div className="card">
          <h2>
            Прогон <span className="mono">{selected.id.slice(0, 8)}</span> · {selected.status}
          </h2>
          {selected.notes && <p className="muted">{selected.notes}</p>}
          <table>
            <thead>
              <tr>
                <th>Сценарий</th>
                <th>Статус</th>
                <th>Деталь</th>
                <th>ms</th>
              </tr>
            </thead>
            <tbody>
              {(selected.results || []).map((res) => (
                <tr key={res.id}>
                  <td>
                    <span className="mono">{res.scenario_id}</span>
                    <div className="muted" style={{ fontSize: "0.85rem" }}>
                      {res.title}
                    </div>
                  </td>
                  <td>{res.status}</td>
                  <td style={{ fontSize: "0.85rem" }}>{res.detail}</td>
                  <td className="mono">{res.duration_ms}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
