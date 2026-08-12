import { useEffect, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { api, hasPerm, type DiscoveryCandidate, type DiscoveryJob } from "../api";
import { useAuth } from "../auth";

type ScanKind = "network" | "accounts";

export function DiscoveryPage() {
  const { user } = useAuth();
  const [jobs, setJobs] = useState<DiscoveryJob[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [candidates, setCandidates] = useState<DiscoveryCandidate[]>([]);
  const [scanKind, setScanKind] = useState<ScanKind>("network");
  const [cidr, setCidr] = useState("127.0.0.1");
  const [ports, setPorts] = useState("22,3389,5900");
  const [error, setError] = useState("");
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState(false);

  const canRead = hasPerm(user, "discovery.read");
  const canRun = hasPerm(user, "discovery.run");
  const canImport = hasPerm(user, "assets.write");

  async function loadJobs() {
    try {
      const res = await api.listDiscoveryJobs();
      setJobs(res.jobs || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка загрузки");
    }
  }

  async function loadCandidates(jobId: string) {
    try {
      const res = await api.listDiscoveryCandidates(jobId);
      setCandidates(res.candidates || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка кандидатов");
    }
  }

  useEffect(() => {
    if (!canRead) return;
    void loadJobs();
    const t = setInterval(() => {
      void loadJobs();
      if (selected) void loadCandidates(selected);
    }, 2000);
    return () => clearInterval(t);
  }, [canRead, selected]);

  if (!canRead) {
    return <p className="error">Недостаточно прав</p>;
  }

  async function onStart(e: FormEvent) {
    e.preventDefault();
    if (!canRun) return;
    setBusy(true);
    setError("");
    setMsg("");
    try {
      const job =
        scanKind === "accounts"
          ? await api.createDiscoveryJob({ kind: "accounts" })
          : await api.createDiscoveryJob({ kind: "network", cidr, ports });
      setMsg(
        scanKind === "accounts"
          ? `Account discovery запущен (${job.total_hosts} SSH-активов)`
          : `Скан запущен: ${job.cidr}`,
      );
      setSelected(job.id);
      await loadJobs();
      await loadCandidates(job.id);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка запуска");
    } finally {
      setBusy(false);
    }
  }

  async function onImport(c: DiscoveryCandidate) {
    if (!canImport) return;
    setError("");
    try {
      const res = await api.importDiscoveryCandidate(c.id);
      if (res.kind === "account" && res.account) {
        setMsg(`Импортирована учётка ${res.account.username}`);
      } else if (res.asset) {
        setMsg(`Импортирован актив ${res.asset.name}`);
      } else {
        setMsg("Импорт выполнен");
      }
      if (selected) await loadCandidates(selected);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка импорта");
    }
  }

  const active = jobs.find((j) => j.id === selected) || null;
  const accountsMode = (active?.kind || "") === "accounts" || candidates.some((c) => !!c.username);

  return (
    <div>
      <div className="toolbar">
        <div>
          <h1>Discovery</h1>
          <p className="muted">Сеть (TCP) и учётные записи на SSH-активах</p>
        </div>
      </div>
      {error && <p className="error">{error}</p>}
      {msg && <p className="ok">{msg}</p>}

      {canRun && (
        <form className="card" onSubmit={onStart} style={{ maxWidth: 560, marginBottom: "1.25rem" }}>
          <h2>Новый скан</h2>
          <label>Тип</label>
          <select value={scanKind} onChange={(e) => setScanKind(e.target.value as ScanKind)}>
            <option value="network">Сеть (TCP / хосты)</option>
            <option value="accounts">Учётки (SSH account discovery)</option>
          </select>
          {scanKind === "network" ? (
            <>
              <label>CIDR / IP / диапазон</label>
              <input
                value={cidr}
                onChange={(e) => setCidr(e.target.value)}
                placeholder="192.168.1.0/24 или 10.0.0.1-50"
                required
              />
              <label>Порты (через запятую)</label>
              <input value={ports} onChange={(e) => setPorts(e.target.value)} placeholder="22,3389,5900" />
              <p className="muted">Лимит: 1024 хоста. 22→ssh, 3389→rdp, 5900→vnc.</p>
            </>
          ) : (
            <p className="muted">
              Обходит активные SSH-активы с vault-секретом, читает <span className="mono">getent passwd</span> /
              <span className="mono"> /etc/passwd</span>. Импорт создаёт учётку без секрета (нужна ротация /
              checkout).
            </p>
          )}
          <button className="btn" type="submit" disabled={busy}>
            {busy ? "…" : "Запустить"}
          </button>
        </form>
      )}

      <div className="card" style={{ marginBottom: "1.25rem" }}>
        <h2>Задания</h2>
        <table>
          <thead>
            <tr>
              <th>Тип</th>
              <th>Scope</th>
              <th>Статус</th>
              <th>Прогресс</th>
              <th>Найдено</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {jobs.map((j) => (
              <tr key={j.id}>
                <td className="mono">{j.kind || "network"}</td>
                <td className="mono">{j.kind === "accounts" ? j.cidr : `${j.cidr} · ${j.ports}`}</td>
                <td>
                  <span className={`badge ${j.status === "done" ? "active" : j.status === "failed" ? "locked" : ""}`}>
                    {j.status}
                  </span>
                </td>
                <td className="mono">
                  {j.scanned_hosts}/{j.total_hosts}
                </td>
                <td className="mono">{j.open_ports}</td>
                <td>
                  <button
                    className="btn secondary"
                    type="button"
                    onClick={() => {
                      setSelected(j.id);
                      void loadCandidates(j.id);
                    }}
                  >
                    Кандидаты
                  </button>
                </td>
              </tr>
            ))}
            {jobs.length === 0 && (
              <tr>
                <td colSpan={6} className="muted">
                  Нет заданий
                </td>
              </tr>
            )}
          </tbody>
        </table>
        {active?.error && <p className="error">Ошибка задания: {active.error}</p>}
      </div>

      {selected && (
        <div className="card">
          <h2>Кандидаты</h2>
          <table>
            <thead>
              <tr>
                {accountsMode ? (
                  <>
                    <th>Хост</th>
                    <th>Username</th>
                    <th>Priv</th>
                    <th>Детали</th>
                    <th>Статус</th>
                    <th />
                  </>
                ) : (
                  <>
                    <th>Адрес</th>
                    <th>Порт</th>
                    <th>Протокол</th>
                    <th>Статус</th>
                    <th />
                  </>
                )}
              </tr>
            </thead>
            <tbody>
              {candidates.map((c) =>
                accountsMode || c.username ? (
                  <tr key={c.id}>
                    <td className="mono">
                      {c.source_asset_id ? (
                        <Link to={`/assets/${c.source_asset_id}`}>{c.address}:{c.port}</Link>
                      ) : (
                        `${c.address}:${c.port}`
                      )}
                    </td>
                    <td className="mono">{c.username}</td>
                    <td>{c.privileged ? <span className="badge locked">priv</span> : "—"}</td>
                    <td className="muted mono" style={{ fontSize: "0.85rem" }}>
                      {c.details
                        ? `uid=${String(c.details.uid ?? "")} shell=${String(c.details.shell ?? "")}`
                        : ""}
                    </td>
                    <td>
                      {c.imported_account_id ? (
                        <span className="badge active">импортирован</span>
                      ) : c.already_known ? (
                        <span className="muted">уже в vault</span>
                      ) : (
                        <span className="badge active">новый</span>
                      )}
                    </td>
                    <td>
                      {canImport && !c.imported_account_id && !c.already_known && (
                        <button className="btn" type="button" onClick={() => void onImport(c)}>
                          Импорт
                        </button>
                      )}
                    </td>
                  </tr>
                ) : (
                  <tr key={c.id}>
                    <td className="mono">{c.address}</td>
                    <td className="mono">{c.port}</td>
                    <td className="mono">{c.protocol}</td>
                    <td>
                      {c.imported_asset_id ? (
                        <Link to={`/assets/${c.imported_asset_id}`}>импортирован</Link>
                      ) : c.already_known ? (
                        <span className="muted">уже в inventory</span>
                      ) : (
                        <span className="badge active">новый</span>
                      )}
                    </td>
                    <td>
                      {canImport && !c.imported_asset_id && (
                        <button className="btn" type="button" onClick={() => void onImport(c)}>
                          Импорт
                        </button>
                      )}
                    </td>
                  </tr>
                ),
              )}
              {candidates.length === 0 && (
                <tr>
                  <td colSpan={6} className="muted">
                    {active?.status === "running" || active?.status === "pending"
                      ? "Скан ещё идёт…"
                      : accountsMode
                        ? "Учёток не найдено (нужны SSH-активы с секретом)"
                        : "Открытых портов не найдено"}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
