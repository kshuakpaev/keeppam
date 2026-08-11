import { useEffect, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { api, hasPerm, type Asset } from "../api";
import { useAuth } from "../auth";

const PROTOCOLS = ["ssh", "rdp", "vnc", "https", "postgres", "mysql"];
const TYPES = ["host", "db", "k8s", "api"];

export function AssetsPage() {
  const { user } = useAuth();
  const [assets, setAssets] = useState<Asset[]>([]);
  const [error, setError] = useState("");
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({
    name: "",
    asset_type: "host",
    hostname: "",
    address: "",
    port: 22,
    protocol: "ssh",
    description: "",
    tags: "",
  });

  const canWrite = hasPerm(user, "assets.write");
  const canRead = hasPerm(user, "assets.read");

  async function load() {
    try {
      const res = await api.listAssets();
      setAssets(res.assets || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка загрузки");
    }
  }

  useEffect(() => {
    void load();
  }, []);

  async function onCreate(e: FormEvent) {
    e.preventDefault();
    setError("");
    try {
      await api.createAsset({
        name: form.name,
        asset_type: form.asset_type,
        hostname: form.hostname,
        address: form.address,
        port: Number(form.port) || 22,
        protocol: form.protocol,
        description: form.description,
        tags: form.tags
          .split(",")
          .map((t) => t.trim())
          .filter(Boolean),
      });
      setShowCreate(false);
      setForm({
        name: "",
        asset_type: "host",
        hostname: "",
        address: "",
        port: 22,
        protocol: "ssh",
        description: "",
        tags: "",
      });
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка создания");
    }
  }

  return (
    <div>
      <div className="toolbar">
        <div>
          <h1>Активы</h1>
          <p className="muted">Целевые хосты и сервисы для привилегированного доступа</p>
        </div>
        {canWrite && (
          <button className="btn" type="button" onClick={() => setShowCreate((v) => !v)}>
            {showCreate ? "Отмена" : "Создать"}
          </button>
        )}
      </div>
      {error && <p className="error">{error}</p>}
      {showCreate && (
        <form className="card" onSubmit={onCreate} style={{ marginBottom: "1rem", maxWidth: 560 }}>
          <h2>Новый актив</h2>
          <label>Имя</label>
          <input
            value={form.name}
            onChange={(e) => setForm({ ...form, name: e.target.value })}
            required
          />
          <label>Тип</label>
          <select
            value={form.asset_type}
            onChange={(e) => setForm({ ...form, asset_type: e.target.value })}
          >
            {TYPES.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
          <label>Адрес (IP / FQDN)</label>
          <input
            value={form.address}
            onChange={(e) => setForm({ ...form, address: e.target.value })}
            required
          />
          <label>Hostname (опц.)</label>
          <input
            value={form.hostname}
            onChange={(e) => setForm({ ...form, hostname: e.target.value })}
          />
          <div className="row" style={{ alignItems: "flex-end" }}>
            <div style={{ flex: 1 }}>
              <label>Протокол</label>
              <select
                value={form.protocol}
                onChange={(e) => {
                  const protocol = e.target.value;
                  const ports: Record<string, number> = {
                    ssh: 22,
                    rdp: 3389,
                    vnc: 5900,
                    https: 443,
                    postgres: 5432,
                    mysql: 3306,
                  };
                  setForm({ ...form, protocol, port: ports[protocol] ?? 22 });
                }}
              >
                {PROTOCOLS.map((p) => (
                  <option key={p} value={p}>
                    {p}
                  </option>
                ))}
              </select>
            </div>
            <div style={{ width: 120 }}>
              <label>Порт</label>
              <input
                type="number"
                value={form.port}
                onChange={(e) => setForm({ ...form, port: Number(e.target.value) })}
                required
              />
            </div>
          </div>
          <label>Теги (через запятую)</label>
          <input
            value={form.tags}
            onChange={(e) => setForm({ ...form, tags: e.target.value })}
            placeholder="prod, db, linux"
          />
          <label>Описание</label>
          <input
            value={form.description}
            onChange={(e) => setForm({ ...form, description: e.target.value })}
          />
          <button className="btn" type="submit">
            Создать
          </button>
        </form>
      )}
      <div className="card">
        <table>
          <thead>
            <tr>
              <th>Имя</th>
              <th>Адрес</th>
              <th>Протокол</th>
              <th>Тип</th>
              <th>Статус</th>
              <th>Теги</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {assets.map((a) => (
              <tr key={a.id}>
                <td>{canRead ? <Link to={`/assets/${a.id}`}>{a.name}</Link> : a.name}</td>
                <td className="mono">
                  {a.address}:{a.port}
                </td>
                <td className="mono">{a.protocol}</td>
                <td className="mono">{a.asset_type}</td>
                <td>
                  <span className={`badge ${a.status}`}>{a.status}</span>
                </td>
                <td className="mono">{(a.tags || []).join(", ") || "—"}</td>
                <td>
                  {canRead && (
                    <Link className="btn secondary" to={`/assets/${a.id}`}>
                      Открыть
                    </Link>
                  )}
                </td>
              </tr>
            ))}
            {assets.length === 0 && (
              <tr>
                <td colSpan={7} className="muted">
                  Активов пока нет
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
