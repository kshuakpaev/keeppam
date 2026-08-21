import { useEffect, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { api, hasPerm, type Asset } from "../api";
import { useAuth } from "../auth";
import { useI18n } from "../i18n";

const PROTOCOLS = ["ssh", "rdp", "vnc", "https", "postgres", "mysql", "mssql", "kubectl", "telnet", "tn3270", "citrix"];
const TYPES = ["host", "db", "k8s", "api"];

export function AssetsPage() {
  const { user } = useAuth();
  const { t, te } = useI18n();
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
    database_name: "",
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
      setError(te(err, "assets.loadError"));
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
        database_name: form.database_name || undefined,
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
        database_name: "",
        description: "",
        tags: "",
      });
      await load();
    } catch (err) {
      setError(te(err, "assets.createError"));
    }
  }

  return (
    <div>
      <div className="toolbar">
        <div>
          <h1>{t("assets.title")}</h1>
          <p className="muted">{t("assets.lead")}</p>
        </div>
        {canWrite && (
          <button className="btn" type="button" onClick={() => setShowCreate((v) => !v)}>
            {showCreate ? t("common.cancel") : t("common.create")}
          </button>
        )}
      </div>
      {error && <p className="error">{error}</p>}
      {showCreate && (
        <form className="card" onSubmit={onCreate} style={{ marginBottom: "1rem", maxWidth: 560 }}>
          <h2>{t("assets.new")}</h2>
          <label>{t("common.name")}</label>
          <input
            value={form.name}
            onChange={(e) => setForm({ ...form, name: e.target.value })}
            required
          />
          <label>{t("common.type")}</label>
          <select
            value={form.asset_type}
            onChange={(e) => {
              const asset_type = e.target.value;
              if (asset_type === "k8s") {
                setForm({ ...form, asset_type, protocol: "kubectl", port: 6443 });
              } else if (asset_type === "db") {
                setForm({ ...form, asset_type, protocol: "postgres", port: 5432, database_name: form.database_name || "postgres" });
              } else if (asset_type === "api") {
                setForm({ ...form, asset_type, protocol: "https", port: 443 });
              } else {
                setForm({ ...form, asset_type });
              }
            }}
          >
            {TYPES.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
          <label>{t("common.address")} (IP / FQDN)</label>
          <input
            value={form.address}
            onChange={(e) => setForm({ ...form, address: e.target.value })}
            required
          />
          <label>{t("assets.hostnameOpt")}</label>
          <input
            value={form.hostname}
            onChange={(e) => setForm({ ...form, hostname: e.target.value })}
          />
          <div className="row" style={{ alignItems: "flex-end" }}>
            <div style={{ flex: 1 }}>
              <label>{t("common.protocol")}</label>
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
                    kubectl: 6443,
                  };
                  setForm({
                    ...form,
                    protocol,
                    port: ports[protocol] ?? 22,
                    database_name:
                      protocol === "postgres"
                        ? form.database_name || "postgres"
                        : protocol === "mysql"
                          ? form.database_name
                          : "",
                  });
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
              <label>{t("common.port")}</label>
              <input
                type="number"
                value={form.port}
                onChange={(e) => setForm({ ...form, port: Number(e.target.value) })}
                required
              />
            </div>
          </div>
          {(form.protocol === "postgres" || form.protocol === "mysql" || form.protocol === "mssql") && (
            <>
              <label>Database</label>
              <input
                value={form.database_name}
                onChange={(e) => setForm({ ...form, database_name: e.target.value })}
                placeholder={form.protocol === "postgres" ? "postgres" : form.protocol === "mssql" ? "master" : "(optional)"}
              />
            </>
          )}
          <label>{t("assets.tagsHint")}</label>
          <input
            value={form.tags}
            onChange={(e) => setForm({ ...form, tags: e.target.value })}
          placeholder="prod/linux, db"
          />
          <label>{t("common.description")}</label>
          <input
            value={form.description}
            onChange={(e) => setForm({ ...form, description: e.target.value })}
          />
          <button className="btn" type="submit">
            {t("common.create")}
          </button>
        </form>
      )}
      <div className="card">
        <table>
          <thead>
            <tr>
              <th>{t("common.name")}</th>
              <th>{t("common.address")}</th>
              <th>{t("common.protocol")}</th>
              <th>{t("common.type")}</th>
              <th>{t("common.status")}</th>
              <th>{t("common.tags")}</th>
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
                      {t("common.open")}
                    </Link>
                  )}
                </td>
              </tr>
            ))}
            {assets.length === 0 && (
              <tr>
                <td colSpan={7} className="muted">
                  {t("assets.empty")}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
