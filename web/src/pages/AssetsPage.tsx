import { useEffect, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import {
  connectButtonLabel,
  connectableAccounts,
  startAssetSession,
} from "../assetConnect";
import { api, ApiError, hasPerm, type Asset, type AssetAccount } from "../api";
import { useAuth } from "../auth";
import { useI18n } from "../i18n";
import {
  loadRdpResolutionId,
  rdpResolutionById,
  RDP_RESOLUTIONS,
  saveRdpResolutionId,
} from "../rdpResolution";
import { useSessionTabs } from "../sessionTabs";
import { StepUpDialog } from "./StepUpDialog";

const PROTOCOLS = ["ssh", "rdp", "vnc", "https", "postgres", "mysql", "mssql", "oracle", "kubectl", "telnet", "tn3270", "citrix"];
const TYPES = ["host", "db", "k8s", "api"];

function connectKey(assetId: string, accountId: string) {
  return `${assetId}:${accountId}`;
}

export function AssetsPage() {
  const { user } = useAuth();
  const { t, te } = useI18n();
  const { openTab } = useSessionTabs();
  const [assets, setAssets] = useState<Asset[]>([]);
  const [hiddenAssets, setHiddenAssets] = useState(0);
  const [licenseRestricted, setLicenseRestricted] = useState(false);
  const [licenseRestrictReason, setLicenseRestrictReason] = useState<"expired" | "unlicensed" | "">("");
  const [error, setError] = useState("");
  const [msg, setMsg] = useState("");
  const [connecting, setConnecting] = useState<string | null>(null);
  const [stepUp, setStepUp] = useState<{
    err: ApiError;
    retry: (token: string) => Promise<void>;
  } | null>(null);
  const [rdpResolutionId, setRdpResolutionId] = useState(loadRdpResolutionId);
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
  const canConnect = hasPerm(user, "sessions.connect");
  const hasRdpAssets = assets.some((a) => a.protocol === "rdp" && a.status === "active");

  function rdpSizeForConnect(protocol: string) {
    if (protocol !== "rdp") return {};
    const preset = rdpResolutionById(rdpResolutionId);
    return {
      rdp_width: preset.width > 0 ? preset.width : 0,
      rdp_height: preset.height > 0 ? preset.height : 0,
    };
  }

  async function load() {
    try {
      const res = await api.listAssets();
      setAssets(res.assets || []);
      setHiddenAssets(res.hidden || 0);
      if (res.license_expired) {
        setLicenseRestricted(true);
        setLicenseRestrictReason("expired");
      } else if (res.license_unlicensed) {
        setLicenseRestricted(true);
        setLicenseRestrictReason("unlicensed");
      } else {
        setLicenseRestricted(false);
        setLicenseRestrictReason("");
      }
    } catch (err) {
      setError(te(err, "assets.loadError"));
    }
  }

  useEffect(() => {
    void load();
  }, []);

  async function onConnect(asset: Asset, acc: AssetAccount, stepUpToken?: string) {
    setError("");
    setMsg("");
    const key = connectKey(asset.id, acc.id);
    setConnecting(key);
    try {
      const res = await startAssetSession(asset, acc, {
        step_up_token: stepUpToken,
        supervisorDenied: t("assets.supervisorDenied"),
        supervisorTimeout: t("assets.supervisorTimeout"),
        ...rdpSizeForConnect(asset.protocol),
      });
      setStepUp(null);
      if (res.msg) setMsg(res.msg);
      openTab({
        id: res.sessionId,
        kind: res.kind,
        title: res.title,
        protocol: res.protocol,
      });
    } catch (err) {
      if (!stepUpToken && ApiError.isStepUp(err)) {
        setStepUp({ err, retry: (tok) => onConnect(asset, acc, tok) });
        return;
      }
      setError(te(err, "assets.connectError"));
    } finally {
      setConnecting(null);
    }
  }

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
      {msg && <p className="muted">{msg}</p>}
      {licenseRestricted && hiddenAssets > 0 && (
        <p className="error" style={{ marginBottom: "1rem" }}>
          {t("assets.licenseHidden", {
            reason:
              licenseRestrictReason === "unlicensed" ? t("license.notInstalled") : t("license.expired"),
            shown: assets.length,
            total: assets.length + hiddenAssets,
          })}
        </p>
      )}
      {licenseRestricted && hiddenAssets === 0 && (
        <p className="muted" style={{ marginBottom: "1rem" }}>
          {t("assets.licenseGrace", {
            reason:
              licenseRestrictReason === "unlicensed" ? t("license.notInstalled") : t("license.expired"),
            max: 5,
          })}
        </p>
      )}
      {canConnect && hasRdpAssets && (
        <div className="card" style={{ marginBottom: "1rem", maxWidth: 360 }}>
          <label>{t("assets.rdpResolution")}</label>
          <select
            value={rdpResolutionId}
            onChange={(e) => {
              setRdpResolutionId(e.target.value);
              saveRdpResolutionId(e.target.value);
            }}
          >
            {RDP_RESOLUTIONS.map((r) => (
              <option key={r.id} value={r.id}>
                {r.label}
              </option>
            ))}
          </select>
          <p className="muted" style={{ marginTop: "0.35rem", marginBottom: 0 }}>
            {t("assets.rdpResolutionHint")}
          </p>
        </div>
      )}
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
          {(form.protocol === "postgres" || form.protocol === "mysql" || form.protocol === "mssql" || form.protocol === "oracle") && (
            <>
              <label>{form.protocol === "oracle" ? "Service / SID" : "Database"}</label>
              <input
                value={form.database_name}
                onChange={(e) => setForm({ ...form, database_name: e.target.value })}
                placeholder={
                  form.protocol === "postgres"
                    ? "postgres"
                    : form.protocol === "mssql"
                      ? "master"
                      : form.protocol === "oracle"
                        ? "ORCL"
                        : "(optional)"
                }
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
            {assets.map((a) => {
              const accounts = connectableAccounts(a);
              const multi = accounts.length > 1;
              return (
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
                    <div className="row" style={{ flexWrap: "wrap", gap: "0.35rem" }}>
                      {canConnect &&
                        accounts.map((acc) => {
                          const key = connectKey(a.id, acc.id);
                          return (
                            <button
                              key={acc.id}
                              className="btn"
                              type="button"
                              disabled={connecting === key}
                              onClick={() => void onConnect(a, acc)}
                              title={acc.username}
                            >
                              {connecting === key
                                ? "…"
                                : connectButtonLabel(a.protocol, t, acc, multi)}
                            </button>
                          );
                        })}
                      {canRead && (
                        <Link className="btn secondary" to={`/assets/${a.id}`}>
                          {t("common.open")}
                        </Link>
                      )}
                    </div>
                  </td>
                </tr>
              );
            })}
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
      {stepUp && (
        <StepUpDialog
          err={stepUp.err}
          onCancel={() => setStepUp(null)}
          onDone={(token: string) => void stepUp.retry(token)}
        />
      )}
    </div>
  );
}
