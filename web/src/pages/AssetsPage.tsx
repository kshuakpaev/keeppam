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

const PROTOCOLS = ["ssh", "rdp", "vnc", "https", "postgres", "mysql", "mssql", "oracle", "ftp", "kubectl", "telnet", "tn3270", "citrix"];
const TYPES = ["host", "db", "k8s", "api"];
const PAGE_SIZE_OPTIONS = [20, 50, 100, 200] as const;
const DEFAULT_PAGE_SIZE = 50;

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
  const [tab, setTab] = useState<"listed" | "archived">("listed");
  const [q, setQ] = useState("");
  const [appliedQ, setAppliedQ] = useState("");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(DEFAULT_PAGE_SIZE);
  const [total, setTotal] = useState(0);
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
  const canConnect = hasPerm(user, "sessions.connect") && tab === "listed";
  const canRequest = hasPerm(user, "access.request");
  const fullCatalog =
    hasPerm(user, "assets.write") ||
    hasPerm(user, "assets.acl") ||
    hasPerm(user, "users.write") ||
    hasPerm(user, "audit.read");
  const [browse, setBrowse] = useState<"entitled" | "catalog">("entitled");
  const hasRdpAssets = assets.some((a) => a.protocol === "rdp" && a.status === "active");

  function rdpSizeForConnect(protocol: string) {
    if (protocol !== "rdp") return {};
    const preset = rdpResolutionById(rdpResolutionId);
    return {
      rdp_width: preset.width > 0 ? preset.width : 0,
      rdp_height: preset.height > 0 ? preset.height : 0,
    };
  }

  async function load(nextPage = page, nextQ = appliedQ, nextSize = pageSize) {
    try {
      const offset = (nextPage - 1) * nextSize;
      const res = await api.listAssets({
        status: tab,
        q: nextQ || undefined,
        limit: nextSize,
        offset,
        scope: fullCatalog ? undefined : browse,
      });
      setAssets(res.assets || []);
      setHiddenAssets(res.hidden || 0);
      setTotal(res.total || 0);
      setPage(nextPage);
      setAppliedQ(nextQ);
      setPageSize(nextSize);
      if (tab === "listed" && res.license_expired) {
        setLicenseRestricted(true);
        setLicenseRestrictReason("expired");
      } else if (tab === "listed" && res.license_unlicensed) {
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
    void load(1, "", pageSize);
    // eslint-disable-next-line react-hooks/exhaustive-deps -- reload on tab/browse change only
  }, [tab, browse]);

  async function onArchive(asset: Asset) {
    if (!canWrite) return;
    if (!confirm(t("assets.archiveConfirm", { name: asset.name }))) return;
    setError("");
    try {
      await api.updateAsset(asset.id, { status: "archived" });
      setMsg(t("assets.archivedOk"));
      await load();
    } catch (err) {
      setError(te(err, "assets.archiveError"));
    }
  }

  async function onRestore(asset: Asset) {
    if (!canWrite) return;
    setError("");
    try {
      await api.updateAsset(asset.id, { status: "active" });
      setMsg(t("assets.restoredOk"));
      await load();
    } catch (err) {
      setError(te(err, "assets.restoreError"));
    }
  }

  async function onDeleteForever(asset: Asset) {
    if (!canWrite) return;
    if (!confirm(t("assets.deleteForeverConfirm", { name: asset.name }))) return;
    setError("");
    try {
      await api.deleteAsset(asset.id);
      setMsg(t("assets.deletedOk"));
      await load();
    } catch (err) {
      setError(te(err, "assets.deleteError"));
    }
  }

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
      if (!res.skipTab) {
        openTab({
          id: res.sessionId,
          kind: res.kind,
          title: res.title,
          protocol: res.protocol,
        });
      }
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

  async function onRequest(asset: Asset) {
    const reason = window.prompt(t("assets.reasonPh"));
    if (reason == null) return;
    const trimmed = reason.trim();
    if (!trimmed) return;
    setError("");
    setMsg("");
    try {
      await api.createAccessRequest(asset.id, { reason: trimmed, duration_minutes: 60 });
      setMsg(t("assets.requestSent"));
    } catch (err) {
      setError(te(err, "assets.requestError"));
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
          <p className="muted">{fullCatalog ? t("assets.lead") : t("assets.leadOperator")}</p>
        </div>
        {canWrite && tab === "listed" && (
          <button className="btn" type="button" onClick={() => setShowCreate((v) => !v)}>
            {showCreate ? t("common.cancel") : t("common.create")}
          </button>
        )}
      </div>
      <div className="row" style={{ gap: "0.5rem", marginBottom: "1rem" }}>
        <button
          className={`btn secondary${tab === "listed" ? " active" : ""}`}
          type="button"
          onClick={() => {
            setShowCreate(false);
            setQ("");
            setTab("listed");
          }}
        >
          {t("assets.tabActive")}
        </button>
        {canWrite && (
          <button
            className={`btn secondary${tab === "archived" ? " active" : ""}`}
            type="button"
            onClick={() => {
              setShowCreate(false);
              setQ("");
              setTab("archived");
            }}
          >
            {t("assets.tabArchive")}
          </button>
        )}
        {!fullCatalog && canRequest && tab === "listed" && (
          <>
            <button
              className={`btn secondary${browse === "entitled" ? " active" : ""}`}
              type="button"
              onClick={() => setBrowse("entitled")}
            >
              {t("assets.tabMine")}
            </button>
            <button
              className={`btn secondary${browse === "catalog" ? " active" : ""}`}
              type="button"
              onClick={() => setBrowse("catalog")}
            >
              {t("assets.tabCatalog")}
            </button>
          </>
        )}
      </div>
      <form
        className="row"
        style={{ gap: "0.5rem", marginBottom: "1rem", flexWrap: "wrap" }}
        onSubmit={(e) => {
          e.preventDefault();
          void load(1, q.trim(), pageSize);
        }}
      >
        <input
          placeholder={t("assets.searchPlaceholder")}
          value={q}
          onChange={(e) => setQ(e.target.value)}
          style={{ marginBottom: 0, flex: 1, minWidth: 180 }}
        />
        <button className="btn" type="submit">
          {t("common.find")}
        </button>
      </form>
      {error && <p className="error">{error}</p>}
      {msg && <p className="muted">{msg}</p>}
      {licenseRestricted && hiddenAssets > 0 && (
        <p className="error" style={{ marginBottom: "1rem" }}>
          {t("assets.licenseHidden", {
            reason:
              licenseRestrictReason === "unlicensed" ? t("license.notInstalled") : t("license.expired"),
            shown: Math.max(0, total - hiddenAssets),
            total,
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
      {showCreate && tab === "listed" && (
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
                    mssql: 1433,
                    oracle: 1521,
                    ftp: 21,
                    kubectl: 6443,
                    telnet: 23,
                    tn3270: 23,
                    citrix: 1494,
                  };
                  setForm({
                    ...form,
                    protocol,
                    port: ports[protocol] ?? 22,
                    database_name:
                      protocol === "postgres"
                        ? form.database_name || "postgres"
                        : protocol === "mssql"
                          ? form.database_name || "master"
                          : protocol === "oracle"
                            ? form.database_name || "ORCL"
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
                      {tab === "listed" &&
                        canConnect &&
                        (fullCatalog || a.entitled) &&
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
                      {tab === "listed" && canRequest && !fullCatalog && !a.entitled && (
                        <button className="btn secondary" type="button" onClick={() => void onRequest(a)}>
                          {t("assets.requestJit")}
                        </button>
                      )}
                      {canRead && (
                        <Link className="btn secondary" to={`/assets/${a.id}`}>
                          {t("common.open")}
                        </Link>
                      )}
                      {canWrite && tab === "listed" && (
                        <button className="btn secondary" type="button" onClick={() => void onArchive(a)}>
                          {t("assets.archive")}
                        </button>
                      )}
                      {canWrite && tab === "archived" && (
                        <>
                          <button className="btn" type="button" onClick={() => void onRestore(a)}>
                            {t("assets.restore")}
                          </button>
                          <button className="btn danger" type="button" onClick={() => void onDeleteForever(a)}>
                            {t("assets.deleteForever")}
                          </button>
                        </>
                      )}
                    </div>
                  </td>
                </tr>
              );
            })}
            {assets.length === 0 && (
              <tr>
                <td colSpan={7} className="muted">
                  {appliedQ
                    ? t("assets.searchEmpty")
                    : tab === "archived"
                      ? t("assets.archiveEmpty")
                      : !fullCatalog && browse === "entitled"
                        ? t("assets.emptyEntitled")
                        : t("assets.empty")}
                </td>
              </tr>
            )}
          </tbody>
        </table>
        {(() => {
          const cap = hiddenAssets > 0 ? Math.max(0, total - hiddenAssets) : total;
          const pages = cap > 0 ? Math.ceil(cap / pageSize) : 1;
          return (
            <div className="pager" style={{ marginTop: "0.75rem" }}>
              <span className="muted">
                {cap === 0
                  ? t("common.noRecords")
                  : t("common.pageOf", { page, pages, total: cap })}
              </span>
              <div className="row">
                <label className="row" style={{ gap: "0.35rem" }}>
                  <span className="muted">{t("audit.rowsPerPage")}</span>
                  <select
                    value={pageSize}
                    onChange={(e) => {
                      const n = Number(e.target.value);
                      void load(1, appliedQ, n);
                    }}
                    aria-label={t("audit.rowsPerPage")}
                    style={{ marginBottom: 0, width: 90 }}
                  >
                    {PAGE_SIZE_OPTIONS.map((n) => (
                      <option key={n} value={n}>
                        {n}
                      </option>
                    ))}
                  </select>
                </label>
                <button
                  className="btn secondary"
                  type="button"
                  disabled={page <= 1}
                  onClick={() => void load(1, appliedQ, pageSize)}
                >
                  {t("audit.first")}
                </button>
                <button
                  className="btn secondary"
                  type="button"
                  disabled={page <= 1}
                  onClick={() => void load(page - 1, appliedQ, pageSize)}
                >
                  {t("audit.prev")}
                </button>
                <button
                  className="btn secondary"
                  type="button"
                  disabled={page >= pages}
                  onClick={() => void load(page + 1, appliedQ, pageSize)}
                >
                  {t("audit.next")}
                </button>
                <button
                  className="btn secondary"
                  type="button"
                  disabled={page >= pages}
                  onClick={() => void load(pages, appliedQ, pageSize)}
                >
                  {t("audit.last")}
                </button>
              </div>
            </div>
          );
        })()}
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
