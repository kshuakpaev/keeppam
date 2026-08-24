import { useEffect, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { api, hasPerm, type DiscoveryCandidate, type DiscoveryJob } from "../api";
import { useAuth } from "../auth";
import { useI18n } from "../i18n";

type ScanKind = "network" | "accounts" | "ad_accounts" | "winrm_accounts";

export function DiscoveryPage() {
  const { user } = useAuth();
  const { t, te } = useI18n();
  const [jobs, setJobs] = useState<DiscoveryJob[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [candidates, setCandidates] = useState<DiscoveryCandidate[]>([]);
  const [scanKind, setScanKind] = useState<ScanKind>("network");
  const [cidr, setCidr] = useState("127.0.0.1");
  const [ports, setPorts] = useState("22,3389,5900");
  const [targetAssetId, setTargetAssetId] = useState("");
  const [assets, setAssets] = useState<{ id: string; name: string; protocol: string }[]>([]);
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
      setError(te(err, "discovery.loadError"));
    }
  }

  async function loadCandidates(jobId: string) {
    try {
      const res = await api.listDiscoveryCandidates(jobId);
      setCandidates(res.candidates || []);
    } catch (err) {
      setError(te(err, "discovery.candidatesError"));
    }
  }

  useEffect(() => {
    if (!canRead) return;
    void loadJobs();
    void api.listAssets().then((r) => setAssets(r.assets || [])).catch(() => {});
    const timer = setInterval(() => {
      void loadJobs();
      if (selected) void loadCandidates(selected);
    }, 2000);
    return () => clearInterval(timer);
  }, [canRead, selected]);

  if (!canRead) {
    return <p className="error">{t("common.forbidden")}</p>;
  }

  async function onStart(e: FormEvent) {
    e.preventDefault();
    if (!canRun) return;
    setBusy(true);
    setError("");
    setMsg("");
    try {
      let job: DiscoveryJob;
      if (scanKind === "accounts") {
        job = await api.createDiscoveryJob({ kind: "accounts" });
        setMsg(t("discovery.msg.accountsStarted", { count: job.total_hosts }));
      } else if (scanKind === "ad_accounts") {
        job = await api.createDiscoveryJob({
          kind: "ad_accounts",
          target_asset_id: targetAssetId || undefined,
        });
        setMsg(t("discovery.msg.adStarted"));
      } else if (scanKind === "winrm_accounts") {
        job = await api.createDiscoveryJob({
          kind: "winrm_accounts",
          ports: ports || "winrm,sam",
        });
        setMsg(t("discovery.msg.winrmStarted", { count: job.total_hosts }));
      } else {
        job = await api.createDiscoveryJob({ kind: "network", cidr, ports });
        setMsg(t("discovery.msg.networkStarted", { cidr: job.cidr }));
      }
      setSelected(job.id);
      await loadJobs();
      await loadCandidates(job.id);
    } catch (err) {
      setError(te(err, "discovery.startError"));
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
        setMsg(t("discovery.accountImported", { username: res.account.username }));
      } else if (res.asset) {
        setMsg(t("discovery.assetImported", { name: res.asset.name }));
      } else {
        setMsg(t("discovery.importDone"));
      }
      if (selected) await loadCandidates(selected);
    } catch (err) {
      setError(te(err, "discovery.importError"));
    }
  }

  const active = jobs.find((j) => j.id === selected) || null;
  const accountsMode =
    (active?.kind || "") === "accounts" ||
    (active?.kind || "") === "ad_accounts" ||
    (active?.kind || "") === "winrm_accounts" ||
    candidates.some((c) => !!c.username);

  return (
    <div>
      <div className="toolbar">
        <div>
          <h1>{t("nav.discovery")}</h1>
          <p className="muted">{t("discovery.lead")}</p>
        </div>
      </div>
      {error && <p className="error">{error}</p>}
      {msg && <p className="ok">{msg}</p>}

      {canRun && (
        <form className="card" onSubmit={onStart} style={{ maxWidth: 560, marginBottom: "1.25rem" }}>
          <h2>{t("discovery.newScan")}</h2>
          <label>{t("common.type")}</label>
          <select value={scanKind} onChange={(e) => setScanKind(e.target.value as ScanKind)}>
            <option value="network">{t("discovery.scanNetwork")}</option>
            <option value="accounts">{t("discovery.scanAccounts")}</option>
            <option value="ad_accounts">{t("discovery.scanAd")}</option>
            <option value="winrm_accounts">{t("discovery.scanWinrm")}</option>
          </select>
          {scanKind === "network" ? (
            <>
              <label>{t("discovery.cidrLabel")}</label>
              <input
                value={cidr}
                onChange={(e) => setCidr(e.target.value)}
                placeholder={t("discovery.cidrPlaceholder")}
                required
              />
              <label>{t("discovery.portsLabel")}</label>
              <input value={ports} onChange={(e) => setPorts(e.target.value)} placeholder="22,3389,5900" />
              <p className="muted">{t("discovery.networkHint")}</p>
            </>
          ) : scanKind === "winrm_accounts" ? (
            <>
              <label>{t("discovery.winrmModeLabel")}</label>
              <input value={ports} onChange={(e) => setPorts(e.target.value)} placeholder="winrm,sam" />
              <p className="muted">{t("discovery.winrmHint")}</p>
            </>
          ) : scanKind === "ad_accounts" ? (
            <>
              <label>{t("discovery.adAssetLabel")}</label>
              <select value={targetAssetId} onChange={(e) => setTargetAssetId(e.target.value)}>
                <option value="">{t("discovery.adAssetOption")}</option>
                {assets.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.name} ({a.protocol})
                  </option>
                ))}
              </select>
              <p className="muted">{t("discovery.adHint")}</p>
            </>
          ) : (
            <p className="muted">{t("discovery.sshHint")}</p>
          )}
          <button className="btn" type="submit" disabled={busy}>
            {busy ? "…" : t("discovery.run")}
          </button>
        </form>
      )}

      <div className="card" style={{ marginBottom: "1.25rem" }}>
        <h2>{t("discovery.jobs")}</h2>
        <table>
          <thead>
            <tr>
              <th>{t("common.type")}</th>
              <th>{t("discovery.scope")}</th>
              <th>{t("common.status")}</th>
              <th>{t("discovery.progress")}</th>
              <th>{t("discovery.found")}</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {jobs.map((j) => (
              <tr key={j.id}>
                <td className="mono">{j.kind || "network"}</td>
                <td className="mono">
                  {j.kind === "accounts" || j.kind === "ad_accounts" || j.kind === "winrm_accounts"
                    ? j.cidr
                    : `${j.cidr} · ${j.ports}`}
                </td>
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
                    {t("discovery.candidates")}
                  </button>
                </td>
              </tr>
            ))}
            {jobs.length === 0 && (
              <tr>
                <td colSpan={6} className="muted">
                  {t("discovery.noJobs")}
                </td>
              </tr>
            )}
          </tbody>
        </table>
        {active?.error && <p className="error">{t("discovery.jobError", { error: active.error })}</p>}
      </div>

      {selected && (
        <div className="card">
          <h2>{t("discovery.candidates")}</h2>
          <table>
            <thead>
              <tr>
                {accountsMode ? (
                  <>
                    <th>{t("discovery.host")}</th>
                    <th>Username</th>
                    <th>{t("discovery.priv")}</th>
                    <th>{t("discovery.details")}</th>
                    <th>{t("common.status")}</th>
                    <th />
                  </>
                ) : (
                  <>
                    <th>{t("common.address")}</th>
                    <th>{t("common.port")}</th>
                    <th>{t("common.protocol")}</th>
                    <th>{t("common.status")}</th>
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
                      {c.protocol === "ldap" && c.details
                        ? `dn=${String(c.details.dn ?? "").slice(0, 48)}${String(c.details.dn ?? "").length > 48 ? "…" : ""} · ${(Array.isArray(c.details.reasons) ? c.details.reasons : []).join(",")}`
                        : c.protocol === "winrm" && c.details
                          ? `sid=${String(c.details.sid ?? "")} · ${String(c.details.source ?? "")}`
                          : c.details
                            ? `uid=${String(c.details.uid ?? "")} shell=${String(c.details.shell ?? "")}`
                            : ""}
                    </td>
                    <td>
                      {c.imported_account_id ? (
                        <span className="badge active">{t("discovery.imported")}</span>
                      ) : c.already_known ? (
                        <span className="muted">{t("discovery.alreadyInVault")}</span>
                      ) : (
                        <span className="badge active">{t("discovery.new")}</span>
                      )}
                    </td>
                    <td>
                      {canImport && !c.imported_account_id && !c.already_known && (
                        <button className="btn" type="button" onClick={() => void onImport(c)}>
                          {t("discovery.import")}
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
                        <Link to={`/assets/${c.imported_asset_id}`}>{t("discovery.imported")}</Link>
                      ) : c.already_known ? (
                        <span className="muted">{t("discovery.alreadyInInventory")}</span>
                      ) : (
                        <span className="badge active">{t("discovery.new")}</span>
                      )}
                    </td>
                    <td>
                      {canImport && !c.imported_asset_id && (
                        <button className="btn" type="button" onClick={() => void onImport(c)}>
                          {t("discovery.import")}
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
                      ? t("discovery.scanning")
                      : accountsMode
                        ? active?.kind === "winrm_accounts"
                          ? t("discovery.noAccountsWinrm")
                          : t("discovery.noAccountsSsh")
                        : t("discovery.noOpenPorts")}
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
