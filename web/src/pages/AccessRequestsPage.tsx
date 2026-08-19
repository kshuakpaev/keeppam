import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, hasPerm, type AccessRequest, type BreakGlassEvent, type OpApproval, type PamSession, type SecretCheckoutRequest } from "../api";
import { useAuth } from "../auth";
import { useI18n } from "../i18n";

export function AccessRequestsPage() {
  const { user } = useAuth();
  const { t, te, formatDate } = useI18n();
  const [requests, setRequests] = useState<AccessRequest[]>([]);
  const [checkouts, setCheckouts] = useState<SecretCheckoutRequest[]>([]);
  const [glasses, setGlasses] = useState<BreakGlassEvent[]>([]);
  const [ops, setOps] = useState<OpApproval[]>([]);
  const [waitingSessions, setWaitingSessions] = useState<PamSession[]>([]);
  const [total, setTotal] = useState(0);
  const [status, setStatus] = useState("pending");
  const [error, setError] = useState("");
  const canRequest = hasPerm(user, "access.request");
  const canApprove = hasPerm(user, "access.approve");
  const canApproveSecurity = hasPerm(user, "access.approve.security");
  const canVault = hasPerm(user, "assets.write");
  const canBreakGlass = hasPerm(user, "access.breakglass");
  const canSupervise = hasPerm(user, "sessions.supervise");

  const load = useCallback(async () => {
    try {
      if (canRequest || canApprove || canApproveSecurity) {
        const res = await api.listAccessRequests({
          status: status || undefined,
          limit: 100,
        });
        setRequests(res.requests || []);
        setTotal(res.total || 0);
      }
      if (canVault) {
        const sc = await api.listSecretCheckouts(true);
        setCheckouts(sc.requests || []);
      }
      if (canBreakGlass) {
        const bg = await api.listBreakGlass(false);
        setGlasses(bg.events || []);
      }
      if (canApprove || canApproveSecurity) {
        const op = await api.listOpApprovals();
        setOps(op.approvals || []);
      }
      if (canSupervise) {
        const wait = await api.listSessions({ waiting_supervisor: true, limit: 100 });
        setWaitingSessions(wait.sessions || []);
      }
      setError("");
    } catch (err) {
      setError(te(err));
    }
  }, [status, canVault, canRequest, canApprove, canApproveSecurity, canBreakGlass, canSupervise]);

  useEffect(() => {
    if (canRequest || canApprove || canApproveSecurity || canVault || canBreakGlass || canSupervise) void load();
  }, [canRequest, canApprove, canApproveSecurity, canVault, canBreakGlass, canSupervise, load]);

  useEffect(() => {
    if (!(canApprove || canApproveSecurity || canSupervise)) return;
    const id = window.setInterval(() => void load(), 4000);
    return () => window.clearInterval(id);
  }, [canApprove, canApproveSecurity, canSupervise, load]);

  async function onApprove(id: string) {
    setError("");
    try {
      await api.approveAccessRequest(id);
      await load();
    } catch (err) {
      setError(te(err, "req.failApprove"));
    }
  }

  async function onDeny(id: string) {
    setError("");
    try {
      await api.denyAccessRequest(id);
      await load();
    } catch (err) {
      setError(te(err, "req.failDeny"));
    }
  }

  async function onCancel(id: string) {
    setError("");
    try {
      await api.cancelAccessRequest(id);
      await load();
    } catch (err) {
      setError(te(err, "req.failCancel"));
    }
  }

  async function onApproveCheckout(id: string) {
    setError("");
    try {
      await api.approveSecretCheckout(id);
      await load();
    } catch (err) {
      setError(te(err, "req.failApprove"));
    }
  }

  async function onDenyCheckout(id: string) {
    setError("");
    try {
      await api.denySecretCheckout(id);
      await load();
    } catch (err) {
      setError(te(err, "req.failDeny"));
    }
  }

  async function onApproveOp(id: string) {
    setError("");
    try {
      await api.approveOpApproval(id);
      await load();
    } catch (err) {
      setError(te(err, "req.failApprove"));
    }
  }

  async function onDenyOp(id: string) {
    setError("");
    try {
      await api.denyOpApproval(id);
      await load();
    } catch (err) {
      setError(te(err, "req.failDeny"));
    }
  }

  async function onApproveSupervisor(id: string) {
    setError("");
    try {
      await api.approveSupervisor(id);
      await load();
    } catch (err) {
      setError(te(err, "req.failSupervise"));
    }
  }

  async function onDenySupervisor(id: string) {
    setError("");
    try {
      await api.denySupervisor(id);
      await load();
    } catch (err) {
      setError(te(err, "req.failSuperviseDeny"));
    }
  }

  if (!canRequest && !canApprove && !canApproveSecurity && !canVault && !canBreakGlass && !canSupervise) {
    return <p className="error">{t("common.forbidden")}</p>;
  }

  return (
    <div>
      <div className="toolbar">
        <div>
          <h1>{t("req.title")}</h1>
          <p className="muted">{t("req.lead")}</p>
        </div>
        <button className="btn secondary" type="button" onClick={() => void load()}>
          {t("common.refresh")}
        </button>
      </div>

      {error && <p className="error">{error}</p>}

      {canSupervise && (
        <div className="card" style={{ marginBottom: "1.25rem" }}>
          <h2>{t("req.waitingTitle")}</h2>
          <p className="muted">{t("req.waitingLead")}</p>
          <table>
            <thead>
              <tr>
                <th>{t("common.when")}</th>
                <th>{t("common.who")}</th>
                <th>{t("common.asset")}</th>
                <th>{t("common.protocol")}</th>
                <th>{t("common.group")}</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {waitingSessions.map((s) => (
                <tr key={s.id}>
                  <td className="mono">{formatDate(s.created_at)}</td>
                  <td>{s.username || s.user_id}</td>
                  <td>
                    <Link to={`/assets/${s.asset_id}`}>{s.asset_name || s.asset_id}</Link>
                    <div className="muted mono">{s.account_username}</div>
                  </td>
                  <td className="mono">{s.protocol}</td>
                  <td>{s.supervisor_group_name || t("req.anySupervisor")}</td>
                  <td>
                    <div className="row">
                      {s.user_id !== user?.id && (
                        <>
                          <button className="btn" type="button" onClick={() => void onApproveSupervisor(s.id)}>
                            {t("common.allow")}
                          </button>
                          <button className="btn danger" type="button" onClick={() => void onDenySupervisor(s.id)}>
                            {t("common.deny")}
                          </button>
                        </>
                      )}
                      {s.user_id === user?.id && <span className="muted">{t("req.ownSession")}</span>}
                    </div>
                  </td>
                </tr>
              ))}
              {waitingSessions.length === 0 && (
                <tr>
                  <td colSpan={6} className="muted">
                    {t("req.noWaiting")}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {(canApprove || canApproveSecurity) && (
        <div className="card" style={{ marginBottom: "1.25rem" }}>
          <h2>{t("req.opsTitle")}</h2>
          <p className="muted">{t("req.opsLead")}</p>
          <table>
            <thead>
              <tr>
                <th>{t("common.when")}</th>
                <th>{t("common.who")}</th>
                <th>{t("common.asset")}</th>
                <th>{t("req.channel")}</th>
                <th>{t("req.operation")}</th>
                <th>{t("req.until")}</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {ops.map((o) => (
                <tr key={o.id}>
                  <td className="mono">{new Date(o.created_at).toLocaleString()}</td>
                  <td>{o.username || o.user_id}</td>
                  <td>
                    <Link to={`/assets/${o.asset_id}`}>{o.asset_name || o.asset_id}</Link>
                    <div className="muted mono">
                      <Link to={o.channel === "k8s" ? `/sessions/${o.session_id}/k8s` : o.channel === "ssh" ? `/sessions/${o.session_id}` : `/sessions/${o.session_id}/app`}>
                        {t("req.session")}
                      </Link>
                    </div>
                  </td>
                  <td className="mono">{o.channel}</td>
                  <td>
                    <div className="mono">
                      {o.method} {o.path}
                    </div>
                    <div className="muted">{o.object}</div>
                  </td>
                  <td className="mono">{new Date(o.expires_at).toLocaleString()}</td>
                  <td>
                    <div className="row">
                      {o.user_id !== user?.id && (
                        <>
                          <button className="btn" type="button" onClick={() => void onApproveOp(o.id)}>
                            {t("common.approve")}
                          </button>
                          <button className="btn danger" type="button" onClick={() => void onDenyOp(o.id)}>
                            {t("common.deny")}
                          </button>
                        </>
                      )}
                      {o.user_id === user?.id && <span className="muted">{t("common.ownRequest")}</span>}
                    </div>
                  </td>
                </tr>
              ))}
              {ops.length === 0 && (
                <tr>
                  <td colSpan={7} className="muted">
                    {t("req.noOps")}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {canBreakGlass && (
        <div className="card" style={{ marginBottom: "1.25rem" }}>
          <h2>{t("req.bgTitle")}</h2>
          <p className="muted">{t("req.bgLead")}</p>
          <table>
            <thead>
              <tr>
                <th>{t("common.when")}</th>
                <th>{t("common.who")}</th>
                <th>{t("common.asset")}</th>
                <th>TTL</th>
                <th>{t("req.until")}</th>
                <th>{t("req.reason")}</th>
                <th>{t("common.status")}</th>
              </tr>
            </thead>
            <tbody>
              {glasses.map((g) => (
                <tr key={g.id}>
                  <td className="mono">{new Date(g.created_at).toLocaleString()}</td>
                  <td>{g.username}</td>
                  <td>
                    <Link to={`/assets/${g.asset_id}`}>{g.asset_name}</Link>
                  </td>
                  <td className="mono">{t("req.ttlMin", { n: g.duration_minutes })}</td>
                  <td className="mono">{new Date(g.expires_at).toLocaleString()}</td>
                  <td>{g.reason}</td>
                  <td>
                    <span className={`badge ${g.active ? "locked" : ""}`}>{g.active ? "active" : "closed"}</span>
                  </td>
                </tr>
              ))}
              {glasses.length === 0 && (
                <tr>
                  <td colSpan={7} className="muted">
                    {t("req.noBg")}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {canVault && (
        <div className="card" style={{ marginBottom: "1.25rem" }}>
          <h2>{t("req.checkoutTitle")}</h2>
          <p className="muted">{t("req.checkoutLead")}</p>
          <table>
            <thead>
              <tr>
                <th>{t("req.created")}</th>
                <th>{t("common.who")}</th>
                <th>{t("common.asset")} / {t("common.account")}</th>
                <th>TTL</th>
                <th>{t("req.reason")}</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {checkouts.map((r) => (
                <tr key={r.id}>
                  <td className="mono">{new Date(r.created_at).toLocaleString()}</td>
                  <td>{r.requester_username}</td>
                  <td>
                    <Link to={`/assets/${r.asset_id}`}>{r.asset_name}</Link>
                    <div className="muted mono">{r.account_username}</div>
                  </td>
                  <td className="mono">{t("req.ttlMin", { n: r.ttl_minutes })}</td>
                  <td>{r.reason || "—"}</td>
                  <td>
                    <div className="row">
                      {r.requester_id !== user?.id && (
                        <>
                          <button className="btn" type="button" onClick={() => void onApproveCheckout(r.id)}>
                            {t("common.approve")}
                          </button>
                          <button className="btn danger" type="button" onClick={() => void onDenyCheckout(r.id)}>
                            {t("common.deny")}
                          </button>
                        </>
                      )}
                      {r.requester_id === user?.id && <span className="muted">{t("common.ownRequest")}</span>}
                    </div>
                  </td>
                </tr>
              ))}
              {checkouts.length === 0 && (
                <tr>
                  <td colSpan={6} className="muted">
                    {t("req.noCheckout")}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {(canRequest || canApprove || canApproveSecurity) && (
        <>
          <div className="row" style={{ marginBottom: "0.75rem", gap: "0.5rem" }}>
            {(["pending", "approved", "denied", "cancelled", "expired", ""] as const).map((s) => (
              <button
                key={s || "all"}
                className={`btn secondary${status === s ? " active" : ""}`}
                type="button"
                onClick={() => setStatus(s)}
              >
                {s || t("common.all")}
              </button>
            ))}
          </div>

          <div className="card">
            <h2>{t("req.jitTitle")}</h2>
            <table>
              <thead>
                <tr>
                  <th>{t("req.created")}</th>
                  <th>{t("common.who")}</th>
                  <th>{t("common.asset")}</th>
                  <th>TTL</th>
                  <th>Ticket</th>
                  <th>Risk</th>
                  <th>{t("req.reason")}</th>
                  <th>{t("req.stageCol")}</th>
                  <th>{t("common.status")}</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {requests.map((r) => (
                  <tr key={r.id}>
                    <td className="mono">{new Date(r.created_at).toLocaleString()}</td>
                    <td>{r.requester_username}</td>
                    <td>
                      <Link to={`/assets/${r.asset_id}`}>{r.asset_name}</Link>
                      <div className="muted mono">{r.asset_address}</div>
                    </td>
                    <td className="mono">{t("req.ttlMin", { n: r.duration_minutes })}</td>
                    <td className="mono">{r.ticket_id || "—"}</td>
                    <td className="mono" style={{ fontSize: "0.85rem" }}>
                      {r.risk_score ? (
                        <>
                          {r.risk_score}
                          {(r.risk_factors || []).length ? (
                            <div className="muted">{(r.risk_factors || []).join(", ")}</div>
                          ) : null}
                        </>
                      ) : (
                        "—"
                      )}
                    </td>
                    <td>{r.reason || "—"}</td>
                    <td>
                      {r.approval_mode === "quorum" ? (
                        <>
                          <span className="badge">
                            {t("req.quorum", { votes: r.quorum_votes || 0, n: r.quorum_n || 1, m: r.quorum_m || 1 })}
                          </span>
                          {r.approver_group_name ? (
                            <div className="muted" style={{ fontSize: "0.8rem" }}>
                              {t("req.groupNamed", { name: r.approver_group_name })}
                            </div>
                          ) : null}
                        </>
                      ) : (
                        <>
                          <span className="badge">{r.stage || "manager"}</span>
                          {(r.approval_stages || []).length > 1 ? (
                            <div className="muted" style={{ fontSize: "0.8rem" }}>
                              {(r.approval_stages || []).join(" → ")}
                            </div>
                          ) : null}
                        </>
                      )}
                      {(r.approvals || []).map((a) => (
                        <div key={a.actor_id || a.stage} className="muted" style={{ fontSize: "0.8rem" }}>
                          {a.stage}: {a.username}
                        </div>
                      ))}
                    </td>
                    <td>
                      <span
                        className={`badge ${r.status === "pending" ? "active" : r.status === "denied" ? "locked" : ""}`}
                      >
                        {r.status}
                      </span>
                      {r.approver_username && <div className="muted">by {r.approver_username}</div>}
                    </td>
                    <td>
                      <div className="row">
                        {r.status === "pending" &&
                          r.requester_id !== user?.id &&
                          (r.approval_mode === "quorum"
                            ? canApprove && !(r.approvals || []).some((a) => a.actor_id === user?.id)
                            : (r.stage === "security" && canApproveSecurity) ||
                              ((r.stage || "manager") === "manager" && canApprove)) && (
                          <>
                            <button className="btn" type="button" onClick={() => void onApprove(r.id)}>
                              {r.approval_mode === "quorum"
                                ? t("req.approveQuorum", { next: (r.quorum_votes || 0) + 1, n: r.quorum_n || 1 })
                                : r.stage === "security"
                                  ? t("req.approveSec")
                                  : t("common.approve")}
                            </button>
                            <button className="btn danger" type="button" onClick={() => void onDeny(r.id)}>
                              {t("common.deny")}
                            </button>
                          </>
                        )}
                        {r.status === "pending" &&
                          r.approval_mode === "quorum" &&
                          (r.approvals || []).some((a) => a.actor_id === user?.id) && (
                          <span className="muted">{t("req.yourVote")}</span>
                        )}
                        {r.status === "pending" && r.requester_id === user?.id && (
                          <button className="btn secondary" type="button" onClick={() => void onCancel(r.id)}>
                            {t("req.cancel")}
                          </button>
                        )}
                        {r.status === "pending" && canApprove && r.requester_id === user?.id && (
                          <span className="muted">{t("common.ownRequest")}</span>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
                {requests.length === 0 && (
                  <tr>
                    <td colSpan={10} className="muted">
                      {t("req.noneStatus", { suffix: status ? t("req.statusSuffix", { status }) : "" })}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
            <p className="muted" style={{ marginTop: "0.75rem" }}>
              {t("req.total", { n: total })}
            </p>
          </div>
        </>
      )}
    </div>
  );
}
