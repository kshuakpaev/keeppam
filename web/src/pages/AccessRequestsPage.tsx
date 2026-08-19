import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, hasPerm, type AccessRequest, type BreakGlassEvent, type OpApproval, type PamSession, type SecretCheckoutRequest } from "../api";
import { useAuth } from "../auth";

export function AccessRequestsPage() {
  const { user } = useAuth();
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
      setError(err instanceof Error ? err.message : "Ошибка");
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
      setError(err instanceof Error ? err.message : "Не удалось одобрить");
    }
  }

  async function onDeny(id: string) {
    setError("");
    try {
      await api.denyAccessRequest(id);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Не удалось отклонить");
    }
  }

  async function onCancel(id: string) {
    setError("");
    try {
      await api.cancelAccessRequest(id);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Не удалось отменить");
    }
  }

  async function onApproveCheckout(id: string) {
    setError("");
    try {
      await api.approveSecretCheckout(id);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Не удалось одобрить checkout");
    }
  }

  async function onDenyCheckout(id: string) {
    setError("");
    try {
      await api.denySecretCheckout(id);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Не удалось отклонить checkout");
    }
  }

  async function onApproveOp(id: string) {
    setError("");
    try {
      await api.approveOpApproval(id);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Не удалось одобрить операцию");
    }
  }

  async function onDenyOp(id: string) {
    setError("");
    try {
      await api.denyOpApproval(id);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Не удалось отклонить операцию");
    }
  }

  async function onApproveSupervisor(id: string) {
    setError("");
    try {
      await api.approveSupervisor(id);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Не удалось разрешить сессию");
    }
  }

  async function onDenySupervisor(id: string) {
    setError("");
    try {
      await api.denySupervisor(id);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Не удалось отклонить сессию");
    }
  }

  if (!canRequest && !canApprove && !canApproveSecurity && !canVault && !canBreakGlass && !canSupervise) {
    return <p className="error">Недостаточно прав</p>;
  }

  return (
    <div>
      <div className="toolbar">
        <div>
          <h1>Запросы доступа</h1>
          <p className="muted">JIT к активам, супервайзер сессии, операции в сессии (object ACL), dual-control checkout и break-glass</p>
        </div>
        <button className="btn secondary" type="button" onClick={() => void load()}>
          Обновить
        </button>
      </div>

      {error && <p className="error">{error}</p>}

      {canSupervise && (
        <div className="card" style={{ marginBottom: "1.25rem" }}>
          <h2>Сессии ждут супервайзера</h2>
          <p className="muted">
            Четыре глаза: подключение к цели не начинается, пока другой пользователь с правом sessions.supervise
            не разрешит. Свою сессию одобрить нельзя. Таймаут 15 мин.
          </p>
          <table>
            <thead>
              <tr>
                <th>Когда</th>
                <th>Кто</th>
                <th>Актив</th>
                <th>Протокол</th>
                <th>Группа</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {waitingSessions.map((s) => (
                <tr key={s.id}>
                  <td className="mono">{new Date(s.created_at).toLocaleString()}</td>
                  <td>{s.username || s.user_id}</td>
                  <td>
                    <Link to={`/assets/${s.asset_id}`}>{s.asset_name || s.asset_id}</Link>
                    <div className="muted mono">{s.account_username}</div>
                  </td>
                  <td className="mono">{s.protocol}</td>
                  <td>{s.supervisor_group_name || "любой супервайзер"}</td>
                  <td>
                    <div className="row">
                      {s.user_id !== user?.id && (
                        <>
                          <button className="btn" type="button" onClick={() => void onApproveSupervisor(s.id)}>
                            Разрешить
                          </button>
                          <button className="btn danger" type="button" onClick={() => void onDenySupervisor(s.id)}>
                            Отклонить
                          </button>
                        </>
                      )}
                      {s.user_id === user?.id && <span className="muted">своя сессия</span>}
                    </div>
                  </td>
                </tr>
              ))}
              {waitingSessions.length === 0 && (
                <tr>
                  <td colSpan={6} className="muted">
                    Нет сессий, ждущих супервайзера.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {(canApprove || canApproveSecurity) && (
        <div className="card" style={{ marginBottom: "1.25rem" }}>
          <h2>Операции в сессии</h2>
          <p className="muted">
            HTTP/kubectl object ACL и SSH-команды с risk_action=require_approval. Запрос держится до 60 с,
            пока кто-то с access.approve не нажмёт. Свой запрос одобрить нельзя. Команда на хост не уходит, пока нет approve.
          </p>
          <table>
            <thead>
              <tr>
                <th>Когда</th>
                <th>Кто</th>
                <th>Актив</th>
                <th>Канал</th>
                <th>Операция</th>
                <th>До</th>
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
                        сессия
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
                            Одобрить
                          </button>
                          <button className="btn danger" type="button" onClick={() => void onDenyOp(o.id)}>
                            Отклонить
                          </button>
                        </>
                      )}
                      {o.user_id === user?.id && <span className="muted">свой запрос</span>}
                    </div>
                  </td>
                </tr>
              ))}
              {ops.length === 0 && (
                <tr>
                  <td colSpan={7} className="muted">
                    Нет операций, ждущих согласования.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {canBreakGlass && (
        <div className="card" style={{ marginBottom: "1.25rem" }}>
          <h2>Break-glass</h2>
          <p className="muted">Экстренные открытия доступа. Все события пишутся в аудит с severity=critical.</p>
          <table>
            <thead>
              <tr>
                <th>Когда</th>
                <th>Кто</th>
                <th>Актив</th>
                <th>TTL</th>
                <th>До</th>
                <th>Причина</th>
                <th>Статус</th>
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
                  <td className="mono">{g.duration_minutes} мин</td>
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
                    Нет break-glass событий.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {canVault && (
        <div className="card" style={{ marginBottom: "1.25rem" }}>
          <h2>Checkout секретов (dual-control)</h2>
          <p className="muted">Одобрить должен другой администратор (не заявитель).</p>
          <table>
            <thead>
              <tr>
                <th>Создан</th>
                <th>Кто</th>
                <th>Актив / учётка</th>
                <th>TTL</th>
                <th>Причина</th>
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
                  <td className="mono">{r.ttl_minutes} мин</td>
                  <td>{r.reason || "—"}</td>
                  <td>
                    <div className="row">
                      {r.requester_id !== user?.id && (
                        <>
                          <button className="btn" type="button" onClick={() => void onApproveCheckout(r.id)}>
                            Одобрить
                          </button>
                          <button className="btn danger" type="button" onClick={() => void onDenyCheckout(r.id)}>
                            Отклонить
                          </button>
                        </>
                      )}
                      {r.requester_id === user?.id && <span className="muted">свой запрос</span>}
                    </div>
                  </td>
                </tr>
              ))}
              {checkouts.length === 0 && (
                <tr>
                  <td colSpan={6} className="muted">
                    Нет pending checkout-запросов.
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
                {s || "все"}
              </button>
            ))}
          </div>

          <div className="card">
            <h2>JIT доступ</h2>
            <table>
              <thead>
                <tr>
                  <th>Создан</th>
                  <th>Кто</th>
                  <th>Актив</th>
                  <th>TTL</th>
                  <th>Ticket</th>
                  <th>Risk</th>
                  <th>Причина</th>
                  <th>Этап</th>
                  <th>Статус</th>
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
                    <td className="mono">{r.duration_minutes} мин</td>
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
                            кворум {r.quorum_votes || 0}/{r.quorum_n || 1} из {r.quorum_m || 1}
                          </span>
                          {r.approver_group_name ? (
                            <div className="muted" style={{ fontSize: "0.8rem" }}>
                              группа {r.approver_group_name}
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
                                ? `Одобрить (${(r.quorum_votes || 0) + 1}/${r.quorum_n || 1})`
                                : r.stage === "security"
                                  ? "Одобрить ИБ"
                                  : "Одобрить"}
                            </button>
                            <button className="btn danger" type="button" onClick={() => void onDeny(r.id)}>
                              Отклонить
                            </button>
                          </>
                        )}
                        {r.status === "pending" &&
                          r.approval_mode === "quorum" &&
                          (r.approvals || []).some((a) => a.actor_id === user?.id) && (
                          <span className="muted">ваш голос учтён</span>
                        )}
                        {r.status === "pending" && r.requester_id === user?.id && (
                          <button className="btn secondary" type="button" onClick={() => void onCancel(r.id)}>
                            Отменить
                          </button>
                        )}
                        {r.status === "pending" && canApprove && r.requester_id === user?.id && (
                          <span className="muted">свой запрос</span>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
                {requests.length === 0 && (
                  <tr>
                    <td colSpan={10} className="muted">
                      Запросов нет{status ? ` со статусом ${status}` : ""}.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
            <p className="muted" style={{ marginTop: "0.75rem" }}>
              Всего: {total}
            </p>
          </div>
        </>
      )}
    </div>
  );
}
