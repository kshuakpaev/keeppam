import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, hasPerm, type AccessRequest, type BreakGlassEvent, type SecretCheckoutRequest } from "../api";
import { useAuth } from "../auth";

export function AccessRequestsPage() {
  const { user } = useAuth();
  const [requests, setRequests] = useState<AccessRequest[]>([]);
  const [checkouts, setCheckouts] = useState<SecretCheckoutRequest[]>([]);
  const [glasses, setGlasses] = useState<BreakGlassEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [status, setStatus] = useState("pending");
  const [error, setError] = useState("");
  const canRequest = hasPerm(user, "access.request");
  const canApprove = hasPerm(user, "access.approve");
  const canApproveSecurity = hasPerm(user, "access.approve.security");
  const canVault = hasPerm(user, "assets.write");
  const canBreakGlass = hasPerm(user, "access.breakglass");

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
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка");
    }
  }, [status, canVault, canRequest, canApprove, canApproveSecurity, canBreakGlass]);

  useEffect(() => {
    if (canRequest || canApprove || canApproveSecurity || canVault || canBreakGlass) void load();
  }, [canRequest, canApprove, canApproveSecurity, canVault, canBreakGlass, load]);

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

  if (!canRequest && !canApprove && !canApproveSecurity && !canVault && !canBreakGlass) {
    return <p className="error">Недостаточно прав</p>;
  }

  return (
    <div>
      <div className="toolbar">
        <div>
          <h1>Запросы доступа</h1>
          <p className="muted">JIT к активам (руководитель → ИБ), dual-control checkout и break-glass</p>
        </div>
        <button className="btn secondary" type="button" onClick={() => void load()}>
          Обновить
        </button>
      </div>

      {error && <p className="error">{error}</p>}

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
                      <span className="badge">{r.stage || "manager"}</span>
                      {(r.approval_stages || []).length > 1 ? (
                        <div className="muted" style={{ fontSize: "0.8rem" }}>
                          {(r.approval_stages || []).join(" → ")}
                        </div>
                      ) : null}
                      {(r.approvals || []).map((a) => (
                        <div key={a.stage} className="muted" style={{ fontSize: "0.8rem" }}>
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
                          ((r.stage === "security" && canApproveSecurity) ||
                            ((r.stage || "manager") === "manager" && canApprove)) && (
                          <>
                            <button className="btn" type="button" onClick={() => void onApprove(r.id)}>
                              Одобрить {r.stage === "security" ? "ИБ" : ""}
                            </button>
                            <button className="btn danger" type="button" onClick={() => void onDeny(r.id)}>
                              Отклонить
                            </button>
                          </>
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
