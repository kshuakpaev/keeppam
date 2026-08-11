import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, hasPerm, type AccessRequest } from "../api";
import { useAuth } from "../auth";

export function AccessRequestsPage() {
  const { user } = useAuth();
  const [requests, setRequests] = useState<AccessRequest[]>([]);
  const [total, setTotal] = useState(0);
  const [status, setStatus] = useState("pending");
  const [error, setError] = useState("");
  const canRequest = hasPerm(user, "access.request");
  const canApprove = hasPerm(user, "access.approve");

  const load = useCallback(async () => {
    try {
      const res = await api.listAccessRequests({
        status: status || undefined,
        limit: 100,
      });
      setRequests(res.requests || []);
      setTotal(res.total || 0);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка");
    }
  }, [status]);

  useEffect(() => {
    if (canRequest) void load();
  }, [canRequest, load]);

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

  if (!canRequest) {
    return <p className="error">Недостаточно прав</p>;
  }

  return (
    <div>
      <div className="toolbar">
        <div>
          <h1>Запросы доступа</h1>
          <p className="muted">JIT: временный доступ к активам после согласования</p>
        </div>
        <button className="btn secondary" type="button" onClick={() => void load()}>
          Обновить
        </button>
      </div>

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

      {error && <p className="error">{error}</p>}
      <div className="card">
        <table>
          <thead>
            <tr>
              <th>Время</th>
              <th>Заявитель</th>
              <th>Актив</th>
              <th>TTL</th>
              <th>Ticket</th>
              <th>Причина</th>
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
                <td>{r.reason || "—"}</td>
                <td>
                  <span className={`badge ${r.status === "pending" ? "active" : r.status === "denied" ? "locked" : ""}`}>
                    {r.status}
                  </span>
                  {r.approver_username && (
                    <div className="muted">by {r.approver_username}</div>
                  )}
                </td>
                <td>
                  <div className="row">
                    {r.status === "pending" && canApprove && r.requester_id !== user?.id && (
                      <>
                        <button className="btn" type="button" onClick={() => void onApprove(r.id)}>
                          Одобрить
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
                <td colSpan={7} className="muted">
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
    </div>
  );
}
