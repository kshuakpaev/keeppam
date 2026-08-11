import { useCallback, useEffect, useState, type FormEvent } from "react";
import { api, type AuditEvent } from "../api";

const DEFAULT_PAGE_SIZE = 50;
const PAGE_SIZE_OPTIONS = [20, 50, 100, 1000] as const;

const SEARCH_FIELDS = [
  { value: "all", label: "Все столбцы" },
  { value: "action", label: "Action" },
  { value: "actor_id", label: "Actor" },
  { value: "resource_type", label: "Resource type" },
  { value: "resource_id", label: "Resource id" },
  { value: "ip", label: "IP" },
  { value: "user_agent", label: "User-Agent" },
] as const;

export function AuditPage() {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [q, setQ] = useState("");
  const [field, setField] = useState("all");
  const [appliedQ, setAppliedQ] = useState("");
  const [appliedField, setAppliedField] = useState("all");
  const [page, setPage] = useState(1);
  const [pages, setPages] = useState(0);
  const [total, setTotal] = useState(0);
  const [pageSize, setPageSize] = useState<number>(DEFAULT_PAGE_SIZE);
  const [appliedPageSize, setAppliedPageSize] = useState<number>(DEFAULT_PAGE_SIZE);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const load = useCallback(
    async (nextPage: number, nextQ: string, nextField: string, nextLimit: number) => {
      setLoading(true);
      setError("");
      try {
        const res = await api.listAudit({
          q: nextQ || undefined,
          field: nextField,
          page: nextPage,
          limit: nextLimit,
        });
        setEvents(res.events || []);
        setTotal(res.total);
        setPages(res.pages);
        setPage(res.page);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Ошибка");
      } finally {
        setLoading(false);
      }
    },
    [],
  );

  useEffect(() => {
    void load(1, "", "all", DEFAULT_PAGE_SIZE);
  }, [load]);

  function onSearch(e: FormEvent) {
    e.preventDefault();
    setAppliedQ(q);
    setAppliedField(field);
    setAppliedPageSize(pageSize);
    void load(1, q, field, pageSize);
  }

  function onPageSizeChange(next: number) {
    setPageSize(next);
    setAppliedPageSize(next);
    void load(1, appliedQ, appliedField, next);
  }

  function goTo(p: number) {
    if (p < 1 || (pages > 0 && p > pages) || p === page) return;
    void load(p, appliedQ, appliedField, appliedPageSize);
  }

  return (
    <div>
      <div className="toolbar">
        <div>
          <h1>Аудит</h1>
          <p className="muted">События входа и администрирования</p>
        </div>
      </div>

      <form className="card search-bar" onSubmit={onSearch}>
        <select
          value={field}
          onChange={(e) => setField(e.target.value)}
          aria-label="Поле поиска"
          style={{ marginBottom: 0, width: 180 }}
        >
          {SEARCH_FIELDS.map((f) => (
            <option key={f.value} value={f.value}>
              {f.label}
            </option>
          ))}
        </select>
        <input
          placeholder="Поиск…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          style={{ marginBottom: 0, flex: 1, minWidth: 180 }}
        />
        <button className="btn" type="submit" disabled={loading}>
          Найти
        </button>
      </form>

      {error && <p className="error">{error}</p>}

      <div className="card">
        <div className="pager">
          <span className="muted">
            {total === 0
              ? "Нет записей"
              : `Стр. ${page} из ${pages || 1} · всего ${total}`}
          </span>
          <div className="row">
            <label className="row" style={{ gap: "0.35rem" }}>
              <span className="muted">Строк</span>
              <select
                value={pageSize}
                onChange={(e) => onPageSizeChange(Number(e.target.value))}
                disabled={loading}
                aria-label="Количество строк на странице"
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
              disabled={loading || page <= 1}
              onClick={() => goTo(1)}
            >
              Первый
            </button>
            <button
              className="btn secondary"
              type="button"
              disabled={loading || page <= 1}
              onClick={() => goTo(page - 1)}
            >
              Предыдущий
            </button>
            <button
              className="btn secondary"
              type="button"
              disabled={loading || pages === 0 || page >= pages}
              onClick={() => goTo(page + 1)}
            >
              Следующий
            </button>
            <button
              className="btn secondary"
              type="button"
              disabled={loading || pages === 0 || page >= pages}
              onClick={() => goTo(pages)}
            >
              Последний
            </button>
          </div>
        </div>

        <table>
          <thead>
            <tr>
              <th>Время</th>
              <th>Action</th>
              <th>Actor</th>
              <th>Resource</th>
              <th>IP</th>
            </tr>
          </thead>
          <tbody>
            {events.map((e) => (
              <tr key={e.id}>
                <td className="mono">{new Date(e.ts).toLocaleString()}</td>
                <td className="mono">{e.action}</td>
                <td className="mono">{e.actor_id?.slice(0, 8) || "—"}</td>
                <td className="mono">
                  {e.resource_type}:{e.resource_id?.slice(0, 8) || "—"}
                </td>
                <td className="mono">{e.ip}</td>
              </tr>
            ))}
            {!loading && events.length === 0 && (
              <tr>
                <td colSpan={5} className="muted">
                  Ничего не найдено
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
