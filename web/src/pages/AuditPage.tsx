import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import { api, type AuditEvent, type AuditVerify } from "../api";
import { useI18n } from "../i18n";

const DEFAULT_PAGE_SIZE = 50;
const PAGE_SIZE_OPTIONS = [20, 50, 100, 1000] as const;

const SEARCH_FIELD_VALUES = [
  "all",
  "action",
  "actor_id",
  "resource_type",
  "resource_id",
  "ip",
  "user_agent",
] as const;

export function AuditPage() {
  const { t, te } = useI18n();
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
  const [chain, setChain] = useState<AuditVerify | null>(null);
  const [chainBusy, setChainBusy] = useState(false);

  const searchFields = useMemo(
    () =>
      SEARCH_FIELD_VALUES.map((value) => ({
        value,
        label:
          value === "all"
            ? t("audit.searchAllColumns")
            : value === "action"
              ? "Action"
              : value === "actor_id"
                ? "Actor"
                : value === "resource_type"
                  ? "Resource type"
                  : value === "resource_id"
                    ? "Resource id"
                    : value === "ip"
                      ? "IP"
                      : "User-Agent",
      })),
    [t],
  );

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
        setError(te(err, "audit.loadError"));
      } finally {
        setLoading(false);
      }
    },
    [te],
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

  async function onVerify() {
    setChainBusy(true);
    setError("");
    try {
      setChain(await api.verifyAudit());
    } catch (err) {
      setError(te(err, "audit.verifyError"));
    } finally {
      setChainBusy(false);
    }
  }

  async function onSeal() {
    setChainBusy(true);
    setError("");
    try {
      await api.sealAudit();
      setChain(await api.verifyAudit());
    } catch (err) {
      setError(te(err, "audit.sealError"));
    } finally {
      setChainBusy(false);
    }
  }

  return (
    <div>
      <div className="toolbar">
        <div>
          <h1>{t("audit.title")}</h1>
          <p className="muted">{t("audit.lead")}</p>
        </div>
        <div className="row" style={{ gap: "0.5rem" }}>
          <button className="btn secondary" type="button" disabled={chainBusy} onClick={() => void onVerify()}>
            {t("audit.verifyChain")}
          </button>
          <button className="btn secondary" type="button" disabled={chainBusy} onClick={() => void onSeal()}>
            {t("audit.sealTail")}
          </button>
        </div>
      </div>

      {chain && (
        <div className="card" style={{ marginBottom: "1rem" }}>
          <p style={{ margin: 0 }}>
            {t("audit.chain")}{" "}
            <span className={chain.ok ? "ok" : "error"}>{chain.ok ? t("audit.chainOk") : t("audit.chainBroken")}</span>
            {" · "}
            {t("audit.chainStats", {
              events: chain.events,
              batches: chain.batches,
              unsealed: chain.unsealed,
            })}
            {chain.breaks?.length ? (
              <>
                <br />
                <span className="error">
                  {t("audit.breakAt", { reason: chain.breaks[0].reason, id: chain.breaks[0].id })}
                </span>
              </>
            ) : null}
          </p>
          {chain.tail_hash && (
            <p className="muted mono" style={{ margin: "0.35rem 0 0", fontSize: "0.85rem" }}>
              tail {chain.tail_hash.slice(0, 16)}…
            </p>
          )}
        </div>
      )}

      <form className="card search-bar" onSubmit={onSearch}>
        <select
          value={field}
          onChange={(e) => setField(e.target.value)}
          aria-label={t("audit.searchFieldLabel")}
          style={{ marginBottom: 0, width: 180 }}
        >
          {searchFields.map((f) => (
            <option key={f.value} value={f.value}>
              {f.label}
            </option>
          ))}
        </select>
        <input
          placeholder={t("audit.searchPlaceholder")}
          value={q}
          onChange={(e) => setQ(e.target.value)}
          style={{ marginBottom: 0, flex: 1, minWidth: 180 }}
        />
        <button className="btn" type="submit" disabled={loading}>
          {t("common.find")}
        </button>
      </form>

      {error && <p className="error">{error}</p>}

      <div className="card">
        <div className="pager">
          <span className="muted">
            {total === 0
              ? t("common.noRecords")
              : t("common.pageOf", { page, pages: pages || 1, total })}
          </span>
          <div className="row">
            <label className="row" style={{ gap: "0.35rem" }}>
              <span className="muted">{t("audit.rowsPerPage")}</span>
              <select
                value={pageSize}
                onChange={(e) => onPageSizeChange(Number(e.target.value))}
                disabled={loading}
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
              disabled={loading || page <= 1}
              onClick={() => goTo(1)}
            >
              {t("audit.first")}
            </button>
            <button
              className="btn secondary"
              type="button"
              disabled={loading || page <= 1}
              onClick={() => goTo(page - 1)}
            >
              {t("audit.prev")}
            </button>
            <button
              className="btn secondary"
              type="button"
              disabled={loading || pages === 0 || page >= pages}
              onClick={() => goTo(page + 1)}
            >
              {t("audit.next")}
            </button>
            <button
              className="btn secondary"
              type="button"
              disabled={loading || pages === 0 || page >= pages}
              onClick={() => goTo(pages)}
            >
              {t("audit.last")}
            </button>
          </div>
        </div>

        <table>
          <thead>
            <tr>
              <th>{t("audit.time")}</th>
              <th>Action</th>
              <th>Actor</th>
              <th>{t("audit.resource")}</th>
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
                  {t("audit.nothingFound")}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
