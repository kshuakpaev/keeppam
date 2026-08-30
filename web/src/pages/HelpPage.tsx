import { useEffect, useMemo, useState, type FormEvent } from "react";
import { Link, useLocation } from "react-router-dom";
import { api } from "../api";
import { useI18n } from "../i18n";
import {
  HELP_GROUPS,
  HELP_TOPICS,
  findTopic,
  helpText,
  type HelpTopic,
} from "../help/content";

export function HelpPage() {
  const { t, te, lang } = useI18n();
  const location = useLocation();
  const [query, setQuery] = useState("");
  const [openIds, setOpenIds] = useState<Set<string>>(() => new Set(["workflows", "overview"]));
  const [askQ, setAskQ] = useState("");
  const [askA, setAskA] = useState("");
  const [askErr, setAskErr] = useState("");
  const [askBusy, setAskBusy] = useState(false);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return HELP_TOPICS;
    return HELP_TOPICS.filter((topic) => {
      const hay = [
        helpText(lang, topic.title),
        helpText(lang, topic.summary),
        ...topic.body.map((p) => helpText(lang, p)),
        ...(topic.actions ?? []).flatMap((a) => [helpText(lang, a.name), helpText(lang, a.desc)]),
        ...(topic.table
          ? [helpText(lang, topic.table.headers[0]), helpText(lang, topic.table.headers[1]), ...topic.table.rows.flatMap((r) => [helpText(lang, r[0]), helpText(lang, r[1])])]
          : []),
      ]
        .join("\n")
        .toLowerCase();
      return hay.includes(q);
    });
  }, [query, lang]);

  const byGroup = useMemo(() => {
    return HELP_GROUPS.map((g) => ({
      ...g,
      topics: filtered.filter((t) => t.group === g.id),
    })).filter((g) => g.topics.length > 0);
  }, [filtered]);

  useEffect(() => {
    const hash = location.hash.replace(/^#/, "");
    if (!hash) return;
    setOpenIds((prev) => new Set(prev).add(hash));
    const el = document.getElementById(`help-${hash}`);
    if (el) {
      window.setTimeout(() => el.scrollIntoView({ behavior: "smooth", block: "start" }), 50);
    }
  }, [location.hash]);

  function toggle(id: string) {
    setOpenIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function expandAll() {
    setOpenIds(new Set(filtered.map((t) => t.id)));
  }

  function collapseAll() {
    setOpenIds(new Set());
  }

  async function onAsk(e: FormEvent) {
    e.preventDefault();
    const q = askQ.trim();
    if (!q) return;
    setAskBusy(true);
    setAskErr("");
    setAskA("");
    try {
      const res = await api.helpAsk(q);
      setAskA(res.answer || "");
    } catch (err) {
      setAskErr(te(err, "help.askHint"));
    } finally {
      setAskBusy(false);
    }
  }

  return (
    <div className="help-page">
      <div className="toolbar">
        <div>
          <h1>{t("help.title")}</h1>
          <p className="muted">{t("help.subtitle")}</p>
        </div>
        <div className="row" style={{ gap: "0.5rem", flexWrap: "wrap" }}>
          <button type="button" className="btn secondary" onClick={expandAll}>
            {t("help.expandAll")}
          </button>
          <button type="button" className="btn secondary" onClick={collapseAll}>
            {t("help.collapseAll")}
          </button>
        </div>
      </div>

      <form className="card" style={{ marginBottom: "1rem", maxWidth: 640 }} onSubmit={(e) => void onAsk(e)}>
        <p className="muted">{t("help.askHint")}</p>
        <label>{t("help.ask")}</label>
        <input
          value={askQ}
          onChange={(e) => setAskQ(e.target.value)}
          placeholder={t("help.searchPh")}
          autoComplete="off"
        />
        <button className="btn" type="submit" disabled={askBusy || !askQ.trim()} style={{ marginTop: "0.5rem" }}>
          {t("help.ask")}
        </button>
        {askErr ? <p className="error">{askErr}</p> : null}
        {askA ? <p style={{ marginTop: "0.75rem", whiteSpace: "pre-wrap" }}>{askA}</p> : null}
      </form>

      <div className="help-layout">
        <aside className="help-toc card">
          <label className="help-search">
            <span className="muted">{t("help.search")}</span>
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder={t("help.searchPh")}
              autoComplete="off"
            />
          </label>
          <nav className="help-toc-nav" aria-label={t("help.toc")}>
            {byGroup.map((g) => (
              <div key={g.id} className="help-toc-group">
                <div className="help-toc-group-title">{helpText(lang, g.title)}</div>
                <ul>
                  {g.topics.map((topic) => (
                    <li key={topic.id}>
                      <a
                        href={`#${topic.id}`}
                        className={location.hash === `#${topic.id}` ? "active" : undefined}
                        onClick={() => setOpenIds((prev) => new Set(prev).add(topic.id))}
                      >
                        {helpText(lang, topic.title)}
                      </a>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </nav>
          {filtered.length === 0 ? <p className="muted">{t("help.noResults")}</p> : null}
        </aside>

        <div className="help-content">
          {byGroup.map((g) => (
            <section key={g.id} className="help-section">
              <h2 className="help-section-title">{helpText(lang, g.title)}</h2>
              {g.topics.map((topic) => (
                <HelpArticle
                  key={topic.id}
                  topic={topic}
                  open={openIds.has(topic.id) || !!query.trim()}
                  onToggle={() => toggle(topic.id)}
                />
              ))}
            </section>
          ))}
        </div>
      </div>
    </div>
  );
}

function HelpArticle({
  topic,
  open,
  onToggle,
}: {
  topic: HelpTopic;
  open: boolean;
  onToggle: () => void;
}) {
  const { t, lang } = useI18n();

  return (
    <article id={`help-${topic.id}`} className={`help-article card${open ? " open" : ""}`}>
      <button type="button" className="help-article-head" onClick={onToggle} aria-expanded={open}>
        <span className="help-article-chevron" aria-hidden>
          {open ? "▾" : "▸"}
        </span>
        <span>
          <strong>{helpText(lang, topic.title)}</strong>
          <span className="muted help-article-summary">{helpText(lang, topic.summary)}</span>
        </span>
      </button>
      {open ? (
        <div className="help-article-body">
          {topic.body.map((p, i) => (
            <p key={i}>{helpText(lang, p)}</p>
          ))}
          {topic.table ? (
            <table className="help-table">
              <thead>
                <tr>
                  <th>{helpText(lang, topic.table.headers[0])}</th>
                  <th>{helpText(lang, topic.table.headers[1])}</th>
                </tr>
              </thead>
              <tbody>
                {topic.table.rows.map((row, i) => (
                  <tr key={i}>
                    <td>{helpText(lang, row[0])}</td>
                    <td>{helpText(lang, row[1])}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : null}
          {topic.actions && topic.actions.length > 0 ? (
            <div className="help-actions">
              <h3>{t("help.actions")}</h3>
              <dl>
                {topic.actions.map((a, i) => (
                  <div key={i} className="help-action">
                    <dt>{helpText(lang, a.name)}</dt>
                    <dd>{helpText(lang, a.desc)}</dd>
                  </div>
                ))}
              </dl>
            </div>
          ) : null}
          <div className="help-links row" style={{ gap: "0.75rem", flexWrap: "wrap" }}>
            {topic.href ? (
              <Link className="btn secondary" to={topic.href}>
                {t("help.openPage")}
              </Link>
            ) : null}
            {(topic.related ?? []).map((rid) => {
              const rel = findTopic(rid);
              if (!rel) return null;
              return (
                <a key={rid} className="help-related" href={`#${rid}`}>
                  {helpText(lang, rel.title)}
                </a>
              );
            })}
          </div>
        </div>
      ) : null}
    </article>
  );
}
