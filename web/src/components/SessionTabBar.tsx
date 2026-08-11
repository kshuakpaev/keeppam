import { useMatch } from "react-router-dom";
import { useSessionTabs } from "../sessionTabs";

export function SessionTabBar() {
  const { tabs, activateTab, closeTab } = useSessionTabs();
  const match = useMatch("/sessions/:id/:kind");
  const routeId = match?.params.id;
  const viewing =
    !!routeId &&
    !!match?.params.kind &&
    ["terminal", "sql", "desktop", "app"].includes(match.params.kind);

  if (tabs.length === 0) return null;

  return (
    <div className="session-tabbar" role="tablist" aria-label="Открытые сессии">
      {tabs.map((t) => {
        const active = viewing && t.id === routeId;
        return (
          <div
            key={t.id}
            className={`session-tab${active ? " active" : ""}`}
            role="tab"
            aria-selected={active}
            title={`${t.title} · ${t.protocol}`}
          >
            <button className="session-tab-btn" type="button" onClick={() => activateTab(t.id)}>
              <span className="session-tab-kind">{labelKind(t.kind)}</span>
              <span className="session-tab-title">{t.title}</span>
            </button>
            <button
              className="session-tab-close"
              type="button"
              title="Закрыть и завершить сессию"
              aria-label="Закрыть"
              onClick={(e) => {
                e.stopPropagation();
                void closeTab(t.id, { endSession: true });
              }}
            >
              ×
            </button>
          </div>
        );
      })}
    </div>
  );
}

function labelKind(kind: string): string {
  switch (kind) {
    case "terminal":
      return "SSH";
    case "sql":
      return "SQL";
    case "desktop":
      return "RDP";
    case "app":
      return "APP";
    default:
      return kind.toUpperCase();
  }
}
