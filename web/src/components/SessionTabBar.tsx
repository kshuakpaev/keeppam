import { useMatch } from "react-router-dom";
import { useSessionTabs } from "../sessionTabs";
import { useI18n } from "../i18n";

export function SessionTabBar() {
  const { t } = useI18n();
  const { tabs, activateTab, closeTab } = useSessionTabs();
  const match = useMatch("/sessions/:id/:kind");
  const routeId = match?.params.id;
  const viewing =
    !!routeId &&
    !!match?.params.kind &&
    ["terminal", "sql", "desktop", "app"].includes(match.params.kind);

  if (tabs.length === 0) return null;

  return (
    <div className="session-tabbar" role="tablist" aria-label={t("tabs.open")}>
      {tabs.map((tab) => {
        const active = viewing && tab.id === routeId;
        return (
          <div
            key={tab.id}
            className={`session-tab${active ? " active" : ""}`}
            role="tab"
            aria-selected={active}
            title={`${tab.title} · ${tab.protocol}`}
          >
            <button className="session-tab-btn" type="button" onClick={() => activateTab(tab.id)}>
              <span className="session-tab-kind">{labelKind(tab.kind)}</span>
              <span className="session-tab-title">{tab.title}</span>
            </button>
            <button
              className="session-tab-close"
              type="button"
              title={t("tabs.closeEnd")}
              aria-label={t("tabs.close")}
              onClick={(e) => {
                e.stopPropagation();
                void closeTab(tab.id, { endSession: true });
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
