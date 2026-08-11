import { useMatch } from "react-router-dom";
import { useSessionTabs, type SessionTabKind } from "../sessionTabs";
import { AppSession } from "../sessions/AppSession";
import { DesktopSession } from "../sessions/DesktopSession";
import { SqlSession } from "../sessions/SqlSession";
import { TerminalSession } from "../sessions/TerminalSession";

const SESSION_KINDS = new Set(["terminal", "sql", "desktop", "app"]);

export function SessionKeepAliveHost() {
  const { tabs, closeTab } = useSessionTabs();
  const match = useMatch("/sessions/:id/:kind");
  const routeId = match?.params.id;
  const routeKind = match?.params.kind;
  const viewingSession = !!(routeId && routeKind && SESSION_KINDS.has(routeKind));

  if (tabs.length === 0) return null;

  return (
    <div className={`session-keepalive${viewingSession ? " viewing" : ""}`} aria-hidden={!viewingSession}>
      {tabs.map((t) => {
        const visible = viewingSession && routeId === t.id;
        return (
          <div
            key={t.id}
            className={`session-panel${visible ? " visible" : ""}`}
            data-session-id={t.id}
            data-kind={t.kind}
          >
            {renderSession(t.kind, t.id, t.title, visible, () => {
              void closeTab(t.id, { endSession: true });
            })}
          </div>
        );
      })}
    </div>
  );
}

function renderSession(
  kind: SessionTabKind,
  id: string,
  title: string,
  visible: boolean,
  onClose: () => void,
) {
  switch (kind) {
    case "terminal":
      return <TerminalSession id={id} title={title} visible={visible} onClose={onClose} />;
    case "sql":
      return <SqlSession id={id} title={title} visible={visible} onClose={onClose} />;
    case "desktop":
      return <DesktopSession id={id} title={title} visible={visible} onClose={onClose} />;
    case "app":
      return <AppSession id={id} title={title} visible={visible} onClose={onClose} />;
  }
}
