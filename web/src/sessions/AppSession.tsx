import { useEffect, useState } from "react";
import { api } from "../api";
import { SessionStepUpHost } from "../components/SessionStepUpHost";
import { DesktopSession } from "./DesktopSession";

type Props = {
  id: string;
  title: string;
  visible: boolean;
  onClose: () => void;
};

export function AppSession({ id, title, visible, onClose }: Props) {
  const [closing, setClosing] = useState(false);
  const [isolated, setIsolated] = useState(false);
  const src = `/api/v1/sessions/${id}/app/`;
  void visible;

  useEffect(() => {
    let cancelled = false;
    api
      .getSession(id)
      .then((s) => {
        if (!cancelled && s.isolated) setIsolated(true);
      })
      .catch(() => {
        /* keep proxy iframe */
      });
    return () => {
      cancelled = true;
    };
  }, [id]);

  if (isolated) {
    return <DesktopSession id={id} title={title} visible={visible} onClose={onClose} />;
  }

  async function handleClose() {
    if (closing) return;
    setClosing(true);
    onClose();
  }

  return (
    <div className="app-session session-panel-inner">
      <div className="page-head">
        <div>
          <h1>App · {title}</h1>
          <p className="muted">HTTPS proxy session (recording_mode=full)</p>
        </div>
        <button className="btn secondary" type="button" disabled={closing} onClick={() => void handleClose()}>
          {closing ? "Завершение…" : "Завершить"}
        </button>
      </div>
      <iframe
        className="app-frame"
        title="app"
        src={src}
        sandbox="allow-forms allow-scripts allow-same-origin allow-popups"
      />
      <SessionStepUpHost sessionId={id} />
    </div>
  );
}
