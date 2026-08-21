import { useI18n } from "../i18n";
import { FitAddon } from "@xterm/addon-fit";
import { useEffect, useRef, useState } from "react";
import { Terminal } from "xterm";
import "xterm/css/xterm.css";

type Props = {
  id: string;
  title: string;
  visible: boolean;
  onClose: () => void;
};

export function TerminalSession({ id, title, visible, onClose }: Props) {
  const { t } = useI18n();
  const hostRef = useRef<HTMLDivElement>(null);
  const termRef = useRef<Terminal | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const [status, setStatus] = useState("");
  const [error, setError] = useState("");
  const [closing, setClosing] = useState(false);

  useEffect(() => {
    if (!hostRef.current) return;

    const term = new Terminal({
      cursorBlink: true,
      fontFamily: '"IBM Plex Mono", ui-monospace, monospace',
      fontSize: 14,
      theme: {
        background: "#0b1016",
        foreground: "#e8eef5",
        cursor: "#2f9e7a",
        selectionBackground: "#2a3544",
      },
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(hostRef.current);
    fit.fit();
    termRef.current = term;
    fitRef.current = fit;

    const cols = term.cols;
    const rows = term.rows;
    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(
      `${proto}//${window.location.host}/api/v1/sessions/${id}/ws?cols=${cols}&rows=${rows}`,
    );
    ws.binaryType = "arraybuffer";
    wsRef.current = ws;

    ws.onopen = () => setStatus(t("term.connected"));
    ws.onmessage = (ev) => {
      if (typeof ev.data === "string") {
        try {
          const msg = JSON.parse(ev.data) as { type?: string; message?: string };
          if (msg.type === "ready") {
            setStatus(t("term.active"));
            term.focus();
          } else if (msg.type === "error") {
            setError(msg.message || t("term.error"));
            setStatus(t("term.error"));
          }
        } catch {
          term.write(ev.data);
        }
        return;
      }
      const bytes = new Uint8Array(ev.data as ArrayBuffer);
      term.write(bytes);
    };
    ws.onerror = () => {
      setError("WebSocket error");
      setStatus(t("term.error"));
    };
    ws.onclose = () => {
      setStatus(t("term.ended"));
    };

    term.onData((data) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: "input", data }));
      }
    });

    const onResize = () => {
      fit.fit();
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: "resize", cols: term.cols, rows: term.rows }));
      }
    };
    window.addEventListener("resize", onResize);

    return () => {
      window.removeEventListener("resize", onResize);
      ws.close();
      term.dispose();
      termRef.current = null;
      fitRef.current = null;
      wsRef.current = null;
    };
  }, [id]);

  useEffect(() => {
    if (!visible) return;
    const t = window.setTimeout(() => {
      fitRef.current?.fit();
      termRef.current?.focus();
      const term = termRef.current;
      const ws = wsRef.current;
      if (term && ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: "resize", cols: term.cols, rows: term.rows }));
      }
    }, 50);
    return () => window.clearTimeout(t);
  }, [visible]);

  async function handleClose() {
    if (closing) return;
    setClosing(true);
    try {
      wsRef.current?.close();
    } catch {
      /* ignore */
    }
    onClose();
  }

  return (
    <div className="terminal-page session-panel-inner">
      <div className="toolbar">
        <div>
          <h1>{t("term.title")}</h1>
          <p className="muted">
            {title} · {status || t("term.connecting")}
            <span className="mono"> · {id.slice(0, 8)}</span>
          </p>
        </div>
        <button className="btn secondary" type="button" disabled={closing} onClick={() => void handleClose()}>
          {closing ? t("common.loading") : t("tabs.close")}
        </button>
      </div>
      {error && <p className="error">{error}</p>}
      <div className="terminal-host card" ref={hostRef} />
    </div>
  );
}
