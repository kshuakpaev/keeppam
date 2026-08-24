import { useI18n } from "../i18n";
import { FitAddon } from "@xterm/addon-fit";
import { useEffect, useRef, useState } from "react";
import { Terminal } from "xterm";
import "xterm/css/xterm.css";
import {
  getMemoryClipboardText,
  rememberClipboardText,
  writeLocalClipboardText,
} from "../sessionClipboard";

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
  const [clipMsg, setClipMsg] = useState("");

  useEffect(() => {
    if (!hostRef.current) return;

    const term = new Terminal({
      cursorBlink: true,
      fontFamily: '"IBM Plex Mono", ui-monospace, monospace',
      fontSize: 14,
      rightClickSelectsWord: false,
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

    function applyPaste(text: string) {
      if (!text) return false;
      rememberClipboardText(text);
      term.paste(text);
      setClipMsg(t("clip.pasted"));
      term.focus();
      return true;
    }

    async function copySelection() {
      const sel = term.getSelection();
      if (!sel) {
        setClipMsg(t("clip.noSelection"));
        return;
      }
      rememberClipboardText(sel);
      const ok = await writeLocalClipboardText(sel);
      setClipMsg(ok ? t("clip.copied") : t("clip.copyFailed"));
    }

    function pasteFromMemoryOrFail() {
      const text = getMemoryClipboardText();
      if (!applyPaste(text)) setClipMsg(t("clip.emptyOrDenied"));
    }

    // Return false → xterm ignores the key (no SIGINT / no literal). Browser keeps
    // default so native copy/paste events still reach xterm's textarea.
    term.attachCustomKeyEventHandler((ev) => {
      if (ev.type !== "keydown") return true;
      const mod = ev.ctrlKey || ev.metaKey;
      if (!mod) return true;
      const key = ev.key.toLowerCase();
      if (key === "c" && (ev.shiftKey || term.hasSelection())) {
        // Also push to OS clipboard explicitly (HTTP-safe via execCommand fallback).
        void copySelection();
        return false;
      }
      if (key === "v") {
        return false;
      }
      return true;
    });

    const host = hostRef.current;

    // Remember clipboard text from native paste; do NOT cancel — xterm handles paste.
    const onPaste = (e: ClipboardEvent) => {
      const text = e.clipboardData?.getData("text/plain") || "";
      if (text) {
        rememberClipboardText(text);
        setClipMsg(t("clip.pasted"));
      }
    };

    const onCopy = (e: ClipboardEvent) => {
      const sel = term.getSelection();
      if (!sel) return;
      e.preventDefault();
      e.clipboardData?.setData("text/plain", sel);
      rememberClipboardText(sel);
      setClipMsg(t("clip.copied"));
    };

    // Linux SSH: right-click pastes last known text (from Ctrl+V / copy in this tab).
    // Browser blocks reading the OS clipboard on HTTP from contextmenu.
    const onContext = (e: MouseEvent) => {
      e.preventDefault();
      e.stopPropagation();
      const text = getMemoryClipboardText();
      if (applyPaste(text)) return;
      setClipMsg(t("clip.rightClickNeedCtrlV"));
    };

    host.addEventListener("paste", onPaste);
    host.addEventListener("copy", onCopy);
    host.addEventListener("contextmenu", onContext);

    const onResize = () => {
      fit.fit();
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: "resize", cols: term.cols, rows: term.rows }));
      }
    };
    window.addEventListener("resize", onResize);

    (term as Terminal & { __kpCopy?: () => void; __kpPaste?: () => void }).__kpCopy = () => void copySelection();
    (term as Terminal & { __kpPaste?: () => void }).__kpPaste = () => pasteFromMemoryOrFail();

    return () => {
      window.removeEventListener("resize", onResize);
      host.removeEventListener("paste", onPaste);
      host.removeEventListener("copy", onCopy);
      host.removeEventListener("contextmenu", onContext);
      ws.close();
      term.dispose();
      termRef.current = null;
      fitRef.current = null;
      wsRef.current = null;
    };
  }, [id, t]);

  useEffect(() => {
    if (!visible) return;
    const timer = window.setTimeout(() => {
      fitRef.current?.fit();
      termRef.current?.focus();
      const term = termRef.current;
      const ws = wsRef.current;
      if (term && ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: "resize", cols: term.cols, rows: term.rows }));
      }
    }, 50);
    return () => window.clearTimeout(timer);
  }, [visible]);

  useEffect(() => {
    if (!clipMsg) return;
    const timer = window.setTimeout(() => setClipMsg(""), 3000);
    return () => window.clearTimeout(timer);
  }, [clipMsg]);

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

  function onCopyClick() {
    const term = termRef.current as (Terminal & { __kpCopy?: () => void }) | null;
    term?.__kpCopy?.();
  }

  function onPasteClick() {
    const term = termRef.current as (Terminal & { __kpPaste?: () => void }) | null;
    term?.__kpPaste?.();
  }

  return (
    <div className="terminal-page session-panel-inner">
      <div className="toolbar">
        <div>
          <h1>{t("term.title")}</h1>
          <p className="muted">
            {title} · {status || t("term.connecting")}
            <span className="mono"> · {id.slice(0, 8)}</span>
            {clipMsg ? <span> · {clipMsg}</span> : null}
          </p>
        </div>
        <div className="row" style={{ gap: "0.5rem" }}>
          <button className="btn secondary" type="button" onClick={onCopyClick} title={t("clip.copyHint")}>
            {t("clip.copy")}
          </button>
          <button className="btn secondary" type="button" onClick={onPasteClick} title={t("clip.pasteHint")}>
            {t("clip.paste")}
          </button>
          <button className="btn secondary" type="button" disabled={closing} onClick={() => void handleClose()}>
            {closing ? t("common.loading") : t("tabs.close")}
          </button>
        </div>
      </div>
      {error && <p className="error">{error}</p>}
      <div className="terminal-host card" ref={hostRef} />
    </div>
  );
}
