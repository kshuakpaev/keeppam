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
  const tRef = useRef(t);
  tRef.current = t;
  const visibleRef = useRef(visible);
  visibleRef.current = visible;
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
    const tr = ((key, vars) => tRef.current(key, vars)) as typeof t;

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

    const markDead = (msg?: string) => {
      if ((ws as WebSocket & { __kpDead?: boolean }).__kpDead) return;
      (ws as WebSocket & { __kpDead?: boolean }).__kpDead = true;
      setStatus(tr("term.ended"));
      setError((prev) => prev || msg || tr("term.wsLost"));
    };

    ws.onopen = () => setStatus(tr("term.connected"));
    ws.onmessage = (ev) => {
      if (typeof ev.data === "string") {
        try {
          const msg = JSON.parse(ev.data) as { type?: string; message?: string };
          if (msg.type === "pong") return;
          if (msg.type === "ready") {
            setStatus(tr("term.active"));
            setError("");
            term.focus();
          } else if (msg.type === "error") {
            setError(msg.message || tr("term.error"));
            setStatus(tr("term.error"));
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
      setStatus(tr("term.error"));
    };
    ws.onclose = () => {
      markDead();
    };

    // App-level keepalive (helps when network path ignores WS control frames).
    const keepalive = window.setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) {
        try {
          ws.send(JSON.stringify({ type: "ping" }));
        } catch {
          markDead();
        }
      } else if (ws.readyState === WebSocket.CLOSED || ws.readyState === WebSocket.CLOSING) {
        markDead();
      }
    }, 25000);

    term.onData((data) => {
      if (ws.readyState !== WebSocket.OPEN) {
        markDead();
        return;
      }
      try {
        ws.send(JSON.stringify({ type: "input", data }));
      } catch {
        markDead();
      }
    });

    function applyPaste(text: string) {
      if (!text) return false;
      rememberClipboardText(text);
      term.paste(text);
      setClipMsg(tr("clip.pasted"));
      term.focus();
      return true;
    }

    async function copySelection() {
      const sel = term.getSelection();
      if (!sel) {
        setClipMsg(tr("clip.noSelection"));
        return;
      }
      rememberClipboardText(sel);
      const ok = await writeLocalClipboardText(sel);
      setClipMsg(ok ? tr("clip.copied") : tr("clip.copyFailed"));
    }

    function pasteFromMemoryOrFail() {
      const text = getMemoryClipboardText();
      if (!applyPaste(text)) setClipMsg(tr("clip.emptyOrDenied"));
    }

    term.attachCustomKeyEventHandler((ev) => {
      if (ev.type !== "keydown") return true;
      const mod = ev.ctrlKey || ev.metaKey;
      if (!mod) return true;
      const key = ev.key.toLowerCase();
      if (key === "c" && (ev.shiftKey || term.hasSelection())) {
        void copySelection();
        return false;
      }
      if (key === "v") {
        return false;
      }
      return true;
    });

    const host = hostRef.current;

    const onPaste = (e: ClipboardEvent) => {
      const text = e.clipboardData?.getData("text/plain") || "";
      if (text) {
        rememberClipboardText(text);
        setClipMsg(tr("clip.pasted"));
      }
    };

    const onCopy = (e: ClipboardEvent) => {
      const sel = term.getSelection();
      if (!sel) return;
      e.preventDefault();
      e.clipboardData?.setData("text/plain", sel);
      rememberClipboardText(sel);
      setClipMsg(tr("clip.copied"));
    };

    const onContext = (e: MouseEvent) => {
      e.preventDefault();
      e.stopPropagation();
      const text = getMemoryClipboardText();
      if (applyPaste(text)) return;
      setClipMsg(tr("clip.rightClickNeedCtrlV"));
    };

    const onHostMouseDown = () => {
      term.focus();
    };

    const focusIfNeeded = () => {
      if (!visibleRef.current) return;
      try {
        term.focus();
      } catch {
        /* ignore */
      }
    };

    const onVisibility = () => {
      if (!document.hidden) focusIfNeeded();
    };

    const onWinFocus = () => focusIfNeeded();

    // If focus left the xterm textarea, first keypress while session is visible restores it.
    const onDocKeyDown = (e: KeyboardEvent) => {
      if (!visibleRef.current) return;
      const target = e.target as HTMLElement | null;
      if (!target) return;
      if (target.closest?.(".xterm")) return;
      if (target.closest?.("input, textarea, select, button, [contenteditable=true]")) return;
      focusIfNeeded();
    };

    host.addEventListener("paste", onPaste);
    host.addEventListener("copy", onCopy);
    host.addEventListener("contextmenu", onContext);
    host.addEventListener("mousedown", onHostMouseDown);
    document.addEventListener("visibilitychange", onVisibility);
    window.addEventListener("focus", onWinFocus);
    document.addEventListener("keydown", onDocKeyDown, true);

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
      window.clearInterval(keepalive);
      window.removeEventListener("resize", onResize);
      document.removeEventListener("visibilitychange", onVisibility);
      window.removeEventListener("focus", onWinFocus);
      document.removeEventListener("keydown", onDocKeyDown, true);
      host.removeEventListener("paste", onPaste);
      host.removeEventListener("copy", onCopy);
      host.removeEventListener("contextmenu", onContext);
      host.removeEventListener("mousedown", onHostMouseDown);
      ws.close();
      term.dispose();
      termRef.current = null;
      fitRef.current = null;
      wsRef.current = null;
    };
  }, [id]);

  // Restore fit/focus when returning to this tab (after CSS shows the panel).
  useEffect(() => {
    if (!visible) return;
    let cancelled = false;
    const restore = () => {
      if (cancelled) return;
      const term = termRef.current;
      const fit = fitRef.current;
      const ws = wsRef.current;
      if (!term) return;
      try {
        fit?.fit();
        term.refresh(0, Math.max(0, term.rows - 1));
        term.focus();
      } catch {
        /* ignore */
      }
      if (ws && ws.readyState === WebSocket.OPEN && term.cols > 0 && term.rows > 0) {
        ws.send(JSON.stringify({ type: "resize", cols: term.cols, rows: term.rows }));
      } else if (ws && ws.readyState !== WebSocket.CONNECTING && ws.readyState !== WebSocket.OPEN) {
        setStatus(tRef.current("term.ended"));
        setError((prev) => prev || tRef.current("term.wsLost"));
      }
    };
    const raf = window.requestAnimationFrame(() => {
      window.requestAnimationFrame(restore);
    });
    const t1 = window.setTimeout(restore, 50);
    const t2 = window.setTimeout(restore, 250);
    return () => {
      cancelled = true;
      window.cancelAnimationFrame(raf);
      window.clearTimeout(t1);
      window.clearTimeout(t2);
    };
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
