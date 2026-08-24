import Guacamole from "guacamole-common-js";
import { useEffect, useRef, useState } from "react";
import { api } from "../api";
import { autoRdpSize } from "../rdpResolution";
import { SessionStepUpHost } from "../components/SessionStepUpHost";
import { useI18n } from "../i18n";
import {
  bindGuacClipboardReceive,
  KEY_V,
  readLocalClipboardText,
  sendRemotePasteKeys,
  sendTextToGuacClipboard,
} from "../sessionClipboard";

type Props = {
  id: string;
  title: string;
  visible: boolean;
  onClose: () => void;
};

type GuacKeyboard = {
  onkeydown: ((k: number) => boolean | void) | null;
  onkeyup: ((k: number) => void) | null;
  modifiers: { ctrl?: boolean; meta?: boolean; alt?: boolean; shift?: boolean };
  pressed: Record<number, boolean>;
};

type GuacClient = {
  disconnect: () => void;
  sendKeyEvent?: (pressed: number, keysym: number) => void;
  createClipboardStream: (mimetype: string) => { index: number };
  onclipboard: ((stream: unknown, mimetype: string) => void) | null;
  sendAck?: (index: number, message: string, code: number) => void;
};

export function DesktopSession({ id, title, visible, onClose }: Props) {
  const { t } = useI18n();
  const hostRef = useRef<HTMLDivElement>(null);
  const clientRef = useRef<GuacClient | null>(null);
  const keyboardRef = useRef<GuacKeyboard | null>(null);
  const clipAllowedRef = useRef(false);
  const skipVKeyupRef = useRef(false);
  const startedRef = useRef(false);
  const [status, setStatus] = useState("");
  const [error, setError] = useState("");
  const [closing, setClosing] = useState(false);
  const [clipEnabled, setClipEnabled] = useState(false);
  const [clipMsg, setClipMsg] = useState("");

  useEffect(() => {
    if (!hostRef.current) return;
    if (startedRef.current) return;
    startedRef.current = true;

    let cancelled = false;
    const container = hostRef.current;
    let cleanup: (() => void) | undefined;

    void (async () => {
      let width = 0;
      let height = 0;
      let clipboardOn = false;
      try {
        const sess = await api.getSession(id);
        if (sess.rdp_width && sess.rdp_height) {
          width = sess.rdp_width;
          height = sess.rdp_height;
        }
        clipboardOn = !!sess.policy_snapshot?.rdp_clipboard;
      } catch {
        /* use auto below */
      }
      if (cancelled || !hostRef.current) return;
      clipAllowedRef.current = clipboardOn;
      setClipEnabled(clipboardOn);
      if (width <= 0 || height <= 0) {
        const auto = autoRdpSize();
        width = auto.width;
        height = auto.height;
      }

      const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
      const tunnel = new Guacamole.WebSocketTunnel(
        `${proto}//${window.location.host}/api/v1/sessions/${id}/guac?width=${width}&height=${height}`,
      );
      const client = new Guacamole.Client(tunnel) as GuacClient & {
        getDisplay: () => {
          getElement: () => HTMLElement;
          getWidth: () => number;
          getHeight: () => number;
          scale: (s: number) => void;
          onresize: (() => void) | null;
          getScale: () => number;
        };
        onerror: ((statusObj: { message?: string; code?: number }) => void) | null;
        onstatechange: ((state: number) => void) | null;
        sendMouseState: (state: unknown) => void;
        sendSize: (w: number, h: number) => void;
        connect: () => void;
      };
      clientRef.current = client;
      const display = client.getDisplay();
      const el = display.getElement() as HTMLElement;
      el.style.position = "relative";
      el.style.transformOrigin = "0 0";
      container.innerHTML = "";
      container.appendChild(el);

      const fit = () => {
        const dw = display.getWidth() || width;
        const dh = display.getHeight() || height;
        if (!dw || !dh) return;
        const scale = Math.min(container.clientWidth / dw, container.clientHeight / dh, 1);
        display.scale(scale > 0 ? scale : 1);
      };

      client.onerror = (statusObj: { message?: string; code?: number }) => {
        setError(statusObj?.message || `Guacamole error ${statusObj?.code ?? ""}`);
        setStatus(t("term.error"));
      };
      client.onstatechange = (state: number) => {
        if (state === 3) {
          setStatus(t("term.active"));
          fit();
        }
        if (state === 5) setStatus(t("term.ended"));
      };
      display.onresize = () => fit();

      bindGuacClipboardReceive(Guacamole, client, () => clipAllowedRef.current, (_text, ok) => {
        setClipMsg(ok ? t("clip.copied") : t("clip.copyFailed"));
      });

      async function pasteTextToRemote(text: string) {
        if (!clipAllowedRef.current || !text) return false;
        const ok = await sendTextToGuacClipboard(Guacamole, client, text);
        if (!ok) return false;
        // Brief delay so guacd/cliprdr applies buffer before Ctrl+V
        await new Promise((r) => window.setTimeout(r, 50));
        sendRemotePasteKeys(client);
        return true;
      }

      // InputSink must stay in-DOM and focusable so browser can fire paste.
      const sink = new Guacamole.InputSink();
      const sinkEl = sink.getElement() as HTMLTextAreaElement;
      document.body.appendChild(sinkEl);

      const keyboard = new Guacamole.Keyboard(document) as GuacKeyboard;
      keyboardRef.current = keyboard;

      function attachKeyboard() {
        keyboard.onkeydown = (keysym: number) => {
          // Ctrl/Cmd+V: allow browser default so `paste` fires with clipboardData
          // (Guacamole would otherwise preventDefault and paste never arrives).
          const mods = keyboard.modifiers;
          if (
            clipAllowedRef.current &&
            keysym === KEY_V &&
            (mods.ctrl || mods.meta) &&
            !mods.alt &&
            !mods.shift
          ) {
            skipVKeyupRef.current = true;
            // Still track Ctrl on remote; do not send V yet.
            return true; // → do not preventDefault
          }
          client.sendKeyEvent?.(1, keysym);
          return false;
        };
        keyboard.onkeyup = (keysym: number) => {
          if (keysym === KEY_V && skipVKeyupRef.current) {
            skipVKeyupRef.current = false;
            return;
          }
          client.sendKeyEvent?.(0, keysym);
        };
      }
      attachKeyboard();

      const onPaste = (e: ClipboardEvent) => {
        if (!clipAllowedRef.current) return;
        // Only handle when our session is the active keyboard target
        if (!visibleRef.current) return;
        const text = e.clipboardData?.getData("text/plain") ?? "";
        if (!text) return;
        e.preventDefault();
        e.stopPropagation();
        void pasteTextToRemote(text).then((ok) => {
          setClipMsg(ok ? t("clip.syncedRemote") : t("clip.copyFailed"));
        });
      };

      // visible captured via ref for paste handler
      const visibleRef = { current: true };

      const onCopy = (e: ClipboardEvent) => {
        // Remote→local is handled via onclipboard; nothing to do for local copy here.
        void e;
      };

      document.addEventListener("paste", onPaste, true);
      document.addEventListener("copy", onCopy, true);

      // Keep sink focused so paste/composition work (Guacamole InputSink design).
      const focusSink = () => {
        if (clipAllowedRef.current) sink.focus();
        else container.focus();
      };
      container.addEventListener("mousedown", focusSink);
      el.addEventListener("mousedown", focusSink);

      const mouse = new Guacamole.Mouse(el);
      const sendMouse = (state: unknown) => {
        const s = display.getScale() || 1;
        const st = state as {
          x: number;
          y: number;
          left: boolean;
          middle: boolean;
          right: boolean;
          up: boolean;
          down: boolean;
        };
        client.sendMouseState({
          ...st,
          x: Math.round(st.x / s),
          y: Math.round(st.y / s),
        });
      };
      mouse.onmousedown = sendMouse;
      mouse.onmouseup = sendMouse;
      mouse.onmousemove = sendMouse;

      const onWinResize = () => {
        fit();
        try {
          client.sendSize(
            Math.max(800, Math.floor(container.clientWidth)),
            Math.max(600, Math.floor(container.clientHeight)),
          );
        } catch {
          /* ignore */
        }
      };
      window.addEventListener("resize", onWinResize);

      client.connect();
      container.tabIndex = 0;
      focusSink();

      // Expose helpers for toolbar / visibility effect
      (client as GuacClient & { __kpPaste?: (text: string) => Promise<boolean>; __kpAttachKb?: () => void; __kpVisible?: { current: boolean } }).__kpPaste =
        pasteTextToRemote;
      (client as GuacClient & { __kpAttachKb?: () => void }).__kpAttachKb = attachKeyboard;
      (client as GuacClient & { __kpVisible?: { current: boolean } }).__kpVisible = visibleRef;

      cleanup = () => {
        window.removeEventListener("resize", onWinResize);
        document.removeEventListener("paste", onPaste, true);
        document.removeEventListener("copy", onCopy, true);
        container.removeEventListener("mousedown", focusSink);
        el.removeEventListener("mousedown", focusSink);
        try {
          client.disconnect();
        } catch {
          /* ignore */
        }
        clientRef.current = null;
        if (keyboardRef.current) {
          keyboardRef.current.onkeydown = null;
          keyboardRef.current.onkeyup = null;
        }
        keyboardRef.current = null;
        sinkEl.remove();
        startedRef.current = false;
      };
    })();

    return () => {
      cancelled = true;
      cleanup?.();
    };
  }, [id, t]);

  // Disable global keyboard capture when tab is hidden.
  useEffect(() => {
    const kb = keyboardRef.current;
    const client = clientRef.current as
      | (GuacClient & { __kpAttachKb?: () => void; __kpVisible?: { current: boolean } })
      | null;
    if (client?.__kpVisible) client.__kpVisible.current = visible;
    if (!kb || !client?.sendKeyEvent) return;
    if (visible) {
      client.__kpAttachKb?.();
      hostRef.current?.focus();
    } else {
      kb.onkeydown = null;
      kb.onkeyup = null;
    }
  }, [visible]);

  useEffect(() => {
    if (!clipMsg) return;
    const timer = window.setTimeout(() => setClipMsg(""), 2500);
    return () => window.clearTimeout(timer);
  }, [clipMsg]);

  async function handleClose() {
    if (closing) return;
    setClosing(true);
    try {
      clientRef.current?.disconnect();
    } catch {
      /* ignore */
    }
    onClose();
  }

  async function onPasteClick() {
    if (!clipAllowedRef.current) {
      setClipMsg(t("clip.rdpDisabled"));
      return;
    }
    const client = clientRef.current as (GuacClient & { __kpPaste?: (text: string) => Promise<boolean> }) | null;
    if (!client?.__kpPaste) return;
    const text = await readLocalClipboardText();
    if (!text) {
      setClipMsg(t("clip.emptyOrDenied"));
      return;
    }
    const ok = await client.__kpPaste(text);
    setClipMsg(ok ? t("clip.syncedRemote") : t("clip.copyFailed"));
  }

  return (
    <div className="session-panel-inner desktop-session">
      <div className="toolbar" style={{ flexShrink: 0 }}>
        <div>
          <h1 style={{ margin: 0 }}>{title || t("desktop.title")}</h1>
          <p className="muted">
            {status || t("term.connecting")}
            {clipEnabled ? (
              <span> · {t("clip.rdpOn")}</span>
            ) : (
              <span> · {t("clip.rdpOff")}</span>
            )}
            {clipMsg ? <span> · {clipMsg}</span> : null}
          </p>
        </div>
        <div className="row" style={{ gap: "0.5rem" }}>
          <button
            className="btn secondary"
            type="button"
            disabled={!clipEnabled}
            onClick={() => void onPasteClick()}
            title={clipEnabled ? t("clip.pasteHintRdp") : t("clip.rdpDisabled")}
          >
            {t("clip.paste")}
          </button>
          <button className="btn secondary" type="button" disabled={closing} onClick={() => void handleClose()}>
            {closing ? t("common.loading") : t("tabs.close")}
          </button>
        </div>
      </div>
      {error && <p className="error">{error}</p>}
      <div
        ref={hostRef}
        style={{
          flex: 1,
          minHeight: 0,
          overflow: "auto",
          background: "#0b0b0b",
          position: "relative",
          borderTop: "1px solid var(--border, #2a3544)",
        }}
      />
      <SessionStepUpHost sessionId={id} />
    </div>
  );
}
