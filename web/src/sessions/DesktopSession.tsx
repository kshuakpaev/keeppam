import Guacamole from "guacamole-common-js";
import { useEffect, useRef, useState } from "react";
import { SessionStepUpHost } from "../components/SessionStepUpHost";

type Props = {
  id: string;
  title: string;
  visible: boolean;
  onClose: () => void;
};

export function DesktopSession({ id, title, visible, onClose }: Props) {
  const hostRef = useRef<HTMLDivElement>(null);
  const clientRef = useRef<{ disconnect: () => void; sendKeyEvent?: (p: number, k: number) => void } | null>(
    null,
  );
  const keyboardRef = useRef<{ onkeydown: ((k: number) => void) | null; onkeyup: ((k: number) => void) | null } | null>(
    null,
  );
  const startedRef = useRef(false);
  const [status, setStatus] = useState("подключение…");
  const [error, setError] = useState("");
  const [closing, setClosing] = useState(false);

  useEffect(() => {
    if (!hostRef.current) return;
    if (startedRef.current) return;
    startedRef.current = true;

    const container = hostRef.current;
    const width = Math.max(1024, Math.floor(window.innerWidth - 64));
    const height = Math.max(768, Math.floor(window.innerHeight - 160));
    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const tunnel = new Guacamole.WebSocketTunnel(
      `${proto}//${window.location.host}/api/v1/sessions/${id}/guac?width=${width}&height=${height}`,
    );
    const client = new Guacamole.Client(tunnel);
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
      setStatus("ошибка");
    };
    client.onstatechange = (state: number) => {
      if (state === 3) {
        setStatus("сессия активна");
        fit();
      }
      if (state === 5) setStatus("сессия завершена");
    };
    display.onresize = () => fit();

    const sink = new Guacamole.InputSink();
    const sinkEl = sink.getElement() as HTMLElement;
    sinkEl.style.position = "fixed";
    sinkEl.style.left = "-1000px";
    document.body.appendChild(sinkEl);
    const keyboard = new Guacamole.Keyboard(document);
    keyboardRef.current = keyboard;
    keyboard.onkeydown = (keysym: number) => client.sendKeyEvent(1, keysym);
    keyboard.onkeyup = (keysym: number) => client.sendKeyEvent(0, keysym);

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
    container.focus();

    return () => {
      window.removeEventListener("resize", onWinResize);
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
  }, [id]);

  // Disable global keyboard capture when tab is hidden.
  useEffect(() => {
    const kb = keyboardRef.current;
    const client = clientRef.current;
    if (!kb || !client?.sendKeyEvent) return;
    if (visible) {
      kb.onkeydown = (keysym: number) => client.sendKeyEvent!(1, keysym);
      kb.onkeyup = (keysym: number) => client.sendKeyEvent!(0, keysym);
      hostRef.current?.focus();
    } else {
      kb.onkeydown = null;
      kb.onkeyup = null;
    }
  }, [visible]);

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

  return (
    <div className="session-panel-inner desktop-session">
      <div className="toolbar" style={{ flexShrink: 0 }}>
        <div>
          <h1 style={{ margin: 0 }}>{title || "Desktop"}</h1>
          <p className="muted">{status}</p>
        </div>
        <button className="btn secondary" type="button" disabled={closing} onClick={() => void handleClose()}>
          {closing ? "Завершение…" : "Закрыть"}
        </button>
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
