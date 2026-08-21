import { useEffect, useState } from "react";
import { api } from "../api";

type Props = {
  id: string;
  title: string;
  visible: boolean;
  onClose: () => void;
};

type WireCreds = { token?: string; addr?: string; user?: string };

function loadWire(id: string): WireCreds {
  try {
    const raw = sessionStorage.getItem(`kp_wire_${id}`);
    if (!raw) return {};
    return JSON.parse(raw) as WireCreds;
  } catch {
    return {};
  }
}

export function Tn3270Session({ id, title, visible, onClose }: Props) {
  const [status, setStatus] = useState("…");
  const [error, setError] = useState("");
  const [wire, setWire] = useState<WireCreds>(() => loadWire(id));
  const [closing, setClosing] = useState(false);

  useEffect(() => {
    let stop = false;
    const tick = async () => {
      try {
        const s = await api.getSession(id);
        if (stop) return;
        setStatus(s.status);
        if (!wire.addr && s.protocol === "tn3270") {
          setWire((w) => ({ ...w, user: s.id, addr: w.addr || ":2324" }));
        }
      } catch (err) {
        if (!stop) setError(String(err));
      }
    };
    void tick();
    const t = setInterval(() => void tick(), 4000);
    return () => {
      stop = true;
      clearInterval(t);
    };
  }, [id, wire.addr]);

  async function end() {
    setClosing(true);
    try {
      await api.endSession(id);
    } catch {
      /* ignore */
    }
    onClose();
  }

  const addr = wire.addr || ":2324";
  const hostPort = addr.includes(":") ? addr.replace(/^:/, "PAM_HOST:") : addr;

  return (
    <div className="session-shell" style={{ display: visible ? undefined : "none" }}>
      <div className="session-toolbar row" style={{ justifyContent: "space-between" }}>
        <div>
          <strong>{title}</strong>
          <span className="muted" style={{ marginLeft: "0.75rem" }}>
            tn3270 · {status}
          </span>
        </div>
        <button className="btn secondary" type="button" disabled={closing} onClick={() => void end()}>
          {closing ? "…" : "End"}
        </button>
      </div>
      <div className="card" style={{ maxWidth: 640, margin: "1rem" }}>
        <h2>Native TN3270 client</h2>
        <p className="muted">
          HTML5-эмулятор 3270 в этом срезе нет. Подключайтесь x3270 / c3270 / wc3270 к шлюзу KeepPAM.
        </p>
        <ol>
          <li>
            Клиент: <code className="mono">x3270 {hostPort}</code>
          </li>
          <li>
            На экране KeepPAM: Session UUID ={" "}
            <code className="mono">{wire.user || id}</code>
          </li>
          <li>
            Wire token ={" "}
            <code className="mono">{wire.token || "(показан при Connect)"}</code>
          </li>
          <li>Enter → proxy на mainframe (запись JSONL + screen_text в events).</li>
        </ol>
        {error && <p className="error">{error}</p>}
      </div>
    </div>
  );
}
