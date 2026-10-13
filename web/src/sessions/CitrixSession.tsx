import { useEffect, useState } from "react";
import { api } from "../api";

type Props = {
  id: string;
  title: string;
  visible: boolean;
  onClose: () => void;
};

type WireCreds = { token?: string; addr?: string; user?: string; ica?: string; filename?: string };

function loadWire(id: string): WireCreds {
  try {
    const raw = sessionStorage.getItem(`kp_wire_${id}`);
    if (!raw) return {};
    return JSON.parse(raw) as WireCreds;
  } catch {
    return {};
  }
}

export function CitrixSession({ id, title, visible, onClose }: Props) {
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
        if (!wire.user) setWire((w) => ({ ...w, user: s.id, addr: w.addr || ":1081" }));
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
  }, [id, wire.user]);

  function downloadICA() {
    if (!wire.ica) return;
    const blob = new Blob([wire.ica], { type: "application/x-ica" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = wire.filename || `keeppam-${id.slice(0, 8)}.ica`;
    a.click();
    URL.revokeObjectURL(url);
  }

  async function end() {
    setClosing(true);
    try {
      await api.endSession(id);
    } catch {
      /* ignore */
    }
    onClose();
  }

  return (
    <div className="session-shell" style={{ display: visible ? undefined : "none" }}>
      <div className="session-toolbar row" style={{ justifyContent: "space-between" }}>
        <div>
          <strong>{title}</strong>
          <span className="muted" style={{ marginLeft: "0.75rem" }}>
            citrix · {status}
          </span>
        </div>
        <button className="btn secondary" type="button" disabled={closing} onClick={() => void end()}>
          {closing ? "…" : "End"}
        </button>
      </div>
      <div className="card" style={{ maxWidth: 640, margin: "1rem" }}>
        <h2>Citrix via SOCKS</h2>
        <p className="muted">
          KeepPAM выдаёт <code>.ica</code> с ProxyType=Socks на шлюз. ICA/CGP байты
          пишутся в pcap рядом с JSONL; пиксельный HDX — OEM-плагин (
          <code>citrix_transport=hdx</code>).
        </p>
        <ol>
          <li>
            SOCKS: <code className="mono">{wire.addr || ":1081"}</code> · user=
            <code className="mono">{wire.user || id}</code>
          </li>
          <li>
            {wire.ica ? (
              <button className="btn" type="button" onClick={downloadICA}>
                Скачать .ica
              </button>
            ) : (
              <span className="muted">.ica был в ответе Connect (обновите сессию с портала)</span>
            )}
          </li>
          <li>Откройте файл в Citrix Workspace / Receiver.</li>
        </ol>
        {error && <p className="error">{error}</p>}
      </div>
    </div>
  );
}
