import { useEffect, useState } from "react";
import { api } from "../api";

type Props = {
  id: string;
  title: string;
  visible: boolean;
  onClose: () => void;
};

export function K8sSession({ id, title, visible, onClose }: Props) {
  const [kubeconfig, setKubeconfig] = useState("");
  const [addr, setAddr] = useState("");
  const [status, setStatus] = useState("");
  const [error, setError] = useState("");
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    let stop = false;
    async function load() {
      try {
        const kc = await api.getKubeconfig(id);
        if (stop) return;
        setKubeconfig(kc.kubeconfig);
        setAddr(kc.k8s_addr);
        setError("");
      } catch (err) {
        if (!stop) setError(err instanceof Error ? err.message : "Нет kubeconfig");
      }
      try {
        const s = await api.getSession(id);
        if (!stop) setStatus(s.status);
      } catch {
        /* ignore */
      }
    }
    void load();
    const t = setInterval(() => void load(), 20000);
    return () => {
      stop = true;
      clearInterval(t);
    };
  }, [id]);

  function download() {
    const blob = new Blob([kubeconfig], { type: "text/yaml" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `keeppam-${id.slice(0, 8)}.kubeconfig`;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  async function copy() {
    try {
      await navigator.clipboard.writeText(kubeconfig);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      setError("Не удалось скопировать");
    }
  }

  return (
    <div className="card" style={{ maxWidth: 720, display: visible ? undefined : "none" }}>
      <div className="toolbar">
        <div>
          <h1>kubectl через PAM</h1>
          <p className="muted">
            {title} · {status || "…"} · {addr || ":16443"}
          </p>
        </div>
        <button className="btn danger" type="button" onClick={onClose}>
          Завершить
        </button>
      </div>
      {error && <p className="error">{error}</p>}
      <p className="muted">
        Vault-секрет кластера не выдаётся. Этот kubeconfig указывает на KeepPAM{" "}
        <span className="mono">{addr || "https://localhost:16443"}</span>. exec / attach / port-forward
        запрещены.
      </p>
      <pre className="mono" style={{ whiteSpace: "pre-wrap", fontSize: "0.8rem" }}>
        {`export KUBECONFIG=./keeppam-${id.slice(0, 8)}.kubeconfig
kubectl get ns
kubectl get pods -A`}
      </pre>
      <textarea
        readOnly
        value={kubeconfig}
        rows={12}
        style={{ width: "100%", fontFamily: "monospace", fontSize: "0.8rem" }}
      />
      <div className="row" style={{ marginTop: "0.75rem" }}>
        <button className="btn" type="button" disabled={!kubeconfig} onClick={download}>
          Скачать kubeconfig
        </button>
        <button className="btn secondary" type="button" disabled={!kubeconfig} onClick={() => void copy()}>
          {copied ? "Скопировано" : "Копировать"}
        </button>
        <a className="btn secondary" href={api.getRecordingUrl(id)} target="_blank" rel="noreferrer">
          Лог запросов
        </a>
      </div>
    </div>
  );
}
