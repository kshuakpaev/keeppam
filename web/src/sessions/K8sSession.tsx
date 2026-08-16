import { FitAddon } from "@xterm/addon-fit";
import { useEffect, useRef, useState } from "react";
import { Terminal } from "xterm";
import "xterm/css/xterm.css";
import { api, type K8sBrowseItem, type K8sResourceKind } from "../api";

type Props = {
  id: string;
  title: string;
  visible: boolean;
  onClose: () => void;
};

function podContainers(obj: unknown): string[] {
  const spec = (obj as { spec?: { containers?: { name?: string }[]; initContainers?: { name?: string }[] } })?.spec;
  const names: string[] = [];
  for (const c of spec?.containers || []) {
    if (c.name) names.push(c.name);
  }
  for (const c of spec?.initContainers || []) {
    if (c.name) names.push(c.name);
  }
  return names;
}

export function K8sSession({ id, title, visible, onClose }: Props) {
  const [kubeconfig, setKubeconfig] = useState("");
  const [addr, setAddr] = useState("");
  const [status, setStatus] = useState("");
  const [aclNs, setAclNs] = useState<string[]>([]);
  const [namespaces, setNamespaces] = useState<string[]>([]);
  const [catalog, setCatalog] = useState<K8sResourceKind[]>([]);
  const [resource, setResource] = useState("pods");
  const [group, setGroup] = useState("");
  const [ns, setNs] = useState("");
  const [items, setItems] = useState<K8sBrowseItem[]>([]);
  const [objectText, setObjectText] = useState("");
  const [manifest, setManifest] = useState("");
  const [applyLog, setApplyLog] = useState("");
  const [error, setError] = useState("");
  const [copied, setCopied] = useState(false);
  const [loading, setLoading] = useState(false);
  const [execPod, setExecPod] = useState("");
  const [execNs, setExecNs] = useState("");
  const [execContainer, setExecContainer] = useState("");
  const [containers, setContainers] = useState<string[]>([]);
  const [execCmd, setExecCmd] = useState("/bin/sh");
  const [runOut, setRunOut] = useState("");
  const [execOpen, setExecOpen] = useState(false);
  const [pfPort, setPfPort] = useState("8080");
  const [pfMethod, setPfMethod] = useState("GET");
  const [pfPath, setPfPath] = useState("/");
  const [pfOut, setPfOut] = useState("");
  const launchRef = useRef({ ns: "", pod: "", container: "", cmd: "/bin/sh", mode: "exec" as "exec" | "attach" });
  const hostRef = useRef<HTMLDivElement>(null);
  const termRef = useRef<Terminal | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const wsRef = useRef<WebSocket | null>(null);

  const kind = catalog.find((k) => k.resource === resource && (k.group || "") === group) || catalog.find((k) => k.resource === resource);

  useEffect(() => {
    let stop = false;
    async function load() {
      try {
        const kc = await api.getKubeconfig(id);
        if (stop) return;
        setKubeconfig(kc.kubeconfig);
        setAddr(kc.k8s_addr);
      } catch (err) {
        if (!stop) setError(err instanceof Error ? err.message : "Нет kubeconfig");
      }
      try {
        const s = await api.getSession(id);
        if (!stop) {
          setStatus(s.status);
          setAclNs(s.k8s_namespaces || []);
        }
      } catch {
        /* ignore */
      }
      try {
        const cat = await api.k8sCatalog(id);
        if (!stop) setCatalog(cat.resources || []);
      } catch {
        /* gateway */
      }
      try {
        const n = await api.k8sNamespaces(id);
        if (stop) return;
        setNamespaces(n.namespaces || []);
        if (!ns && (n.namespaces || []).length) setNs(n.namespaces[0]);
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
  }, [id]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!execOpen || !hostRef.current) return;
    const term = new Terminal({
      cursorBlink: true,
      fontFamily: '"IBM Plex Mono", ui-monospace, monospace',
      fontSize: 13,
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
    const launch = launchRef.current;
    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const qs = new URLSearchParams();
    qs.set("namespace", launch.ns);
    qs.set("pod", launch.pod);
    if (launch.container) qs.set("container", launch.container);
    qs.set("cols", String(term.cols));
    qs.set("rows", String(term.rows));
    if (launch.mode !== "attach") {
      const cmd = launch.cmd.trim() || "/bin/sh";
      if (cmd.includes(" ") || cmd.includes("\t")) {
        qs.append("command", "/bin/sh");
        qs.append("command", "-c");
        qs.append("command", cmd);
      } else {
        qs.append("command", cmd);
      }
    }
    const path = launch.mode === "attach" ? "attach" : "exec";
    const ws = new WebSocket(`${proto}//${window.location.host}/api/v1/sessions/${id}/k8s/${path}?${qs}`);
    ws.binaryType = "arraybuffer";
    wsRef.current = ws;
    ws.onmessage = (ev) => {
      if (typeof ev.data === "string") {
        try {
          const msg = JSON.parse(ev.data) as { type?: string; message?: string };
          if (msg.type === "ready") {
            term.focus();
            return;
          }
          if (msg.type === "error") {
            setError(msg.message || "exec error");
          }
        } catch {
          term.write(ev.data);
        }
        return;
      }
      term.write(new Uint8Array(ev.data as ArrayBuffer));
    };
    ws.onerror = () => setError("WebSocket exec error");
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
  }, [execOpen, id]);

  async function refreshList() {
    if (!kind) return;
    if (kind.namespaced && !ns) {
      setError("Выберите namespace");
      return;
    }
    setLoading(true);
    setError("");
    try {
      const res = await api.k8sList(id, {
        resource: kind.resource,
        group: kind.group,
        namespace: kind.namespaced ? ns : undefined,
      });
      setItems(res.items || []);
    } catch (err) {
      setItems([]);
      setError(err instanceof Error ? err.message : "Ошибка списка");
    } finally {
      setLoading(false);
    }
  }

  async function openItem(it: K8sBrowseItem) {
    if (!kind) return;
    setLoading(true);
    setError("");
    try {
      const res = await api.k8sGet(id, {
        resource: kind.resource,
        group: kind.group,
        namespace: kind.namespaced ? it.namespace || ns : undefined,
        name: it.name,
      });
      setObjectText(JSON.stringify(res.object, null, 2));
      if (kind.resource === "pods") {
        setExecPod(it.name);
        setExecNs(it.namespace || ns);
        const ctrs = podContainers(res.object);
        setContainers(ctrs);
        setExecContainer(ctrs[0] || "");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка get");
    } finally {
      setLoading(false);
    }
  }

  async function saveObject() {
    setLoading(true);
    setError("");
    try {
      const object = JSON.parse(objectText) as unknown;
      const res = await api.k8sReplace(id, object);
      setObjectText(JSON.stringify(res.object, null, 2));
      await refreshList();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка сохранения");
    } finally {
      setLoading(false);
    }
  }

  async function deleteNamed(name: string, namespace?: string) {
    if (!kind) return;
    if (!window.confirm(`Удалить ${kind.resource} ${namespace || ns || ""}/${name}?`)) return;
    setLoading(true);
    setError("");
    try {
      await api.k8sDelete(id, {
        resource: kind.resource,
        group: kind.group,
        namespace: kind.namespaced ? namespace || ns : undefined,
        name,
      });
      if (objectText.includes(`"name": "${name}"`) || objectText.includes(`"name":"${name}"`)) {
        setObjectText("");
      }
      await refreshList();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка удаления");
    } finally {
      setLoading(false);
    }
  }

  async function applyYaml() {
    setLoading(true);
    setError("");
    setApplyLog("");
    try {
      const res = await api.k8sApply(id, { manifest, namespace: ns || undefined });
      const lines = (res.results || []).map((r) => {
        const loc = [r.namespace, r.name].filter(Boolean).join("/");
        return r.error ? `${r.verb} ${r.resource} ${loc}: ${r.error}` : `${r.verb} ${r.resource} ${loc} (${r.status})`;
      });
      setApplyLog(lines.join("\n"));
      if ((res.results || []).some((r) => r.error)) {
        setError("Apply: есть ошибки, см. лог");
      }
      await refreshList();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка apply");
    } finally {
      setLoading(false);
    }
  }

  async function runOnce() {
    if (!execPod) {
      setError("Откройте pod");
      return;
    }
    setLoading(true);
    setError("");
    setRunOut("");
    try {
      const res = await api.k8sExecOnce(id, {
        namespace: execNs || ns,
        pod: execPod,
        container: execContainer || undefined,
        command: execCmd.trim() || "id",
      });
      const parts = [res.stdout, res.stderr, res.message].filter(Boolean);
      setRunOut(parts.join("\n"));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка exec");
    } finally {
      setLoading(false);
    }
  }

  async function runPortForward() {
    if (!execPod) {
      setError("Откройте pod");
      return;
    }
    const port = Number(pfPort);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      setError("Порт 1..65535");
      return;
    }
    setLoading(true);
    setError("");
    setPfOut("");
    try {
      const res = await api.k8sPortForwardHTTP(id, {
        namespace: execNs || ns,
        pod: execPod,
        port,
        method: pfMethod,
        path: pfPath.trim() || "/",
      });
      const hdr = Object.entries(res.headers || {})
        .map(([k, v]) => `${k}: ${v}`)
        .join("\n");
      setPfOut(`HTTP ${res.status}${res.truncated ? " (truncated)" : ""}\n${hdr}\n\n${res.body || ""}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка port-forward");
    } finally {
      setLoading(false);
    }
  }

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
    <div className="session-panel-inner" style={{ maxWidth: 960, display: visible ? undefined : "none" }}>
      <div className="toolbar">
        <div>
          <h1>kubectl через PAM</h1>
          <p className="muted">
            {title} · {status || "…"} · {addr || ":16443"}
            {aclNs.length ? ` · ACL ${aclNs.join(", ")}` : ""}
          </p>
        </div>
        <button className="btn danger" type="button" onClick={onClose}>
          Завершить
        </button>
      </div>
      {error && <p className="error">{error}</p>}
      <p className="muted">
        Apply / delete / exec / attach / HTTP port-forward в браузере (cookie PAM). kubectl exec/attach/port-forward
        на :16443 по-прежнему запрещены. Secret.data маскируется; сохранять замаскированный Secret нельзя.
      </p>
      <div className="row" style={{ alignItems: "flex-end", flexWrap: "wrap", gap: "0.75rem" }}>
        <div>
          <label>Resource</label>
          <select
            value={`${group}|${resource}`}
            onChange={(e) => {
              const i = e.target.value.indexOf("|");
              setGroup(e.target.value.slice(0, i));
              setResource(e.target.value.slice(i + 1));
              setItems([]);
              setObjectText("");
            }}
          >
            {catalog.map((k) => (
              <option key={`${k.group || ""}|${k.resource}`} value={`${k.group || ""}|${k.resource}`}>
                {k.name}
              </option>
            ))}
          </select>
        </div>
        {kind?.namespaced !== false && (
          <div>
            <label>Namespace</label>
            {namespaces.length ? (
              <select value={ns} onChange={(e) => setNs(e.target.value)}>
                {namespaces.map((n) => (
                  <option key={n} value={n}>
                    {n}
                  </option>
                ))}
              </select>
            ) : (
              <input value={ns} onChange={(e) => setNs(e.target.value)} placeholder="default" />
            )}
          </div>
        )}
        <button className="btn" type="button" disabled={loading} onClick={() => void refreshList()}>
          {loading ? "…" : "Обновить"}
        </button>
      </div>
      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>Namespace</th>
            <th>Status</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {items.map((it) => (
            <tr key={`${it.namespace || ""}/${it.name}`}>
              <td>
                <button className="btn secondary" type="button" style={{ padding: "0.1rem 0.4rem" }} onClick={() => void openItem(it)}>
                  {it.name}
                </button>
              </td>
              <td className="mono">{it.namespace || "—"}</td>
              <td>{it.status || "—"}</td>
              <td>
                <button
                  className="btn secondary"
                  type="button"
                  style={{ padding: "0.1rem 0.4rem" }}
                  onClick={() => void deleteNamed(it.name, it.namespace)}
                >
                  Удалить
                </button>
              </td>
            </tr>
          ))}
          {items.length === 0 && (
            <tr>
              <td colSpan={4} className="muted">
                Нажмите «Обновить»
              </td>
            </tr>
          )}
        </tbody>
      </table>
      {objectText && (
        <>
          <div className="row" style={{ marginTop: "0.75rem", gap: "0.5rem", flexWrap: "wrap" }}>
            <button className="btn" type="button" disabled={loading} onClick={() => void saveObject()}>
              Сохранить
            </button>
            <button
              className="btn secondary"
              type="button"
              disabled={loading}
              onClick={() => {
                try {
                  const obj = JSON.parse(objectText) as { metadata?: { name?: string; namespace?: string } };
                  const name = obj.metadata?.name;
                  if (name) void deleteNamed(name, obj.metadata?.namespace);
                } catch {
                  setError("Невалидный JSON");
                }
              }}
            >
              Удалить объект
            </button>
          </div>
          <textarea
            value={objectText}
            onChange={(e) => setObjectText(e.target.value)}
            rows={16}
            style={{ width: "100%", fontFamily: "monospace", fontSize: "0.8rem", marginTop: "0.5rem" }}
          />
        </>
      )}
      {kind?.resource === "pods" && (
        <div className="card" style={{ marginTop: "1rem" }}>
          <h2>Exec / Attach</h2>
          <p className="muted">Интерактивный shell (exec) или attach к процессу контейнера. Не :16443.</p>
          <div className="row" style={{ alignItems: "flex-end", flexWrap: "wrap", gap: "0.75rem" }}>
            <div>
              <label>Pod</label>
              <input value={execPod} onChange={(e) => setExecPod(e.target.value)} placeholder="имя pod" />
            </div>
            {containers.length > 0 && (
              <div>
                <label>Container</label>
                <select value={execContainer} onChange={(e) => setExecContainer(e.target.value)}>
                  {containers.map((c) => (
                    <option key={c} value={c}>
                      {c}
                    </option>
                  ))}
                </select>
              </div>
            )}
            <div style={{ flex: 1, minWidth: 180 }}>
              <label>Command</label>
              <input value={execCmd} onChange={(e) => setExecCmd(e.target.value)} placeholder="/bin/sh" />
            </div>
            <button
              className="btn"
              type="button"
              disabled={loading || !execPod}
              onClick={() => {
                launchRef.current = {
                  ns: execNs || ns,
                  pod: execPod,
                  container: execContainer,
                  cmd: execCmd.trim() || "/bin/sh",
                  mode: "exec",
                };
                setExecOpen(true);
              }}
            >
              Shell
            </button>
            <button className="btn secondary" type="button" disabled={loading || !execPod} onClick={() => void runOnce()}>
              Run
            </button>
            <button
              className="btn secondary"
              type="button"
              disabled={loading || !execPod}
              onClick={() => {
                launchRef.current = {
                  ns: execNs || ns,
                  pod: execPod,
                  container: execContainer,
                  cmd: "",
                  mode: "attach",
                };
                setExecOpen(true);
              }}
            >
              Attach
            </button>
            {execOpen && (
              <button className="btn secondary" type="button" onClick={() => setExecOpen(false)}>
                Закрыть терминал
              </button>
            )}
          </div>
          {execOpen && <div className="k8s-exec-host card" ref={hostRef} style={{ marginTop: "0.75rem" }} />}
          {runOut && (
            <pre className="mono" style={{ whiteSpace: "pre-wrap", fontSize: "0.8rem", marginTop: "0.75rem" }}>
              {runOut}
            </pre>
          )}
        </div>
      )}
      {kind?.resource === "pods" && (
        <div className="card" style={{ marginTop: "1rem" }}>
          <h2>Port-forward HTTP</h2>
          <p className="muted">
            Одноразовый HTTP к порту контейнера через API portforward. Слушатель на хосте PAM не открывается. Тела
            Cookie/Authorization в ответе редактируются.
          </p>
          <div className="row" style={{ alignItems: "flex-end", flexWrap: "wrap", gap: "0.75rem" }}>
            <div style={{ width: 100 }}>
              <label>Port</label>
              <input value={pfPort} onChange={(e) => setPfPort(e.target.value)} placeholder="8080" />
            </div>
            <div>
              <label>Method</label>
              <select value={pfMethod} onChange={(e) => setPfMethod(e.target.value)}>
                {["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"].map((m) => (
                  <option key={m} value={m}>
                    {m}
                  </option>
                ))}
              </select>
            </div>
            <div style={{ flex: 1, minWidth: 180 }}>
              <label>Path</label>
              <input value={pfPath} onChange={(e) => setPfPath(e.target.value)} placeholder="/" />
            </div>
            <button
              className="btn"
              type="button"
              disabled={loading || !execPod}
              onClick={() => void runPortForward()}
            >
              Запрос
            </button>
          </div>
          {pfOut && (
            <pre className="mono" style={{ whiteSpace: "pre-wrap", fontSize: "0.8rem", marginTop: "0.75rem" }}>
              {pfOut}
            </pre>
          )}
        </div>
      )}
      <details style={{ marginTop: "1rem" }}>
        <summary>Apply YAML</summary>
        <p className="muted">Create или replace (при 409). Namespace по умолчанию — выбранный сверху, если в манифесте пусто.</p>
        <textarea
          value={manifest}
          onChange={(e) => setManifest(e.target.value)}
          rows={10}
          placeholder={"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: demo\ndata:\n  k: v"}
          style={{ width: "100%", fontFamily: "monospace", fontSize: "0.8rem" }}
        />
        <button className="btn" type="button" disabled={loading || !manifest.trim()} onClick={() => void applyYaml()}>
          Apply
        </button>
        {applyLog && (
          <pre className="mono" style={{ whiteSpace: "pre-wrap", fontSize: "0.8rem", marginTop: "0.5rem" }}>
            {applyLog}
          </pre>
        )}
      </details>
      <details style={{ marginTop: "1rem" }}>
        <summary className="muted">kubeconfig для локального kubectl</summary>
        <pre className="mono" style={{ whiteSpace: "pre-wrap", fontSize: "0.8rem" }}>
          {aclNs.length > 0
            ? `export KUBECONFIG=./keeppam-${id.slice(0, 8)}.kubeconfig
kubectl get ns
kubectl get pods -n ${aclNs[0]}`
            : `export KUBECONFIG=./keeppam-${id.slice(0, 8)}.kubeconfig
kubectl get ns
kubectl get pods -A`}
        </pre>
        <textarea
          readOnly
          value={kubeconfig}
          rows={8}
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
      </details>
    </div>
  );
}
