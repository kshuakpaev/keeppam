import { FitAddon } from "@xterm/addon-fit";
import { useEffect, useRef, useState } from "react";
import { Link, Navigate, useLocation, useParams } from "react-router-dom";
import { Terminal } from "xterm";
import { api, type PamSession, type TranscriptLine, type SessionFile, type AISummary } from "../api";
import { useAuth } from "../auth";
import { useI18n } from "../i18n";
import { openSessionRecording } from "../guacRecording";
import { recordElementToWebM } from "../webmExport";
import "xterm/css/xterm.css";

type CastHeader = {
  version: number;
  width: number;
  height: number;
};

type CastEv = [number, string, string];

function formatMs(ms: number): string {
  const s = Math.max(0, Math.floor(ms / 1000));
  const m = Math.floor(s / 60);
  const r = s % 60;
  return `${m}:${r.toString().padStart(2, "0")}`;
}

type CitrixRec = {
  t?: string;
  event?: string;
  host?: string;
  port?: number;
  bytes_up?: number;
  bytes_down?: number;
  meta?: Record<string, unknown>;
};

export function SessionReplayPage() {
  const { t, te } = useI18n();
  const { user, loading } = useAuth();
  const { id } = useParams<{ id: string }>();
  const kiosk = useLocation().pathname.endsWith("/player");
  const hostRef = useRef<HTMLDivElement>(null);
  const [error, setError] = useState("");
  const [meta, setMeta] = useState("");
  const [protocol, setProtocol] = useState("");
  const [isolated, setIsolated] = useState(false);
  const [nativeRdp, setNativeRdp] = useState(false);
  const [playing, setPlaying] = useState(false);
  const [position, setPosition] = useState(0);
  const [duration, setDuration] = useState(0);
  const [exporting, setExporting] = useState(false);
  const [exportingMp4, setExportingMp4] = useState(false);
  const [ready, setReady] = useState(false);
  const [transcript, setTranscript] = useState<TranscriptLine[]>([]);
  const [outputLines, setOutputLines] = useState<TranscriptLine[]>([]);
  const [keystrokes, setKeystrokes] = useState<TranscriptLine[]>([]);
  const [screenText, setScreenText] = useState<TranscriptLine[]>([]);
  const [files, setFiles] = useState<SessionFile[]>([]);
  const [transferFiles, setTransferFiles] = useState<TranscriptLine[]>([]);
  const [windowTitles, setWindowTitles] = useState<TranscriptLine[]>([]);
  const [processes, setProcesses] = useState<TranscriptLine[]>([]);
  const [indexBusy, setIndexBusy] = useState(false);
  const [ocrBusy, setOcrBusy] = useState(false);
  const [playSpeed, setPlaySpeed] = useState(1);
  const [aiSum, setAiSum] = useState<AISummary | null>(null);
  const [citrixEvents, setCitrixEvents] = useState<CitrixRec[]>([]);
  const recordingRef = useRef<{
    play: () => void;
    pause: () => void;
    seek: (ms: number, cb?: () => void) => void;
    getPosition: () => number;
    getDuration: () => number;
    isPlaying: () => boolean;
    setSpeed?: (speed: number) => void;
    getSpeed?: () => number;
  } | null>(null);
  const sshRef = useRef<{
    term: Terminal;
    events: CastEv[];
    replay: (speed: number, fromSec?: number, onDone?: () => void) => () => void;
    stop?: () => void;
  } | null>(null);

  useEffect(() => {
    if (!id || !hostRef.current) return;
    let cancelled = false;
    let timer: number | undefined;
    const container = hostRef.current;
    setReady(false);
    setPlaySpeed(1);

    (async () => {
      try {
        const sess: PamSession = await api.getSession(id);
        if (cancelled) return;
        setMeta(`${sess.asset_name} · ${sess.account_username} · ${sess.username}`);
        setProtocol(sess.protocol);
        setIsolated(!!sess.isolated);
        const recPath = sess.recording_path || "";
        const isNativeRdp =
          recPath.includes("rdp-native") ||
          recPath.endsWith(".pcap") ||
          recPath.endsWith(".rec") ||
          recPath.endsWith(".irdp");
        setNativeRdp(isNativeRdp);
        try {
          const fl = await api.listSessionFiles(id);
          if (!cancelled) setFiles(fl.files || []);
        } catch {
          if (!cancelled) setFiles([]);
        }
        if (sess.protocol === "ssh" || sess.protocol === "rdp" || sess.protocol === "vnc" || sess.isolated) {
          try {
            const tr = await api.getSessionTranscript(id);
            if (!cancelled) {
              setTranscript(tr.lines || []);
              setOutputLines(tr.output || []);
              setKeystrokes(tr.keystrokes || []);
              setScreenText(tr.screen_text || []);
              setTransferFiles(tr.files || []);
              setWindowTitles(tr.window_titles || []);
              setProcesses(tr.processes || []);
              if (tr.io_hidden) setError(t("replay.ioHidden"));
            }
          } catch {
            /* replay still works */
          }
          void api
            .getSessionAISummary(id)
            .then((s) => {
              if (!cancelled) setAiSum(s);
            })
            .catch(() => {
              if (!cancelled) setAiSum(null);
            });
        }

        const res = await fetch(api.getRecordingUrl(id), { credentials: "include" });
        if (res.status === 403) {
          throw new Error(t("replay.ioHidden"));
        }
        if (!res.ok) throw new Error(t("replay.unavailable"));

        if (isNativeRdp) {
          if (!cancelled) setReady(true);
          return;
        }

        if (sess.protocol === "citrix") {
          const text = await res.text();
          if (cancelled) return;
          const rows: CitrixRec[] = [];
          for (const line of text.trim().split("\n")) {
            if (!line) continue;
            try {
              rows.push(JSON.parse(line) as CitrixRec);
            } catch {
              /* skip */
            }
          }
          setCitrixEvents(rows);
          setReady(true);
          return;
        }

        if (sess.protocol === "rdp" || sess.protocol === "vnc" || sess.isolated) {
          const blob = await res.blob();
          if (cancelled) return;
          const recording = openSessionRecording(blob);
          recordingRef.current = recording;
          const display = recording.getDisplay();
          const el = display.getElement() as HTMLElement;
          el.style.position = "relative";
          el.style.transformOrigin = "0 0";
          container.innerHTML = "";
          container.appendChild(el);

          const fit = () => {
            const dw = display.getWidth();
            const dh = display.getHeight();
            if (!dw || !dh) return;
            const scale = Math.min(container.clientWidth / dw, container.clientHeight / dh, 1);
            display.scale(scale > 0 ? scale : 1);
          };

          recording.onerror = (msg: string) => {
            setError(msg || t("replay.parseError"));
          };
          recording.onprogress = (dur: number) => {
            setDuration(dur);
          };
          recording.onload = () => {
            if (cancelled) return;
            setDuration(recording.getDuration());
            fit();
            recording.play();
            setPlaying(true);
            setReady(true);
          };
          recording.onplay = () => setPlaying(true);
          recording.onpause = () => setPlaying(false);

          const tick = () => {
            if (cancelled) return;
            setPosition(recording.getPosition());
            setDuration(recording.getDuration());
            fit();
            timer = window.setTimeout(tick, 200);
          };
          tick();
          return;
        }

        // SSH asciicast
        const text = await res.text();
        if (cancelled) return;
        const term = new Terminal({
          cursorBlink: false,
          disableStdin: true,
          fontFamily: '"IBM Plex Mono", ui-monospace, monospace',
          fontSize: 14,
          theme: {
            background: "#0b1016",
            foreground: "#e8eef5",
            cursor: "#2f9e7a",
          },
        });
        const fitAddon = new FitAddon();
        term.loadAddon(fitAddon);
        container.innerHTML = "";
        term.open(container);
        fitAddon.fit();

        const lines = text.trim().split("\n");
        if (lines.length === 0) throw new Error(t("replay.empty"));
        const header = JSON.parse(lines[0]) as CastHeader;
        term.resize(header.width || 80, header.height || 24);
        fitAddon.fit();

        const events: CastEv[] = [];
        for (let i = 1; i < lines.length; i++) {
          try {
            const e = JSON.parse(lines[i]) as CastEv;
            if (e[1] === "o") events.push(e);
          } catch {
            /* skip */
          }
        }
        if (events.length) setDuration(events[events.length - 1][0] * 1000);

        const replay = (speed: number, fromSec = 0, onDone?: () => void) => {
          let i = 0;
          let stopped = false;
          term.reset();
          while (i < events.length && events[i][0] < fromSec) {
            term.write(events[i][2]);
            i++;
          }
          const t0 = performance.now();
          const tick = () => {
            if (cancelled || stopped) return;
            const elapsed = fromSec + ((performance.now() - t0) / 1000) * speed;
            setPosition(elapsed * 1000);
            while (i < events.length && events[i][0] <= elapsed) {
              term.write(events[i][2]);
              i++;
            }
            if (i < events.length) {
              timer = window.setTimeout(tick, 16);
            } else {
              setPlaying(false);
              onDone?.();
            }
          };
          setPlaying(true);
          tick();
          return () => {
            stopped = true;
          };
        };

        sshRef.current = { term, events, replay };
        setReady(true);
        const stop = replay(1, 0);
        sshRef.current.stop = stop;
      } catch (err) {
        if (!cancelled) setError(te(err, "replay.error"));
      }
    })();

    return () => {
      cancelled = true;
      if (timer) window.clearTimeout(timer);
      try {
        recordingRef.current?.pause();
      } catch {
        /* ignore */
      }
      recordingRef.current = null;
      sshRef.current = null;
      container.innerHTML = "";
    };
  }, [id]);

  function togglePlay() {
    const rec = recordingRef.current;
    if (!rec) return;
    if (rec.isPlaying()) rec.pause();
    else rec.play();
  }

  async function exportWebM() {
    if (!id || !hostRef.current || !ready) return;
    setExporting(true);
    setError("");
    try {
      const filename = `session-${id}.webm`;
      if (protocol === "rdp" || protocol === "vnc") {
        const rec = recordingRef.current;
        if (!rec) throw new Error(t("replay.notLoaded"));
        rec.setSpeed?.(1);
        setPlaySpeed(1);
        await recordElementToWebM(hostRef.current, {
          filename,
          fps: 15,
          run: () =>
            new Promise<void>((resolve, reject) => {
              const dur = rec.getDuration() || duration;
              rec.pause();
              rec.seek(0, () => {
                rec.play();
                setPlaying(true);
                const start = Date.now();
                const watch = () => {
                  const pos = rec.getPosition();
                  if (pos >= dur - 50 || (!rec.isPlaying() && pos > 0 && Date.now() - start > 500)) {
                    rec.pause();
                    resolve();
                    return;
                  }
                  if (Date.now() - start > Math.max(dur, 1000) + 15000) {
                    reject(new Error(t("replay.exportTimeout")));
                    return;
                  }
                  window.setTimeout(watch, 100);
                };
                watch();
              });
            }),
        });
      } else {
        const ssh = sshRef.current;
        if (!ssh) throw new Error(t("replay.notLoaded"));
        await recordElementToWebM(hostRef.current, {
          filename,
          fps: 15,
          run: () =>
            new Promise<void>((resolve) => {
              ssh.replay(8, 0, () => resolve());
            }),
        });
      }
    } catch (err) {
      setError(te(err, "replay.exportError"));
    } finally {
      setExporting(false);
    }
  }

  async function exportMP4() {
    if (!id) return;
    setExportingMp4(true);
    setError("");
    try {
      const res = await api.exportSessionMP4(id);
      const a = document.createElement("a");
      a.href = res.url;
      a.download = `session-${id}.mp4`;
      a.click();
    } catch (err) {
      setError(te(err, "replay.mp4Error"));
    } finally {
      setExportingMp4(false);
    }
  }

  async function indexTranscript() {
    if (!id) return;
    setIndexBusy(true);
    setError("");
    try {
      const res = await api.indexSessionTranscript(id, { force: true });
      setTranscript(res.lines || []);
      setOutputLines(res.output || []);
      setKeystrokes(res.keystrokes || []);
      setScreenText(res.screen_text || []);
      setTransferFiles(res.files || []);
      setWindowTitles(res.window_titles || []);
      setProcesses(res.processes || []);
    } catch (err) {
      setError(te(err, "replay.indexError"));
    } finally {
      setIndexBusy(false);
    }
  }

  async function ocrScreen() {
    if (!id) return;
    setOcrBusy(true);
    setError("");
    try {
      const res = await api.indexSessionTranscript(id, { force: true, ocr: true });
      setKeystrokes(res.keystrokes || []);
      setScreenText(res.screen_text || []);
      setWindowTitles(res.window_titles || []);
      setProcesses(res.processes || []);
    } catch (err) {
      setError(te(err, "replay.ocrError"));
    } finally {
      setOcrBusy(false);
    }
  }

  const isGuac = (protocol === "rdp" || protocol === "vnc" || isolated) && !nativeRdp;
  const isCitrix = protocol === "citrix";

  if (kiosk) {
    if (loading) return <p className="muted">…</p>;
    if (!user) return <Navigate to="/login" replace />;
  }

  function seekToMs(ms: number) {
    const rec = recordingRef.current;
    if (rec) {
      rec.seek(ms, () => setPosition(rec.getPosition()));
      return;
    }
    const ssh = sshRef.current;
    if (!ssh) return;
    ssh.stop?.();
    const stop = ssh.replay(playSpeed, Math.max(0, ms / 1000));
    ssh.stop = stop;
  }

  function setPlaybackSpeed(speed: number) {
    setPlaySpeed(speed);
    const rec = recordingRef.current;
    if (rec?.setSpeed) {
      rec.setSpeed(speed);
      return;
    }
    const ssh = sshRef.current;
    if (!ssh) return;
    ssh.stop?.();
    const from = position / 1000;
    const stop = ssh.replay(speed, from);
    ssh.stop = stop;
  }

  const fileRows: TranscriptLine[] =
    transferFiles.length > 0
      ? transferFiles
      : files.map((f) => ({
          ts: f.created_at,
          type: "file_transfer",
          command: `${f.direction} ${f.protocol} ${f.filename}`,
          filename: f.filename,
          file_id: f.id,
          captured: f.captured,
          path: f.remote_path,
          direction: f.direction,
          protocol: f.protocol,
        }));

  return (
    <div
      style={{ display: "flex", flexDirection: "column", height: "100vh", minHeight: 0, position: "relative" }}
      onContextMenu={kiosk ? (e) => e.preventDefault() : undefined}
    >
      <div className="toolbar" style={{ flexShrink: 0 }}>
        <div>
          {!kiosk && (
            <p className="muted" style={{ marginBottom: "0.35rem" }}>
              <Link to="/sessions">{t("nav.sessions")}</Link> / replay
            </p>
          )}
          <h1 style={{ margin: 0 }}>{kiosk ? t("replay.player") : t("replay.title")}</h1>
          <p className="muted">
            {meta || "…"}
            {protocol ? ` · ${protocol}` : ""}
            {playing ? ` · ${t("replay.playing")}` : ""}
            {exporting ? ` · ${t("replay.encoding")}` : ""}
            {exportingMp4 ? ` · ${t("replay.mp4Busy")}` : ""}
          </p>
        </div>
        <div className="row">
          {isGuac && (
            <button className="btn secondary" type="button" onClick={togglePlay} disabled={exporting || exportingMp4}>
              {playing ? t("replay.pause") : t("replay.play")}
            </button>
          )}
          {(isGuac || protocol === "ssh") && ready && (
            <span className="row" style={{ gap: 4, alignItems: "center" }}>
              <span className="muted">{t("replay.speed")}</span>
              {[1, 2, 4].map((s) => (
                <button
                  key={s}
                  className={playSpeed === s ? "btn" : "btn secondary"}
                  type="button"
                  disabled={exporting}
                  onClick={() => setPlaybackSpeed(s)}
                >
                  {s}×
                </button>
              ))}
            </span>
          )}
          {!kiosk && (
            <button
              className="btn secondary"
              type="button"
              disabled={!ready || exporting || exportingMp4 || isCitrix}
              onClick={() => void exportWebM()}
            >
              {exporting ? t("replay.encoding") : t("replay.exportWebm")}
            </button>
          )}
          {!kiosk && isGuac && (
            <button
              className="btn secondary"
              type="button"
              disabled={!ready || exporting || exportingMp4}
              onClick={() => void exportMP4()}
            >
              {exportingMp4 ? t("replay.mp4Busy") : t("replay.exportMp4")}
            </button>
          )}
          {!kiosk && isGuac && (
            <button className="btn secondary" type="button" disabled={ocrBusy || indexBusy} onClick={() => void ocrScreen()}>
              {ocrBusy ? "OCR…" : t("replay.ocr")}
            </button>
          )}
          {!kiosk && id && (protocol === "ssh" || isGuac) && (
            <button className="btn secondary" type="button" disabled={indexBusy || ocrBusy} onClick={() => void indexTranscript()}>
              {indexBusy ? "…" : t("replay.index")}
            </button>
          )}
          {!kiosk && id && (
            <a className="btn secondary" href={api.getRecordingUrl(id)}>
              {t("sess.download")}
            </a>
          )}
          {!kiosk && id && (
            <a className="btn secondary" href={api.getRecordingPcapUrl(id)}>
              {t("replay.exportPcap")}
            </a>
          )}
          {!kiosk && id && (
            <Link className="btn secondary" to={`/sessions/${id}/player`}>
              {t("replay.openPlayer")}
            </Link>
          )}
          <Link className="btn secondary" to="/sessions">
            {t("common.back")}
          </Link>
        </div>
      </div>
      {error && <p className="error">{error}</p>}
      {kiosk && (
        <div
          style={{
            position: "absolute",
            top: 72,
            right: 24,
            zIndex: 2,
            color: "rgba(255,255,255,0.45)",
            fontSize: 12,
            pointerEvents: "none",
            textTransform: "uppercase",
            letterSpacing: "0.08em",
          }}
        >
          {user?.username} · {t("watch.watermark")}
        </div>
      )}
      {nativeRdp && (
        <p className="muted" style={{ padding: "0 1rem" }}>
          {t("replay.nativeHint")}
        </p>
      )}
      {(isGuac || protocol === "ssh") && (
        <div className="row" style={{ padding: "0.5rem 1rem", gap: "0.75rem", alignItems: "center" }}>
          <span className="mono muted">{formatMs(position)}</span>
          <input
            type="range"
            min={0}
            max={Math.max(duration, 1)}
            value={Math.min(position, duration)}
            onChange={(e) => seekToMs(Number(e.target.value))}
            style={{ flex: 1 }}
            disabled={exporting}
          />
          <span className="mono muted">{formatMs(duration)}</span>
        </div>
      )}
      {aiSum && aiSum.status !== "skipped" ? (
        <div className="card" style={{ margin: "0 1rem 0.75rem" }}>
          <div className="row" style={{ justifyContent: "space-between", alignItems: "center" }}>
            <h2 style={{ margin: 0 }}>{t("replay.aiSummary")}</h2>
            {id ? (
              <button
                className="btn secondary"
                type="button"
                onClick={() =>
                  void api.postSessionAISummary(id, true).then(setAiSum).catch(() => undefined)
                }
              >
                {t("replay.aiRefresh")}
              </button>
            ) : null}
          </div>
          {aiSum.status === "pending" ? (
            <p className="muted">{t("replay.aiPending")}</p>
          ) : (
            <>
              <p>
                <strong>{aiSum.headline}</strong>
              </p>
              <p className="muted">{aiSum.summary}</p>
              {aiSum.screen_narrative ? <p className="muted">{aiSum.screen_narrative}</p> : null}
              <ul className="plain-list">
                {(aiSum.bullets || []).map((b, i) => (
                  <li key={i}>
                    {b.offset != null ? (
                      <button type="button" className="btn secondary" onClick={() => seekToMs(b.offset! * 1000)}>
                        {b.text}
                      </button>
                    ) : (
                      <span>{b.text}</span>
                    )}
                  </li>
                ))}
              </ul>
            </>
          )}
        </div>
      ) : null}
      <div style={{ display: "flex", flex: 1, minHeight: 0, gap: protocol === "ssh" || isGuac || isCitrix ? "0.75rem" : 0 }}>
      <div
        ref={hostRef}
        className={isGuac ? undefined : isCitrix ? undefined : "terminal-host card"}
        style={
          isCitrix
            ? { display: "none" }
            : isGuac
            ? {
                flex: 1,
                minHeight: 0,
                overflow: "auto",
                background: "#0b0b0b",
                position: "relative",
              }
            : { flex: 1, minHeight: 0 }
        }
      />
      {isCitrix && (
        <div className="card" style={{ flex: 1, minHeight: 0, overflow: "auto", margin: "0 1rem 1rem" }}>
          <h2 style={{ marginTop: 0 }}>{t("replay.citrixEvents")}</h2>
          <p className="muted">{t("replay.citrixHint")}</p>
          {citrixEvents.length === 0 ? (
            <p className="muted">{t("replay.emptyCitrix")}</p>
          ) : (
            <ul className="plain-list">
              {citrixEvents.map((ev, i) => (
                <li key={`${ev.t}-${i}`}>
                  <span className="mono muted">{ev.t ? new Date(ev.t).toLocaleTimeString() : ""}</span>{" "}
                  <strong>{ev.event || "event"}</strong>
                  {ev.host ? ` ${ev.host}${ev.port ? `:${ev.port}` : ""}` : ""}
                  {ev.bytes_up != null || ev.bytes_down != null
                    ? ` ↑${ev.bytes_up ?? 0} ↓${ev.bytes_down ?? 0}`
                    : ""}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
      {protocol === "ssh" && (
        <aside className="card" style={{ width: 320, flexShrink: 0, overflow: "auto", margin: "0 1rem 1rem 0" }}>
          <h2 style={{ marginTop: 0 }}>{t("replay.commands")}</h2>
          <p className="muted">
            {transcript.length === 0
              ? t("replay.emptyCommands")
              : t("replay.nLines", { n: transcript.length })}
          </p>
          <ul className="plain-list">
            {transcript.map((ln, i) => (
              <li key={`${ln.ts}-${i}`}>
                <span className="mono" title={ln.type}>
                  {ln.command || ln.type}
                </span>
                <span className="muted">{ln.source || ln.type}</span>
              </li>
            ))}
          </ul>
          <h2>{t("replay.output")}</h2>
          <p className="muted">
            {outputLines.length === 0 ? t("replay.emptyOutput") : t("replay.nLines", { n: outputLines.length })}
          </p>
          <ul className="plain-list">
            {outputLines.map((ln, i) => (
              <li key={`o-${ln.ts}-${i}`}>
                <span className="mono" title="output">
                  {ln.command || ln.type}
                </span>
              </li>
            ))}
          </ul>
          <h2>{t("replay.files")}</h2>
          <p className="muted">
            {fileRows.length === 0 ? t("replay.emptyFiles") : t("replay.nFiles", { n: fileRows.length })}
          </p>
          <ul className="plain-list">
            {fileRows.map((f, i) => (
              <li key={f.file_id || `${f.ts}-${i}`}>
                <button
                  type="button"
                  className="mono"
                  style={{ background: "none", border: 0, padding: 0, color: "inherit", cursor: "pointer", textAlign: "left" }}
                  title={f.path || f.filename}
                  onClick={() => seekToMs((f.offset || 0) * 1000)}
                >
                  {f.offset != null ? `[${Math.floor(f.offset)}s] ` : ""}
                  {f.command || f.filename}
                </button>
                {f.captured && f.file_id ? (
                  <a className="btn secondary" href={api.getSessionFileUrl(id!, f.file_id)}>
                    {t("sess.download")}
                  </a>
                ) : (
                  <span className="muted">audit</span>
                )}
              </li>
            ))}
          </ul>
        </aside>
      )}
      {isGuac && (
        <aside className="card" style={{ width: 320, flexShrink: 0, overflow: "auto", margin: "0 1rem 1rem 0" }}>
          <h2 style={{ marginTop: 0 }}>{t("replay.keys")}</h2>
          <p className="muted">
            {keystrokes.length === 0
              ? t("replay.emptyKeys")
              : t("replay.nLines", { n: keystrokes.length })}
          </p>
          <ul className="plain-list">
            {keystrokes.map((ln, i) => (
              <li key={`k-${ln.ts}-${i}`}>
                <span className="mono" title="keystroke">
                  {ln.command || ln.type}
                </span>
              </li>
            ))}
          </ul>
          <h2>{t("replay.screen")}</h2>
          <p className="muted">
            {screenText.length === 0
              ? t("replay.emptyOcr")
              : t("replay.nFrags", { n: screenText.length })}
          </p>
          <ul className="plain-list">
            {screenText.map((ln, i) => (
              <li key={`s-${ln.ts}-${i}`}>
                <span className="mono" title="screen_text">
                  {ln.offset != null ? `[${ln.offset}s] ` : ""}
                  {ln.command || ln.type}
                </span>
              </li>
            ))}
          </ul>
          <h2>{t("replay.titles")}</h2>
          <p className="muted">
            {windowTitles.length === 0 ? t("replay.emptyTitles") : t("replay.nFrags", { n: windowTitles.length })}
          </p>
          <ul className="plain-list">
            {windowTitles.map((ln, i) => (
              <li key={`w-${ln.ts}-${i}`}>
                <button
                  type="button"
                  className="mono"
                  style={{ background: "none", border: 0, padding: 0, color: "inherit", cursor: "pointer", textAlign: "left" }}
                  onClick={() => seekToMs((ln.offset || 0) * 1000)}
                >
                  {ln.offset != null ? `[${ln.offset}s] ` : ""}
                  {ln.command}
                </button>
              </li>
            ))}
          </ul>
          <h2>{t("replay.processes")}</h2>
          <p className="muted">
            {processes.length === 0 ? t("replay.emptyProcesses") : t("replay.nFrags", { n: processes.length })}
          </p>
          <ul className="plain-list">
            {processes.map((ln, i) => (
              <li key={`p-${ln.ts}-${i}`}>
                <button
                  type="button"
                  className="mono"
                  style={{ background: "none", border: 0, padding: 0, color: "inherit", cursor: "pointer", textAlign: "left" }}
                  onClick={() => seekToMs((ln.offset || 0) * 1000)}
                >
                  {ln.offset != null ? `[${ln.offset}s] ` : ""}
                  {ln.command}
                  {ln.source ? ` [${ln.source}]` : ""}
                </button>
              </li>
            ))}
          </ul>
          {fileRows.length > 0 && (
            <>
              <h2>{t("replay.files")}</h2>
              <p className="muted">{t("replay.nFiles", { n: fileRows.length })}</p>
              <ul className="plain-list">
                {fileRows.map((f, i) => (
                  <li key={f.file_id || `gf-${f.ts}-${i}`}>
                    <button
                      type="button"
                      className="mono"
                      style={{ background: "none", border: 0, padding: 0, color: "inherit", cursor: "pointer", textAlign: "left" }}
                      onClick={() => seekToMs((f.offset || 0) * 1000)}
                    >
                      {f.offset != null ? `[${Math.floor(f.offset)}s] ` : ""}
                      {f.command || f.filename}
                    </button>
                  </li>
                ))}
              </ul>
            </>
          )}
        </aside>
      )}
      </div>
    </div>
  );
}
