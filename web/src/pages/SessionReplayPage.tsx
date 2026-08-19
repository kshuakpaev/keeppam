import { FitAddon } from "@xterm/addon-fit";
import { useEffect, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { Terminal } from "xterm";
import { api, type PamSession, type TranscriptLine, type SessionFile } from "../api";
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

export function SessionReplayPage() {
  const { t, te } = useI18n();
  const { id } = useParams<{ id: string }>();
  const hostRef = useRef<HTMLDivElement>(null);
  const [error, setError] = useState("");
  const [meta, setMeta] = useState("");
  const [protocol, setProtocol] = useState("");
  const [isolated, setIsolated] = useState(false);
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
  const [indexBusy, setIndexBusy] = useState(false);
  const [ocrBusy, setOcrBusy] = useState(false);
  const recordingRef = useRef<{
    play: () => void;
    pause: () => void;
    seek: (ms: number, cb?: () => void) => void;
    getPosition: () => number;
    getDuration: () => number;
    isPlaying: () => boolean;
  } | null>(null);
  const sshRef = useRef<{
    term: Terminal;
    events: CastEv[];
    replay: (speed: number, onDone?: () => void) => () => void;
  } | null>(null);

  useEffect(() => {
    if (!id || !hostRef.current) return;
    let cancelled = false;
    let timer: number | undefined;
    const container = hostRef.current;
    setReady(false);

    (async () => {
      try {
        const sess: PamSession = await api.getSession(id);
        if (cancelled) return;
        setMeta(`${sess.asset_name} · ${sess.account_username} · ${sess.username}`);
        setProtocol(sess.protocol);
        setIsolated(!!sess.isolated);
        try {
          const fl = await api.listSessionFiles(id);
          if (!cancelled) setFiles(fl.files || []);
        } catch {
          if (!cancelled) setFiles([]);
        }
        if (sess.protocol === "ssh" || sess.protocol === "rdp" || sess.protocol === "vnc" || sess.isolated) {
          try {
            const t = await api.getSessionTranscript(id);
            if (!cancelled) {
              setTranscript(t.lines || []);
              setOutputLines(t.output || []);
              setKeystrokes(t.keystrokes || []);
              setScreenText(t.screen_text || []);
            }
          } catch {
            /* replay still works */
          }
        }

        const res = await fetch(api.getRecordingUrl(id), { credentials: "include" });
        if (!res.ok) throw new Error(t("replay.unavailable"));

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

        const replay = (speed: number, onDone?: () => void) => {
          let i = 0;
          let stopped = false;
          term.reset();
          const start = performance.now();
          const tick = () => {
            if (cancelled || stopped) return;
            const elapsed = ((performance.now() - start) / 1000) * speed;
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
        replay(1);
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

  function onSeek(value: number) {
    const rec = recordingRef.current;
    if (!rec) return;
    rec.seek(value, () => setPosition(rec.getPosition()));
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
              ssh.replay(8, () => resolve());
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
    } catch (err) {
      setError(te(err, "replay.ocrError"));
    } finally {
      setOcrBusy(false);
    }
  }

  const isGuac = protocol === "rdp" || protocol === "vnc" || isolated;

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100vh", minHeight: 0 }}>
      <div className="toolbar" style={{ flexShrink: 0 }}>
        <div>
          <p className="muted" style={{ marginBottom: "0.35rem" }}>
            <Link to="/sessions">{t("nav.sessions")}</Link> / replay
          </p>
          <h1 style={{ margin: 0 }}>{t("replay.title")}</h1>
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
          <button
            className="btn secondary"
            type="button"
            disabled={!ready || exporting || exportingMp4}
            onClick={() => void exportWebM()}
          >
            {exporting ? t("replay.encoding") : t("replay.exportWebm")}
          </button>
          {isGuac && (
            <button
              className="btn secondary"
              type="button"
              disabled={!ready || exporting || exportingMp4}
              onClick={() => void exportMP4()}
            >
              {exportingMp4 ? t("replay.mp4Busy") : t("replay.exportMp4")}
            </button>
          )}
          {isGuac && (
            <button className="btn secondary" type="button" disabled={ocrBusy || indexBusy} onClick={() => void ocrScreen()}>
              {ocrBusy ? "OCR…" : t("replay.ocr")}
            </button>
          )}
          {id && (protocol === "ssh" || isGuac) && (
            <button className="btn secondary" type="button" disabled={indexBusy || ocrBusy} onClick={() => void indexTranscript()}>
              {indexBusy ? "…" : t("replay.index")}
            </button>
          )}
          {id && (
            <a className="btn secondary" href={api.getRecordingUrl(id)}>
              {t("sess.download")}
            </a>
          )}
          <Link className="btn secondary" to="/sessions">
            {t("common.back")}
          </Link>
        </div>
      </div>
      {error && <p className="error">{error}</p>}
      {isGuac && (
        <div className="row" style={{ padding: "0.5rem 1rem", gap: "0.75rem", alignItems: "center" }}>
          <span className="mono muted">{formatMs(position)}</span>
          <input
            type="range"
            min={0}
            max={Math.max(duration, 1)}
            value={Math.min(position, duration)}
            onChange={(e) => onSeek(Number(e.target.value))}
            style={{ flex: 1 }}
            disabled={exporting}
          />
          <span className="mono muted">{formatMs(duration)}</span>
        </div>
      )}
      <div style={{ display: "flex", flex: 1, minHeight: 0, gap: protocol === "ssh" || isGuac ? "0.75rem" : 0 }}>
      <div
        ref={hostRef}
        className={isGuac ? undefined : "terminal-host card"}
        style={
          isGuac
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
            {files.length === 0 ? t("replay.emptyFiles") : t("replay.nFiles", { n: files.length })}
          </p>
          <ul className="plain-list">
            {files.map((f) => (
              <li key={f.id}>
                <span className="mono" title={f.remote_path || f.filename}>
                  {f.direction} {f.protocol} {f.filename}
                </span>
                {f.captured ? (
                  <a className="btn secondary" href={api.getSessionFileUrl(id!, f.id)}>
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
        </aside>
      )}
      </div>
    </div>
  );
}
