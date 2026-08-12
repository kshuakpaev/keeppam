import { FitAddon } from "@xterm/addon-fit";
import { useEffect, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { Terminal } from "xterm";
import { api, type PamSession } from "../api";
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

        const res = await fetch(api.getRecordingUrl(id), { credentials: "include" });
        if (!res.ok) throw new Error("запись недоступна");

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
            setError(msg || "ошибка разбора записи");
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
        if (lines.length === 0) throw new Error("пустая запись");
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
        if (!cancelled) setError(err instanceof Error ? err.message : "Ошибка replay");
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
        if (!rec) throw new Error("запись не загружена");
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
                    reject(new Error("таймаут экспорта"));
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
        if (!ssh) throw new Error("запись не загружена");
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
      setError(err instanceof Error ? err.message : "Ошибка экспорта");
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
      setError(err instanceof Error ? err.message : "Ошибка MP4");
    } finally {
      setExportingMp4(false);
    }
  }

  const isGuac = protocol === "rdp" || protocol === "vnc" || isolated;

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100vh", minHeight: 0 }}>
      <div className="toolbar" style={{ flexShrink: 0 }}>
        <div>
          <p className="muted" style={{ marginBottom: "0.35rem" }}>
            <Link to="/sessions">Сессии</Link> / replay
          </p>
          <h1 style={{ margin: 0 }}>Воспроизведение</h1>
          <p className="muted">
            {meta || "…"}
            {protocol ? ` · ${protocol}` : ""}
            {playing ? " · играет" : ""}
            {exporting ? " · кодирование…" : ""}
            {exportingMp4 ? " · MP4…" : ""}
          </p>
        </div>
        <div className="row">
          {isGuac && (
            <button className="btn secondary" type="button" onClick={togglePlay} disabled={exporting || exportingMp4}>
              {playing ? "Пауза" : "Играть"}
            </button>
          )}
          <button
            className="btn secondary"
            type="button"
            disabled={!ready || exporting || exportingMp4}
            onClick={() => void exportWebM()}
          >
            {exporting ? "Кодирование…" : "Экспорт WebM"}
          </button>
          {isGuac && (
            <button
              className="btn secondary"
              type="button"
              disabled={!ready || exporting || exportingMp4}
              onClick={() => void exportMP4()}
            >
              {exportingMp4 ? "MP4…" : "Экспорт MP4"}
            </button>
          )}
          {id && (
            <a className="btn secondary" href={api.getRecordingUrl(id)}>
              Скачать
            </a>
          )}
          <Link className="btn secondary" to="/sessions">
            Назад
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
            : undefined
        }
      />
    </div>
  );
}
