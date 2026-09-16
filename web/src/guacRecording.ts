import Guacamole from "guacamole-common-js";

/**
 * guacamole-common-js@1.5.0 never assigns `recordingBlob = source` on the Blob
 * constructor path, so `new SessionRecording(blob)` always fails. Feed the same
 * bytes through a synthetic tunnel instead (supported API).
 */
export function openSessionRecording(blob: Blob) {
  const tunnel: {
    connect: () => void;
    disconnect: () => void;
    sendMessage: (...args: unknown[]) => void;
    oninstruction: ((opcode: string, args: string[]) => void) | null;
    onerror: ((status: { message?: string }) => void) | null;
    onstatechange: ((state: number) => void) | null;
  } = {
    connect() {},
    disconnect() {},
    sendMessage() {},
    oninstruction: null,
    onerror: null,
    onstatechange: null,
  };

  const recording = new Guacamole.SessionRecording(tunnel);

  void (async () => {
    try {
      const buf = await blob.arrayBuffer();
      // Byte-preserving string (same idea as FileReader.readAsText for ASCII/base64 guac streams).
      const text = new TextDecoder("latin1").decode(new Uint8Array(buf));

      const parser = new Guacamole.Parser();
      parser.oninstruction = (opcode: string, args: string[]) => {
        tunnel.oninstruction?.(opcode, args);
      };

      const feed = 256 * 1024;
      for (let i = 0; i < text.length; i += feed) {
        parser.receive(text.slice(i, i + feed));
        await new Promise((r) => setTimeout(r, 0));
      }

      tunnel.onstatechange?.(Guacamole.Tunnel.State.CLOSED);
    } catch (err) {
      tunnel.onerror?.({
        message: err instanceof Error ? err.message : "failed to load recording",
      });
      tunnel.onstatechange?.(Guacamole.Tunnel.State.CLOSED);
    }
  })();

  return withPlaybackSpeed(recording);
}

/** guacamole-common-js 1.5 SessionRecording has no rate API; 2×/4× follow wall clock. */
function withPlaybackSpeed(recording: {
  play: () => void;
  pause: () => void;
  seek: (ms: number, cb?: () => void) => void;
  getPosition: () => number;
  getDuration: () => number;
  isPlaying: () => boolean;
  onplay: (() => void) | null;
  onpause: (() => void) | null;
  setSpeed?: (speed: number) => void;
  getSpeed?: () => number;
  getDisplay: () => { getElement: () => HTMLElement; getWidth: () => number; getHeight: () => number; scale: (n: number) => void };
  onerror: ((msg: string) => void) | null;
  onprogress: ((dur: number) => void) | null;
  onload: (() => void) | null;
}) {
  const nativePlay = recording.play.bind(recording);
  const nativePause = recording.pause.bind(recording);
  const nativeSeek = recording.seek.bind(recording);
  const nativeIsPlaying = recording.isPlaying.bind(recording);
  const nativeGetPosition = recording.getPosition.bind(recording);

  let speed = 1;
  let wantPlaying = false;
  let timer: number | undefined;
  let inNative = false;
  let originVideo = 0;
  let originReal = 0;
  let seekBusy = false;

  const runNative = <T,>(fn: () => T): T => {
    inNative = true;
    try {
      return fn();
    } finally {
      inNative = false;
    }
  };

  const stopTimer = () => {
    if (timer != null) {
      window.clearTimeout(timer);
      timer = undefined;
    }
  };

  const armClock = (fromMs?: number) => {
    originVideo = fromMs != null ? fromMs : nativeGetPosition();
    originReal = performance.now();
  };

  const clockPos = () => originVideo + (performance.now() - originReal) * speed;

  const tick = () => {
    if (!wantPlaying || speed === 1) return;
    const dur = recording.getDuration();
    if (dur <= 0) {
      timer = window.setTimeout(tick, 50);
      return;
    }
    const target = Math.min(dur, clockPos());
    if (target >= dur - 1) {
      wantPlaying = false;
      stopTimer();
      runNative(() => nativeSeek(dur, () => nativePause()));
      recording.onpause?.();
      return;
    }
    if (seekBusy) {
      timer = window.setTimeout(tick, 16);
      return;
    }
    seekBusy = true;
    let settled = false;
    const done = () => {
      if (settled) return;
      settled = true;
      seekBusy = false;
      if (!wantPlaying || speed === 1) return;
      timer = window.setTimeout(tick, 50);
    };
    const watchdog = window.setTimeout(done, 400);
    runNative(() => {
      nativeSeek(target, () => {
        window.clearTimeout(watchdog);
        done();
      });
    });
  };

  recording.play = () => {
    if (inNative) {
      nativePlay();
      return;
    }
    wantPlaying = true;
    stopTimer();
    if (speed === 1) {
      nativePlay();
      return;
    }
    if (nativeIsPlaying()) runNative(() => nativePause());
    armClock();
    recording.onplay?.();
    tick();
  };

  recording.pause = () => {
    if (inNative) {
      nativePause();
      return;
    }
    const wasCustom = wantPlaying && speed !== 1;
    wantPlaying = false;
    stopTimer();
    runNative(() => nativePause());
    if (wasCustom) recording.onpause?.();
  };

  recording.isPlaying = () => {
    if (inNative) return nativeIsPlaying();
    if (speed === 1) return nativeIsPlaying();
    return wantPlaying;
  };

  recording.getPosition = () => {
    if (wantPlaying && speed !== 1) {
      return Math.min(recording.getDuration(), Math.max(0, clockPos()));
    }
    return nativeGetPosition();
  };

  recording.seek = (position: number, callback?: () => void) => {
    if (inNative) {
      nativeSeek(position, callback);
      return;
    }
    armClock(position);
    runNative(() => {
      nativeSeek(position, () => {
        if (wantPlaying && speed !== 1) {
          stopTimer();
          tick();
        }
        callback?.();
      });
    });
  };

  recording.setSpeed = (next: number) => {
    const s = next > 0 ? next : 1;
    if (s === speed) return;
    const playing = recording.isPlaying();
    if (playing) recording.pause();
    speed = s;
    if (playing) recording.play();
  };

  recording.getSpeed = () => speed;
  return recording;
}

export function createLiveGuacPlayer(container: HTMLElement) {
  const tunnel: {
    connect: () => void;
    disconnect: () => void;
    sendMessage: (...args: unknown[]) => void;
    oninstruction: ((opcode: string, args: string[]) => void) | null;
    onerror: ((status: { message?: string }) => void) | null;
    onstatechange: ((state: number) => void) | null;
  } = {
    connect() {},
    disconnect() {},
    sendMessage() {},
    oninstruction: null,
    onerror: null,
    onstatechange: null,
  };
  const client = new Guacamole.Client(tunnel);
  const display = client.getDisplay();
  const el = display.getElement() as HTMLElement;
  el.style.maxWidth = "100%";
  container.appendChild(el);
  client.connect();
  const parser = new Guacamole.Parser();
  parser.oninstruction = (opcode: string, args: string[]) => {
    tunnel.oninstruction?.(opcode, args);
  };
  return {
    feed(chunk: string) {
      parser.receive(chunk);
    },
    dispose() {
      try {
        client.disconnect();
      } catch {
        /* ignore */
      }
      el.remove();
    },
  };
}
