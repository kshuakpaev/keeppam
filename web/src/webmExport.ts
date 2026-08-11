/** Capture layered canvases (Guacamole / xterm) into a WebM via MediaRecorder. */

function pickMime(): string {
  const candidates = [
    "video/webm;codecs=vp9",
    "video/webm;codecs=vp8",
    "video/webm",
  ];
  for (const m of candidates) {
    if (typeof MediaRecorder !== "undefined" && MediaRecorder.isTypeSupported(m)) return m;
  }
  return "video/webm";
}

function findCanvases(root: HTMLElement): HTMLCanvasElement[] {
  return Array.from(root.querySelectorAll("canvas")).filter(
    (c) => c.width > 0 && c.height > 0,
  );
}

export async function recordElementToWebM(
  root: HTMLElement,
  opts: {
    fps?: number;
    /** Called once recording has started; resolve when capture should stop. */
    run: () => Promise<void>;
    filename: string;
  },
): Promise<void> {
  if (typeof MediaRecorder === "undefined") {
    throw new Error("MediaRecorder недоступен в этом браузере");
  }
  const canvases = findCanvases(root);
  if (canvases.length === 0) {
    throw new Error("нет canvas для захвата");
  }

  const fps = opts.fps ?? 15;
  const w = Math.max(...canvases.map((c) => c.width));
  const h = Math.max(...canvases.map((c) => c.height));
  const out = document.createElement("canvas");
  out.width = w;
  out.height = h;
  const ctx = out.getContext("2d");
  if (!ctx) throw new Error("2d context unavailable");

  const stream = out.captureStream(fps);
  const mime = pickMime();
  const chunks: BlobPart[] = [];
  const recorder = new MediaRecorder(stream, { mimeType: mime });
  recorder.ondataavailable = (e) => {
    if (e.data.size > 0) chunks.push(e.data);
  };

  let drawing = true;
  const draw = () => {
    if (!drawing) return;
    ctx.fillStyle = "#000";
    ctx.fillRect(0, 0, w, h);
    for (const c of canvases) {
      try {
        ctx.drawImage(c, 0, 0);
      } catch {
        /* tainted / disposed */
      }
    }
    requestAnimationFrame(draw);
  };

  const stopped = new Promise<void>((resolve) => {
    recorder.onstop = () => resolve();
  });

  recorder.start(200);
  draw();
  try {
    await opts.run();
    // brief tail so last frames land
    await new Promise((r) => setTimeout(r, 300));
  } finally {
    drawing = false;
    if (recorder.state !== "inactive") recorder.stop();
    for (const t of stream.getTracks()) t.stop();
  }
  await stopped;

  const blob = new Blob(chunks, { type: mime });
  if (blob.size === 0) throw new Error("пустой WebM");
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = opts.filename;
  a.click();
  URL.revokeObjectURL(url);
}
