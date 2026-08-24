/** Guacamole remote↔local clipboard helpers (text/plain). */

type GuacClient = {
  createClipboardStream: (mimetype: string) => {
    index: number;
    onack?: ((status: { code?: number }) => void) | null;
  };
  sendAck?: (index: number, message: string, code: number) => void;
  sendKeyEvent?: (pressed: number, keysym: number) => void;
};

type GuacLib = {
  StringWriter: new (stream: unknown) => {
    sendText: (text: string) => void;
    sendEnd: () => void;
    onack: ((status: { code?: number }) => void) | null;
  };
  StringReader: new (stream: unknown) => {
    ontext: ((text: string) => void) | null;
    onend: (() => void) | null;
  };
};

const CTRL_L = 0xffe3;
const KEY_V = 0x76;

export function writeLocalClipboardText(text: string): Promise<boolean> {
  if (!text) return Promise.resolve(false);
  if (navigator.clipboard?.writeText) {
    return navigator.clipboard.writeText(text).then(
      () => true,
      () => writeLocalClipboardFallback(text),
    );
  }
  return Promise.resolve(writeLocalClipboardFallback(text));
}

function writeLocalClipboardFallback(text: string): boolean {
  try {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.left = "-9999px";
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand("copy");
    ta.remove();
    return ok;
  } catch {
    return false;
  }
}

export async function readLocalClipboardText(): Promise<string> {
  try {
    if (typeof window !== "undefined" && window.isSecureContext && navigator.clipboard?.readText) {
      return await navigator.clipboard.readText();
    }
  } catch {
    /* fall through */
  }
  return "";
}

/** Last text we successfully copied/pasted in this tab (works on HTTP where Clipboard API is blocked). */
let memoryClipboard = "";

export function rememberClipboardText(text: string) {
  if (text) memoryClipboard = text;
}

export function getMemoryClipboardText(): string {
  return memoryClipboard;
}

/**
 * Best-effort clipboard read from a user-gesture handler (e.g. contextmenu).
 * Order: execCommand paste (sync) → Clipboard API → in-tab memory.
 */
export function readClipboardFromUserGesture(): string {
  const viaExec = tryExecCommandPaste();
  if (viaExec) return viaExec;
  return memoryClipboard;
}

function tryExecCommandPaste(): string {
  const ta = document.createElement("textarea");
  ta.setAttribute("autocomplete", "off");
  ta.setAttribute("autocorrect", "off");
  ta.setAttribute("autocapitalize", "off");
  ta.setAttribute("spellcheck", "false");
  ta.value = "";
  ta.style.cssText =
    "position:fixed;left:0;top:0;width:2px;height:2px;opacity:0;border:0;padding:0;margin:0;z-index:2147483647";
  document.body.appendChild(ta);
  ta.focus();
  ta.select();
  let text = "";
  const grab = (e: ClipboardEvent) => {
    text = e.clipboardData?.getData("text/plain") || "";
    e.preventDefault();
  };
  ta.addEventListener("paste", grab);
  try {
    document.execCommand("paste");
  } catch {
    /* ignore */
  }
  ta.removeEventListener("paste", grab);
  if (!text) text = ta.value || "";
  ta.remove();
  if (text) memoryClipboard = text;
  return text;
}

/** Cancel handle for an in-flight captureNextPaste. */
let activeCaptureCancel: (() => void) | null = null;

/**
 * Right-click paste when Clipboard API is unavailable (typical HTTP):
 * resolve on the next real paste event (Ctrl+V) or timeout.
 */
export function captureNextPaste(timeoutMs = 8000): Promise<string> {
  activeCaptureCancel?.();
  return new Promise((resolve) => {
    const finish = (text: string) => {
      activeCaptureCancel = null;
      window.clearTimeout(timer);
      document.removeEventListener("paste", onDocPaste, true);
      if (text) memoryClipboard = text;
      resolve(text);
    };
    activeCaptureCancel = () => finish("");
    const onDocPaste = (e: ClipboardEvent) => {
      const text = e.clipboardData?.getData("text/plain") || "";
      if (!text) return;
      e.preventDefault();
      e.stopPropagation();
      finish(text);
    };
    document.addEventListener("paste", onDocPaste, true);
    const timer = window.setTimeout(() => finish(""), timeoutMs);
  });
}

/** Push text to remote clipboard; resolves after server ack (or timeout). */
export function sendTextToGuacClipboard(
  Guacamole: GuacLib,
  client: GuacClient,
  text: string,
): Promise<boolean> {
  if (!text) return Promise.resolve(false);
  return new Promise((resolve) => {
    let done = false;
    const finish = (ok: boolean) => {
      if (done) return;
      done = true;
      resolve(ok);
    };
    try {
      const stream = client.createClipboardStream("text/plain");
      const writer = new Guacamole.StringWriter(stream);
      const timer = window.setTimeout(() => finish(true), 400);
      writer.onack = (status) => {
        window.clearTimeout(timer);
        // 0x0000 SUCCESS
        finish(!status?.code || status.code === 0);
      };
      // Chunk large pastes
      const chunk = 4096;
      for (let i = 0; i < text.length; i += chunk) {
        writer.sendText(text.slice(i, i + chunk));
      }
      writer.sendEnd();
    } catch {
      finish(false);
    }
  });
}

export function sendRemotePasteKeys(client: GuacClient) {
  client.sendKeyEvent?.(1, CTRL_L);
  client.sendKeyEvent?.(1, KEY_V);
  client.sendKeyEvent?.(0, KEY_V);
  client.sendKeyEvent?.(0, CTRL_L);
}

export function bindGuacClipboardReceive(
  Guacamole: GuacLib,
  client: GuacClient & { onclipboard: ((stream: unknown, mimetype: string) => void) | null },
  enabled: () => boolean,
  onReceived?: (text: string, ok: boolean) => void,
) {
  client.onclipboard = (stream, mimetype) => {
    if (!enabled()) {
      client.sendAck?.((stream as { index: number }).index, "Clipboard denied by policy", 0x0100);
      return;
    }
    const mt = String(mimetype || "");
    if (!mt.startsWith("text/") && mt !== "") {
      client.sendAck?.((stream as { index: number }).index, "Only text clipboard supported", 0x0100);
      return;
    }
    const reader = new Guacamole.StringReader(stream);
    let data = "";
    reader.ontext = (chunk) => {
      data += chunk;
    };
    reader.onend = () => {
      if (!data) return;
      void writeLocalClipboardText(data).then((ok) => onReceived?.(data, ok));
    };
  };
}

export { CTRL_L, KEY_V };
