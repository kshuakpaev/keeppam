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

  return recording;
}
