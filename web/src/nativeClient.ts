/** Download a text blob as a file in the browser. */
export function downloadTextFile(filename: string, content: string, mime = "text/plain;charset=utf-8") {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.rel = "noopener";
  a.style.display = "none";
  document.body.appendChild(a);
  a.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true, view: window }));
  document.body.removeChild(a);
  window.setTimeout(() => URL.revokeObjectURL(url), 2500);
}

export type NativeClientBundle = {
  native_conn_file?: string;
  native_conn_filename?: string;
  native_launcher?: string;
  native_launcher_filename?: string;
  native_launcher_sh?: string;
  native_launcher_sh_filename?: string;
  native_hint?: string;
  rdp_file?: string;
  rdp_filename?: string;
  rdp_launcher?: string;
  rdp_launcher_filename?: string;
  rdp_hint?: string;
  ssh_file?: string;
  ssh_filename?: string;
  ssh_launcher?: string;
  ssh_launcher_filename?: string;
  ssh_launcher_sh?: string;
  ssh_launcher_sh_filename?: string;
  ssh_hint?: string;
};

function ensureExt(name: string, ext: string): string {
  const n = (name || "").trim() || `keeppam${ext}`;
  const lower = n.toLowerCase();
  if (lower.endsWith(ext.toLowerCase())) return n;
  return n.replace(/\.[^.]+$/, "") + ext;
}

export type DownloadNativeOpts = {
  /** ssh | rdp — controls which artifacts are saved */
  protocol?: string;
};

/**
 * Save Native Client artifacts.
 * RDP: .rdp + optional .cmd (cmdkey).
 * SSH: PuTTY launcher .cmd first (Fudo-style), then OpenSSH config / .sh.
 */
export function downloadNativeClientBundle(bundle: NativeClientBundle, opts?: DownloadNativeOpts) {
  const protocol = (opts?.protocol || "").toLowerCase();
  const isRdp = protocol === "rdp" || !!(bundle.rdp_file && !bundle.ssh_file);

  if (isRdp) {
    const conn = bundle.rdp_file || bundle.native_conn_file;
    if (!conn) return bundle.rdp_hint || bundle.native_hint || "";
    const connName = ensureExt(
      bundle.rdp_filename || bundle.native_conn_filename || "keeppam.rdp",
      ".rdp",
    );
    downloadTextFile(connName, conn, "application/x-rdp");
    const launcher = bundle.rdp_launcher || bundle.native_launcher;
    const launcherName = ensureExt(
      bundle.rdp_launcher_filename || bundle.native_launcher_filename || "keeppam-rdp.cmd",
      ".cmd",
    );
    if (launcher) {
      window.setTimeout(() => downloadTextFile(launcherName, launcher, "application/x-bat"), 450);
    }
    return bundle.rdp_hint || bundle.native_hint || "";
  }

  // SSH: PuTTY .cmd first so the primary download opens the native client.
  const launcher = bundle.ssh_launcher || bundle.native_launcher;
  const launcherName = ensureExt(
    bundle.ssh_launcher_filename || bundle.native_launcher_filename || "keeppam-putty.cmd",
    ".cmd",
  );
  if (launcher) {
    downloadTextFile(launcherName, launcher, "application/x-bat");
  }
  const conn = bundle.ssh_file || bundle.native_conn_file;
  const connName = bundle.ssh_filename || bundle.native_conn_filename || "keeppam.sshconfig";
  if (conn) {
    window.setTimeout(() => downloadTextFile(connName, conn, "text/plain;charset=utf-8"), 400);
  }
  const sh = bundle.ssh_launcher_sh || bundle.native_launcher_sh;
  const shName = bundle.ssh_launcher_sh_filename || bundle.native_launcher_sh_filename;
  if (sh && shName) {
    window.setTimeout(() => downloadTextFile(shName, sh, "text/x-shellscript"), 800);
  }
  return bundle.ssh_hint || bundle.native_hint || "";
}
