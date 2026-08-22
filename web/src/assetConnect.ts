import { api, type Asset, type AssetAccount } from "./api";
import { isSQLProtocol, kindForProtocol, type SessionTabKind } from "./sessionTabs";

const CONNECT_PROTOCOLS = new Set([
  "ssh",
  "telnet",
  "tn3270",
  "citrix",
  "rdp",
  "vnc",
  "postgres",
  "mysql",
  "mssql",
  "https",
  "kubectl",
]);

const SUPERVISOR_WAIT_MS = 15 * 60 * 1000;

export function isConnectableProtocol(protocol: string): boolean {
  return CONNECT_PROTOCOLS.has(protocol);
}

export function isConnectableAccount(asset: Asset, acc: AssetAccount): boolean {
  if (asset.status !== "active" || acc.status !== "active") return false;
  if (!isConnectableProtocol(asset.protocol)) return false;
  if (acc.has_secret) return true;
  return asset.protocol === "tn3270" || asset.protocol === "citrix";
}

export function connectableAccounts(asset: Asset): AssetAccount[] {
  return (asset.accounts || []).filter((acc) => isConnectableAccount(asset, acc));
}

export function connectButtonLabel(
  protocol: string,
  t: (key: string, vars?: Record<string, string | number>) => string,
  acc?: AssetAccount,
  withUsername?: boolean,
): string {
  let base: string;
  if (protocol === "ssh") base = t("assets.connectSsh");
  else if (protocol === "kubectl") base = t("assets.connectK8s");
  else if (isSQLProtocol(protocol)) base = t("assets.connectSql");
  else if (protocol === "https") base = t("assets.connectApp");
  else base = t("assets.connectOpen", { proto: protocol.toUpperCase() });
  if (withUsername && acc) return `${base} · ${acc.username}`;
  return base;
}

async function waitForSupervisor(sessionId: string, denied: string, timeout: string) {
  const deadline = Date.now() + SUPERVISOR_WAIT_MS;
  while (Date.now() < deadline) {
    const row = await api.getSession(sessionId);
    if (!row.waiting_supervisor) {
      if (row.status === "ended" || row.status === "failed") {
        throw new Error(row.error_message || denied);
      }
      return row;
    }
    await new Promise((r) => setTimeout(r, 1500));
  }
  throw new Error(timeout);
}

export type StartAssetSessionOpts = {
  ticket_id?: string;
  reason?: string;
  db_privilege?: "readonly" | "readwrite";
  step_up_token?: string;
  rdp_width?: number;
  rdp_height?: number;
  httpsIsolated?: boolean;
  supervisorDenied: string;
  supervisorTimeout: string;
};

export type StartAssetSessionResult = {
  sessionId: string;
  kind: SessionTabKind;
  title: string;
  protocol: string;
  msg?: string;
};

export async function startAssetSession(
  asset: Asset,
  acc: AssetAccount,
  opts: StartAssetSessionOpts,
): Promise<StartAssetSessionResult> {
  let sess = await api.createSession(asset.id, acc.id, {
    ticket_id: opts.ticket_id,
    reason: opts.reason,
    db_privilege:
      asset.protocol === "postgres" || asset.protocol === "mysql" ? opts.db_privilege : undefined,
    step_up_token: opts.step_up_token,
    rdp_width: asset.protocol === "rdp" ? opts.rdp_width : undefined,
    rdp_height: asset.protocol === "rdp" ? opts.rdp_height : undefined,
  });
  if (sess.waiting_supervisor) {
    sess = await waitForSupervisor(sess.id, opts.supervisorDenied, opts.supervisorTimeout);
  }

  const title = `${asset.name} · ${acc.username}`;
  const kind = kindForProtocol(asset.protocol, opts.httpsIsolated);
  let msg: string | undefined;

  if (isSQLProtocol(asset.protocol)) {
    if (sess.wire_token) {
      const fallback =
        asset.protocol === "mysql" ? ":13306" : asset.protocol === "mssql" ? ":11433" : ":15432";
      const dbn =
        sess.database_name ||
        asset.database_name ||
        (asset.protocol === "mssql" ? "master" : "postgres");
      msg = `Wire: host=PAM port=${sess.wire_addr || fallback} user=${sess.wire_user || sess.id} password=${sess.wire_token} dbname=${dbn} (Encrypt=Optional)`;
    }
  }
  if (asset.protocol === "telnet" && sess.wire_token) {
    msg = `Telnet wire: telnet PAM ${sess.wire_addr || ":2323"} — login=${sess.wire_user || sess.id} password=${sess.wire_token}`;
  }
  if (asset.protocol === "tn3270" && sess.wire_token) {
    sessionStorage.setItem(
      `kp_wire_${sess.id}`,
      JSON.stringify({
        token: sess.wire_token,
        addr: sess.wire_addr || ":2324",
        user: sess.wire_user || sess.id,
      }),
    );
    msg = `TN3270: x3270 PAM ${sess.wire_addr || ":2324"} — UUID=${sess.wire_user || sess.id} token=${sess.wire_token}`;
  }
  if (asset.protocol === "citrix" && (sess.citrix_ica || sess.wire_token)) {
    sessionStorage.setItem(
      `kp_wire_${sess.id}`,
      JSON.stringify({
        token: sess.wire_token,
        addr: sess.wire_addr || ":1081",
        user: sess.wire_user || sess.id,
        ica: sess.citrix_ica,
        filename: sess.citrix_filename,
      }),
    );
    if (sess.citrix_ica) {
      const blob = new Blob([sess.citrix_ica], { type: "application/x-ica" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = sess.citrix_filename || `keeppam-${sess.id.slice(0, 8)}.ica`;
      a.click();
      URL.revokeObjectURL(url);
    }
    msg = sess.wire_hint || `Citrix SOCKS ${sess.wire_addr || ":1081"}`;
  }
  if (asset.protocol === "rdp" && sess.rdp_file) {
    const blob = new Blob([sess.rdp_file], { type: "application/x-rdp" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = sess.rdp_filename || `keeppam-${sess.id.slice(0, 8)}.rdp`;
    a.click();
    URL.revokeObjectURL(url);
    msg = sess.rdp_hint || `Native RDP: ${sess.rdp_addr || ""}`;
  }

  return {
    sessionId: sess.id,
    kind,
    title,
    protocol: asset.protocol,
    msg,
  };
}
