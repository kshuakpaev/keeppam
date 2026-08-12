/** Minimal WebAuthn helpers (base64url + PublicKeyCredential conversion). */

function b64urlToBuf(value: string): ArrayBuffer {
  const pad = "=".repeat((4 - (value.length % 4)) % 4);
  const b64 = (value + pad).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

function bufToB64url(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

type JSONValue = string | number | boolean | null | JSONValue[] | { [k: string]: JSONValue };

function reviveCreateOptions(publicKey: Record<string, unknown>): PublicKeyCredentialCreationOptions {
  const challenge = b64urlToBuf(String(publicKey.challenge));
  const user = publicKey.user as Record<string, unknown>;
  const exclude = (publicKey.excludeCredentials as Array<Record<string, unknown>> | undefined) || [];
  return {
    ...(publicKey as unknown as PublicKeyCredentialCreationOptions),
    challenge,
    user: {
      ...(user as unknown as PublicKeyCredentialUserEntity),
      id: b64urlToBuf(String(user.id)),
    },
    excludeCredentials: exclude.map((c) => ({
      ...(c as unknown as PublicKeyCredentialDescriptor),
      id: b64urlToBuf(String(c.id)),
    })),
  };
}

function reviveRequestOptions(publicKey: Record<string, unknown>): PublicKeyCredentialRequestOptions {
  const allow = (publicKey.allowCredentials as Array<Record<string, unknown>> | undefined) || [];
  return {
    ...(publicKey as unknown as PublicKeyCredentialRequestOptions),
    challenge: b64urlToBuf(String(publicKey.challenge)),
    allowCredentials: allow.map((c) => ({
      ...(c as unknown as PublicKeyCredentialDescriptor),
      id: b64urlToBuf(String(c.id)),
    })),
  };
}

function credentialToJSON(cred: PublicKeyCredential): Record<string, JSONValue> {
  const anyCred = cred as PublicKeyCredential & {
    response: AuthenticatorAttestationResponse & AuthenticatorAssertionResponse;
  };
  const response: Record<string, JSONValue> = {
    clientDataJSON: bufToB64url(anyCred.response.clientDataJSON),
  };
  if ("attestationObject" in anyCred.response && anyCred.response.attestationObject) {
    response.attestationObject = bufToB64url(anyCred.response.attestationObject);
    const transports =
      typeof anyCred.response.getTransports === "function" ? anyCred.response.getTransports() : [];
    if (transports.length) response.transports = transports;
  }
  if ("authenticatorData" in anyCred.response && anyCred.response.authenticatorData) {
    response.authenticatorData = bufToB64url(anyCred.response.authenticatorData);
    response.signature = bufToB64url(anyCred.response.signature);
    if (anyCred.response.userHandle) {
      response.userHandle = bufToB64url(anyCred.response.userHandle);
    }
  }
  return {
    id: cred.id,
    rawId: bufToB64url(cred.rawId),
    type: cred.type,
    response,
    clientExtensionResults: cred.getClientExtensionResults() as unknown as JSONValue,
    authenticatorAttachment: (cred as PublicKeyCredential & { authenticatorAttachment?: string })
      .authenticatorAttachment || null,
  };
}

/** Server returns CredentialCreation { publicKey: ... } or the publicKey itself. */
export async function webauthnRegister(options: unknown): Promise<Record<string, JSONValue>> {
  const root = options as Record<string, unknown>;
  const publicKey = (root.publicKey || root) as Record<string, unknown>;
  const cred = (await navigator.credentials.create({
    publicKey: reviveCreateOptions(publicKey),
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error("Регистрация ключа отменена");
  return credentialToJSON(cred);
}

export async function webauthnAssert(options: unknown): Promise<Record<string, JSONValue>> {
  const root = options as Record<string, unknown>;
  const publicKey = (root.publicKey || root) as Record<string, unknown>;
  const cred = (await navigator.credentials.get({
    publicKey: reviveRequestOptions(publicKey),
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error("Проверка ключа отменена");
  return credentialToJSON(cred);
}

export function webauthnSupported(): boolean {
  return typeof window !== "undefined" && !!window.PublicKeyCredential;
}
