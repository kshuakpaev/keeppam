import { useState, type FormEvent } from "react";
import { api, type ApiError } from "../api";
import { webauthnAssert, webauthnSupported } from "../webauthn";

export function StepUpDialog(props: {
  err: ApiError;
  onDone: (token: string) => void;
  onCancel: () => void;
}) {
  const { err, onDone, onCancel } = props;
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const challenge = err.challenge_token || "";
  const factors = (err.risk_factors || []).join(", ") || "none";

  async function onTotp(e: FormEvent) {
    e.preventDefault();
    if (!challenge) return;
    setBusy(true);
    setError("");
    try {
      const res = await api.stepUpTotp(challenge, code.trim());
      onDone(res.step_up_token);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Неверный код");
    } finally {
      setBusy(false);
    }
  }

  async function onPasskey() {
    if (!challenge) return;
    setBusy(true);
    setError("");
    try {
      const options = await api.stepUpWebAuthnBegin(challenge);
      const credential = await webauthnAssert(options);
      const res = await api.stepUpWebAuthnFinish(challenge, credential);
      onDone(res.step_up_token);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Ошибка WebAuthn");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="overlay" role="dialog" aria-modal="true">
      <div className="card" style={{ width: "min(420px, 92vw)" }}>
        <h2 style={{ marginTop: 0 }}>Повторный MFA</h2>
        <p className="muted">
          Риск {err.risk_score ?? "—"} &gt; {err.max_risk ?? "—"} ({factors}). Подтвердите вход.
        </p>
        {error && <p className="error">{error}</p>}
        {err.totp && (
          <form onSubmit={(e) => void onTotp(e)}>
            <label htmlFor="stepup-code">Код TOTP</label>
            <input
              id="stepup-code"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              inputMode="numeric"
              autoComplete="one-time-code"
              autoFocus
            />
            <button className="btn" type="submit" disabled={busy || !code.trim()}>
              Подтвердить TOTP
            </button>
          </form>
        )}
        {err.webauthn && webauthnSupported() && (
          <button className="btn" type="button" style={{ marginTop: "0.75rem" }} disabled={busy} onClick={() => void onPasskey()}>
            Ключ безопасности / Passkey
          </button>
        )}
        <button className="btn secondary" type="button" style={{ marginTop: "0.75rem" }} disabled={busy} onClick={onCancel}>
          Отмена
        </button>
      </div>
    </div>
  );
}
