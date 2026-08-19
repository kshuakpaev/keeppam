import { useState, type FormEvent } from "react";
import { api, type ApiError } from "../api";
import { useI18n } from "../i18n";
import { webauthnAssert, webauthnSupported } from "../webauthn";

export function StepUpDialog(props: {
  err: ApiError;
  onDone: (token: string) => void;
  onCancel: () => void;
}) {
  const { t, te } = useI18n();
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
      setError(te(e, "login.badCode"));
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
      setError(te(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="overlay" role="dialog" aria-modal="true">
      <div className="card" style={{ width: "min(420px, 92vw)" }}>
        <h2 style={{ marginTop: 0 }}>{err.operation ? t("stepup.titleOp") : t("stepup.title")}</h2>
        <p className="muted">
          {t("stepup.risk", {
            score: err.risk_score ?? "—",
            max: err.max_risk ?? "—",
            factors: factors,
            what: err.operation ? t("stepup.op") : t("stepup.login"),
          })}
          {err.operation ? ` · ${err.operation}` : ""}
        </p>
        {error && <p className="error">{error}</p>}
        {err.totp && (
          <form onSubmit={(e) => void onTotp(e)}>
            <label htmlFor="stepup-code">{t("login.totp")}</label>
            <input
              id="stepup-code"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              inputMode="numeric"
              autoComplete="one-time-code"
              autoFocus
            />
            <button className="btn" type="submit" disabled={busy || !code.trim()}>
              {t("login.confirmTotp")}
            </button>
          </form>
        )}
        {err.webauthn && webauthnSupported() && (
          <button className="btn" type="button" style={{ marginTop: "0.75rem" }} disabled={busy} onClick={() => void onPasskey()}>
            {t("login.passkey")}
          </button>
        )}
        <button className="btn secondary" type="button" style={{ marginTop: "0.75rem" }} disabled={busy} onClick={onCancel}>
          {t("common.cancel")}
        </button>
      </div>
    </div>
  );
}
