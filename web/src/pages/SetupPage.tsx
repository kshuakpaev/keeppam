import QRCode from "qrcode";
import { useEffect, useState, type FormEvent } from "react";
import { Navigate, useNavigate } from "react-router-dom";
import { api } from "../api";
import { useAuth } from "../auth";
import brandMark from "../assets/keeppam-mark.png";
import { LangSwitch, useI18n } from "../i18n";
import { webauthnRegister, webauthnSupported } from "../webauthn";

export function SetupPage() {
  const { user, refresh, loading } = useAuth();
  const { t, te } = useI18n();
  const nav = useNavigate();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [code, setCode] = useState("");
  const [secret, setSecret] = useState("");
  const [qr, setQr] = useState("");
  const [error, setError] = useState("");
  const [msg, setMsg] = useState("");
  const [step, setStep] = useState<"password" | "mfa">("password");
  const [mfaMode, setMfaMode] = useState<"choose" | "totp" | "passkey">("choose");
  const [passkeyName, setPasskeyName] = useState("Passkey");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!loading && user) {
      if (!user.must_change_password && user.mfa_enabled) {
        nav("/", { replace: true });
      } else if (!user.must_change_password && !user.mfa_enabled) {
        setStep("mfa");
      }
    }
  }, [user, loading, nav]);

  if (loading) return <div className="auth-page muted">{t("common.loading")}</div>;
  if (!user) return <Navigate to="/login" replace />;

  async function onPassword(e: FormEvent) {
    e.preventDefault();
    setError("");
    if (next !== confirm) {
      setError(t("setup.mismatch"));
      return;
    }
    try {
      await api.changePassword(current, next);
      setMsg(t("setup.passwordUpdated"));
      await refresh();
      setStep("mfa");
    } catch (err) {
      setError(te(err));
    }
  }

  async function startMfa() {
    setError("");
    try {
      const setup = await api.mfaSetup();
      setSecret(setup.secret);
      setQr(await QRCode.toDataURL(setup.url, { width: 200, margin: 1 }));
      setMfaMode("totp");
    } catch (err) {
      setError(te(err));
    }
  }

  async function confirmMfa(e: FormEvent) {
    e.preventDefault();
    setError("");
    try {
      await api.mfaConfirm(code);
      await refresh();
      nav("/");
    } catch (err) {
      setError(te(err, "login.badCode"));
    }
  }

  async function registerPasskey() {
    setBusy(true);
    setError("");
    try {
      const options = await api.webauthnRegisterBegin();
      const credential = await webauthnRegister(options);
      await api.webauthnRegisterFinish(credential, passkeyName.trim() || "Passkey");
      await refresh();
      nav("/");
    } catch (err) {
      setError(te(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="auth-page">
      <div className="card auth-card">
        <div className="row" style={{ justifyContent: "space-between", alignItems: "center" }}>
          <div className="brand">
            <img className="brand-mark" src={brandMark} alt="" width={28} height={28} />
            <span>KeepPAM</span>
          </div>
          <LangSwitch />
        </div>
        <h1>{t("setup.title")}</h1>
        <p className="muted">{t("setup.lead")}</p>
        {error && <p className="error">{error}</p>}
        {msg && <p className="ok">{msg}</p>}
        {step === "password" ? (
          <form onSubmit={onPassword}>
            <label htmlFor="current">{t("setup.current")}</label>
            <input
              id="current"
              type="password"
              value={current}
              onChange={(e) => setCurrent(e.target.value)}
              required
            />
            <label htmlFor="next">{t("setup.next")}</label>
            <input
              id="next"
              type="password"
              value={next}
              onChange={(e) => setNext(e.target.value)}
              minLength={10}
              required
            />
            <label htmlFor="confirm">{t("setup.confirm")}</label>
            <input
              id="confirm"
              type="password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              minLength={10}
              required
            />
            <button className="btn" type="submit">
              {t("setup.savePassword")}
            </button>
          </form>
        ) : mfaMode === "choose" ? (
          <div>
            <button className="btn" type="button" onClick={() => void startMfa()}>
              {t("setup.totp")}
            </button>
            {webauthnSupported() && (
              <button
                className="btn"
                type="button"
                style={{ marginTop: "0.75rem" }}
                onClick={() => setMfaMode("passkey")}
              >
                {t("setup.registerPasskey")}
              </button>
            )}
          </div>
        ) : mfaMode === "passkey" ? (
          <div>
            <label htmlFor="passkey-name">{t("setup.keyName")}</label>
            <input
              id="passkey-name"
              value={passkeyName}
              onChange={(e) => setPasskeyName(e.target.value)}
            />
            <button className="btn" type="button" disabled={busy} onClick={() => void registerPasskey()}>
              {t("setup.createPasskey")}
            </button>
            <button
              className="btn"
              type="button"
              style={{ marginTop: "0.5rem" }}
              onClick={() => setMfaMode("choose")}
            >
              {t("common.back")}
            </button>
          </div>
        ) : (
          <div>
            {!qr ? (
              <button className="btn" type="button" onClick={() => void startMfa()}>
                {t("setup.genMfa")}
              </button>
            ) : (
              <form onSubmit={confirmMfa}>
                <p className="muted">{t("setup.scanQr")}</p>
                <div className="qr">
                  <img src={qr} alt="MFA QR" width={200} height={200} />
                </div>
                <p className="mono muted">{t("setup.secret", { secret })}</p>
                <label htmlFor="totp">{t("setup.code")}</label>
                <input
                  id="totp"
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                  required
                />
                <button className="btn" type="submit">
                  {t("setup.enableMfa")}
                </button>
              </form>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
