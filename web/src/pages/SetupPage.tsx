import QRCode from "qrcode";
import { useEffect, useState, type FormEvent } from "react";
import { Navigate, useNavigate } from "react-router-dom";
import { api } from "../api";
import { useAuth } from "../auth";
import { webauthnRegister, webauthnSupported } from "../webauthn";

export function SetupPage() {
  const { user, refresh, loading } = useAuth();
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

  if (loading) return <div className="auth-page muted">Загрузка…</div>;
  if (!user) return <Navigate to="/login" replace />;

  async function onPassword(e: FormEvent) {
    e.preventDefault();
    setError("");
    if (next !== confirm) {
      setError("Пароли не совпадают");
      return;
    }
    try {
      await api.changePassword(current, next);
      setMsg("Пароль обновлён");
      await refresh();
      setStep("mfa");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка");
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
      setError(err instanceof Error ? err.message : "Ошибка MFA");
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
      setError(err instanceof Error ? err.message : "Неверный код");
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
      setError(err instanceof Error ? err.message : "Ошибка WebAuthn");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="auth-page">
      <div className="card auth-card">
        <div className="brand">KeepPAM</div>
        <h1>Первичная настройка</h1>
        <p className="muted">Смена пароля и MFA (TOTP или Passkey) обязательны</p>
        {error && <p className="error">{error}</p>}
        {msg && <p className="ok">{msg}</p>}
        {step === "password" ? (
          <form onSubmit={onPassword}>
            <label htmlFor="current">Текущий пароль</label>
            <input
              id="current"
              type="password"
              value={current}
              onChange={(e) => setCurrent(e.target.value)}
              required
            />
            <label htmlFor="next">Новый пароль (мин. 10 символов)</label>
            <input
              id="next"
              type="password"
              value={next}
              onChange={(e) => setNext(e.target.value)}
              minLength={10}
              required
            />
            <label htmlFor="confirm">Повтор пароля</label>
            <input
              id="confirm"
              type="password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              minLength={10}
              required
            />
            <button className="btn" type="submit">
              Сохранить пароль
            </button>
          </form>
        ) : mfaMode === "choose" ? (
          <div>
            <button className="btn" type="button" onClick={() => void startMfa()}>
              Настроить TOTP
            </button>
            {webauthnSupported() && (
              <button
                className="btn"
                type="button"
                style={{ marginTop: "0.75rem" }}
                onClick={() => setMfaMode("passkey")}
              >
                Зарегистрировать Passkey
              </button>
            )}
          </div>
        ) : mfaMode === "passkey" ? (
          <div>
            <label htmlFor="passkey-name">Имя ключа</label>
            <input
              id="passkey-name"
              value={passkeyName}
              onChange={(e) => setPasskeyName(e.target.value)}
            />
            <button className="btn" type="button" disabled={busy} onClick={() => void registerPasskey()}>
              Создать Passkey
            </button>
            <button
              className="btn"
              type="button"
              style={{ marginTop: "0.5rem" }}
              onClick={() => setMfaMode("choose")}
            >
              Назад
            </button>
          </div>
        ) : (
          <div>
            {!qr ? (
              <button className="btn" type="button" onClick={() => void startMfa()}>
                Сгенерировать MFA
              </button>
            ) : (
              <form onSubmit={confirmMfa}>
                <p className="muted">Отсканируйте QR в приложении-аутентификаторе</p>
                <div className="qr">
                  <img src={qr} alt="MFA QR" width={200} height={200} />
                </div>
                <p className="mono muted">Секрет: {secret}</p>
                <label htmlFor="totp">Код подтверждения</label>
                <input
                  id="totp"
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                  required
                />
                <button className="btn" type="submit">
                  Включить MFA
                </button>
              </form>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
