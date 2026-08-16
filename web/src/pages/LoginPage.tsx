import { useEffect, useState, type FormEvent } from "react";
import { Navigate, useNavigate, useSearchParams } from "react-router-dom";
import { api } from "../api";
import { useAuth } from "../auth";
import { webauthnAssert, webauthnSupported } from "../webauthn";

export function LoginPage() {
  const { user, setUser, loading } = useAuth();
  const nav = useNavigate();
  const [params] = useSearchParams();
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [challenge, setChallenge] = useState<string | null>(params.get("mfa"));
  const [code, setCode] = useState("");
  const [error, setError] = useState(params.get("error") || "");
  const [busy, setBusy] = useState(false);
  const [mode, setMode] = useState("local");
  const [oidcReady, setOidcReady] = useState(false);
  const [samlReady, setSamlReady] = useState(false);
  const [samlIdps, setSamlIdps] = useState<{ slug: string; name: string }[]>([]);

  useEffect(() => {
    void (async () => {
      try {
        const m = await api.authMethods();
        setMode(m.mode);
        setOidcReady(m.oidc_ready);
        setSamlReady(!!m.saml_ready);
        setSamlIdps(m.saml_idps || []);
      } catch {
        /* default local */
      }
    })();
  }, []);

  if (!loading && user) {
    if (user.must_change_password || !user.mfa_enabled) {
      return <Navigate to="/setup" replace />;
    }
    return <Navigate to="/" replace />;
  }

  async function onLogin(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      const res = await api.login(username, password);
      if (res.status === "mfa_required" && res.challenge_token) {
        setChallenge(res.challenge_token);
        return;
      }
      if (res.user) setUser(res.user);
      else setUser(await api.me());
      nav(res.status === "must_setup" ? "/setup" : "/");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка входа");
    } finally {
      setBusy(false);
    }
  }

  async function onMfa(e: FormEvent) {
    e.preventDefault();
    if (!challenge) return;
    setBusy(true);
    setError("");
    try {
      const res = await api.verifyMfa(challenge, code);
      if (res.user) setUser(res.user);
      else setUser(await api.me());
      nav(res.status === "must_setup" ? "/setup" : "/");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Неверный код");
    } finally {
      setBusy(false);
    }
  }

  async function onPasskey() {
    if (!challenge) return;
    setBusy(true);
    setError("");
    try {
      const options = await api.webauthnLoginBegin(challenge);
      const credential = await webauthnAssert(options);
      const res = await api.webauthnLoginFinish(challenge, credential);
      if (res.user) setUser(res.user);
      else setUser(await api.me());
      nav(res.status === "must_setup" ? "/setup" : "/");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка WebAuthn");
    } finally {
      setBusy(false);
    }
  }

  const showPasswordForm =
    mode === "local" ||
    mode === "ldap" ||
    !!challenge ||
    (mode === "oidc" && !oidcReady) ||
    (mode === "saml" && !samlReady);

  return (
    <div className="auth-page">
      <div className="card auth-card">
        <div className="brand">KeepPAM</div>
        <h1>{challenge ? "Подтверждение MFA" : "Вход"}</h1>
        <p className="muted">
          {mode === "oidc" && "SSO (OIDC)"}
          {mode === "saml" && "SSO (SAML 2.0)"}
          {mode === "ldap" && "LDAP / Active Directory"}
          {mode === "local" && "Контроль привилегированного доступа"}
        </p>
        {error && <p className="error">{error}</p>}
        {!challenge && mode === "oidc" && (
          <div style={{ marginBottom: "1rem" }}>
            {oidcReady ? (
              <a className="btn" href="/api/v1/auth/oidc/start" style={{ display: "inline-block" }}>
                Войти через SSO
              </a>
            ) : (
              <p className="error">OIDC включён, но не настроен (issuer / client / secret)</p>
            )}
          </div>
        )}
        {!challenge && mode === "saml" && (
          <div style={{ marginBottom: "1rem" }}>
            {samlReady && samlIdps.length > 0 ? (
              <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
                {samlIdps.map((idp) => (
                  <a
                    key={idp.slug}
                    className="btn"
                    href={
                      idp.slug === "default"
                        ? "/api/v1/auth/saml/start"
                        : `/api/v1/auth/saml/idp/${idp.slug}/start`
                    }
                    style={{ display: "inline-block", textAlign: "center" }}
                  >
                    Войти через {idp.name}
                  </a>
                ))}
              </div>
            ) : (
              <p className="error">SAML включён, но не настроен (IdP metadata / cert + SP key)</p>
            )}
          </div>
        )}
        {showPasswordForm && !challenge && (
          <form onSubmit={onLogin}>
            <label htmlFor="username">Логин</label>
            <input
              id="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              required
            />
            <label htmlFor="password">Пароль</label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              required
            />
            <button className="btn" type="submit" disabled={busy}>
              Войти
            </button>
          </form>
        )}
        {challenge && (
          <div>
            <form onSubmit={onMfa}>
              <label htmlFor="code">Код TOTP</label>
              <input
                id="code"
                value={code}
                onChange={(e) => setCode(e.target.value)}
                inputMode="numeric"
                autoComplete="one-time-code"
              />
              <button className="btn" type="submit" disabled={busy || !code.trim()}>
                Подтвердить TOTP
              </button>
            </form>
            {webauthnSupported() && (
              <button
                className="btn"
                type="button"
                style={{ marginTop: "0.75rem" }}
                disabled={busy}
                onClick={() => void onPasskey()}
              >
                Ключ безопасности / Passkey
              </button>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
