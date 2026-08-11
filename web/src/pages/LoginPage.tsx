import { useEffect, useState, type FormEvent } from "react";
import { Navigate, useNavigate, useSearchParams } from "react-router-dom";
import { api } from "../api";
import { useAuth } from "../auth";

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

  useEffect(() => {
    void (async () => {
      try {
        const m = await api.authMethods();
        setMode(m.mode);
        setOidcReady(m.oidc_ready);
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

  const showPasswordForm =
    mode === "local" || mode === "ldap" || !!challenge || (mode === "oidc" && !oidcReady);

  return (
    <div className="auth-page">
      <div className="card auth-card">
        <div className="brand">KeepPAM</div>
        <h1>{challenge ? "Подтверждение MFA" : "Вход"}</h1>
        <p className="muted">
          {mode === "oidc" && "SSO (OIDC)"}
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
          <form onSubmit={onMfa}>
            <label htmlFor="code">Код TOTP</label>
            <input
              id="code"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              inputMode="numeric"
              autoComplete="one-time-code"
              required
            />
            <button className="btn" type="submit" disabled={busy}>
              Подтвердить
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
