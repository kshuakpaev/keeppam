import { useEffect, useState, type FormEvent } from "react";
import { Navigate, useNavigate, useSearchParams } from "react-router-dom";
import { api } from "../api";
import { useAuth } from "../auth";
import { LangSwitch, useI18n } from "../i18n";
import { webauthnAssert, webauthnSupported } from "../webauthn";

export function LoginPage() {
  const { user, setUser, loading } = useAuth();
  const { t, te } = useI18n();
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
  const [radiusReady, setRadiusReady] = useState(false);
  const [certLogin, setCertLogin] = useState(false);
  const [samlIdps, setSamlIdps] = useState<{ slug: string; name: string }[]>([]);

  useEffect(() => {
    void (async () => {
      try {
        const m = await api.authMethods();
        setMode(m.mode);
        setOidcReady(m.oidc_ready);
        setSamlReady(!!m.saml_ready);
        setRadiusReady(!!m.radius_ready);
        setCertLogin(!!m.cert_login);
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
      setError(te(err, "login.failed"));
    } finally {
      setBusy(false);
    }
  }

  async function onCertLogin() {
    setBusy(true);
    setError("");
    try {
      const res = await api.loginCert();
      if (res.status === "mfa_required" && res.challenge_token) {
        setChallenge(res.challenge_token);
        return;
      }
      if (res.user) setUser(res.user);
      else setUser(await api.me());
      nav(res.status === "must_setup" ? "/setup" : "/");
    } catch (err) {
      setError(te(err, "login.certBad"));
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
      setError(te(err, "login.badCode"));
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
      setError(te(err, "common.error"));
    } finally {
      setBusy(false);
    }
  }

  const showPasswordForm =
    mode === "local" ||
    mode === "ldap" ||
    mode === "radius" ||
    !!challenge ||
    (mode === "oidc" && !oidcReady) ||
    (mode === "saml" && !samlReady);

  return (
    <div className="auth-page">
      <div className="card auth-card">
        <div className="row" style={{ justifyContent: "space-between", alignItems: "center" }}>
          <div className="brand">KeepPAM</div>
          <LangSwitch />
        </div>
        <h1>{challenge ? t("login.mfaTitle") : t("login.title")}</h1>
        <p className="muted">
          {mode === "oidc" && "SSO (OIDC)"}
          {mode === "saml" && "SSO (SAML 2.0)"}
          {mode === "ldap" && "LDAP / Active Directory"}
          {mode === "radius" && t("login.radius")}
          {mode === "local" && t("login.tagline")}
        </p>
        {error && <p className="error">{error}</p>}
        {!challenge && mode === "oidc" && (
          <div style={{ marginBottom: "1rem" }}>
            {oidcReady ? (
              <a className="btn" href="/api/v1/auth/oidc/start" style={{ display: "inline-block" }}>
                {t("login.sso")}
              </a>
            ) : (
              <p className="error">{t("login.oidcBad")}</p>
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
                    {t("login.ssoNamed", { name: idp.name })}
                  </a>
                ))}
              </div>
            ) : (
              <p className="error">{t("login.samlBad")}</p>
            )}
          </div>
        )}
        {!challenge && mode === "radius" && !radiusReady && (
          <p className="error">{t("login.radiusBad")}</p>
        )}
        {!challenge && certLogin && (
          <div style={{ marginBottom: "1rem" }}>
            <button className="btn secondary" type="button" disabled={busy} onClick={() => void onCertLogin()}>
              {t("login.cert")}
            </button>
          </div>
        )}
        {showPasswordForm && !challenge && (
          <form onSubmit={onLogin}>
            <label htmlFor="username">{t("login.username")}</label>
            <input
              id="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              required
            />
            <label htmlFor="password">{t("login.password")}</label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              required
            />
            <button className="btn" type="submit" disabled={busy}>
              {t("login.submit")}
            </button>
          </form>
        )}
        {challenge && (
          <div>
            <form onSubmit={onMfa}>
              <label htmlFor="code">{t("login.totp")}</label>
              <input
                id="code"
                value={code}
                onChange={(e) => setCode(e.target.value)}
                inputMode="numeric"
                autoComplete="one-time-code"
              />
              <button className="btn" type="submit" disabled={busy || !code.trim()}>
                {t("login.confirmTotp")}
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
                {t("login.passkey")}
              </button>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
