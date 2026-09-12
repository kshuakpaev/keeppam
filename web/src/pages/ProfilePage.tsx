import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { api, hasPerm } from "../api";
import { useAuth } from "../auth";
import { useI18n } from "../i18n";

function canChangeLocalPassword(authSource: string | undefined): boolean {
  const src = (authSource || "local").toLowerCase();
  return src === "local" || src === "scim";
}

export function ProfilePage() {
  const { user } = useAuth();
  const { t, te, formatDate } = useI18n();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState(false);

  if (!user) return null;
  const canOpenAdmin = hasPerm(user, "users.read");
  const localPassword = canChangeLocalPassword(user.auth_source);

  async function onPassword(e: FormEvent) {
    e.preventDefault();
    setError("");
    setMsg("");
    if (next !== confirm) {
      setError(t("setup.mismatch"));
      return;
    }
    setBusy(true);
    try {
      await api.changePassword(current, next);
      setCurrent("");
      setNext("");
      setConfirm("");
      setMsg(t("profile.passwordOk"));
    } catch (err) {
      setError(te(err, "common.error"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <h1>{t("nav.profile")}</h1>
      <p className="muted">{t("profile.lead")}</p>
      <div className="card" style={{ maxWidth: 520, marginTop: "1rem" }}>
        <p>
          <strong>{user.display_name || user.username}</strong>
        </p>
        <p className="muted mono">{user.username}</p>
        <p>{user.email}</p>
        <p className="muted">{t("profile.roles", { roles: (user.roles || []).join(", ") || "—" })}</p>
        {(user.groups || []).length > 0 && (
          <p className="muted">{t("profile.groups", { groups: (user.groups || []).join(", ") })}</p>
        )}
        <p className="muted">
          {t("profile.mfaLine", { mfa: user.mfa_enabled ? t("profile.mfaOn") : t("profile.mfaOff"), src: user.auth_source || "local" })}
        </p>
        {user.last_login_at && (
          <p className="muted">{t("profile.lastLogin", { at: formatDate(user.last_login_at) })}</p>
        )}
      </div>

      <div className="card" style={{ maxWidth: 520, marginTop: "1rem" }}>
        <h2 style={{ marginTop: 0 }}>{t("profile.passwordTitle")}</h2>
        {localPassword ? (
          <form onSubmit={(e) => void onPassword(e)}>
            <p className="muted">{t("profile.passwordHint")}</p>
            {error && <p className="error">{error}</p>}
            {msg && <p className="ok">{msg}</p>}
            <label htmlFor="profile-current">{t("setup.current")}</label>
            <input
              id="profile-current"
              type="password"
              autoComplete="current-password"
              value={current}
              onChange={(e) => setCurrent(e.target.value)}
              required
            />
            <label htmlFor="profile-next">{t("setup.next")}</label>
            <input
              id="profile-next"
              type="password"
              autoComplete="new-password"
              value={next}
              onChange={(e) => setNext(e.target.value)}
              minLength={10}
              required
            />
            <label htmlFor="profile-confirm">{t("setup.confirm")}</label>
            <input
              id="profile-confirm"
              type="password"
              autoComplete="new-password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              minLength={10}
              required
            />
            <button className="btn" type="submit" disabled={busy}>
              {t("setup.savePassword")}
            </button>
          </form>
        ) : (
          <p className="muted">{t("profile.passwordExternal", { src: user.auth_source })}</p>
        )}
      </div>

      {canOpenAdmin && (
        <p style={{ marginTop: "1rem" }}>
          <Link to={`/users/${user.id}`}>{t("profile.userCard")}</Link>
        </p>
      )}
    </div>
  );
}
