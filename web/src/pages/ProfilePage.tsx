import { Link } from "react-router-dom";
import { hasPerm } from "../api";
import { useAuth } from "../auth";
import { useI18n } from "../i18n";

export function ProfilePage() {
  const { user } = useAuth();
  const { t, formatDate } = useI18n();
  if (!user) return null;
  const canOpenAdmin = hasPerm(user, "users.read");

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
      {canOpenAdmin && (
        <p style={{ marginTop: "1rem" }}>
          <Link to={`/users/${user.id}`}>{t("profile.userCard")}</Link>
        </p>
      )}
    </div>
  );
}
