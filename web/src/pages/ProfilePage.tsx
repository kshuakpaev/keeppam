import { Link } from "react-router-dom";
import { hasPerm } from "../api";
import { useAuth } from "../auth";

export function ProfilePage() {
  const { user } = useAuth();
  if (!user) return null;
  const canOpenAdmin = hasPerm(user, "users.read");

  return (
    <div>
      <h1>Профиль</h1>
      <p className="muted">Учётная запись KeepPAM</p>
      <div className="card" style={{ maxWidth: 520, marginTop: "1rem" }}>
        <p>
          <strong>{user.display_name || user.username}</strong>
        </p>
        <p className="muted mono">{user.username}</p>
        <p>{user.email}</p>
        <p className="muted">Роли: {(user.roles || []).join(", ") || "—"}</p>
        {(user.groups || []).length > 0 && (
          <p className="muted">Группы: {(user.groups || []).join(", ")}</p>
        )}
        <p className="muted">
          MFA: {user.mfa_enabled ? "включён" : "выкл"} · источник {user.auth_source || "local"}
        </p>
        {user.last_login_at && (
          <p className="muted">Последний вход: {new Date(user.last_login_at).toLocaleString()}</p>
        )}
      </div>
      {canOpenAdmin && (
        <p style={{ marginTop: "1rem" }}>
          <Link to={`/users/${user.id}`}>Карточка пользователя →</Link>
        </p>
      )}
    </div>
  );
}
