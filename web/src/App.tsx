import { useEffect, useRef, useState } from "react";
import { Link, Navigate, NavLink, Outlet, useMatch, useNavigate } from "react-router-dom";
import { api, hasPerm, type AccessRequest } from "./api";
import { useAuth } from "./auth";
import { SessionKeepAliveHost } from "./components/SessionKeepAliveHost";
import { SessionTabBar } from "./components/SessionTabBar";

const SEEN_DECISIONS_KEY = "kp_seen_access_decisions";

function loadSeen(): Set<string> {
  try {
    const raw = localStorage.getItem(SEEN_DECISIONS_KEY);
    return new Set(raw ? (JSON.parse(raw) as string[]) : []);
  } catch {
    return new Set();
  }
}

function saveSeen(ids: Set<string>) {
  localStorage.setItem(SEEN_DECISIONS_KEY, JSON.stringify([...ids].slice(-200)));
}

export function AppLayout() {
  const { user, loading, setUser } = useAuth();
  const nav = useNavigate();
  const sessionMatch = useMatch("/sessions/:id/:kind");
  const viewingSession = !!(
    sessionMatch?.params.id &&
    sessionMatch.params.kind &&
    ["terminal", "sql", "desktop", "app"].includes(sessionMatch.params.kind)
  );
  const [pendingApprove, setPendingApprove] = useState(0);
  const [myPending, setMyPending] = useState(0);
  const [toasts, setToasts] = useState<string[]>([]);
  const prevPending = useRef(0);
  const notifyAsked = useRef(false);

  useEffect(() => {
    if (!user || !hasPerm(user, "access.request")) return;
    let cancelled = false;

    async function tick() {
      try {
        const sum = await api.accessRequestsSummary();
        if (cancelled) return;
        setPendingApprove(sum.pending_approve || 0);
        setMyPending(sum.my_pending || 0);

        if (
          hasPerm(user, "access.approve") &&
          sum.pending_approve > prevPending.current &&
          prevPending.current >= 0
        ) {
          const msg = `Новых запросов доступа: ${sum.pending_approve}`;
          setToasts((t) => [...t, msg].slice(-5));
          if (typeof Notification !== "undefined") {
            if (Notification.permission === "granted") {
              new Notification("KeepPAM", { body: msg });
            } else if (Notification.permission === "default" && !notifyAsked.current) {
              notifyAsked.current = true;
              void Notification.requestPermission();
            }
          }
        }
        prevPending.current = sum.pending_approve || 0;

        const seen = loadSeen();
        const fresh = (sum.my_recent_decisions || []).filter((d: AccessRequest) => !seen.has(d.id));
        if (fresh.length) {
          for (const d of fresh) {
            seen.add(d.id);
            const line = `Запрос к ${d.asset_name}: ${d.status}`;
            setToasts((t) => [...t, line].slice(-5));
            if (typeof Notification !== "undefined" && Notification.permission === "granted") {
              new Notification("KeepPAM", { body: line });
            }
          }
          saveSeen(seen);
        }
      } catch {
        /* ignore poll errors */
      }
    }

    void tick();
    const id = window.setInterval(() => void tick(), 30000);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, [user]);

  if (loading) {
    return <div className="auth-page muted">Загрузка…</div>;
  }
  if (!user) return <Navigate to="/login" replace />;
  if (user.must_change_password || !user.mfa_enabled) {
    return <Navigate to="/setup" replace />;
  }

  async function logout() {
    await api.logout();
    setUser(null);
    nav("/login");
  }

  const badge = pendingApprove > 0 ? pendingApprove : myPending > 0 ? myPending : 0;

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">KeepPAM</div>
        <nav className="nav">
          <NavLink to="/" end>
            Обзор
          </NavLink>
          {hasPerm(user, "assets.read") && <NavLink to="/assets">Активы</NavLink>}
          {hasPerm(user, "discovery.read") && <NavLink to="/discovery">Discovery</NavLink>}
          {hasPerm(user, "access.request") ||
          hasPerm(user, "access.breakglass") ||
          hasPerm(user, "assets.write") ? (
            <NavLink to="/access-requests">
              Запросы
              {badge > 0 && <span className="nav-badge">{badge > 99 ? "99+" : badge}</span>}
            </NavLink>
          ) : null}
          {hasPerm(user, "sessions.read") && <NavLink to="/sessions">Сессии</NavLink>}
          {hasPerm(user, "users.read") && <NavLink to="/users">Пользователи</NavLink>}
          {hasPerm(user, "audit.read") && <NavLink to="/analytics">Аналитика</NavLink>}
          {hasPerm(user, "compliance.read") && <NavLink to="/compliance">Compliance</NavLink>}
          {hasPerm(user, "jea.read") && <NavLink to="/jea">JEA</NavLink>}
          {hasPerm(user, "attacksim.read") && <NavLink to="/attack-sim">Attack sim</NavLink>}
          {hasPerm(user, "audit.read") && <NavLink to="/audit">Аудит</NavLink>}
          {hasPerm(user, "settings.write") && <NavLink to="/config">Конфигурация</NavLink>}
        </nav>
        <div style={{ marginTop: "auto" }}>
          <p className="muted" style={{ marginBottom: "0.5rem" }}>
            {user.display_name || user.username}
          </p>
          <button className="btn secondary" type="button" onClick={() => void logout()}>
            Выйти
          </button>
        </div>
      </aside>
      <main className="main">
        <SessionTabBar />
        <div className="main-body">
          <SessionKeepAliveHost />
          <div className={`main-outlet${viewingSession ? " obscured" : ""}`}>
            <Outlet />
          </div>
        </div>
      </main>
      {toasts.length > 0 && (
        <div className="toast-stack">
          {toasts.map((t, i) => (
            <div key={`${t}-${i}`} className="toast" onClick={() => setToasts((all) => all.filter((_, j) => j !== i))}>
              {t}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export function HomePage() {
  const { user } = useAuth();
  const [overview, setOverview] = useState<{
    sessions_active: number;
    anomalies: number;
    logins_fail: number;
  } | null>(null);

  useEffect(() => {
    if (!hasPerm(user, "audit.read")) return;
    void api
      .getAnalyticsOverview(24)
      .then((d) =>
        setOverview({
          sessions_active: d.stats.sessions_active,
          anomalies: d.anomalies.length,
          logins_fail: d.stats.logins_fail,
        }),
      )
      .catch(() => setOverview(null));
  }, [user]);

  return (
    <div>
      <h1>Обзор</h1>
      <p className="muted">Сессия активна. Роли: {(user?.roles || []).join(", ")}</p>
      <div className="card" style={{ marginTop: "1rem" }}>
        <p>
          <strong>{user?.username}</strong> · {user?.email}
        </p>
        <p className="muted mono">permissions: {(user?.permissions || []).join(", ")}</p>
      </div>
      {overview && (
        <div className="stats-grid" style={{ marginTop: "1.25rem" }}>
          <div className="card stat-card">
            <div className="stat-value">{overview.sessions_active}</div>
            <div className="muted">Активные сессии</div>
          </div>
          <div className={`card stat-card${overview.logins_fail > 0 ? " warn" : ""}`}>
            <div className="stat-value">{overview.logins_fail}</div>
            <div className="muted">Неудачные входы (24ч)</div>
          </div>
          <div className={`card stat-card${overview.anomalies > 0 ? " warn" : ""}`}>
            <div className="stat-value">{overview.anomalies}</div>
            <div className="muted">Сигналы аномалий</div>
          </div>
        </div>
      )}
      {hasPerm(user, "audit.read") && (
        <p style={{ marginTop: "1rem" }}>
          <Link to="/analytics">Открыть аналитику →</Link>
        </p>
      )}
    </div>
  );
}
