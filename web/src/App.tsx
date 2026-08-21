import { useEffect, useRef, useState } from "react";
import { Link, Navigate, NavLink, Outlet, useMatch, useNavigate } from "react-router-dom";
import { api, hasPerm, type AccessRequest, type InboxNotification } from "./api";
import { useAuth } from "./auth";
import { ProfileMenu } from "./components/ProfileMenu";
import { SessionKeepAliveHost } from "./components/SessionKeepAliveHost";
import { SessionTabBar } from "./components/SessionTabBar";
import { LangSwitch, notifyTitle, useI18n } from "./i18n";

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
  const { t } = useI18n();
  const nav = useNavigate();
  const sessionMatch = useMatch("/sessions/:id/:kind");
  const viewingSession = !!(
    sessionMatch?.params.id &&
    sessionMatch.params.kind &&
    ["terminal", "sql", "desktop", "app", "k8s"].includes(sessionMatch.params.kind)
  );
  const [pendingApprove, setPendingApprove] = useState(0);
  const [pendingOps, setPendingOps] = useState(0);
  const [pendingSupervise, setPendingSupervise] = useState(0);
  const [myPending, setMyPending] = useState(0);
  const [toasts, setToasts] = useState<string[]>([]);
  const [inbox, setInbox] = useState<InboxNotification[]>([]);
  const [inboxUnread, setInboxUnread] = useState(0);
  const [inboxOpen, setInboxOpen] = useState(false);
  const [licenseMsg, setLicenseMsg] = useState("");
  const [licenseHard, setLicenseHard] = useState(false);
  const prevPending = useRef(0);
  const prevOps = useRef(0);
  const prevSupervise = useRef(0);
  const notifyAsked = useRef(false);

  useEffect(() => {
    if (!user || !hasPerm(user, "assets.read")) return;
    let cancelled = false;
    void api
      .getLicense()
      .then((lic) => {
        if (cancelled) return;
        if (lic.hard_blocked || lic.soft_warn) {
          setLicenseMsg(lic.message || `${lic.asset_count}/${lic.max_assets}`);
          setLicenseHard(!!lic.hard_blocked);
        } else {
          setLicenseMsg("");
          setLicenseHard(false);
        }
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [user]);

  useEffect(() => {
    if (
      !user ||
      !(
        hasPerm(user, "access.request") ||
        hasPerm(user, "access.approve") ||
        hasPerm(user, "access.approve.security") ||
        hasPerm(user, "sessions.supervise")
      )
    )
      return;
    let cancelled = false;

    async function tick() {
      try {
        const sum = await api.accessRequestsSummary();
        if (cancelled) return;
        setPendingApprove(sum.pending_approve || 0);
        setPendingOps(sum.pending_ops || 0);
        setPendingSupervise(sum.pending_supervise || 0);
        setMyPending(sum.my_pending || 0);

        if (
          (hasPerm(user, "access.approve") || hasPerm(user, "access.approve.security")) &&
          sum.pending_approve > prevPending.current &&
          prevPending.current >= 0
        ) {
          const msg = t("notify.toast.access", { n: sum.pending_approve });
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
        if (
          (hasPerm(user, "access.approve") || hasPerm(user, "access.approve.security")) &&
          (sum.pending_ops || 0) > prevOps.current &&
          prevOps.current >= 0
        ) {
          const msg = t("notify.toast.ops", { n: sum.pending_ops || 0 });
          setToasts((t) => [...t, msg].slice(-5));
          if (typeof Notification !== "undefined" && Notification.permission === "granted") {
            new Notification("KeepPAM", { body: msg });
          }
        }
        prevPending.current = sum.pending_approve || 0;
        prevOps.current = sum.pending_ops || 0;
        if (hasPerm(user, "sessions.supervise") && (sum.pending_supervise || 0) > prevSupervise.current && prevSupervise.current >= 0) {
          const msg = t("notify.toast.supervise", { n: sum.pending_supervise || 0 });
          setToasts((t) => [...t, msg].slice(-5));
          if (typeof Notification !== "undefined" && Notification.permission === "granted") {
            new Notification("KeepPAM", { body: msg });
          }
        }
        prevSupervise.current = sum.pending_supervise || 0;

        const seen = loadSeen();
        const fresh = (sum.my_recent_decisions || []).filter((d: AccessRequest) => !seen.has(d.id));
        if (fresh.length) {
          for (const d of fresh) {
            seen.add(d.id);
            const line = t("notify.toast.decision", { asset: d.asset_name || d.asset_id, status: d.status });
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
    const id = window.setInterval(() => void tick(), 8000);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, [user, t]);

  useEffect(() => {
    if (!user) return;
    let cancelled = false;
    async function tickInbox() {
      try {
        const data = await api.listNotifications(10);
        if (cancelled) return;
        setInbox(data.notifications || []);
        setInboxUnread(data.unread || 0);
      } catch {
        /* ignore */
      }
    }
    void tickInbox();
    const id = window.setInterval(() => void tickInbox(), 25000);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, [user]);

  if (loading) {
    return <div className="auth-page muted">{t("common.loading")}</div>;
  }
  if (!user) return <Navigate to="/login" replace />;
  if (user.must_change_password || !user.mfa_enabled) {
    return <Navigate to="/setup" replace />;
  }

  async function logout() {
    if (user?.auth_source === "saml") {
      window.location.href = "/api/v1/auth/saml/slo";
      return;
    }
    await api.logout();
    setUser(null);
    nav("/login");
  }

  const badge =
    pendingApprove + pendingOps + pendingSupervise > 0
      ? pendingApprove + pendingOps + pendingSupervise
      : myPending > 0
        ? myPending
        : 0;

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand-row">
          <div className="brand">KeepPAM</div>
          <div className="row" style={{ gap: "0.35rem", alignItems: "center" }}>
            <LangSwitch compact />
            <button
              type="button"
              className="bell-btn"
              title={t("notify.title")}
              onClick={() => setInboxOpen((v) => !v)}
            >
            <span aria-hidden>🔔</span>
            {inboxUnread > 0 && <span className="nav-badge">{inboxUnread > 99 ? "99+" : inboxUnread}</span>}
            </button>
          </div>
        </div>
        {inboxOpen && (
          <div className="notify-panel">
            <div className="row" style={{ justifyContent: "space-between", marginBottom: "0.5rem" }}>
              <strong>{t("notify.title")}</strong>
              {inboxUnread > 0 && (
                <button
                  className="btn secondary"
                  type="button"
                  style={{ padding: "0.15rem 0.4rem", fontSize: "0.8rem" }}
                  onClick={() => {
                    void api.readAllNotifications().then(() => {
                      setInboxUnread(0);
                      setInbox((list) => list.map((n) => ({ ...n, read_at: n.read_at || new Date().toISOString() })));
                    });
                  }}
                >
                  {t("notify.readAll")}
                </button>
              )}
            </div>
            {inbox.length === 0 && <p className="muted">{t("common.empty")}</p>}
            {inbox.map((n) => (
              <button
                key={n.id}
                type="button"
                className={`notify-item${n.read_at ? "" : " unread"}`}
                onClick={() => {
                  if (!n.read_at) {
                    void api.readNotification(n.id).then(() => {
                      setInboxUnread((c) => Math.max(0, c - 1));
                      setInbox((list) => list.map((x) => (x.id === n.id ? { ...x, read_at: new Date().toISOString() } : x)));
                    });
                  }
                  setInboxOpen(false);
                  nav("/access-requests");
                }}
              >
                <div>{notifyTitle(t, n.kind, n.title)}</div>
                <div className="muted" style={{ fontSize: "0.8rem" }}>
                  {n.body}
                </div>
              </button>
            ))}
            <Link to="/access-requests" className="muted" onClick={() => setInboxOpen(false)}>
              {t("notify.queue")}
            </Link>
          </div>
        )}
        <nav className="nav">
          <NavLink to="/" end>
            {t("nav.overview")}
          </NavLink>
          {hasPerm(user, "assets.read") && <NavLink to="/assets">{t("nav.assets")}</NavLink>}
          {hasPerm(user, "assets.read") && <NavLink to="/password-sets">{t("nav.passwordSets")}</NavLink>}
          {hasPerm(user, "discovery.read") && <NavLink to="/discovery">{t("nav.discovery")}</NavLink>}
          {hasPerm(user, "access.request") ||
          hasPerm(user, "access.approve") ||
          hasPerm(user, "access.approve.security") ||
          hasPerm(user, "access.breakglass") ||
          hasPerm(user, "assets.write") ||
          hasPerm(user, "sessions.supervise") ? (
            <NavLink to="/access-requests">
              {t("nav.requests")}
              {badge > 0 && <span className="nav-badge">{badge > 99 ? "99+" : badge}</span>}
            </NavLink>
          ) : null}
          {hasPerm(user, "sessions.read") && <NavLink to="/sessions">{t("nav.sessions")}</NavLink>}
          {hasPerm(user, "sessions.read") && <NavLink to="/forensic">{t("nav.forensic")}</NavLink>}
          {hasPerm(user, "users.read") && <NavLink to="/users">{t("nav.users")}</NavLink>}
          {hasPerm(user, "users.read") && <NavLink to="/groups">{t("nav.groups")}</NavLink>}
          {hasPerm(user, "audit.read") && <NavLink to="/analytics">{t("nav.analytics")}</NavLink>}
          {hasPerm(user, "compliance.read") && <NavLink to="/compliance">{t("nav.compliance")}</NavLink>}
          {hasPerm(user, "jea.read") && <NavLink to="/jea">{t("nav.jea")}</NavLink>}
          {hasPerm(user, "attacksim.read") && <NavLink to="/attack-sim">{t("nav.attacksim")}</NavLink>}
          {hasPerm(user, "audit.read") && <NavLink to="/audit">{t("nav.audit")}</NavLink>}
          {hasPerm(user, "settings.write") && <NavLink to="/config">{t("nav.config")}</NavLink>}
        </nav>
        <ProfileMenu
          name={user.display_name || user.username}
          onLogout={() => void logout()}
        />
      </aside>
      <main className="main">
        <SessionTabBar />
        {licenseMsg && (
          <div
            className={licenseHard ? "error" : "ok"}
            role="status"
            style={{
              margin: "0.75rem 1rem 0",
              padding: "0.6rem 0.85rem",
              borderRadius: 6,
              background: licenseHard ? "rgba(180,40,40,0.12)" : "rgba(180,140,40,0.12)",
            }}
          >
            Лицензия: {licenseMsg}
            {licenseHard ? " (создание активов запрещено)" : ""}
          </div>
        )}
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
  const { t } = useI18n();
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
      <h1>{t("nav.overview")}</h1>
      <p className="muted">{t("home.sessionActive", { roles: (user?.roles || []).join(", ") })}</p>
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
            <div className="muted">{t("home.activeSessions")}</div>
          </div>
          <div className={`card stat-card${overview.logins_fail > 0 ? " warn" : ""}`}>
            <div className="stat-value">{overview.logins_fail}</div>
            <div className="muted">{t("home.failedLogins")}</div>
          </div>
          <div className={`card stat-card${overview.anomalies > 0 ? " warn" : ""}`}>
            <div className="stat-value">{overview.anomalies}</div>
            <div className="muted">{t("home.anomalies")}</div>
          </div>
        </div>
      )}
      {hasPerm(user, "audit.read") && (
        <p style={{ marginTop: "1rem" }}>
          <Link to="/analytics">{t("home.openAnalytics")}</Link>
        </p>
      )}
    </div>
  );
}
