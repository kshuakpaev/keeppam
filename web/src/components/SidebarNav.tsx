import { useEffect, useMemo, useState } from "react";
import { NavLink, useLocation } from "react-router-dom";
import { useI18n } from "../i18n";
import type { MsgKey } from "../i18n/catalog";
import { hasPerm, type User } from "../api";

const STORAGE_KEY = "kp_nav_groups";

type GroupId = "work" | "security" | "admin";

type NavItem = {
  to: string;
  label: MsgKey;
  end?: boolean;
  show: boolean;
  badge?: number;
  /** Path prefixes that count as “active” for this item’s group */
  match?: string[];
};

type NavGroup = {
  id: GroupId;
  label: MsgKey;
  items: NavItem[];
};

type OpenState = Record<GroupId, boolean>;

function loadOpen(): Partial<OpenState> {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return {};
    return JSON.parse(raw) as Partial<OpenState>;
  } catch {
    return {};
  }
}

function saveOpen(state: OpenState) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
  } catch {
    /* ignore */
  }
}

function itemMatches(pathname: string, item: NavItem): boolean {
  if (item.end) return pathname === item.to;
  const prefixes = item.match ?? [item.to];
  return prefixes.some((p) => pathname === p || pathname.startsWith(p + "/"));
}

function groupContainsPath(group: NavGroup, pathname: string): boolean {
  return group.items.some((it) => it.show && itemMatches(pathname, it));
}

type Props = {
  user: User;
  requestsBadge: number;
};

export function SidebarNav({ user, requestsBadge }: Props) {
  const { t } = useI18n();
  const { pathname } = useLocation();

  const canRequests =
    hasPerm(user, "access.request") ||
    hasPerm(user, "access.approve") ||
    hasPerm(user, "access.approve.security") ||
    hasPerm(user, "access.breakglass") ||
    hasPerm(user, "assets.write") ||
    hasPerm(user, "sessions.supervise");

  const groups = useMemo<NavGroup[]>(
    () => [
      {
        id: "work",
        label: "nav.group.work",
        items: [
          { to: "/assets", label: "nav.assets", show: hasPerm(user, "assets.read"), match: ["/assets"] },
          { to: "/discovery", label: "nav.discovery", show: hasPerm(user, "discovery.read") },
          { to: "/password-sets", label: "nav.passwordSets", show: hasPerm(user, "assets.read") },
          {
            to: "/access-requests",
            label: "nav.requests",
            show: canRequests,
            badge: requestsBadge > 0 ? requestsBadge : undefined,
          },
          {
            to: "/sessions",
            label: "nav.sessions",
            show: hasPerm(user, "sessions.read"),
            match: ["/sessions"],
          },
        ],
      },
      {
        id: "security",
        label: "nav.group.security",
        items: [
          { to: "/jea", label: "nav.jea", show: hasPerm(user, "jea.read") },
          { to: "/forensic", label: "nav.forensic", show: hasPerm(user, "sessions.read") },
          { to: "/attack-sim", label: "nav.attacksim", show: hasPerm(user, "attacksim.read") },
          { to: "/audit", label: "nav.audit", show: hasPerm(user, "audit.read") },
          { to: "/analytics", label: "nav.analytics", show: hasPerm(user, "audit.read") },
          { to: "/compliance", label: "nav.compliance", show: hasPerm(user, "compliance.read") },
        ],
      },
      {
        id: "admin",
        label: "nav.group.admin",
        items: [
          { to: "/users", label: "nav.users", show: hasPerm(user, "users.read") },
          { to: "/groups", label: "nav.groups", show: hasPerm(user, "users.read") },
          { to: "/config", label: "nav.config", show: hasPerm(user, "settings.write") },
        ],
      },
    ],
    [user, canRequests, requestsBadge],
  );

  // Overview + Help always shown outside accordion groups.

  const visibleGroups = useMemo(
    () =>
      groups
        .map((g) => ({ ...g, items: g.items.filter((it) => it.show) }))
        .filter((g) => g.items.length > 0),
    [groups],
  );

  const [open, setOpen] = useState<OpenState>(() => {
    const stored = loadOpen();
    return {
      work: stored.work ?? true,
      security: stored.security ?? false,
      admin: stored.admin ?? false,
    };
  });

  // Ensure the group that owns the current route is expanded.
  useEffect(() => {
    const owner = visibleGroups.find((g) => groupContainsPath(g, pathname));
    if (!owner) return;
    setOpen((prev) => {
      if (prev[owner.id]) return prev;
      const next = { ...prev, [owner.id]: true };
      saveOpen(next);
      return next;
    });
  }, [pathname, visibleGroups]);

  function toggle(id: GroupId) {
    setOpen((prev) => {
      const next = { ...prev, [id]: !prev[id] };
      saveOpen(next);
      return next;
    });
  }

  return (
    <nav className="nav" aria-label="Main">
      <NavLink to="/" end>
        {t("nav.overview")}
      </NavLink>
      <NavLink to="/help">{t("nav.help")}</NavLink>

      {visibleGroups.map((group) => {
        const expanded = !!open[group.id];
        const badgeSum = group.items.reduce((n, it) => n + (it.badge || 0), 0);
        const activeHere = groupContainsPath(group, pathname);
        return (
          <div key={group.id} className={`nav-group${activeHere ? " active-group" : ""}`}>
            <button
              type="button"
              className="nav-group-toggle"
              aria-expanded={expanded}
              onClick={() => toggle(group.id)}
            >
              <span className="nav-group-chevron" aria-hidden>
                {expanded ? "▾" : "▸"}
              </span>
              <span className="nav-group-label">{t(group.label)}</span>
              {!expanded && badgeSum > 0 ? (
                <span className="nav-badge">{badgeSum > 99 ? "99+" : badgeSum}</span>
              ) : null}
            </button>
            {expanded ? (
              <div className="nav-group-items">
                {group.items.map((item) => (
                  <NavLink key={item.to} to={item.to} end={item.end}>
                    {t(item.label)}
                    {item.badge ? <span className="nav-badge">{item.badge > 99 ? "99+" : item.badge}</span> : null}
                  </NavLink>
                ))}
              </div>
            ) : null}
          </div>
        );
      })}
    </nav>
  );
}
