import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { useNavigate } from "react-router-dom";
import { api } from "./api";

export type SessionTabKind = "terminal" | "sql" | "desktop" | "app" | "k8s" | "tn3270" | "citrix";

export type SessionTab = {
  id: string;
  kind: SessionTabKind;
  title: string;
  protocol: string;
};

type Persisted = {
  tabs: SessionTab[];
  activeId: string | null;
};

type Ctx = {
  tabs: SessionTab[];
  activeId: string | null;
  openTab: (tab: SessionTab, opts?: { navigate?: boolean }) => void;
  activateTab: (id: string) => void;
  closeTab: (id: string, opts?: { endSession?: boolean }) => Promise<void>;
  pathFor: (tab: SessionTab) => string;
};

const STORAGE_KEY = "kp_open_session_tabs";
const SessionTabsContext = createContext<Ctx | null>(null);

function loadPersisted(): Persisted {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return { tabs: [], activeId: null };
    const parsed = JSON.parse(raw) as Persisted;
    if (!Array.isArray(parsed.tabs)) return { tabs: [], activeId: null };
    return {
      tabs: parsed.tabs.filter(
        (t) => t && t.id && ["terminal", "sql", "desktop", "app", "k8s", "tn3270", "citrix"].includes(t.kind),
      ),
      activeId: parsed.activeId || null,
    };
  } catch {
    return { tabs: [], activeId: null };
  }
}

function savePersisted(tabs: SessionTab[], activeId: string | null) {
  const payload: Persisted = { tabs, activeId };
  localStorage.setItem(STORAGE_KEY, JSON.stringify(payload));
}

export function pathForTab(tab: SessionTab): string {
  const title = encodeURIComponent(tab.title || tab.kind);
  return `/sessions/${tab.id}/${tab.kind}?title=${title}`;
}

export function isSQLProtocol(protocol: string): boolean {
  return protocol === "postgres" || protocol === "mysql" || protocol === "mssql" || protocol === "oracle";
}

export function kindForProtocol(protocol: string, isolated?: boolean): SessionTabKind {
  if (protocol === "rdp" || protocol === "vnc") return "desktop";
  if (isSQLProtocol(protocol)) return "sql";
  if (protocol === "https") return isolated ? "desktop" : "app";
  if (protocol === "kubectl") return "k8s";
  if (protocol === "tn3270") return "tn3270";
  if (protocol === "citrix") return "citrix";
  return "terminal";
}

export function SessionTabsProvider({ children }: { children: ReactNode }) {
  const nav = useNavigate();
  const initial = useMemo(() => loadPersisted(), []);
  const [tabs, setTabs] = useState<SessionTab[]>(initial.tabs);
  const [activeId, setActiveId] = useState<string | null>(initial.activeId);
  const [hydrated, setHydrated] = useState(false);

  useEffect(() => {
    savePersisted(tabs, activeId);
  }, [tabs, activeId]);

  // Validate restored tabs against API (drop ended sessions).
  useEffect(() => {
    let cancelled = false;
    async function validate() {
      const cur = loadPersisted();
      if (!cur.tabs.length) {
        setHydrated(true);
        return;
      }
      const alive: SessionTab[] = [];
      for (const t of cur.tabs) {
        try {
          const s = await api.getSession(t.id);
          if (s.status === "active" || s.status === "pending") {
            alive.push({
              ...t,
              kind: kindForProtocol(s.protocol || t.protocol, s.isolated),
              title: t.title || s.asset_name || t.kind,
              protocol: s.protocol || t.protocol,
            });
          }
        } catch {
          /* drop */
        }
      }
      if (cancelled) return;
      setTabs(alive);
      const nextActive =
        alive.find((t) => t.id === cur.activeId)?.id ?? alive[0]?.id ?? null;
      setActiveId(nextActive);
      setHydrated(true);
    }
    void validate();
    return () => {
      cancelled = true;
    };
  }, []);

  const openTab = useCallback(
    (tab: SessionTab, opts?: { navigate?: boolean }) => {
      const title = decodeURIComponent(tab.title || tab.kind);
      const normalized: SessionTab = { ...tab, title };
      setTabs((prev) => {
        const i = prev.findIndex((t) => t.id === normalized.id);
        if (i >= 0) {
          const next = [...prev];
          next[i] = { ...next[i], ...normalized, title: normalized.title || next[i].title };
          return next;
        }
        return [...prev, normalized];
      });
      setActiveId(normalized.id);
      if (opts?.navigate !== false) {
        nav(pathForTab(normalized));
      }
    },
    [nav],
  );

  const activateTab = useCallback(
    (id: string) => {
      const tab = tabs.find((t) => t.id === id);
      if (!tab) return;
      setActiveId(id);
      nav(pathForTab(tab));
    },
    [nav, tabs],
  );

  const closeTab = useCallback(
    async (id: string, opts?: { endSession?: boolean }) => {
      const end = opts?.endSession !== false;
      if (end) {
        try {
          await api.endSession(id);
        } catch {
          /* ignore — still close UI tab */
        }
      }
      let fallbackPath: string | null = null;
      setTabs((prev) => {
        const next = prev.filter((t) => t.id !== id);
        const wasActive = activeId === id;
        if (wasActive) {
          const fallback = next[next.length - 1] ?? null;
          setActiveId(fallback?.id ?? null);
          fallbackPath = fallback ? pathForTab(fallback) : "/sessions";
        }
        return next;
      });
      if (fallbackPath) nav(fallbackPath);
    },
    [activeId, nav],
  );

  const value = useMemo<Ctx>(
    () => ({
      tabs,
      activeId,
      openTab,
      activateTab,
      closeTab,
      pathFor: pathForTab,
    }),
    [tabs, activeId, openTab, activateTab, closeTab],
  );

  // Avoid flash of stale tabs before validation on first paint is ok;
  // children always render.
  void hydrated;

  return <SessionTabsContext.Provider value={value}>{children}</SessionTabsContext.Provider>;
}

export function useSessionTabs(): Ctx {
  const ctx = useContext(SessionTabsContext);
  if (!ctx) throw new Error("useSessionTabs outside provider");
  return ctx;
}
