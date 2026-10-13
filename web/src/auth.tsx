import {
  createContext,
  createElement,
  useCallback,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";
import { api, redirectIdleLogout, type User } from "./api";

type AuthState = {
  user: User | null;
  loading: boolean;
  refresh: () => Promise<void>;
  setUser: (u: User | null) => void;
};

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    try {
      const me = await api.me();
      setUser(me);
    } catch {
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useIdleLogout(!!user);

  return createElement(AuthContext.Provider, { value: { user, loading, refresh, setUser } }, children);
}

const IDLE_DEFAULT_MIN = 5;
const IDLE_MAX_MIN = 30;

function clampIdleMin(n: number | undefined): number {
  if (n == null || n < 1 || n > IDLE_MAX_MIN) return IDLE_DEFAULT_MIN;
  return n;
}

function useIdleLogout(active: boolean) {
  useEffect(() => {
    if (!active) return;
    let timeoutMs = IDLE_DEFAULT_MIN * 60_000;
    let last = Date.now();
    let dirty = true;
    let lastPing = 0;
    let lastConfig = 0;
    let stopped = false;

    const expire = () => {
      if (stopped) return;
      stopped = true;
      void api
        .logout()
        .catch(() => {})
        .finally(() => redirectIdleLogout());
    };

    const bump = () => {
      last = Date.now();
      dirty = true;
    };
    const onMouse = () => {
      if (Date.now() - last < 1000) return;
      bump();
    };
    const opts: AddEventListenerOptions = { capture: true, passive: true };
    document.addEventListener("mousedown", bump, opts);
    document.addEventListener("keydown", bump, opts);
    document.addEventListener("wheel", bump, opts);
    document.addEventListener("touchstart", bump, opts);
    document.addEventListener("mousemove", onMouse, opts);
    const onVisible = () => {
      if (document.visibilityState === "visible" && Date.now() - last >= timeoutMs) expire();
    };
    document.addEventListener("visibilitychange", onVisible);

    const pullTimeout = () => {
      lastConfig = Date.now();
      void api
        .authMethods()
        .then((m) => {
          timeoutMs = clampIdleMin(m.idle_timeout_min) * 60_000;
        })
        .catch(() => {});
    };
    pullTimeout();

    const timer = window.setInterval(() => {
      if (stopped) return;
      if (Date.now() - last >= timeoutMs) {
        expire();
        return;
      }
      if (Date.now() - lastConfig >= 60_000) pullTimeout();
      if (dirty && Date.now() - lastPing >= 15_000) {
        dirty = false;
        lastPing = Date.now();
        void api
          .touchActivity()
          .then((r) => {
            timeoutMs = clampIdleMin(r.idle_timeout_min) * 60_000;
          })
          .catch(() => {});
      }
    }, 1000);

    return () => {
      stopped = true;
      window.clearInterval(timer);
      document.removeEventListener("mousedown", bump, opts);
      document.removeEventListener("keydown", bump, opts);
      document.removeEventListener("wheel", bump, opts);
      document.removeEventListener("touchstart", bump, opts);
      document.removeEventListener("mousemove", onMouse, opts);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [active]);
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("AuthProvider missing");
  return ctx;
}
