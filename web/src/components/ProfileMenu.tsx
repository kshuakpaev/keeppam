import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useI18n } from "../i18n";
import { hasPerm, type User } from "../api";

type Props = {
  user: User;
  name: string;
  onLogout: () => void;
};

export function ProfileMenu({ user, name, onLogout }: Props) {
  const nav = useNavigate();
  const { t } = useI18n();
  const [open, setOpen] = useState(false);
  const box = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    function onDoc(e: MouseEvent) {
      if (box.current && !box.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") setOpen(false);
    }
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  function go(path: string) {
    setOpen(false);
    nav(path);
  }

  return (
    <div className="profile-menu" ref={box}>
      {open && (
        <div className="profile-dropdown" role="menu">
          <button type="button" role="menuitem" onClick={() => go("/profile")}>
            {t("nav.profile")}
          </button>
          {hasPerm(user, "settings.write") && (
            <button type="button" role="menuitem" onClick={() => go("/config")}>
              {t("nav.config")}
            </button>
          )}
          <button
            type="button"
            role="menuitem"
            className="danger"
            onClick={() => {
              setOpen(false);
              onLogout();
            }}
          >
            {t("nav.logout")}
          </button>
        </div>
      )}
      <button
        type="button"
        className="profile-trigger"
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
      >
        <span className="profile-trigger-name">{name}</span>
        <span className="profile-trigger-caret" aria-hidden>
          {open ? "▴" : "▾"}
        </span>
      </button>
    </div>
  );
}
