import { useEffect } from "react";
import { useParams, useSearchParams } from "react-router-dom";
import { useSessionTabs } from "../sessionTabs";

export function DesktopPage() {
  const { id } = useParams<{ id: string }>();
  const [params] = useSearchParams();
  const { openTab } = useSessionTabs();

  useEffect(() => {
    if (!id) return;
    openTab(
      {
        id,
        kind: "desktop",
        title: params.get("title") || "Desktop",
        protocol: "rdp",
      },
      { navigate: false },
    );
  }, [id, params.get("title"), openTab]); // eslint-disable-line react-hooks/exhaustive-deps

  return null;
}
