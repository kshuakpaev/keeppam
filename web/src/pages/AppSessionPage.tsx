import { useEffect } from "react";
import { useParams, useSearchParams } from "react-router-dom";
import { useSessionTabs } from "../sessionTabs";

export function AppSessionPage() {
  const { id } = useParams<{ id: string }>();
  const [params] = useSearchParams();
  const { openTab } = useSessionTabs();

  useEffect(() => {
    if (!id) return;
    openTab(
      {
        id,
        kind: "app",
        title: params.get("title") || "App",
        protocol: "https",
      },
      { navigate: false },
    );
  }, [id, params.get("title"), openTab]); // eslint-disable-line react-hooks/exhaustive-deps

  return null;
}
