import { useEffect } from "react";
import { useParams, useSearchParams } from "react-router-dom";
import { useSessionTabs } from "../sessionTabs";

export function CitrixPage() {
  const { id } = useParams<{ id: string }>();
  const [params] = useSearchParams();
  const { openTab } = useSessionTabs();

  useEffect(() => {
    if (!id) return;
    openTab(
      {
        id,
        kind: "citrix",
        title: params.get("title") || "Citrix",
        protocol: "citrix",
      },
      { navigate: false },
    );
  }, [id, params.get("title"), openTab]); // eslint-disable-line react-hooks/exhaustive-deps

  return null;
}
