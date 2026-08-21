import { useEffect } from "react";
import { useParams, useSearchParams } from "react-router-dom";
import { useSessionTabs } from "../sessionTabs";

/** Registers TN3270 tab; UI lives in SessionKeepAliveHost. */
export function Tn3270Page() {
  const { id } = useParams<{ id: string }>();
  const [params] = useSearchParams();
  const { openTab } = useSessionTabs();

  useEffect(() => {
    if (!id) return;
    openTab(
      {
        id,
        kind: "tn3270",
        title: params.get("title") || "TN3270",
        protocol: "tn3270",
      },
      { navigate: false },
    );
  }, [id, params.get("title"), openTab]); // eslint-disable-line react-hooks/exhaustive-deps

  return null;
}
