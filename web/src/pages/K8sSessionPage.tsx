import { useEffect } from "react";
import { useParams, useSearchParams } from "react-router-dom";
import { useSessionTabs } from "../sessionTabs";

export function K8sSessionPage() {
  const { id } = useParams<{ id: string }>();
  const [params] = useSearchParams();
  const { openTab } = useSessionTabs();

  useEffect(() => {
    if (!id) return;
    openTab(
      {
        id,
        kind: "k8s",
        title: params.get("title") || "kubectl",
        protocol: "kubectl",
      },
      { navigate: false },
    );
  }, [id, params.get("title"), openTab]); // eslint-disable-line react-hooks/exhaustive-deps

  return null;
}
