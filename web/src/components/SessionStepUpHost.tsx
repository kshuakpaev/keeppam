import { useEffect, useState } from "react";
import { ApiError, api } from "../api";
import { StepUpDialog } from "../pages/StepUpDialog";

export function SessionStepUpHost({ sessionId }: { sessionId: string }) {
  const [err, setErr] = useState<ApiError | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function tick() {
      try {
        const p = await api.getOpStepUp(sessionId);
        if (cancelled) return;
        if (p.pending && p.challenge_token) {
          setErr(
            new ApiError("mfa_required", 403, {
              code: "mfa_required",
              challenge_token: p.challenge_token,
              totp: p.totp,
              webauthn: p.webauthn,
              risk_score: p.risk_score,
              max_risk: p.max_risk,
              risk_factors: p.risk_factors,
              operation: p.operation,
            }),
          );
        } else {
          setErr(null);
        }
      } catch {
        /* ignore poll errors */
      }
    }
    void tick();
    const id = window.setInterval(() => void tick(), 2000);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, [sessionId]);

  if (!err) return null;
  return (
    <StepUpDialog
      err={err}
      onDone={() => setErr(null)}
      onCancel={() => setErr(null)}
    />
  );
}
