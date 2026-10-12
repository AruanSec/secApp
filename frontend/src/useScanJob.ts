import { useEffect, useRef, useState } from "react";
import { api, ApiError, type JobStatusResponse } from "./api";

export function useScanJob(onComplete: () => void) {
  const [job, setJob] = useState<JobStatusResponse | null>(null);
  const [jobId, setJobId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const completeRef = useRef(onComplete);
  completeRef.current = onComplete;

  useEffect(() => {
    if (!jobId) return;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const poll = async () => {
      try {
        const current = await api.job(jobId, controller.signal);
        if (controller.signal.aborted) return;
        setJob(current);
        setError(null);
        if (["completed", "failed"].includes(current.status)) {
          setJobId(null);
          completeRef.current();
          return;
        }
      } catch (err) {
        if (controller.signal.aborted) return;
        setError(err instanceof Error ? err.message : "Could not fetch scan progress");
        if (err instanceof ApiError && err.status === 404) {
          setJobId(null);
          setJob((current) => current ? { ...current, status: "failed", error: "This job is no longer available. Start a new scan." } : current);
          return;
        }
      }
      if (!controller.signal.aborted) timer = setTimeout(poll, 1000);
    };
    void poll();
    return () => {
      controller.abort();
      if (timer) clearTimeout(timer);
    };
  }, [jobId]);

  return {
    job,
    active: jobId !== null,
    error,
    reset: () => { setJob(null); setError(null); },
    track: (id: string) => {
      setJob({ job_id: id, status: "pending", results: [] });
      setError(null);
      setJobId(id);
    },
  };
}
