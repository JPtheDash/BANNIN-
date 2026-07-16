import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ApiError, fetchScanStatus, triggerScan, type ScanJob } from "../api";
import { useDash } from "../Layout";

const PLUGINS = ["semgrep", "osv", "trivy", "gitleaks", "checkov", "zap"];

type Phase = { kind: "idle" } | { kind: "error"; message: string } | { kind: "job"; job: ScanJob };

export default function Scan() {
  const { selectScan } = useDash();
  const navigate = useNavigate();
  const [target, setTarget] = useState("");
  const [plugins, setPlugins] = useState<string[]>([]);
  const [phase, setPhase] = useState<Phase>({ kind: "idle" });
  const pollRef = useRef<number | null>(null);

  const isURL = /^https?:\/\//.test(target.trim());

  useEffect(() => {
    return () => {
      if (pollRef.current !== null) window.clearInterval(pollRef.current);
    };
  }, []);

  function togglePlugin(name: string) {
    setPlugins((ps) => (ps.includes(name) ? ps.filter((p) => p !== name) : [...ps, name]));
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (pollRef.current !== null) window.clearInterval(pollRef.current);
    try {
      const job = await triggerScan(target.trim(), plugins.length > 0 ? plugins : undefined);
      setPhase({ kind: "job", job });
      pollRef.current = window.setInterval(async () => {
        try {
          const updated = await fetchScanStatus(job.id);
          setPhase({ kind: "job", job: updated });
          if (updated.status !== "running" && pollRef.current !== null) {
            window.clearInterval(pollRef.current);
          }
        } catch (err) {
          if (pollRef.current !== null) window.clearInterval(pollRef.current);
          setPhase({ kind: "error", message: err instanceof ApiError ? err.message : String(err) });
        }
      }, 2000);
    } catch (err) {
      setPhase({ kind: "error", message: err instanceof ApiError ? err.message : String(err) });
    }
  }

  function viewResults(reportId: number) {
    selectScan(reportId);
    navigate("/");
  }

  return (
    <div className="max-w-2xl space-y-6">
      <div>
        <h1 className="text-lg font-semibold">New scan</h1>
        <p className="mt-1 text-sm text-[var(--color-muted)]">
          Scan a running app's URL (DAST, via ZAP) or a local path on the machine running{" "}
          <code className="rounded bg-[var(--color-panel-raised)] px-1 py-0.5">bannin serve</code> — no config file
          edits needed.
        </p>
      </div>

      <form onSubmit={submit} className="space-y-4 rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-5">
        <div>
          <label className="mb-1.5 block text-xs font-medium uppercase tracking-wide text-[var(--color-muted)]">
            Target
          </label>
          <input
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="https://juice-shop.herokuapp.com/  or  ./some/path"
            required
            className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-panel-raised)] px-3 py-2 text-sm outline-none placeholder:text-[var(--color-muted-2)] focus:border-[var(--color-accent)]"
          />
          <p className="mt-1.5 text-xs text-[var(--color-muted)]">
            {isURL
              ? "Looks like a URL — defaults to the ZAP (DAST) scanner unless you pick others below."
              : "Looks like a local path — defaults to semgrep, osv, trivy, gitleaks unless you pick others below."}
          </p>
        </div>

        <div>
          <label className="mb-1.5 block text-xs font-medium uppercase tracking-wide text-[var(--color-muted)]">
            Scanners (optional — leave unset to auto-select)
          </label>
          <div className="flex flex-wrap gap-2">
            {PLUGINS.map((p) => (
              <button
                type="button"
                key={p}
                onClick={() => togglePlugin(p)}
                className={`rounded-full border px-3 py-1 text-xs font-medium ${
                  plugins.includes(p)
                    ? "border-[var(--color-accent)] bg-[var(--color-accent)]/15 text-[var(--color-accent)]"
                    : "border-[var(--color-border)] text-[var(--color-muted)] hover:text-[var(--color-ink)]"
                }`}
              >
                {p}
              </button>
            ))}
          </div>
        </div>

        <button
          type="submit"
          disabled={phase.kind === "job" && phase.job.status === "running"}
          className="rounded-lg bg-[var(--color-accent)] px-4 py-2 text-sm font-semibold text-[#04222b] disabled:cursor-not-allowed disabled:opacity-50"
        >
          {phase.kind === "job" && phase.job.status === "running" ? "Scanning…" : "Run scan"}
        </button>
      </form>

      {phase.kind === "error" && (
        <p className="rounded-xl border border-sev-critical/30 bg-sev-critical/10 px-4 py-3 text-sm text-sev-critical">
          {phase.message}
        </p>
      )}

      {phase.kind === "job" && (
        <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-5 text-sm">
          <div className="flex items-center justify-between">
            <span className="font-medium">{phase.job.target}</span>
            <StatusPill status={phase.job.status} />
          </div>

          {phase.job.status === "running" && (
            <p className="mt-2 text-xs text-[var(--color-muted)]">
              Running in the background — this page polls automatically. ZAP scans of a real app can take a few
              minutes.
            </p>
          )}

          {phase.job.status === "failed" && (
            <p className="mt-2 text-xs text-sev-critical">{phase.job.error ?? "Scan failed."}</p>
          )}

          {phase.job.status === "done" && (
            <div className="mt-3">
              {phase.job.error && <p className="mb-2 text-xs text-sev-medium">{phase.job.error}</p>}
              <button
                onClick={() => phase.job.report_id !== undefined && viewResults(phase.job.report_id)}
                className="rounded-lg border border-[var(--color-accent)] px-3 py-1.5 text-xs font-semibold text-[var(--color-accent)] hover:bg-[var(--color-accent)]/10"
              >
                View results
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function StatusPill({ status }: { status: ScanJob["status"] }) {
  const cls =
    status === "done"
      ? "bg-ok/15 text-ok"
      : status === "failed"
        ? "bg-sev-critical/15 text-sev-critical"
        : "bg-running/15 text-running";
  return <span className={`rounded-full px-2.5 py-1 text-[10px] font-semibold uppercase tracking-wide ${cls}`}>{status}</span>;
}
