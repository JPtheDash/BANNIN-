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
  const [elapsed, setElapsed] = useState(0);
  const pollRef = useRef<number | null>(null);
  const clockRef = useRef<number | null>(null);

  const isURL = /^https?:\/\//.test(target.trim());

  useEffect(() => {
    return () => {
      if (pollRef.current !== null) window.clearInterval(pollRef.current);
      if (clockRef.current !== null) window.clearInterval(clockRef.current);
    };
  }, []);

  function togglePlugin(name: string) {
    setPlugins((ps) => (ps.includes(name) ? ps.filter((p) => p !== name) : [...ps, name]));
  }

  function stopClock() {
    if (clockRef.current !== null) {
      window.clearInterval(clockRef.current);
      clockRef.current = null;
    }
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (pollRef.current !== null) window.clearInterval(pollRef.current);
    stopClock();
    try {
      const job = await triggerScan(target.trim(), plugins.length > 0 ? plugins : undefined);
      setPhase({ kind: "job", job });
      // Client-side elapsed clock: reassures during long, quiet phases
      // (ZAP's active scan can run minutes without emitting a new line).
      const startedAt = Date.now();
      setElapsed(0);
      clockRef.current = window.setInterval(() => setElapsed(Math.floor((Date.now() - startedAt) / 1000)), 1000);
      pollRef.current = window.setInterval(async () => {
        try {
          const updated = await fetchScanStatus(job.id);
          setPhase({ kind: "job", job: updated });
          if (updated.status !== "running" && pollRef.current !== null) {
            window.clearInterval(pollRef.current);
            stopClock();
          }
        } catch (err) {
          if (pollRef.current !== null) window.clearInterval(pollRef.current);
          stopClock();
          setPhase({ kind: "error", message: err instanceof ApiError ? err.message : String(err) });
        }
      }, 2000);
    } catch (err) {
      stopClock();
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
              minutes. <span className="text-[var(--color-muted-2)]">Elapsed {formatElapsed(elapsed)}.</span>
            </p>
          )}

          <ProgressLog lines={phase.job.progress} running={phase.job.status === "running"} />

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

// ProgressLog shows the scanner's live output (spider/active-scan
// phases, percentages) so a long scan reports what it's doing instead of
// an opaque "running". It auto-scrolls to the newest line.
function ProgressLog({ lines, running }: { lines?: string[]; running: boolean }) {
  const endRef = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    endRef.current?.scrollIntoView({ block: "end" });
  }, [lines]);

  if (!lines || lines.length === 0) {
    if (!running) return null;
    return (
      <p className="mt-3 text-xs text-[var(--color-muted-2)]">Waiting for the scanner to report activity…</p>
    );
  }

  return (
    <div className="mt-3">
      <div className="mb-1 flex items-center gap-2 text-[10px] font-semibold uppercase tracking-wide text-[var(--color-muted)]">
        {running && <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-running" />}
        Live activity
      </div>
      <div className="max-h-48 overflow-y-auto rounded-lg border border-[var(--color-border)] bg-[var(--color-panel-raised)] p-3 font-mono text-[11px] leading-relaxed text-[var(--color-muted)]">
        {lines.map((line, i) => (
          <div key={i} className="whitespace-pre-wrap break-words">
            {line}
          </div>
        ))}
        <div ref={endRef} />
      </div>
    </div>
  );
}

function formatElapsed(seconds: number): string {
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return m > 0 ? `${m}m ${s}s` : `${s}s`;
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
