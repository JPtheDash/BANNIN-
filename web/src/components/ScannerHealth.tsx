import type { PluginRun } from "../api";

export default function ScannerHealth({ runs }: { runs: PluginRun[] }) {
  if (runs.length === 0) {
    return (
      <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-5">
        <div className="text-sm font-semibold">Scanner health</div>
        <p className="mt-3 text-xs text-[var(--color-muted)]">
          No per-plugin telemetry on this report (older scan, or a build predating plugin_runs).
        </p>
      </div>
    );
  }

  return (
    <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-5">
      <div className="text-sm font-semibold">Scanner health</div>
      <div className="mt-3 grid grid-cols-1 gap-2.5 sm:grid-cols-2 lg:grid-cols-3">
        {runs.map((r) => (
          <div
            key={r.name}
            className="rounded-xl border border-[var(--color-border)] bg-[var(--color-panel-raised)] px-3.5 py-3"
          >
            <div className="flex items-center justify-between">
              <span className="font-medium">{r.name}</span>
              <span
                className={`rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${
                  r.success ? "bg-ok/15 text-ok" : "bg-sev-critical/15 text-sev-critical"
                }`}
              >
                {r.success ? "OK" : "Failed"}
              </span>
            </div>
            <div className="mt-1 text-xs text-[var(--color-muted)]">
              {r.findings} finding{r.findings !== 1 && "s"} · {r.duration_ms}ms
            </div>
            {r.error && <div className="mt-1.5 text-xs text-sev-critical">{r.error}</div>}
          </div>
        ))}
      </div>
    </div>
  );
}
