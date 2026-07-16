import type { DashState } from "../Layout";

export default function TopBar({
  state,
  selectScan,
}: {
  state: DashState;
  selectScan: (id: number) => void;
}) {
  const ready = state.status === "ready";

  return (
    <header className="flex items-center justify-between border-b border-[var(--color-border)] bg-[var(--color-panel)] px-8 py-3.5">
      <div className="min-w-0">
        <div className="truncate text-sm font-semibold text-[var(--color-ink)]">
          {ready ? state.report.target : "—"}
        </div>
        <div className="text-xs text-[var(--color-muted)]">
          {ready ? (
            <>
              Last scan {new Date(state.report.generated_at).toLocaleString()} ·{" "}
              {state.report.findings.length} finding{state.report.findings.length !== 1 && "s"}
            </>
          ) : (
            "Waiting for scan data"
          )}
        </div>
      </div>

      {ready && state.history.length > 1 && (
        <select
          value={state.selectedId}
          onChange={(e) => selectScan(Number(e.target.value))}
          className="rounded-md border border-[var(--color-border)] bg-[var(--color-panel-raised)] px-2.5 py-1.5 text-xs text-[var(--color-ink)]"
        >
          {state.history.map((h) => (
            <option key={h.id} value={h.id}>
              {new Date(h.generated_at).toLocaleString()} · {h.total} findings
            </option>
          ))}
        </select>
      )}
    </header>
  );
}
