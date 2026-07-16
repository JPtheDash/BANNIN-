import { useDash } from "../Layout";

export default function Settings() {
  const { state } = useDash();

  return (
    <div className="max-w-xl space-y-4">
      <h1 className="text-lg font-semibold">Settings</h1>
      <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-5 text-sm">
        <div className="mb-3 text-xs font-semibold uppercase tracking-wide text-[var(--color-muted)]">Connection</div>
        <div className="flex justify-between border-b border-[var(--color-border)]/60 py-1.5">
          <span className="text-[var(--color-muted)]">Target</span>
          <span>{state.status === "ready" ? state.report.target : "—"}</span>
        </div>
        <div className="flex justify-between py-1.5">
          <span className="text-[var(--color-muted)]">Auth</span>
          <span>
            {import.meta.env.VITE_API_TOKEN ? "Bearer token configured (VITE_API_TOKEN)" : "Disabled (no VITE_API_TOKEN set)"}
          </span>
        </div>
      </div>
      <p className="text-xs text-[var(--color-muted)]">
        This dashboard reads from the <code className="rounded bg-[var(--color-panel-raised)] px-1 py-0.5">bannin serve</code>{" "}
        API. Configure scanning, storage and auth in <code className="rounded bg-[var(--color-panel-raised)] px-1 py-0.5">bannin.yaml</code>.
      </p>
    </div>
  );
}
