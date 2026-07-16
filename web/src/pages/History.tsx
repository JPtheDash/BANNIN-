import { useNavigate } from "react-router-dom";
import { useDash } from "../Layout";

export default function History() {
  const { state, selectScan } = useDash();
  const navigate = useNavigate();
  if (state.status !== "ready") return null;

  return (
    <div>
      <h1 className="mb-4 text-lg font-semibold">Scan history</h1>
      {state.history.length === 1 && state.history[0].id === 0 && (
        <p className="mb-4 text-xs text-[var(--color-muted)]">
          Single-report mode — set <code className="rounded bg-[var(--color-panel-raised)] px-1 py-0.5">storage.driver: sqlite</code> in bannin.yaml for full history.
        </p>
      )}
      <div className="overflow-hidden rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)]">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-[var(--color-border)] text-left text-xs uppercase tracking-wide text-[var(--color-muted)]">
              <th className="px-5 py-2.5 font-medium">Scanned at</th>
              <th className="px-2 py-2.5 font-medium">Target</th>
              <th className="px-2 py-2.5 text-right font-medium">Findings</th>
              <th className="px-5 py-2.5 font-medium">Severity mix</th>
            </tr>
          </thead>
          <tbody>
            {state.history.map((h) => (
              <tr
                key={h.id}
                onClick={() => {
                  selectScan(h.id);
                  navigate("/");
                }}
                className={`cursor-pointer border-b border-[var(--color-border)]/60 last:border-0 hover:bg-[var(--color-panel-raised)] ${
                  h.id === state.selectedId ? "bg-[var(--color-panel-raised)]" : ""
                }`}
              >
                <td className="px-5 py-2.5">{new Date(h.generated_at).toLocaleString()}</td>
                <td className="max-w-xs truncate px-2 py-2.5 text-[var(--color-muted)]">{h.target}</td>
                <td className="px-2 py-2.5 text-right font-semibold tabular-nums">{h.total}</td>
                <td className="px-5 py-2.5 text-xs text-[var(--color-muted)]">
                  {Object.entries(h.by_severity)
                    .map(([sev, n]) => `${sev} ${n}`)
                    .join(" · ") || "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
