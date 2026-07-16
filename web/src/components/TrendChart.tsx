import type { HistoryEntry } from "../api";

// Area/line trend of total findings across scan history, oldest to newest.
// Single-report deployments (FileStore) only ever have one point — the
// chart still renders, just as a flat line, rather than being hidden.
export default function TrendChart({ history }: { history: HistoryEntry[] }) {
  const points = [...history].reverse();
  const w = 560;
  const h = 160;
  const pad = 24;

  const max = Math.max(1, ...points.map((p) => p.total));
  const step = points.length > 1 ? (w - pad * 2) / (points.length - 1) : 0;

  const coords = points.map((p, i) => {
    const x = pad + i * step;
    const y = h - pad - (p.total / max) * (h - pad * 2);
    return { x, y, p };
  });

  const line = coords.map((c) => `${c.x},${c.y}`).join(" ");
  const area = `${pad},${h - pad} ${line} ${coords.at(-1)?.x ?? pad},${h - pad}`;

  return (
    <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-5">
      <div className="text-sm font-semibold">Findings over time</div>
      {points.length === 0 ? (
        <p className="mt-6 text-center text-xs text-[var(--color-muted)]">No scan history yet.</p>
      ) : (
        <svg viewBox={`0 0 ${w} ${h}`} className="mt-3 w-full">
          <defs>
            <linearGradient id="trend-fill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="var(--color-accent)" stopOpacity="0.35" />
              <stop offset="100%" stopColor="var(--color-accent)" stopOpacity="0" />
            </linearGradient>
          </defs>
          <polygon points={area} fill="url(#trend-fill)" />
          <polyline points={line} fill="none" stroke="var(--color-accent)" strokeWidth="2.5" />
          {coords.map((c, i) => (
            <circle key={i} cx={c.x} cy={c.y} r="3" fill="var(--color-accent)" />
          ))}
        </svg>
      )}
    </div>
  );
}
