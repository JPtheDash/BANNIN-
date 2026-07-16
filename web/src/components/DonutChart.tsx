export interface DonutSlice {
  label: string;
  value: number;
  color: string;
}

export default function DonutChart({ data, title }: { data: DonutSlice[]; title: string }) {
  const total = data.reduce((s, d) => s + d.value, 0);
  const r = 60;
  const circumference = 2 * Math.PI * r;
  let offsetAcc = 0;

  return (
    <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-5">
      <div className="text-sm font-semibold">{title}</div>
      {total === 0 ? (
        <p className="mt-6 text-center text-xs text-[var(--color-muted)]">No data.</p>
      ) : (
        <div className="mt-3 flex items-center gap-6">
          <svg viewBox="0 0 140 140" className="h-32 w-32 shrink-0 -rotate-90">
            <circle cx="70" cy="70" r={r} fill="none" stroke="var(--color-border)" strokeWidth="18" />
            {data
              .filter((d) => d.value > 0)
              .map((d) => {
                const frac = d.value / total;
                const dash = frac * circumference;
                const el = (
                  <circle
                    key={d.label}
                    cx="70"
                    cy="70"
                    r={r}
                    fill="none"
                    stroke={d.color}
                    strokeWidth="18"
                    strokeDasharray={`${dash} ${circumference - dash}`}
                    strokeDashoffset={-offsetAcc}
                  />
                );
                offsetAcc += dash;
                return el;
              })}
          </svg>
          <ul className="min-w-0 flex-1 space-y-1.5">
            {data.map((d) => (
              <li key={d.label} className="flex items-center justify-between gap-3 text-xs">
                <span className="flex min-w-0 items-center gap-1.5 text-[var(--color-muted)]">
                  <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: d.color }} />
                  <span className="truncate">{d.label}</span>
                </span>
                <span className="font-semibold tabular-nums">{d.value}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
