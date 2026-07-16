export default function KpiCard({
  label,
  value,
  sub,
  accent,
}: {
  label: string;
  value: string | number;
  sub?: string;
  accent?: string;
}) {
  return (
    <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] px-5 py-4">
      <div className="text-xs font-medium uppercase tracking-wide text-[var(--color-muted)]">{label}</div>
      <div className="mt-1.5 text-[28px] font-bold leading-none" style={accent ? { color: accent } : undefined}>
        {value}
      </div>
      {sub && <div className="mt-1.5 text-xs text-[var(--color-muted)]">{sub}</div>}
    </div>
  );
}
