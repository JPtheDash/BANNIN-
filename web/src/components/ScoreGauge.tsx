import { scoreBand } from "../lib/score";

// Semicircular gauge, hand-rolled SVG arc (no charting lib needed for one shape).
export default function ScoreGauge({ score, trend }: { score: number; trend?: number }) {
  const r = 80;
  const cx = 100;
  const cy = 100;
  const circumference = Math.PI * r;
  const pct = Math.max(0, Math.min(100, score)) / 100;
  const offset = circumference * (1 - pct);
  const band = scoreBand(score);

  return (
    <div className="flex flex-col items-center">
      <svg viewBox="0 0 200 110" className="w-56">
        <path
          d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`}
          fill="none"
          stroke="var(--color-border)"
          strokeWidth="14"
          strokeLinecap="round"
        />
        <path
          d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`}
          fill="none"
          stroke="var(--color-accent)"
          strokeWidth="14"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          style={{ transition: "stroke-dashoffset 0.6s ease" }}
        />
      </svg>
      <div className="-mt-9 text-center">
        <div className="text-[40px] font-bold leading-none">{Math.round(score)}</div>
        <div className={`mt-1 text-xs font-semibold uppercase tracking-wide ${band.className}`}>{band.label}</div>
      </div>
      {trend !== undefined && trend !== 0 && (
        <div className={`mt-2 text-xs font-medium ${trend > 0 ? "text-ok" : "text-sev-high"}`}>
          {trend > 0 ? "+" : ""}
          {trend} vs previous scan
        </div>
      )}
    </div>
  );
}
