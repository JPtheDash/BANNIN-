import type { Severity } from "./api";

const DOT: Record<Severity, string> = {
  critical: "bg-sev-critical",
  high: "bg-sev-high",
  medium: "bg-sev-medium",
  low: "bg-sev-low",
  info: "bg-sev-info",
};

export default function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-neutral-600 dark:text-neutral-300">
      <span className={`h-2.5 w-2.5 rounded-full ${DOT[severity] ?? "bg-sev-info"}`} />
      {severity}
    </span>
  );
}
