import type { Severity } from "../api";

// Heuristic 0-100 posture score derived from this scan's own severity mix.
// Not a fabricated cross-repo/industry benchmark — just a legible rollup
// of the same by_severity counts the tiles and donut already show.
const WEIGHT: Record<Severity, number> = { critical: 20, high: 10, medium: 4, low: 1, info: 0 };

export function securityScore(bySeverity: Partial<Record<Severity, number>>): number {
  let penalty = 0;
  for (const [sev, n] of Object.entries(bySeverity)) {
    penalty += WEIGHT[sev as Severity] * (n ?? 0);
  }
  return Math.max(0, 100 - penalty);
}

export function scoreBand(score: number): { label: string; className: string } {
  if (score >= 90) return { label: "Strong", className: "text-ok" };
  if (score >= 70) return { label: "Fair", className: "text-sev-medium" };
  if (score >= 40) return { label: "Weak", className: "text-sev-high" };
  return { label: "Critical", className: "text-sev-critical" };
}
