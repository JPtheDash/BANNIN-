import { useDash } from "../Layout";
import { CATEGORY_LABEL, type Category, type Severity } from "../api";
import ScoreGauge from "../components/ScoreGauge";
import KpiCard from "../components/KpiCard";
import DonutChart from "../components/DonutChart";
import TrendChart from "../components/TrendChart";
import ScannerHealth from "../components/ScannerHealth";
import { securityScore } from "../lib/score";

const SEV_COLOR: Record<Severity, string> = {
  critical: "var(--color-sev-critical)",
  high: "var(--color-sev-high)",
  medium: "var(--color-sev-medium)",
  low: "var(--color-sev-low)",
  info: "var(--color-sev-info)",
};

const CATEGORY_ORDER: Category[] = ["sast", "sca", "secrets", "iac", "dast"];
const CATEGORY_COLOR: Record<Category, string> = {
  sast: "#22b8cf",
  sca: "#7dd3fc",
  secrets: "#ff4d4f",
  iac: "#fa8c16",
  dast: "#b794f4",
};

export default function Overview() {
  const { state } = useDash();
  if (state.status !== "ready") return null;
  const { report, history } = state;

  const bySeverity: Partial<Record<Severity, number>> = {};
  const byCategory: Partial<Record<Category, number>> = {};
  for (const f of report.findings) {
    bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
    byCategory[f.category] = (byCategory[f.category] ?? 0) + 1;
  }

  const score = securityScore(bySeverity);
  const prev = history[1];
  const trend = prev ? Math.round(score - securityScore(prev.by_severity)) : undefined;

  const critical = bySeverity.critical ?? 0;
  const high = bySeverity.high ?? 0;
  const runs = report.plugin_runs ?? [];
  const failedRuns = runs.filter((r) => !r.success).length;

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-[280px_1fr]">
        <div className="flex items-center justify-center rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] py-6">
          <ScoreGauge score={score} trend={trend} />
        </div>
        <div className="grid grid-cols-2 gap-3.5 sm:grid-cols-3">
          <KpiCard label="Critical findings" value={critical} accent="var(--color-sev-critical)" />
          <KpiCard label="High findings" value={high} accent="var(--color-sev-high)" />
          <KpiCard label="Total findings" value={report.findings.length} />
          <KpiCard label="Scanners run" value={report.plugins.length} sub={runs.length > 0 ? `${runs.length - failedRuns}/${runs.length} healthy` : undefined} />
          <KpiCard label="Scan history" value={history.length} sub={history.length === 1 ? "single-report mode" : "scans recorded"} />
          <KpiCard label="Last scan" value={new Date(report.generated_at).toLocaleDateString()} sub={new Date(report.generated_at).toLocaleTimeString()} />
        </div>
      </div>

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        <DonutChart
          title="Findings by severity"
          data={(["critical", "high", "medium", "low", "info"] as Severity[]).map((s) => ({
            label: s,
            value: bySeverity[s] ?? 0,
            color: SEV_COLOR[s],
          }))}
        />
        <DonutChart
          title="Findings by category"
          data={CATEGORY_ORDER.map((c) => ({
            label: CATEGORY_LABEL[c],
            value: byCategory[c] ?? 0,
            color: CATEGORY_COLOR[c],
          }))}
        />
      </div>

      <TrendChart history={history} />

      <ScannerHealth runs={runs} />
    </div>
  );
}
