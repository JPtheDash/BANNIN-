import { useDash } from "../Layout";
import ScannerHealth from "../components/ScannerHealth";

export default function Scanners() {
  const { state } = useDash();
  if (state.status !== "ready") return null;
  const { report } = state;

  return (
    <div className="space-y-4">
      <h1 className="text-lg font-semibold">Scanners</h1>
      <p className="text-sm text-[var(--color-muted)]">
        Configured: {report.plugins.join(", ") || "none"}
      </p>
      <ScannerHealth runs={report.plugin_runs ?? []} />
    </div>
  );
}
