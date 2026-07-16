import { useDash } from "../Layout";
import FindingsTable from "../components/FindingsTable";

export default function Findings() {
  const { state } = useDash();
  if (state.status !== "ready") return null;

  return (
    <div>
      <h1 className="mb-4 text-lg font-semibold">Findings</h1>
      <FindingsTable findings={state.report.findings} />
    </div>
  );
}
