import { useMemo, useState } from "react";
import { CATEGORY_LABEL, type Finding, type Severity } from "../api";
import SeverityBadge from "../SeverityBadge";
import FindingDrawer from "./FindingDrawer";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export default function FindingsTable({ findings }: { findings: Finding[] }) {
  const [severityFilter, setSeverityFilter] = useState<Severity | "all">("all");
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<Finding | null>(null);

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return findings.filter((f) => {
      if (severityFilter !== "all" && f.severity !== severityFilter) return false;
      if (!q) return true;
      return (
        f.title.toLowerCase().includes(q) ||
        f.scanner.toLowerCase().includes(q) ||
        f.rule_id.toLowerCase().includes(q) ||
        (f.location.path ?? "").toLowerCase().includes(q)
      );
    });
  }, [findings, severityFilter, query]);

  return (
    <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)]">
      <div className="flex flex-wrap items-center gap-3 border-b border-[var(--color-border)] px-5 py-3.5">
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search findings…"
          className="min-w-48 flex-1 rounded-lg border border-[var(--color-border)] bg-[var(--color-panel-raised)] px-3 py-1.5 text-sm outline-none placeholder:text-[var(--color-muted-2)] focus:border-[var(--color-accent)]"
        />
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value as Severity | "all")}
          className="rounded-lg border border-[var(--color-border)] bg-[var(--color-panel-raised)] px-2.5 py-1.5 text-sm"
        >
          <option value="all">All severities</option>
          {SEVERITY_ORDER.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <span className="text-xs text-[var(--color-muted)]">
          {rows.length} of {findings.length}
        </span>
      </div>

      {rows.length === 0 ? (
        <p className="px-5 py-8 text-center text-sm text-[var(--color-muted)]">No findings match.</p>
      ) : (
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-[var(--color-border)] text-left text-xs uppercase tracking-wide text-[var(--color-muted)]">
              <th className="px-5 py-2.5 font-medium">Severity</th>
              <th className="px-2 py-2.5 font-medium">Finding</th>
              <th className="px-2 py-2.5 font-medium">Category</th>
              <th className="px-2 py-2.5 font-medium">Scanner</th>
              <th className="px-2 py-2.5 text-right font-medium">Risk</th>
              <th className="px-5 py-2.5 font-medium">Location</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((f) => {
              const where = [f.location.path, f.location.start_line]
                .filter((v) => v !== undefined && v !== "")
                .join(":");
              return (
                <tr
                  key={f.id}
                  onClick={() => setSelected(f)}
                  className="cursor-pointer border-b border-[var(--color-border)]/60 last:border-0 hover:bg-[var(--color-panel-raised)]"
                >
                  <td className="px-5 py-2.5">
                    <SeverityBadge severity={f.severity} />
                  </td>
                  <td className="max-w-xs truncate px-2 py-2.5 font-medium">{f.title}</td>
                  <td className="px-2 py-2.5 text-xs text-[var(--color-muted)]">{CATEGORY_LABEL[f.category]}</td>
                  <td className="px-2 py-2.5 text-xs text-[var(--color-muted)]">{f.scanner}</td>
                  <td className="px-2 py-2.5 text-right font-semibold tabular-nums">{f.risk.score}</td>
                  <td className="max-w-[14rem] truncate px-5 py-2.5 text-xs text-[var(--color-muted)]">{where || "—"}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}

      {selected && <FindingDrawer finding={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}
