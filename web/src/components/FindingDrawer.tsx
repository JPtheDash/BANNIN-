import type { ReactNode } from "react";
import { CATEGORY_LABEL, type Finding } from "../api";
import SeverityBadge from "../SeverityBadge";

export default function FindingDrawer({ finding, onClose }: { finding: Finding; onClose: () => void }) {
  const where = [finding.location.path, finding.location.start_line].filter((v) => v !== undefined && v !== "").join(":");

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <div className="absolute inset-0 bg-black/60" onClick={onClose} />
      <div className="relative flex h-full w-full max-w-xl flex-col overflow-y-auto border-l border-[var(--color-border)] bg-[var(--color-panel)] shadow-2xl animate-[slide-in_0.2s_ease]">
        <div className="flex items-start justify-between gap-4 border-b border-[var(--color-border)] px-6 py-4">
          <div className="min-w-0">
            <SeverityBadge severity={finding.severity} />
            <h2 className="mt-1.5 text-lg font-semibold leading-snug">{finding.title}</h2>
          </div>
          <button
            onClick={onClose}
            className="shrink-0 rounded-lg border border-[var(--color-border)] px-2.5 py-1 text-xs text-[var(--color-muted)] hover:text-[var(--color-ink)]"
          >
            Close
          </button>
        </div>

        <div className="space-y-5 px-6 py-5 text-sm">
          {finding.description && <p className="text-[var(--color-muted)]">{finding.description}</p>}

          <Section title="Risk">
            <div className="flex items-baseline gap-2">
              <span className="text-2xl font-bold">{finding.risk.score}</span>
              <span className="text-xs text-[var(--color-muted)]">/ 100</span>
            </div>
            {finding.risk.factors && finding.risk.factors.length > 0 && (
              <ul className="mt-2 space-y-1">
                {finding.risk.factors.map((f, i) => (
                  <li key={i} className="flex justify-between text-xs text-[var(--color-muted)]">
                    <span>{f.reason}</span>
                    <span className={f.delta >= 0 ? "text-sev-high" : "text-ok"}>
                      {f.delta >= 0 ? "+" : ""}
                      {f.delta}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </Section>

          <Section title="Details">
            <Field label="Category" value={CATEGORY_LABEL[finding.category]} />
            <Field label="Scanner" value={finding.scanner} />
            <Field label="Rule ID" value={finding.rule_id} />
            {finding.aliases && finding.aliases.length > 0 && (
              <Field label="Also known as" value={finding.aliases.join(", ")} />
            )}
            {where && <Field label="Location" value={where} mono />}
            {finding.cwe && finding.cwe.length > 0 && <Field label="CWE" value={finding.cwe.join(", ")} />}
            {finding.metadata?.package && (
              <Field
                label="Package"
                value={`${finding.metadata.package}${finding.metadata.version ? `@${finding.metadata.version}` : ""}`}
                mono
              />
            )}
            {finding.metadata?.also_reported_by && (
              <Field label="Also reported by" value={finding.metadata.also_reported_by} />
            )}
          </Section>

          {finding.references && finding.references.length > 0 && (
            <Section title="References">
              <ul className="space-y-1">
                {finding.references.map((r) => (
                  <li key={r} className="truncate">
                    <a href={r} target="_blank" rel="noreferrer" className="text-[var(--color-accent)] hover:underline">
                      {r}
                    </a>
                  </li>
                ))}
              </ul>
            </Section>
          )}
        </div>
      </div>
    </div>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div>
      <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-[var(--color-muted)]">{title}</div>
      {children}
    </div>
  );
}

function Field({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex justify-between gap-4 border-b border-[var(--color-border)]/60 py-1.5 last:border-0">
      <span className="text-[var(--color-muted)]">{label}</span>
      <span className={`text-right ${mono ? "font-mono text-xs" : ""}`}>{value}</span>
    </div>
  );
}
