import { NavLink } from "react-router-dom";

const NAV = [
  { to: "/", label: "Overview", end: true },
  { to: "/scan", label: "New Scan" },
  { to: "/findings", label: "Findings" },
  { to: "/scanners", label: "Scanners" },
  { to: "/history", label: "History" },
  { to: "/settings", label: "Settings" },
];

export default function Sidebar() {
  return (
    <aside className="flex w-60 shrink-0 flex-col border-r border-[var(--color-border)] bg-[var(--color-panel)]">
      <div className="flex items-center gap-2.5 px-5 py-5">
        <img src="/logo.svg" alt="" className="h-8 w-8" />
        <div className="leading-tight">
          <div className="text-[15px] font-bold tracking-wide">BANNIN</div>
          <div className="text-[10px] uppercase tracking-wider text-[var(--color-muted-2)]">DevSecOps</div>
        </div>
      </div>

      <nav className="mt-2 flex flex-col gap-0.5 px-3">
        {NAV.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.end}
            className={({ isActive }) =>
              `rounded-lg px-3 py-2 text-sm font-medium transition-colors ${
                isActive
                  ? "bg-[var(--color-panel-raised)] text-[var(--color-ink)]"
                  : "text-[var(--color-muted)] hover:bg-[var(--color-panel-raised)]/60 hover:text-[var(--color-ink)]"
              }`
            }
          >
            {item.label}
          </NavLink>
        ))}
      </nav>

      <div className="mt-auto px-5 py-4 text-[11px] text-[var(--color-muted-2)]">
        Findings, scans and history reflect this target's real scan data — no synthetic fleet or org data.
      </div>
    </aside>
  );
}
