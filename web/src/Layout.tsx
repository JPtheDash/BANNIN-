import { useEffect, useState } from "react";
import { NavLink, Outlet, useOutletContext } from "react-router-dom";
import {
  ApiError,
  fetchHistory,
  fetchReportById,
  NoReportError,
  type HistoryEntry,
  type Report,
} from "./api";
import Sidebar from "./components/Sidebar";
import TopBar from "./components/TopBar";

export type DashState =
  | { status: "loading" }
  | { status: "no-report" }
  | { status: "error"; message: string }
  | { status: "ready"; history: HistoryEntry[]; selectedId: number; report: Report };

export interface DashContext {
  state: DashState;
  selectScan: (id: number) => void;
}

export function useDash() {
  return useOutletContext<DashContext>();
}

export default function Layout() {
  const [state, setState] = useState<DashState>({ status: "loading" });

  useEffect(() => {
    let cancelled = false;
    fetchHistory()
      .then(async (history) => {
        if (history.length === 0) {
          if (!cancelled) setState({ status: "no-report" });
          return;
        }
        const selectedId = history[0].id;
        const report = await fetchReportById(selectedId);
        if (!cancelled) setState({ status: "ready", history, selectedId, report });
      })
      .catch((err) => {
        if (cancelled) return;
        if (err instanceof NoReportError) setState({ status: "no-report" });
        else setState({ status: "error", message: err instanceof ApiError ? err.message : String(err) });
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // Re-fetches history alongside the requested report, not just the
  // report itself — the caller may be jumping to a scan (e.g. one just
  // triggered from the New Scan page) that isn't in the last-loaded
  // history list yet.
  function selectScan(id: number) {
    setState({ status: "loading" });
    Promise.all([fetchReportById(id), fetchHistory()])
      .then(([report, history]) => setState({ status: "ready", history, selectedId: id, report }))
      .catch((err) => setState({ status: "error", message: err instanceof ApiError ? err.message : String(err) }));
  }

  return (
    <div className="flex min-h-screen bg-[var(--color-bg)]">
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar state={state} selectScan={selectScan} />
        <main className="min-w-0 flex-1 px-8 py-6">
          {state.status === "loading" && <p className="mb-4 text-[var(--color-muted)]">Loading…</p>}
          {state.status === "no-report" && (
            <p className="mb-4 text-[var(--color-muted)]">
              No scan has been run yet. Run{" "}
              <code className="rounded bg-[var(--color-panel-raised)] px-1.5 py-0.5">bannin scan</code>, or use{" "}
              <NavLink to="/scan" className="text-[var(--color-accent)] hover:underline">
                New Scan
              </NavLink>
              .
            </p>
          )}
          {state.status === "error" && (
            <p className="mb-4 text-sev-critical">Couldn't reach the dashboard API: {state.message}</p>
          )}
          <Outlet context={{ state, selectScan } satisfies DashContext} />
        </main>
      </div>
    </div>
  );
}
