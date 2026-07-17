// Mirrors pkg/plugin.Finding, internal/report.{Finding,Report}, and
// internal/dashboard.Summary's JSON tags exactly — keep in sync with
// the Go structs when their schema changes.

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Category = "sast" | "sca" | "secrets" | "iac" | "dast";

export const CATEGORY_LABEL: Record<Category, string> = {
  sast: "Static Analysis (SAST)",
  sca: "Dependencies (SCA)",
  secrets: "Secrets",
  iac: "Infrastructure (IaC)",
  dast: "Dynamic Analysis (DAST)",
};

export interface Location {
  path?: string;
  start_line?: number;
  end_line?: number;
}

export interface RiskFactor {
  name: string;
  delta: number;
  reason: string;
}

export interface RiskAssessment {
  score: number;
  factors?: RiskFactor[];
}

export interface Finding {
  id: string;
  scanner: string;
  rule_id: string;
  aliases?: string[];
  category: Category;
  title: string;
  description?: string;
  severity: Severity;
  location: Location;
  cwe?: string[];
  references?: string[];
  metadata?: Record<string, string>;
  risk: RiskAssessment;
}

export interface PluginRun {
  name: string;
  success: boolean;
  error?: string;
  findings: number;
  duration_ms: number;
}

export interface Report {
  generated_at: string;
  target: string;
  plugins: string[];
  plugin_runs?: PluginRun[];
  findings: Finding[];
}

export interface Summary {
  target: string;
  generated_at: string;
  total: number;
  by_severity: Partial<Record<Severity, number>>;
  by_scanner: Record<string, number>;
  top_risks: Finding[];
}

// Mirrors internal/dashboard.HistoryEntry. FileStore (storage.driver
// != "sqlite") synthesizes a single id-0 entry for the last scan;
// SQLStore returns real history, newest first.
export interface HistoryEntry {
  id: number;
  generated_at: string;
  target: string;
  total: number;
  by_severity: Partial<Record<Severity, number>>;
}

export class NoReportError extends Error {}
export class ApiError extends Error {}

// Set at build/dev time (.env: VITE_API_TOKEN=...) to match the
// bannin serve instance's server.auth_token. Unset when auth is
// disabled server-side (the default for local dev).
const API_TOKEN = import.meta.env.VITE_API_TOKEN as string | undefined;

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: {
      ...(API_TOKEN ? { Authorization: `Bearer ${API_TOKEN}` } : {}),
      ...(init?.headers ?? {}),
    },
  });
  if (res.status === 401) {
    throw new ApiError("dashboard API rejected the request: missing or invalid auth token (set VITE_API_TOKEN)");
  }
  if (res.status === 404) {
    const body = await res.json().catch(() => ({}));
    throw new NoReportError(body.error ?? "no report available");
  }
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new ApiError(body.error ?? `request to ${path} failed: ${res.status}`);
  }
  return res.json();
}

const get = <T>(path: string) => request<T>(path);

export const fetchSummary = () => get<Summary>("/api/v1/summary");
export const fetchReport = () => get<Report>("/api/v1/report");
export const fetchHistory = () => get<HistoryEntry[]>("/api/v1/history");
export const fetchReportById = (id: number) => get<Report>(`/api/v1/reports/${id}`);

// Mirrors api/server's scanJob / scanJobView JSON shape.
export interface ScanJob {
  id: string;
  target: string;
  status: "running" | "done" | "failed";
  error?: string;
  report_id?: number;
  // Rolling tail of live progress lines from the scanner (e.g. ZAP's
  // spider/active-scan phases), newest last. Present while running.
  progress?: string[];
}

// Triggers an on-demand scan (POST /api/v1/scan). plugins is optional —
// the server defaults to ["zap"] for an http(s) target and the usual
// static-analysis set otherwise. Returns immediately with a job to poll
// via fetchScanStatus; the scan itself runs in the background.
export const triggerScan = (target: string, plugins?: string[]) =>
  request<ScanJob>("/api/v1/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target, plugins }),
  });

export const fetchScanStatus = (id: string) => get<ScanJob>(`/api/v1/scans/${id}`);
