# BANNIN

Open-source DevSecOps orchestration platform. Runs security scanners
(Semgrep, Trivy, OSV Scanner, Gitleaks, Checkov, ZAP) through a common
plugin interface, normalizes their output into one finding model,
correlates and risk-scores it, and produces unified HTML/JSON/SARIF
reports and a dashboard.

## Status: Milestone 12 — policy engine (CI gate)

`internal/policy` now evaluates the normalized findings against
`policy.fail_on_severity` from config: `Evaluate` returns a `Decision`
carrying every finding at or above the threshold, and `bannin scan`
prints `Policy: PASS/FAIL` and exits nonzero on violations — making it
usable as a CI quality gate. Setting `fail_on_severity: ""` disables
gating (the default is `high`). An invalid threshold is an error, not a
guess: a misconfigured gate that silently passed (or failed) everything
would defeat the point. One deliberate precedence rule: a plugin that
failed to run outranks a policy verdict — CI must not go green when
part of the scan never happened.

Verified for real: scanning `./examples/demo-app` with the default gate
prints `Policy: FAIL — 20 finding(s) at or above high severity` and
exits 1; a clean directory prints `Policy: PASS` and exits 0; gating
disabled skips the verdict and exits 0. See `docs/architecture.md` for
the hexagonal architecture this skeleton is built toward.

## Architecture decisions (Milestone 1)

- **Module path**: `github.com/jyotidash/bannin`, Go 1.24. Update the
  module path in `go.mod` and all internal import paths once the real
  repo location is known — everything downstream depends on it being
  correct before Milestone 2.
- **Hexagonal layout**: `pkg/plugin` will hold the port (`Scanner`
  interface, `Finding` model); `plugins/*` are driven adapters that
  satisfy it; `cmd/bannin` (CLI) and `api/server` (HTTP) are driving
  adapters; `internal/*` is the framework-agnostic core. Full rationale
  in `docs/architecture.md`.
- **`cmd/bannin`** holds only the binary entrypoint plus its Cobra command
  tree (`root.go`, `version.go`, `scan.go`). It stays free of business
  logic — `scan` just wires config, logging, and `internal/scanner`
  together and reports what happened; the orchestration logic itself
  lives in `internal/`.
- **`internal/`** is unexported-by-design: scanner, parser, policy, risk,
  correlation, report, dashboard, storage, scheduler, config, logging,
  auth, utils. Each is a placeholder package (`doc.go` only) so the tree
  compiles today and gets filled in milestone-by-milestone.
- **`pkg/plugin`** is public (not `internal/`) because third-party plugin
  authors need to import the `Scanner` contract from outside this module.
  `Scanner.Run` returns a `RawResult` (raw bytes + exit code) and
  `Scanner.Parse` turns that into `[]Finding` — execution and
  interpretation are separate steps so each can be tested/retried on its
  own.
- **`plugins/`** is siblings-not-nested to `internal/` on purpose: plugins
  only depend on `pkg/plugin`, never on each other or on internal
  packages. `plugins/semgrep`, `plugins/osv`, and `plugins/trivy` all
  follow this — `cmd/bannin/plugins.go` is the composition root that
  imports the plugin packages and `internal/scanner` to wire them
  together; neither side depends on the other directly.
- **A plugin can produce more than one kind of Finding** —
  `plugins/trivy` covers both dependency vulnerabilities and IaC
  misconfigurations in a single `Scanner`, mapping both onto the same
  `Finding` model rather than needing two separate plugins.
- **Severity mapping is plugin-specific and best-effort** — Semgrep's
  ERROR/WARNING/INFO maps directly; OSV Scanner's advisories are
  inconsistent across ecosystems (some carry a textual
  `database_specific.severity`, some a numeric CVSS score, many (e.g.
  most Go vulndb entries) carry neither), so `plugins/osv` prefers the
  textual severity, falls back to thresholding the CVSS score, and
  defaults to medium rather than guessing wrong in either direction.
- **`api/`, `web/`, `configs/`, `scripts/`, `docs/`, `examples/`,
  `testdata/`, `docker/`, `.github/`, `Makefile`** are all scaffolded now
  per the target project structure, but only as directory placeholders
  (or, for `docker/`, `.github/workflows/ci.yml`, and `Makefile`, plain
  build plumbing with no orchestration logic in it). Populating them with
  real behavior stays milestone-gated — see each directory's own
  `README.md`/`doc.go` for what's deferred and to which milestone.
- **`internal/logging`** wraps Zap behind `New(level, out)`, taking an
  explicit `zapcore.WriteSyncer` (nil defaults to stderr) so callers —
  and tests — can redirect output without touching globals.
- **`internal/scanner.Manager` runs plugins sequentially, on purpose** —
  parallel execution is `internal/scheduler`'s job (a later milestone).
  `Manager.Resolve` is a separate step from `Manager.Scan` so an
  unregistered/mistyped plugin name is caught before any tool runs.
- **Secrets never ride along in findings** — `plugins/gitleaks` always
  invokes the tool with `--redact`, doesn't model the report's
  Secret/Match fields at all, and has a test asserting that even an
  unredacted report fed directly into `Parse` cannot leak a secret
  value into any `Finding` field.
- **One findings pipeline feeds every consumer** — after the plugins
  run, results flow merge (`internal/scanner.Collect`) → severity
  normalization (`plugin.NormalizeFindings`; unrecognized clamps to
  medium) → exact-duplicate removal (`internal/correlation.Dedupe`) →
  deterministic severity sort (`plugin.SortFindings`). Everything
  downstream — the CLI summary, `report.json`, the policy gate, and
  later HTML/SARIF, dashboard, notifications, AI summaries — consumes
  this same normalized `[]Finding`. `Finding`/`Location` carry stable
  snake_case JSON tags; that schema is the exporter contract.
- **Dedupe is deliberately conservative** — it collapses only literal
  duplicates (same rule ID, location, and affected package). The same
  advisory under different identifiers (OSV's `GO-…` vs Trivy's
  `CVE-…`) survives as two findings; alias reconciliation is real
  correlation work, a later milestone.
- **Severity ordering lives on the domain model** — `Severity.Rank()`
  in `pkg/plugin`, because both sorting and the policy gate need it and
  third-party plugin authors should see the same ordering the core
  uses.
- **Policy gating fails loud, not smart** — `internal/policy.Evaluate`
  rejects an invalid threshold instead of guessing, and a plugin that
  failed to run outranks a passing policy verdict (CI must not go green
  when part of the scan never happened).
- **The first four plugins (`semgrep`, `osv`, `trivy`, `gitleaks`) are
  implemented** — `checkov` and `zap` are later milestones. Adding one
  now would violate the "one milestone at a time" build order.

## Layout

```
cmd/bannin/            binary entrypoint (CLI adapter)
internal/
  scanner/               scanner manager (discovery + execution + Collect, implemented)
  parser/                 raw tool output -> intermediate records
  policy/                  pass/fail gating rules (fail_on_severity implemented)
  risk/                     risk scoring
  correlation/               cross-scanner finding correlation (exact dedupe implemented)
  report/                     HTML/JSON/SARIF rendering (JSON + CLI summary implemented)
  dashboard/                   local web UI backend
  storage/                      SQLite (later Postgres) persistence
  scheduler/                     parallel plugin execution
  config/                         Viper/YAML config loader
  logging/                         Zap-backed structured logger
  auth/                             credentials / access control
  utils/                             shared helpers
pkg/
  plugin/                 Scanner interface + Finding model (port, implemented)
plugins/
  semgrep/ osv/ trivy/ gitleaks/ (implemented)  checkov/ zap/ (driven adapters)
api/
  server/                 HTTP API adapter for the dashboard
web/                      React + Vite + Tailwind dashboard frontend
configs/                  example YAML configuration
scripts/                  dev/build/release scripts
docs/                     architecture and design notes
examples/
  demo-app/               vulnerable sample app for `bannin scan` (populated)
testdata/                 shared integration test fixtures
docker/                   Dockerfile(s) for the CLI (and later, tool images)
.github/workflows/        CI (build, vet, test)
Makefile                  build/test/vet/run/clean targets
```

## Build / test

Requires Go 1.24+.

```
go build ./...
go vet ./...
go test ./...
```

Or via `make build`, `make vet`, `make test`.

All three (build, vet, test) pass locally with Go 1.26.5.

```
go run ./cmd/bannin version                                  # bannin dev
go run ./cmd/bannin scan                                     # scans, prints summary + policy verdict, writes report.json; exits 1 on violations
go run ./cmd/bannin scan --config configs/bannin.example.yaml
go run ./cmd/bannin --help
```

Scanning requires the underlying tools on PATH (`brew install semgrep
osv-scanner trivy gitleaks`); a missing tool fails that plugin's health
check cleanly without stopping the others.

## Next milestone

Milestone 13 — HTML report rendering in `internal/report`: a
self-contained `report.html` generated from the same `Report` envelope
`report.json` uses, honoring `"html"` in `report.formats`.
