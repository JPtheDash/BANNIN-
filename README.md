# BANNIN

Open-source DevSecOps orchestration platform. Runs security scanners
(Semgrep, Trivy, OSV Scanner, Gitleaks, Checkov, ZAP) through a common
plugin interface, normalizes their output into one finding model,
correlates and risk-scores it, and produces unified HTML/JSON/SARIF
reports and a dashboard.

## Status: Milestone 14 — parallel plugin execution

`internal/scheduler` now provides `Map`, a generic order-preserving
worker pool: results[i] always corresponds to items[i] regardless of
completion order, so scan output stays deterministic. `Manager.Scan`
delegates fan-out to it and runs all configured plugins concurrently
(they spend their time waiting on external tool subprocesses).
Cancellation flows through the context — plugins already use
`exec.CommandContext`, so a cancelled scan kills the tool processes.
Alongside this, `runOne` now contains plugin panics: a third-party
plugin that panics becomes its own failed `Result` instead of killing
the process — which unrecovered goroutine panics otherwise would.

Verified with the race detector across the full test suite, and A/B
benchmarked honestly (same binary, same warm tool caches, workers=1 vs
unlimited): a four-plugin scan of `./examples/demo-app` dropped from
9.7s to 5.2s (~1.9x; bounded by the slowest tool, with CPU utilization
rising 37% → 68%). The first naive measurement showed a misleading
"65s → 8.5s" — that was almost entirely tool-cache warm-up, which is
why the A/B was done.

See `docs/architecture.md` for the hexagonal architecture this
skeleton is built toward.

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
- **Concurrency policy lives in `internal/scheduler`, not the Manager** —
  `scheduler.Map` is a generic, order-preserving worker pool;
  `Manager.Scan` delegates fan-out to it and only defines what running
  one plugin means. Results always arrive in input order, so output is
  deterministic despite concurrent execution. `Manager.Resolve` stays a
  separate step from `Manager.Scan` so an unregistered/mistyped plugin
  name is caught before any tool runs, and `runOne` contains plugin
  panics as failed Results (an unrecovered goroutine panic would kill
  the process).
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
- **Reports treat scanner output as hostile input** — `report.html` is
  rendered exclusively through `html/template`'s contextual escaping
  and ships zero JavaScript, because advisory descriptions, rule
  titles, and reference URLs originate from scanned artifacts and
  vulnerability databases. Severity colors never carry meaning alone
  (every badge pairs the color with the severity word), and the file is
  fully self-contained for archiving from CI.
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
  report/                     HTML/JSON/SARIF rendering (HTML + JSON + CLI summary implemented)
  dashboard/                   local web UI backend
  storage/                      SQLite (later Postgres) persistence
  scheduler/                     parallel plugin execution (implemented)
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

## Roadmap

Completed:

- [x] M1 — project skeleton (hexagonal layout, placeholder packages)
- [x] M2 — Cobra CLI (`bannin scan`, `bannin version`, `--config`)
- [x] M3 — config loader (Viper/YAML + validation, `internal/config`)
- [x] M4 — structured logging (Zap, `internal/logging`)
- [x] M5 — plugin port (`pkg/plugin`: `Scanner` interface, `Finding` model)
- [x] M6 — scanner manager (`internal/scanner`: registry + execution)
- [x] M7–M10 — first four plugins: Semgrep, OSV Scanner, Trivy,
      Gitleaks, plus the intentionally-vulnerable `examples/demo-app`
- [x] M11 — findings pipeline (merge → normalize → dedupe → sort;
      CLI summary; `report.json`)
- [x] M12 — policy engine (`fail_on_severity` CI gate, exit codes)
- [x] M13 — self-contained HTML report
- [x] M14 — parallel plugin execution (`internal/scheduler`)

Remaining (proposed order — each one milestone at a time):

- [ ] M15 — scan history: persist each Report to SQLite
      (`internal/storage`; `storage.driver`/`dsn` config is loaded but
      unused today)
- [ ] M16 — correlation v2: reconcile the same advisory across
      identifier schemes (CVE/GHSA/GO-…), normalize finding paths
      relative to the scan target
- [ ] M17 — risk scoring (`internal/risk`): weight findings beyond raw
      severity (reachability, fix availability, exposure)
- [ ] M18 — dashboard backend (`internal/dashboard` + `api/server`
      HTTP adapter over stored scan history)
- [ ] M19 — dashboard frontend (`web/`: React + Vite + Tailwind)
- [ ] M20 — auth (`internal/auth`) for the API/dashboard
- [ ] M21 — Checkov plugin (IaC scanning)
- [ ] M22 — OWASP ZAP plugin (DAST)

Deferred / on request: SARIF export (HTML + JSON cover current needs),
a `scan.concurrency` config knob, per-plugin timeouts, Postgres storage
driver, release/dist tooling. Housekeeping notes: `internal/parser` is
vestigial (parsing lives in each plugin's `Parse`) and should be folded
or removed when convenient; the repo has no LICENSE file yet — pick one
before publicizing.
