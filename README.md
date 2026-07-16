# BANNIN

Open-source DevSecOps orchestration platform. Runs security scanners
(Semgrep, Trivy, OSV Scanner, Gitleaks, Checkov, ZAP) through a common
plugin interface, normalizes their output into one finding model,
correlates and risk-scores it, and produces unified HTML/JSON/SARIF
reports and a dashboard.

## Status: Milestone 17 — risk scoring

Reports are now prioritized work lists, not severity dumps.
`internal/risk.Assess` gives every finding a 0–100 score built from
signals the pipeline already carries: a severity baseline (critical 90
/ high 70 / medium 50 / low 30 / info 10) adjusted by cross-scanner
corroboration (+10, from M16's `also_reported_by`), exposed secrets
(+15 — a leaked credential needs no exploit), runtime-confirmed DAST
findings (+10, a URL location means reachability was observed, not
assumed), fix availability (+5, an upgrade path exists), and
test/example/vendored paths (−15, matched as whole segments so
`demo-app` never counts as `demo`).

The score is never a black box: it is exactly the sum of its factors,
each shipped with the finding as `risk.factors` (name, delta, reason)
in `report.json` and rendered inline in the HTML ("critical severity
baseline (+90) · independently reported by trivy (+10) · …"). It is a
prioritization aid layered on top of severity — no reachability
analysis or exploit-intelligence feeds are involved, and severity
remains the dominant signal by construction.

`report.New` wraps each finding with its assessment (an additive JSON
schema change: entries gain a `risk` object) and orders findings
highest score first; ties keep the pipeline's deterministic severity
sort. The CLI summary gained a "Top risks" section, and the HTML
report shows the score beside each finding. The policy gate still
operates on severity, unchanged. `plugin.Finding` itself is untouched
— risk is computed downstream, exactly the consumer M11 designed the
normalized collection for.

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
  medium) → path normalization (`correlation.NormalizePaths`; before
  the correlation passes, which compare locations literally) →
  exact-duplicate removal (`correlation.Dedupe`) → alias
  reconciliation (`correlation.ReconcileAliases`) → deterministic
  severity sort (`plugin.SortFindings`). Everything downstream — the
  CLI summary, `report.json`, the policy gate, and later dashboard,
  notifications, AI summaries — consumes this same normalized
  `[]Finding`. `Finding`/`Location` carry stable snake_case JSON tags;
  that schema is the exporter contract.
- **Correlation merges on evidence, never heuristics** — `Dedupe`
  collapses only literal duplicates (same rule ID, location, affected
  package). `ReconcileAliases` merges the same advisory under different
  identifier schemes (OSV's `GHSA-`/`PYSEC-`/`GO-…` vs Trivy's `CVE-…`)
  only when the databases' own alias lists link them, and only within
  the same package, version, and location. A merged finding keeps the
  most severe member's severity (scanners disagreeing is a reason to
  err louder, not quieter) and records agreement in
  `also_reported_by`.
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
- **All six planned plugins are implemented** — `semgrep`, `osv`,
  `trivy`, `gitleaks` run in the default `scan.plugins`; `checkov` and
  `zap` are opt-in (a default scan must not fail for users without
  checkov installed, and zap needs a running app's URL as its target
  rather than a directory).

## Layout

```
cmd/bannin/            binary entrypoint (CLI adapter)
internal/
  scanner/               scanner manager (discovery + execution + Collect, implemented)
  parser/                 raw tool output -> intermediate records
  policy/                  pass/fail gating rules (fail_on_severity implemented)
  risk/                     risk scoring
  correlation/               path normalization, exact dedupe, alias reconciliation
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
  semgrep/ osv/ trivy/ gitleaks/ checkov/ zap/   (all six implemented)
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
- [x] M21 — Checkov plugin (IaC scanning; opt-in via `scan.plugins`)
- [x] M22 — OWASP ZAP plugin (DAST; opt-in, takes a URL target —
      live verification pending a machine with ZAP or Docker)
- [x] M16 — correlation v2: alias reconciliation across identifier
      schemes (CVE/GHSA/PYSEC/GO-…) and finding paths normalized
      relative to the scan target
- [x] M17 — risk scoring (`internal/risk`): explainable 0–100 score
      per finding; reports and CLI summary are risk-ordered

Remaining (in the order they'll be built — M15 deliberately last):

- [ ] M18 — dashboard backend (`internal/dashboard` + `api/server`
      HTTP adapter)
- [ ] M19 — dashboard frontend (`web/`: React + Vite + Tailwind)
- [ ] M20 — auth (`internal/auth`) for the API/dashboard
- [ ] M15 — scan history: persist each Report to SQLite
      (`internal/storage`; `storage.driver`/`dsn` config is loaded but
      unused today)

Deferred / on request: SARIF export (HTML + JSON cover current needs),
a `scan.concurrency` config knob, per-plugin timeouts, Postgres storage
driver, release/dist tooling. Housekeeping notes: `internal/parser` is
vestigial (parsing lives in each plugin's `Parse`) and should be folded
or removed when convenient; the repo has no LICENSE file yet — pick one
before publicizing.
