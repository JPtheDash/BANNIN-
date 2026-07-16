# BANNIN architecture

## Style

Hexagonal architecture (ports & adapters), with domain-driven boundaries
between orchestration concerns. SOLID and dependency injection throughout:
packages depend on interfaces they define or receive, never on concrete
implementations from sibling packages.

## Ports vs adapters, concretely

- **Port**: `pkg/plugin.Scanner` — the contract the orchestrator
  (`internal/scanner`) is written against.
- **Adapters (driven side)**: `plugins/*` — Semgrep, OSV, Trivy, Gitleaks,
  Checkov, ZAP. Each is a real external tool wrapped to satisfy the
  `Scanner` port, depending only on `pkg/plugin` and the standard
  library — never on `internal/`. The orchestrator (`internal/scanner`)
  never imports a plugin package directly either; `cmd/bannin`, as the
  composition root, imports both and calls `Registry.Register` to wire
  them together.
- **Adapters (driving side)**: `cmd/bannin` (CLI, via Cobra) and
  `api/server` (HTTP, for the dashboard) — both are entry points that
  call into `internal/` use cases, never the other way around.
- **Domain/use-case core**: `internal/scanner`, `internal/parser`,
  `internal/correlation`, `internal/risk`, `internal/policy`,
  `internal/report` — the actual orchestration logic, framework-agnostic.
- **Infrastructure adapters**: `internal/storage` (SQLite now, Postgres
  later, behind a repository interface), `internal/logging` (Zap),
  `internal/config` (Viper/YAML).

## Why pkg/ vs internal/

`pkg/` holds the small, stable, public surface (`plugin.Scanner`,
`plugin.Finding`) that external plugin authors are meant to import.
Everything else stays in `internal/` so it can be freely refactored
without breaking anyone importing this module as a library.

## Build order

See the root README's "Next milestone" note and the milestone list in
project history. Architecture decisions above should not be read as
"already implemented" — `pkg/plugin` (the port, Milestone 5) and
`internal/scanner` (the manager driving it, Milestone 6) are real, but
no `plugins/*` adapter exists yet, and `api/` and `web/` are still
directory placeholders.
