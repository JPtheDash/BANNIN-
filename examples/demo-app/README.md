# examples/demo-app/

An intentionally-vulnerable sample application — the Phase 1 acceptance
test target:

    bannin scan ./examples/demo-app

Every flaw here is deliberate bait for a specific plugin. Do not fix
any of it:

- `app.py` — `eval()` on user input, string-formatted SQL, shell
  command injection (Semgrep), plus a fabricated Slack webhook URL
  (Gitleaks; not a real credential).
- `requirements.txt` — old pins with known CVEs (OSV Scanner and
  Trivy's vulnerability scanner).
- `Dockerfile` — `:latest` base image, runs as root, no HEALTHCHECK
  (Trivy's misconfig scanner).

Because this directory lives inside the BANNIN repo, a scan of the
repo root surfaces these findings too (from every plugin, not just
Gitleaks). That's expected and deliberate: suppressing them at the
repo root would also suppress them when scanning this directory
directly, since Gitleaks fingerprints are resolved relative to the
working directory, not the scan target — which would defeat the
purpose of the demo.
