# Intentionally vulnerable demo application — the Phase 1 acceptance
# target for `bannin scan ./examples/demo-app`. Every flaw below is
# deliberate; do not "fix" this file. See README.md in this directory.

import os
import sqlite3

# Deliberately fabricated credential so Gitleaks has something to
# detect. gitleaks:allow is NOT set here on purpose — the whole point
# is for the scan to flag it. This trips gitleaks' generic-api-key
# rule (keyword + entropy heuristic, verified locally) rather than a
# vendor-specific format — a vendor-shaped fake (Slack webhook, GitHub
# PAT, Stripe key, ...) matches the same regex GitHub's push protection
# scans for, secret or not, and gets the push blocked regardless of the
# value being fake.
DEMO_SERVICE_TOKEN = "4f8d9a2b7c1e6f3a0d5b8c2e7f1a4d9b6c3e0f8a2d5b7c1e"


def run_expression(user_input):
    # Semgrep: eval() on user-controlled input (code injection).
    return eval(user_input)


def get_user(conn: sqlite3.Connection, username: str):
    # Semgrep: SQL built by string formatting (SQL injection).
    query = "SELECT * FROM users WHERE name = '%s'" % username
    return conn.execute(query).fetchall()


def fetch_report(url: str):
    # Semgrep: shell command built from unsanitized input.
    os.system("curl " + url)
