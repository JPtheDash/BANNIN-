# Intentionally vulnerable demo application — the Phase 1 acceptance
# target for `bannin scan ./examples/demo-app`. Every flaw below is
# deliberate; do not "fix" this file. See README.md in this directory.

import os
import sqlite3

# Deliberately fabricated credential (not a real token) so Gitleaks has
# something to detect. gitleaks:allow is NOT set here on purpose — the
# whole point is for the scan to flag it.
SLACK_WEBHOOK = "https://hooks.slack.com/services/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"


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
