"""
Deliberately vulnerable Flask app used to test the AI triage pipeline.
retest

See README.md for the full inventory of seeded vulnerabilities. Each finding
is labeled in the README as TP (true positive), TP-subtle, or FP-trap.

DO NOT DEPLOY. This is unsafe by design.
"""

import hashlib
import os
import pickle
import re
import sqlite3
import subprocess

import requests
from flask import Flask, request, redirect

from utils import run_diagnostic_cmd

app = Flask(__name__)

# [V1] TP — hardcoded secret checked into source.
API_KEY = "sk_live_51H8aQzJk9Xp0rL2mNvB7cD4fE6gH8i"
app.secret_key = "hunter2-super-secret-do-not-share"


DB_PATH = "users.db"


def db():
    return sqlite3.connect(DB_PATH)


@app.route("/login")
def login():
    """[V2] TP — SQL injection via string concatenation."""
    username = request.args.get("username", "")
    password = request.args.get("password", "")
    # Vulnerable: raw query built by concatenation.
    query = "SELECT id FROM users WHERE username = '" + username + \
            "' AND password = '" + hashlib.md5(password.encode()).hexdigest() + "'"
    # [V3] TP — MD5 used for password hashing (weak crypto) on the line above.
    row = db().execute(query).fetchone()
    return {"ok": bool(row)}


@app.route("/ping")
def ping():
    """[V4] TP — command injection via shell=True with user input."""
    host = request.args.get("host", "localhost")
    # Vulnerable: attacker can pass "localhost; rm -rf /" in `host`.
    output = subprocess.check_output(
        f"ping -c 1 {host}", shell=True, text=True
    )
    return {"output": output}


@app.route("/diag")
def diag():
    """[V5] FP-trap — subprocess with user input BUT strict allowlist.

    Semgrep's regex-based rule for subprocess-with-user-input will flag this.
    The AI triage SHOULD mark it false_positive because `action` can only be
    one of three constant strings before it reaches the subprocess call.
    """
    action = request.args.get("action", "status")
    ALLOWED = {"status", "uptime", "version"}
    if action not in ALLOWED:
        return {"error": "invalid action"}, 400
    # Safe: `action` is constrained to a closed, constant set.
    return {"output": subprocess.check_output(["systemctl", action], text=True)}


HOSTNAME_RE = re.compile(r"^[a-z0-9-]+\.internal$")
INTERNAL_HOSTS = {"api.internal", "cache.internal", "db.internal"}


@app.route("/internal-ping")
def internal_ping():
    """[V10] FP-trap (stronger) — user input flows into subprocess with
    shell=True, which Semgrep's taint rule WILL flag. But the value is
    gated by both a strict regex AND an allowlist, so no attacker-controlled
    value ever reaches the sink. The AI should recognize this and mark it
    false_positive.
    """
    host = request.args.get("host", "api.internal")
    if not HOSTNAME_RE.match(host) or host not in INTERNAL_HOSTS:
        return {"error": "invalid host"}, 400
    # Taint analysis can't model the regex + set check, so Semgrep still
    # sees request.args -> shell=True and fires. It's a false positive.
    return {"output": subprocess.check_output(
        f"ping -c 1 {host}", shell=True, text=True
    )}


@app.route("/fetch")
def fetch():
    """[V6] TP — SSRF: fetching an arbitrary user-supplied URL with no
    allowlist, no scheme check, and no IP/hostname validation.
    """
    url = request.args.get("url")
    r = requests.get(url, timeout=5)
    return {"status": r.status_code, "body": r.text[:500]}


@app.route("/admin/run-diag")
def admin_run_diag():
    """[V11] TP, reachable cross-file. The sink is in utils.py but user
    input flows here from the public HTTP surface, so reachability analysis
    should confirm the finding as exploitable.
    """
    cmd = request.args.get("cmd", "uptime")
    return {"output": run_diagnostic_cmd(cmd)}


@app.route("/restore", methods=["POST"])
def restore():
    """[V7] TP — insecure deserialization of untrusted bytes via pickle."""
    blob = request.get_data()
    state = pickle.loads(blob)  # trivially RCE if attacker controls body.
    return {"restored": list(state.keys()) if isinstance(state, dict) else "ok"}


@app.route("/redirect")
def open_redirect():
    """[V8] TP-subtle — open redirect. Flask's redirect doesn't validate the
    target; phishers love this one. Semgrep may or may not flag depending on
    ruleset; AI should reason about it anyway.
    """
    target = request.args.get("next", "/")
    return redirect(target)


@app.route("/greet")
def greet():
    """Safe endpoint used to show the AI doesn't just rubber-stamp everything
    as vulnerable. Should produce no findings.
    """
    name = request.args.get("name", "friend")
    # Escaped by Flask's default Jinja auto-escape if we rendered; here we
    # return JSON so there's no XSS surface.
    return {"message": f"Hello, {name[:50]}"}


if __name__ == "__main__":
    # [V9] TP — debug=True in production is RCE via the Werkzeug debugger.
    app.run(host="0.0.0.0", port=5000, debug=True)


_TEST_D_ALLOWED = {"status", "uptime", "version"}
_TEST_D_RE = re.compile(r"^[a-z]+$")

@app.route("/test-d")
def test_d():
    action = request.args.get("action", "status")
    # Both guards must pass — regex + closed allowlist. Taint analysis
    # can't model this; AI should recognize it.
    if not _TEST_D_RE.match(action) or action not in _TEST_D_ALLOWED:
        return {"error": "invalid"}, 400
    return {"output": subprocess.check_output(
        f"systemctl {action}", shell=True, text=True
    )}
