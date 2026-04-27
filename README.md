# vuln-flask-app

Deliberately vulnerable Flask app. Used as ground truth for the AI triage
pipeline — every intentional finding is listed below with its expected
verdict, so you can measure whether the triage is working.

**DO NOT DEPLOY.**

## Seeded findings

| ID  | Location              | Class                            | Expected verdict | Notes |
|-----|-----------------------|----------------------------------|------------------|-------|
| V1  | `app.py` `API_KEY`    | Hardcoded secret                 | `true_positive`  | Obvious. |
| V2  | `app.py` `/login`     | SQL injection (string concat)    | `true_positive`  | High severity. |
| V3  | `app.py` `/login`     | Weak hash (MD5 for passwords)    | `true_positive`  | Medium. |
| V4  | `app.py` `/ping`      | Command injection, `shell=True`  | `true_positive`  | Critical. |
| V5  | `app.py` `/diag`      | Allowlisted exec (weak trap)     | not flagged      | Semgrep's taint analysis correctly ignores this; included for comparison. |
| V6  | `app.py` `/fetch`     | SSRF                             | `true_positive`  | High. |
| V7  | `app.py` `/restore`   | Insecure deserialization (pickle)| `true_positive`  | Critical. |
| V8  | `app.py` `/redirect`  | Open redirect                    | `true_positive`  | Subtle; AI should reason about it even if rule severity is low. |
| V9  | `app.py` `__main__`   | Debug mode enabled               | `true_positive`  | Critical if shipped. |
| V10 | `app.py` `/internal-ping` | **FP-trap** — regex+allowlist gate before `shell=True` | `false_positive` | Taint rule fires because it can't model the guard; AI should reject it. |
| V11 | `utils.py` `run_diagnostic_cmd` | Cross-file reachable command injection | `true_positive` + **reachable** | Sink lives in `utils.py`; Phase 3 should trace the call chain from `/admin/run-diag` (user input) to the sink and confirm exploitability. |
| V12 | `utils.py` `legacy_import_data` | pickle on dead code | `true_positive` + **not reachable** | Function isn't called from anywhere. Phase 3 should downgrade severity to `info`/`low` and recommend deletion rather than flagging as an emergency. |
| D1  | `requirements.txt`    | Flask 2.0.1 / Jinja2 2.11.2 / requests 2.25.0 / Werkzeug 2.0.1 | SCA-`true_positive` | Known CVEs. Picked up by Phase 5. |

## Running Semgrep against it

```bash
pip install semgrep
semgrep --config auto --json app.py > findings.json
```

Expect 6–10 SAST findings depending on the ruleset version. The interesting
test is whether the AI correctly flags V5 as a false positive while keeping
V2, V4, V6, V7 as true positives.

## What would the fixes look like (spoiler)

- V1: move `API_KEY` to env var; rotate it.
- V2: parameterized query: `db().execute("SELECT id FROM users WHERE username = ? AND password = ?", (username, hashed))`.
- V3: `bcrypt`, `argon2-cffi`, or `passlib`.
- V4: drop `shell=True`, pass args as a list, validate `host` against a regex.
- V6: URL allowlist or block RFC1918/link-local ranges.
- V7: switch to JSON; never `pickle.loads` untrusted input.
- V8: validate `target` is a same-origin path.
- V9: gate debug on `FLASK_ENV=development`.

# triggered azure-openai test 1776724675
