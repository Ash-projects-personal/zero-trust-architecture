"""Run the zero trust demo end to end and score the decisions.

Starts the protected service, fires 10 real HTTP requests with
different identities (valid, expired, tampered, unknown, missing,
under privileged, unmanaged device), reads the access log the
service actually wrote, and compares every decision with the
expected one recorded here before the run.

Also runs the IAM policy analyser over the fixture policies in
data/policies/ and counts its findings.

Writes outputs/metrics.json, outputs/demo_results.json,
outputs/access_log.jsonl (written by the service itself) and
outputs/run_log.txt.
"""
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

from iam_policy_parser import analyse_policy  # noqa: E402
from service import SECRET  # noqa: E402
from tokens import mint_token  # noqa: E402

BASE = "http://127.0.0.1:5557"
OUT = os.path.join(ROOT, "outputs")
LOG_PATH = os.path.join(OUT, "access_log.jsonl")


def tamper(token):
    head, payload, sig = token.split(".")
    flipped = ("A" if payload[0] != "A" else "B") + payload[1:]
    return "%s.%s.%s" % (head, flipped, sig)


def build_requests():
    now = int(time.time())
    alice = mint_token(SECRET, "alice", ["user"], True, now=now)
    admin_managed = mint_token(SECRET, "admin1", ["admin", "user"], True, now=now)
    admin_unmanaged = mint_token(SECRET, "admin1", ["admin", "user"], False, now=now)
    expired = mint_token(SECRET, "alice", ["user"], True, expires_in_seconds=-60, now=now)
    stranger = mint_token(SECRET, "mallory", ["user"], True, now=now)
    return [
        {"label": "no token, public page", "path": "/public", "token": None, "expected": "ALLOW"},
        {"label": "no token, profile", "path": "/profile", "token": None, "expected": "DENY"},
        {"label": "alice, profile", "path": "/profile", "token": alice, "expected": "ALLOW"},
        {"label": "alice, admin data", "path": "/admin/data", "token": alice, "expected": "DENY"},
        {"label": "admin on managed device, admin data", "path": "/admin/data", "token": admin_managed, "expected": "ALLOW"},
        {"label": "admin on unmanaged device, admin data", "path": "/admin/data", "token": admin_unmanaged, "expected": "DENY"},
        {"label": "expired alice token, profile", "path": "/profile", "token": expired, "expected": "DENY"},
        {"label": "tampered alice token, profile", "path": "/profile", "token": tamper(alice), "expected": "DENY"},
        {"label": "unknown subject token, profile", "path": "/profile", "token": stranger, "expected": "DENY"},
        {"label": "alice, public page", "path": "/public", "token": alice, "expected": "ALLOW"},
    ]


def wait_for_service(proc, timeout=20):
    start = time.time()
    while time.time() - start < timeout:
        if proc.poll() is not None:
            raise RuntimeError("service exited early")
        try:
            if requests.get(BASE + "/public", timeout=2).status_code in (200, 401, 403):
                return
        except requests.RequestException:
            pass
        time.sleep(0.3)
    raise RuntimeError("service did not come up")


def main():
    os.makedirs(OUT, exist_ok=True)
    if os.path.exists(LOG_PATH):
        os.remove(LOG_PATH)
    stamp = datetime.now(timezone.utc).isoformat()

    # IAM analyser first (pure file work).
    policies_dir = os.path.join(ROOT, "data", "policies")
    iam_findings = []
    per_policy = {}
    for name in sorted(os.listdir(policies_dir)):
        if name.endswith(".json"):
            doc = json.load(open(os.path.join(policies_dir, name)))
            found = analyse_policy(name, doc)
            per_policy[name] = len(found)
            iam_findings.extend(found)

    proc = subprocess.Popen(
        [sys.executable, os.path.join(HERE, "service.py")],
        env={**os.environ, "ACCESS_LOG": LOG_PATH},
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    results = []
    try:
        wait_for_service(proc)
        # The readiness probe above hits /public once, logged like
        # any request. Reset the log so the scored set is exact.
        if os.path.exists(LOG_PATH):
            os.remove(LOG_PATH)
        for case in build_requests():
            headers = {}
            if case["token"]:
                headers["Authorization"] = "Bearer %s" % case["token"]
            resp = requests.get(BASE + case["path"], headers=headers, timeout=10)
            got = "ALLOW" if resp.status_code == 200 else "DENY"
            results.append({**case, "token": "present" if case["token"] else "absent",
                            "http_status": resp.status_code, "decision": got,
                            "match": got == case["expected"]})
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    time.sleep(0.2)
    log_lines = []
    if os.path.exists(LOG_PATH):
        log_lines = [json.loads(line) for line in open(LOG_PATH) if line.strip()]
    log_matches = all(
        entry["decision"] == result["decision"]
        for entry, result in zip(log_lines, results)
    ) and len(log_lines) == len(results)

    allowed = sum(1 for r in results if r["decision"] == "ALLOW")
    matched = sum(1 for r in results if r["match"])
    metrics = {
        "demo": "local Flask service on 127.0.0.1, requests made by this script, decisions read back from the service access log",
        "requests_made": len(results),
        "allowed": allowed,
        "denied": len(results) - allowed,
        "decisions_matching_expected": matched,
        "decision_agreement_rate": round(matched / len(results), 3) if results else 0.0,
        "access_log_lines": len(log_lines),
        "access_log_matches_responses": log_matches,
        "iam_policies_analysed": len(per_policy),
        "iam_findings_total": len(iam_findings),
        "iam_findings_per_policy": per_policy,
        "run_at": stamp,
    }
    with open(os.path.join(OUT, "metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2)
    with open(os.path.join(OUT, "demo_results.json"), "w") as f:
        json.dump({"requests": results, "iam_findings": iam_findings}, f, indent=2)

    log = ["zero trust rebuild run at %s" % stamp]
    for r in results:
        log.append("%-42s %-12s expected %-5s got %-5s HTTP %s %s"
                   % (r["label"], r["path"], r["expected"], r["decision"],
                      r["http_status"], "ok" if r["match"] else "MISMATCH"))
    log.append("allowed %d denied %d, matched %d/%d, access log lines %d"
               % (allowed, len(results) - allowed, matched, len(results), len(log_lines)))
    log.append("IAM analyser: %d policies, %d findings %s"
               % (len(per_policy), len(iam_findings), per_policy))
    with open(os.path.join(OUT, "run_log.txt"), "w") as f:
        f.write("\n".join(log) + "\n")
    print("\n".join(log))


if __name__ == "__main__":
    main()
