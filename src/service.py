"""The protected service.

Three resources with three trust levels (see policy.py). Every
request, allowed or denied, appends one line to the access log
with the subject (or anonymous), the resource, the decision, and
the reason. That log is the audit trail the demo produces, and
run_demo.py scores the decisions written into it.
"""
import json
import os
from datetime import datetime, timezone

from flask import Flask, request, jsonify

from policy import decide
from tokens import verify_token, TokenError

USERS = {
    "alice": {"roles": ["user"]},
    "admin1": {"roles": ["admin", "user"]},
}

SECRET = os.environ.get("DEMO_SECRET", "local-demo-secret-not-a-real-credential")


def create_app(log_path):
    app = Flask(__name__)

    def log(subject, resource, allowed, reason):
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "subject": subject,
            "resource": resource,
            "decision": "ALLOW" if allowed else "DENY",
            "reason": reason,
        }
        with open(log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def handle(resource):
        claims = None
        subject = "anonymous"
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            try:
                claims = verify_token(SECRET, auth[len("Bearer "):])
                subject = claims.get("sub", "unknown")
            except TokenError as exc:
                allowed, reason = decide(resource, None, False)
                log(subject, resource, False, "token rejected: %s" % exc)
                return jsonify({"error": "unauthorized", "reason": str(exc)}), 401
        known = subject in USERS
        allowed, reason = decide(resource, claims, known)
        log(subject, resource, allowed, reason)
        if not allowed:
            status = 401 if claims is None else 403
            return jsonify({"error": "denied", "reason": reason}), status
        return jsonify({"resource": resource, "served_to": subject}), 200

    @app.route("/public")
    def public():
        return handle("/public")

    @app.route("/profile")
    def profile():
        return handle("/profile")

    @app.route("/admin/data")
    def admin_data():
        return handle("/admin/data")

    return app


if __name__ == "__main__":
    create_app(os.environ.get("ACCESS_LOG", "outputs/access_log.jsonl")).run(
        host="127.0.0.1", port=5557
    )
