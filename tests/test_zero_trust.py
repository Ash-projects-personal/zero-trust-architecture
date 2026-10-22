import json
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from iam_policy_parser import analyse_policy  # noqa: E402
from policy import decide  # noqa: E402
from tokens import TokenError, mint_token, verify_token  # noqa: E402

SECRET = "test-secret"


def test_token_roundtrip():
    token = mint_token(SECRET, "alice", ["user"], True)
    claims = verify_token(SECRET, token)
    assert claims["sub"] == "alice"
    assert claims["device_managed"] is True


def test_token_tamper_rejected():
    token = mint_token(SECRET, "alice", ["user"], True)
    head, payload, sig = token.split(".")
    bad = "%s.%s.%s" % (head, ("A" if payload[0] != "A" else "B") + payload[1:], sig)
    with pytest.raises(TokenError):
        verify_token(SECRET, bad)


def test_token_expiry_rejected():
    now = int(time.time())
    token = mint_token(SECRET, "alice", ["user"], True, expires_in_seconds=-5, now=now)
    with pytest.raises(TokenError):
        verify_token(SECRET, token, now=now)


def test_policy_matrix():
    user = {"roles": ["user"], "device_managed": True}
    admin_unmanaged = {"roles": ["admin"], "device_managed": False}
    assert decide("/public", None, False)[0] is True
    assert decide("/profile", None, False)[0] is False
    assert decide("/profile", user, True)[0] is True
    assert decide("/profile", user, False)[0] is False
    assert decide("/admin/data", user, True)[0] is False
    assert decide("/admin/data", admin_unmanaged, True)[0] is False
    admin_managed = {"roles": ["admin"], "device_managed": True}
    assert decide("/admin/data", admin_managed, True)[0] is True


def test_iam_parser_counts():
    root = os.path.join(os.path.dirname(__file__), "..", "data", "policies")
    counts = {}
    for name in sorted(os.listdir(root)):
        if name.endswith(".json"):
            doc = json.load(open(os.path.join(root, name)))
            counts[name] = len(analyse_policy(name, doc))
    assert counts["policy_readonly.json"] == 0
    assert counts["policy_admin_wildcard.json"] == 3
    assert counts["policy_dev.json"] == 3


def test_metrics_match_demo_results():
    out = os.path.join(os.path.dirname(__file__), "..", "outputs")
    metrics = json.load(open(os.path.join(out, "metrics.json")))
    results = json.load(open(os.path.join(out, "demo_results.json")))
    assert metrics["requests_made"] == len(results["requests"])
    assert metrics["iam_findings_total"] == len(results["iam_findings"])
