"""Unit tests for the IAM policy parser + least-privilege analyser."""
from __future__ import annotations

import json

import pytest

from iam_policy_parser import (
    PolicyFinding,
    analyze_policies,
    analyze_policy,
    parse_policy,
)


def _stmt(**kw):
    stmt = {"Effect": "Allow"}
    stmt.update(kw)
    return {"Version": "2012-10-17", "Statement": [stmt]}


# ---------------------------------------------------------------------------
# parse_policy
# ---------------------------------------------------------------------------

def test_parse_policy_accepts_dict_json_and_bytes():
    doc = {"Version": "2012-10-17", "Statement": []}
    assert parse_policy(doc) == doc
    assert parse_policy(json.dumps(doc)) == doc
    assert parse_policy(json.dumps(doc).encode()) == doc


def test_parse_policy_rejects_bad_input():
    with pytest.raises(TypeError):
        parse_policy(12345)


# ---------------------------------------------------------------------------
# Wildcard actions
# ---------------------------------------------------------------------------

def test_star_action_is_critical():
    findings = analyze_policy(_stmt(Action="*", Resource="*"), "AdminAllTheThings")
    assert any(
        f.severity == "CRITICAL" and "Wildcard action" in f.issue
        for f in findings
    )


def test_service_wide_wildcard_on_sensitive_service_is_high():
    findings = analyze_policy(_stmt(Action="iam:*", Resource="*"), "IamFull")
    assert any(f.severity == "HIGH" and "iam:*" in f.issue for f in findings)


def test_service_wide_wildcard_on_nonsensitive_service_is_ignored():
    findings = analyze_policy(_stmt(Action="cloudwatch:*", Resource="*"), "CW")
    assert not any("cloudwatch:*" in f.issue for f in findings)


# ---------------------------------------------------------------------------
# Wildcard resources
# ---------------------------------------------------------------------------

def test_wildcard_resource_on_sensitive_action_is_flagged():
    findings = analyze_policy(
        _stmt(Action="s3:GetObject", Resource="*"), "s3AllRead"
    )
    assert any(
        f.severity == "HIGH" and "Wildcard resource" in f.issue for f in findings
    )


def test_scoped_resource_is_not_flagged():
    findings = analyze_policy(
        _stmt(
            Action="s3:GetObject",
            Resource="arn:aws:s3:::my-bucket/data/*",
        ),
        "ScopedRead",
    )
    assert findings == []


# ---------------------------------------------------------------------------
# MFA condition
# ---------------------------------------------------------------------------

def test_missing_mfa_condition_on_destructive_action_flagged():
    findings = analyze_policy(
        _stmt(Action="iam:DeleteUser", Resource="arn:aws:iam::123:user/*"),
        "DeleteUsers",
    )
    assert any("without MFA condition" in f.issue for f in findings)


def test_mfa_condition_present_is_accepted():
    stmt = _stmt(
        Action="iam:DeleteUser",
        Resource="arn:aws:iam::123:user/*",
        Condition={"Bool": {"aws:MultiFactorAuthPresent": "true"}},
    )
    findings = analyze_policy(stmt, "DeleteWithMfa")
    assert not any("without MFA condition" in f.issue for f in findings)


# ---------------------------------------------------------------------------
# Open principal
# ---------------------------------------------------------------------------

def test_star_principal_is_critical():
    stmt = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::public/*",
            }
        ],
    }
    findings = analyze_policy(stmt, "PublicBucket")
    assert any(f.severity == "CRITICAL" and "all principals" in f.issue for f in findings)


def test_aws_star_principal_is_critical():
    stmt = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::open/*",
            }
        ],
    }
    findings = analyze_policy(stmt, "AwsStar")
    assert any(f.severity == "CRITICAL" for f in findings)


# ---------------------------------------------------------------------------
# Deny statements
# ---------------------------------------------------------------------------

def test_deny_statements_are_never_flagged():
    stmt = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Deny", "Action": "*", "Resource": "*"},
        ],
    }
    assert analyze_policy(stmt, "GuardRail") == []


# ---------------------------------------------------------------------------
# Bulk analysis
# ---------------------------------------------------------------------------

def test_analyze_policies_aggregates_findings():
    policies = {
        "Bad": _stmt(Action="*", Resource="*"),
        "Good": _stmt(
            Action="s3:GetObject",
            Resource="arn:aws:s3:::scoped-bucket/data/*",
        ),
    }
    findings = analyze_policies(policies)
    assert any(f.policy_name == "Bad" for f in findings)
    assert not any(f.policy_name == "Good" for f in findings)


def test_policy_finding_serializes_to_dict():
    f = PolicyFinding(
        policy_name="p", statement_sid="", severity="HIGH",
        issue="i", remediation="r",
    )
    assert f.to_dict()["severity"] == "HIGH"
