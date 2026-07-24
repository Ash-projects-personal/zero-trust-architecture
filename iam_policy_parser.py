"""
IAM policy parser + least-privilege analyser.

Parses AWS IAM policy documents (JSON) and returns structured Findings for
common Zero-Trust anti-patterns: wildcard actions, wildcard resources on
sensitive services, missing MFA conditions, and open cross-account trust
policies. This is the deterministic surface backing the audit report the
simulator in ``zt_audit.py`` produces.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


SENSITIVE_SERVICES = {"iam", "kms", "s3", "secretsmanager", "sts", "organizations"}
SENSITIVE_ACTIONS_REQUIRING_MFA = {
    "iam:DeleteUser",
    "iam:DeleteRole",
    "iam:DeleteAccessKey",
    "iam:PutUserPolicy",
    "iam:AttachUserPolicy",
    "kms:ScheduleKeyDeletion",
    "s3:DeleteBucket",
}


@dataclass
class PolicyFinding:
    policy_name: str
    statement_sid: str
    severity: str  # LOW | MEDIUM | HIGH | CRITICAL
    issue: str
    remediation: str

    def to_dict(self):
        return asdict(self)


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def parse_policy(document):
    """Parse a policy from a dict, a JSON string, or a Path. Returns a dict."""
    if isinstance(document, (str, bytes)):
        return json.loads(document)
    if isinstance(document, Path):
        return json.loads(document.read_text())
    if isinstance(document, dict):
        return document
    raise TypeError(f"Unsupported policy input: {type(document).__name__}")


def analyze_policy(document, policy_name="<inline>"):
    """Return a list of ``PolicyFinding`` for a single IAM policy."""
    doc = parse_policy(document)
    findings = []
    for stmt in _as_list(doc.get("Statement")):
        sid = stmt.get("Sid", "")
        effect = stmt.get("Effect", "")
        if effect != "Allow":
            continue

        actions = [a for a in _as_list(stmt.get("Action"))]
        resources = [r for r in _as_list(stmt.get("Resource"))]
        condition = stmt.get("Condition") or {}

        # 1. Fully-wildcarded action
        if "*" in actions:
            findings.append(
                PolicyFinding(
                    policy_name=policy_name,
                    statement_sid=sid,
                    severity="CRITICAL",
                    issue="Wildcard action '*' grants full API access",
                    remediation="Replace '*' with the specific actions the principal needs.",
                )
            )
        else:
            # 1a. Service-wide wildcard on sensitive service (e.g. iam:*)
            for act in actions:
                if ":" in act and act.split(":", 1)[1] == "*":
                    svc = act.split(":", 1)[0].lower()
                    if svc in SENSITIVE_SERVICES:
                        findings.append(
                            PolicyFinding(
                                policy_name=policy_name,
                                statement_sid=sid,
                                severity="HIGH",
                                issue=f"Service-wide wildcard '{act}' on sensitive service '{svc}'",
                                remediation=(
                                    f"List the specific {svc} actions required "
                                    "instead of granting the whole service."
                                ),
                            )
                        )

        # 2. Wildcard resource on sensitive action
        if resources == ["*"] and actions and actions != ["*"]:
            for act in actions:
                svc = act.split(":", 1)[0].lower() if ":" in act else ""
                if svc in SENSITIVE_SERVICES:
                    findings.append(
                        PolicyFinding(
                            policy_name=policy_name,
                            statement_sid=sid,
                            severity="HIGH",
                            issue=f"Wildcard resource '*' on sensitive action '{act}'",
                            remediation="Scope the Resource to specific ARNs.",
                        )
                    )
                    break

        # 3. Missing MFA condition on destructive/sensitive actions
        has_mfa = "aws:MultiFactorAuthPresent" in json.dumps(condition)
        if not has_mfa:
            for act in actions:
                if act in SENSITIVE_ACTIONS_REQUIRING_MFA:
                    findings.append(
                        PolicyFinding(
                            policy_name=policy_name,
                            statement_sid=sid,
                            severity="MEDIUM",
                            issue=f"'{act}' allowed without MFA condition",
                            remediation="Add Condition: {Bool: {aws:MultiFactorAuthPresent: 'true'}}",
                        )
                    )

        # 4. Open cross-account trust (Principal: '*')
        principal = stmt.get("Principal")
        if principal == "*" or (
            isinstance(principal, dict) and principal.get("AWS") == "*"
        ):
            findings.append(
                PolicyFinding(
                    policy_name=policy_name,
                    statement_sid=sid,
                    severity="CRITICAL",
                    issue="Statement allows all principals ('*') — anonymous access",
                    remediation="Restrict Principal to specific account/role ARNs.",
                )
            )

    return findings


def analyze_policies(policies):
    """Analyse a mapping of ``{policy_name: policy_document}``."""
    all_findings = []
    for name, doc in policies.items():
        all_findings.extend(analyze_policy(doc, policy_name=name))
    return all_findings
