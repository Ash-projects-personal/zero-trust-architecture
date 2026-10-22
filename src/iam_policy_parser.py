"""Deterministic IAM policy analyser.

Parses real IAM policy JSON and flags, per statement:
- wildcard action ("*" or a full service wildcard on a sensitive
  service such as iam, s3, ec2)
- wildcard resource ("*")
- a sensitive action allowed with no MFA condition

This is the genuine analysis module the old project buried: it
was real code that the old demo driver never called on any real
input. Here it runs on the fixture policies in data/policies/
and its findings are counted like everything else.
"""

SENSITIVE_SERVICES = {"iam", "s3", "ec2"}
SENSITIVE_ACTIONS = {
    "iam:createuser",
    "iam:attachuserpolicy",
    "iam:attachrolepolicy",
    "s3:deletebucket",
    "ec2:terminateinstances",
}


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _has_mfa_condition(statement):
    condition = statement.get("Condition", {})
    blob = str(condition).lower()
    return "multifactorauthpresent" in blob or "multifactorage" in blob


def analyse_policy(name, document):
    findings = []
    for idx, statement in enumerate(_as_list(document.get("Statement"))):
        if statement.get("Effect") != "Allow":
            continue
        actions = _as_list(statement.get("Action"))
        resources = _as_list(statement.get("Resource"))
        lowered = [a.lower() for a in actions]
        where = "%s statement %d" % (name, idx)

        if any(a == "*" for a in lowered):
            findings.append({"policy": name, "statement": idx,
                             "issue": "wildcard action", "detail": where})
        for action in lowered:
            if action.endswith(":*") and action[:-2] in SENSITIVE_SERVICES:
                findings.append({"policy": name, "statement": idx,
                                 "issue": "service wildcard on sensitive service",
                                 "detail": "%s: %s" % (where, action)})
        if any(r == "*" for r in resources):
            findings.append({"policy": name, "statement": idx,
                             "issue": "wildcard resource", "detail": where})

        touches_sensitive = any(
            a in SENSITIVE_ACTIONS
            or a == "*"
            or (a.endswith(":*") and a[:-2] in SENSITIVE_SERVICES)
            for a in lowered
        )
        if touches_sensitive and not _has_mfa_condition(statement):
            findings.append({"policy": name, "statement": idx,
                             "issue": "sensitive action without MFA condition",
                             "detail": where})
    return findings
