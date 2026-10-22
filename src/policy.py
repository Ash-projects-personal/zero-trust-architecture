"""Access policy for the demo service.

Zero trust in one paragraph, as implemented here: there is no
trusted network and no session that stays trusted. Every request
carries a token, the token is verified on that request, the
identity must be a known subject, and then this table decides
based on the resource: what role is required, and whether a
managed device is required on top. The decision and its reason
are returned together so the service can log both.

Resource table:
- /public     no identity required
- /profile    any verified known identity
- /admin/data role admin AND a managed device
"""

RESOURCES = {
    "/public": {"role": None, "managed_device": False},
    "/profile": {"role": "user", "managed_device": False},
    "/admin/data": {"role": "admin", "managed_device": True},
}

# Roles imply lower roles for this demo: an admin also satisfies
# a plain user requirement.
ROLE_RANK = {"user": 1, "admin": 2}


def decide(resource, claims, known_subject):
    """claims is None when there is no valid token."""
    rule = RESOURCES.get(resource)
    if rule is None:
        return False, "unknown resource"
    if rule["role"] is None:
        return True, "public resource"
    if claims is None:
        return False, "no valid identity token"
    if not known_subject:
        return False, "identity not recognised"
    have = max((ROLE_RANK.get(r, 0) for r in claims.get("roles", [])), default=0)
    if have < ROLE_RANK[rule["role"]]:
        return False, "role %s required" % rule["role"]
    if rule["managed_device"] and not claims.get("device_managed"):
        return False, "managed device required"
    return True, "identity, role and device checks passed"
