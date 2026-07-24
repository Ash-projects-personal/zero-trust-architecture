"""
Security-group violation detector.

Consumes EC2-shaped SecurityGroup dicts (as returned by
``describe_security_groups``) and reports Zero-Trust violations: sensitive
ports open to the world, wide port ranges, all-protocol allows, and
same-VPC "allow everything" rules that break micro-segmentation.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict


SENSITIVE_PORTS = {
    22: "SSH",
    23: "Telnet",
    3306: "MySQL",
    3389: "RDP",
    5432: "Postgres",
    6379: "Redis",
    9200: "Elasticsearch",
    27017: "MongoDB",
}
WORLD_CIDRS = {"0.0.0.0/0", "::/0"}


@dataclass
class SgFinding:
    group_id: str
    severity: str
    issue: str
    remediation: str

    def to_dict(self):
        return asdict(self)


def _port_range(perm):
    """Return (from_port, to_port) or (None, None) for all-protocol rules."""
    return perm.get("FromPort"), perm.get("ToPort")


def _has_world_ingress(perm):
    for r in perm.get("IpRanges", []):
        if r.get("CidrIp") in WORLD_CIDRS:
            return True
    for r in perm.get("Ipv6Ranges", []):
        if r.get("CidrIpv6") in WORLD_CIDRS:
            return True
    return False


def analyze_security_group(sg):
    """Return a list of Findings for a single SG dict."""
    findings = []
    gid = sg.get("GroupId", "<unknown>")
    for perm in sg.get("IpPermissions", []):
        proto = perm.get("IpProtocol")
        from_p, to_p = _port_range(perm)
        world = _has_world_ingress(perm)

        # All-protocol allow to world
        if proto == "-1" and world:
            findings.append(
                SgFinding(
                    group_id=gid,
                    severity="CRITICAL",
                    issue="All-protocol ingress (0-65535) allowed from 0.0.0.0/0",
                    remediation="Delete rule; use specific per-service SGs instead.",
                )
            )
            continue

        # Wide port range to world (100+ ports)
        if world and from_p is not None and to_p is not None and (to_p - from_p) >= 100:
            findings.append(
                SgFinding(
                    group_id=gid,
                    severity="HIGH",
                    issue=f"Wide port range {from_p}-{to_p} exposed to 0.0.0.0/0",
                    remediation="Restrict to individual ports required.",
                )
            )
            continue

        # Sensitive single-port world exposure
        if world and from_p is not None and to_p is not None:
            for port, name in SENSITIVE_PORTS.items():
                if from_p <= port <= to_p:
                    findings.append(
                        SgFinding(
                            group_id=gid,
                            severity="CRITICAL",
                            issue=f"{name} (port {port}) exposed to 0.0.0.0/0",
                            remediation=(
                                f"Restrict {name} to specific CIDRs or "
                                "an internal security-group reference."
                            ),
                        )
                    )
                    break

        # Same-VPC "allow everything" via group ref with all protocols
        if proto == "-1" and perm.get("UserIdGroupPairs"):
            findings.append(
                SgFinding(
                    group_id=gid,
                    severity="MEDIUM",
                    issue="All-protocol allowed between security groups (flat trust)",
                    remediation="Use per-port group references for micro-segmentation.",
                )
            )

    return findings


def analyze_security_groups(sgs):
    """Analyse a list of SG dicts and return every finding."""
    out = []
    for sg in sgs:
        out.extend(analyze_security_group(sg))
    return out
