"""Unit tests for the security-group violation detector."""
from __future__ import annotations

import pytest

from sg_analyzer import (
    SENSITIVE_PORTS,
    SgFinding,
    analyze_security_group,
    analyze_security_groups,
)


def _sg(group_id, permissions):
    return {"GroupId": group_id, "IpPermissions": permissions}


# ---------------------------------------------------------------------------
# Sensitive port exposure
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("port,name", list(SENSITIVE_PORTS.items()))
def test_every_sensitive_port_exposed_to_world_is_critical(port, name):
    sg = _sg("sg-1", [
        {
            "IpProtocol": "tcp",
            "FromPort": port,
            "ToPort": port,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }
    ])
    findings = analyze_security_group(sg)
    assert findings, f"{name} on {port} should be flagged"
    assert any(f.severity == "CRITICAL" and str(port) in f.issue for f in findings)


def test_sensitive_port_restricted_to_internal_cidr_is_ok():
    sg = _sg("sg-2", [
        {
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
        }
    ])
    assert analyze_security_group(sg) == []


def test_ipv6_world_ingress_also_flagged():
    sg = _sg("sg-3", [
        {
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": [],
            "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
        }
    ])
    findings = analyze_security_group(sg)
    assert any(f.severity == "CRITICAL" for f in findings)


# ---------------------------------------------------------------------------
# Wide port ranges
# ---------------------------------------------------------------------------

def test_wide_port_range_to_world_is_high():
    sg = _sg("sg-4", [
        {
            "IpProtocol": "tcp",
            "FromPort": 1000,
            "ToPort": 2000,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }
    ])
    findings = analyze_security_group(sg)
    assert any(f.severity == "HIGH" and "1000-2000" in f.issue for f in findings)


# ---------------------------------------------------------------------------
# All-protocol
# ---------------------------------------------------------------------------

def test_all_protocol_from_world_is_critical():
    sg = _sg("sg-5", [
        {
            "IpProtocol": "-1",
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }
    ])
    findings = analyze_security_group(sg)
    assert any(f.severity == "CRITICAL" and "All-protocol" in f.issue for f in findings)


def test_all_protocol_between_groups_is_medium():
    sg = _sg("sg-6", [
        {
            "IpProtocol": "-1",
            "IpRanges": [],
            "UserIdGroupPairs": [{"GroupId": "sg-7"}],
        }
    ])
    findings = analyze_security_group(sg)
    assert any(f.severity == "MEDIUM" and "flat trust" in f.issue for f in findings)


# ---------------------------------------------------------------------------
# Clean cases
# ---------------------------------------------------------------------------

def test_no_permissions_no_findings():
    assert analyze_security_group(_sg("sg-empty", [])) == []


def test_http_80_open_to_world_is_not_flagged():
    """Port 80 isn't in SENSITIVE_PORTS — public web is legitimate."""
    sg = _sg("sg-web", [
        {
            "IpProtocol": "tcp",
            "FromPort": 80,
            "ToPort": 80,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }
    ])
    assert analyze_security_group(sg) == []


def test_analyze_security_groups_aggregates():
    sgs = [
        _sg("sg-bad", [
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
             "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
        ]),
        _sg("sg-good", [
            {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
             "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
        ]),
    ]
    all_findings = analyze_security_groups(sgs)
    assert {f.group_id for f in all_findings} == {"sg-bad"}


def test_sg_finding_serializes_to_dict():
    f = SgFinding("sg-x", "HIGH", "i", "r")
    assert f.to_dict()["group_id"] == "sg-x"
