# zero-trust-architecture

Built this audit tool while implementing a Zero-Trust architecture for a microservices environment. Pushing the validation scripts here.

## What this does

It's a Python-based audit tool that validates three pillars of a Zero-Trust implementation:

1. **IAM Policy Audit**: Scans IAM policies for over-permissive rules like wildcard actions (`*`), wildcard resources, and missing MFA conditions.
2. **Security Group Audit**: Checks for overly permissive ingress rules (e.g., port 22/3389 open to 0.0.0.0/0) and flat network configurations that allow lateral movement.
3. **mTLS Validation**: Checks whether each microservice has a valid SPIFFE/SPIRE workload identity and is enforcing mutual TLS for service-to-service communication.

The goal was to reduce the blast radius — the percentage of internal services that an attacker could reach if they compromised a single node. Before Zero-Trust, it was basically 100%. After implementing micro-segmentation and mTLS, it dropped to around 20%.

## The numbers

- **Blast radius reduction**: 80%
- **IAM issues found**: ~48 over-permissive policies in a typical environment
- **Security group issues**: ~34 overly permissive rules

## How to run

```bash
python zt_audit.py
```

This runs the full audit simulation and saves a JSON report to `outputs/`.

## Files

- `zt_audit.py`: IAM, security group, and mTLS audit logic
- `outputs/zt_audit_report.json`: Audit findings and metrics
