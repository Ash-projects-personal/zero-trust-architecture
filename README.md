# zero-trust-architecture

Built this audit tool while implementing a Zero-Trust architecture for a microservices environment. Pushing the validation scripts here.

It's a Python-based audit tool that validates three pillars of a Zero-Trust implementation. IAM Policy Audit scans IAM policies for over-permissive rules like wildcard actions, wildcard resources, and missing MFA conditions. Security Group Audit checks for overly permissive ingress rules and flat network configurations that allow lateral movement. mTLS Validation checks whether each microservice has a valid SPIFFE/SPIRE workload identity and is enforcing mutual TLS for service-to-service communication.

The goal was to reduce the blast radius — the percentage of internal services that an attacker could reach if they compromised a single node. Before Zero-Trust it was basically 100%. After implementing micro-segmentation and mTLS it dropped to around 20%.

```bash
python zt_audit.py
```

This runs the full audit simulation and saves a JSON report to outputs/.
