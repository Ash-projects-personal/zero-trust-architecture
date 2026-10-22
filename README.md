# Zero trust, as a working local demo

I rebuilt this project from scratch. The old version claimed an
architecture implemented for a microservices environment, with
mTLS and SPIFFE identity validation and a blast radius cut from
one round number to another. The audit found the headline tool
rolling dice over invented policies and services, an mTLS check
that drew random booleans, and a blast radius formula with the
answer built into it. There was no environment and no
measurement. All of that is gone.

This version is the idea at demo scale, but every part of it
actually runs: signed identity tokens, a policy engine, a
protected service, real requests, and a decision log written by
the service itself.

## How it works

- `src/tokens.py` mints and verifies HMAC signed tokens (the JWT
  shape, a page of standard library code): subject, roles,
  managed device claim, expiry. Verification is signature plus
  expiry on every request, constant time compare, no fallback.
- `src/policy.py` is the resource table: `/public` needs no
  identity, `/profile` needs a verified known identity,
  `/admin/data` needs the admin role and a managed device.
- `src/service.py` is a Flask service holding those resources.
  It verifies the token on each request, checks the subject is
  known, asks the policy, and appends the decision and its
  reason to `outputs/access_log.jsonl` either way.
- `src/iam_policy_parser.py` is the second half: a deterministic
  analyser for real IAM policy JSON, flagging wildcard actions,
  wildcard resources, sensitive service wildcards, and sensitive
  actions with no MFA condition.

## The demo run

`src/run_demo.py` fires 10 real requests: no token at a public
and a protected page, a valid user at both protected levels, an
admin on a managed and an unmanaged device, an expired token, a
tampered token, a validly signed token for an unknown subject,
and a user at the public page. Expected decisions are recorded
before the run.

Results: 4 allowed, 6 denied, 10 of 10 decisions matching
expectation, and the service's own access log holds exactly
those 10 decisions. Every denial is for a distinct stated
reason in the log: no token, wrong role, unmanaged device,
expiry, bad signature, unknown identity. Detail in
`outputs/demo_results.json` and `outputs/metrics.json`.

The IAM analyser runs in the same demo over 3 fixture policies
I wrote: a full wildcard admin policy (3 findings), a developer
policy mixing an S3 wildcard with an MFA guarded action (3
findings), and a scoped read only policy (0 findings). 6
findings in total, each traceable to a statement.

## Run it

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python src/run_demo.py
python -m pytest tests/
```

## What this is not

Not an enterprise deployment, not mTLS, not SPIFFE, and no
network was segmented to produce these numbers. Identity here
is one shared HMAC secret on one machine, which is a teaching
model of the pattern, not a production design. The claim is
only this: the pattern is implemented for real at small scale
and its decisions are logged and scored.

## Files

- `src/tokens.py` token minting and verification
- `src/policy.py` the resource policy table and decision logic
- `src/service.py` the protected service and its access log
- `src/iam_policy_parser.py` the IAM policy analyser
- `src/run_demo.py` the scored request set and the analyser run
- `EXPLAIN.md` how it works and what was re scoped
