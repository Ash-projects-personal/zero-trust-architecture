# How this works, in plain words

## The pattern being demonstrated

Old perimeter security trusts you once you are inside. Zero
trust drops that: every request proves who it is, and the
decision uses more than identity. This demo makes three
different signals decide together. The token proves the caller
holds a credential the service issued (signature and expiry,
checked fresh on each request, there is no session). The
subject check proves the identity is one the service knows, so
a perfectly signed token for a stranger still fails. The policy
then asks what the resource needs: an admin role for the admin
data, and a managed device claim on top, so the right person on
the wrong device is denied and the log says exactly that.

The access log is part of the design, not a debug print. Every
request leaves a line with subject, resource, decision, and
reason, which is the audit trail a real zero trust rollout
needs when someone asks why an access happened.

## The IAM analyser

Policy documents are the other place zero trust quietly fails:
one wildcard statement undoes careful service design. The
analyser parses the JSON and flags the classic shapes. It is
deterministic, so the fixture policies have exact expected
counts (3, 3, 0) pinned in the tests. Two subtleties it handles:
a service wildcard counts as sensitive only for services on the
sensitive list, and an MFA condition anywhere relevant in the
statement clears the missing MFA flag for that statement, which
is why the developer policy's guarded CreateUser statement
produces no finding while its S3 wildcard statement produces
three.

## What was re scoped and why

The original claimed an implementation across a microservices
environment: IAM and security group audits over hundreds of
invented objects, mTLS and workload identity validation, and a
blast radius figure described as dropping from total to a fifth
after micro segmentation. The audit found the demo driver
inventing its inputs and flagging them by probability, the mTLS
check drawing three random booleans per fictional service, and
the blast radius computed as the fictional non compliance share
plus a constant chosen to land near the claim. The genuinely
real code, an IAM policy parser and a security group analyser,
was never called by the demo on real input.

This rebuild makes the demo honest by shrinking it to things
that exist: a real service, real tokens, real requests, real
decisions, and the parser finally run on real documents. The
security group analyser was not carried over; the IAM parser
plus the live policy engine cover the same teaching ground, and
I would rather ship two working halves than three partial ones.

## Weak points

- One shared secret means anyone with the secret mints any
  identity. Real systems use asymmetric keys and a separate
  identity provider, plus short lived tokens and revocation,
  none of which exist here.
- The device claim is self asserted inside the token. Real
  device posture comes from attestation, not from the caller's
  own say so.
- The user registry is a two entry dictionary in the service.
- The IAM analyser reads one document at a time and knows
  nothing about how policies combine on one principal.
