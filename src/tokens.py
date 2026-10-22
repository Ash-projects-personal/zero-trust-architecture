"""Minimal HMAC signed identity tokens.

A token is base64url(header).base64url(payload).base64url(sig),
where sig is HMAC SHA256 over the first two parts with the
service secret. This is the JWT shape, implemented in a page of
standard library code so there is nothing hidden inside a
library call. Payload claims: sub (subject), roles (list),
device_managed (bool), exp (unix seconds).

Verification checks the signature with a constant time compare
and then the expiry. Any failure raises TokenError; there is no
partial credit and no fallback identity.
"""
import base64
import hashlib
import hmac
import json
import time


class TokenError(Exception):
    pass


def _b64encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64decode(text):
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def mint_token(secret, subject, roles, device_managed, expires_in_seconds=3600, now=None):
    now = int(time.time()) if now is None else now
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": subject,
        "roles": roles,
        "device_managed": device_managed,
        "exp": now + expires_in_seconds,
        "iat": now,
    }
    signing_input = "%s.%s" % (
        _b64encode(json.dumps(header).encode()),
        _b64encode(json.dumps(payload).encode()),
    )
    sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    return "%s.%s" % (signing_input, _b64encode(sig))


def verify_token(secret, token, now=None):
    now = int(time.time()) if now is None else now
    parts = token.split(".")
    if len(parts) != 3:
        raise TokenError("malformed token")
    signing_input = "%s.%s" % (parts[0], parts[1])
    expected = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    try:
        given = _b64decode(parts[2])
    except Exception:
        raise TokenError("undecodable signature")
    if not hmac.compare_digest(expected, given):
        raise TokenError("bad signature")
    try:
        payload = json.loads(_b64decode(parts[1]))
    except Exception:
        raise TokenError("undecodable payload")
    if payload.get("exp", 0) < now:
        raise TokenError("token expired")
    return payload
