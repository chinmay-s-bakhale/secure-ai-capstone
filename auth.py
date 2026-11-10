"""
auth.py - JWT authentication for the TechCorp secure AI chat API.

Control layer 1 (Authentication):
  * token_required()  - Flask decorator that guards a route
  * create_token()    - helper used by mint_token.py to issue test tokens
  * get_secret()      - loads the signing secret from the environment ONLY

Threats mitigated: unauthenticated access to the LLM endpoint, token forgery
(signature + algorithm pinning), replay of old tokens (mandatory expiry).
"""
import datetime as dt
import functools
import os

import jwt
from flask import g, jsonify, request

ALGORITHM = "HS256"
MIN_SECRET_LENGTH = 32


def get_secret() -> str:
    """Return the JWT signing secret. It is read from the environment and is
    never hardcoded, never given a default and never written to disk by this
    code. The app refuses to start without a strong value."""
    secret = os.environ.get("JWT_SECRET", "")
    if len(secret) < MIN_SECRET_LENGTH:
        raise RuntimeError(
            "JWT_SECRET is missing or shorter than 32 characters. "
            "Generate one with: openssl rand -hex 32"
        )
    return secret


def create_token(subject: str, minutes: int = 60) -> str:
    """Issue a signed JWT for `subject` that expires in `minutes` minutes.
    A negative value produces an already-expired token (useful for testing)."""
    now = dt.datetime.now(dt.timezone.utc)
    claims = {
        "sub": subject,
        "iat": now,
        "exp": now + dt.timedelta(minutes=minutes),
    }
    return jwt.encode(claims, get_secret(), algorithm=ALGORITHM)


def _unauthorized(message: str):
    response = jsonify({"error": message, "status": "unauthorized"})
    response.status_code = 401
    response.headers["WWW-Authenticate"] = 'Bearer realm="techcorp-ai"'
    return response


def token_required(view):
    """Reject any request that does not carry a valid, unexpired JWT in the
    'Authorization: Bearer <token>' header. The wrapped view (and therefore the
    model call inside it) only runs after verification succeeds."""

    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        scheme, _, supplied = header.partition(" ")
        supplied = supplied.strip()

        if scheme.lower() != "bearer" or not supplied:
            return _unauthorized(
                "Missing or malformed Authorization header. Expected: Bearer <token>"
            )
        try:
            claims = jwt.decode(
                supplied,
                get_secret(),
                algorithms=[ALGORITHM],            # pin the algorithm: blocks alg=none / alg-confusion
                options={"require": ["exp", "sub"]},  # a token without expiry or subject is invalid
            )
        except jwt.ExpiredSignatureError:
            return _unauthorized("Token has expired")
        except jwt.InvalidTokenError:
            return _unauthorized("Invalid token")

        g.current_user = claims["sub"]
        return view(*args, **kwargs)

    return wrapper
