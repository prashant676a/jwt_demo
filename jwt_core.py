import base64
import hashlib
import hmac
import json
import time
import uuid


class InvalidToken(Exception):
    pass


class ExpiredToken(InvalidToken):
    pass


def b64url_encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(text):
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def _json_b64(obj):
    return b64url_encode(json.dumps(obj, separators=(",", ":"), sort_keys=True).encode())


def _sign(signing_input, secret):
    digest = hmac.new(secret.encode(), signing_input.encode("ascii"), hashlib.sha256).digest()
    return b64url_encode(digest)


def encode(payload, secret, expires_in=900, now=None):
    now = int(time.time() if now is None else now)
    header = {"alg": "HS256", "typ": "JWT"}
    claims = dict(payload)
    claims.setdefault("iat", now)
    claims.setdefault("exp", now + expires_in)
    claims.setdefault("jti", str(uuid.uuid4()))
    signing_input = _json_b64(header) + "." + _json_b64(claims)
    return signing_input + "." + _sign(signing_input, secret)


def peek(token):
    header_b64, payload_b64, _signature = token.split(".")
    return {
        "header": json.loads(b64url_decode(header_b64)),
        "payload": json.loads(b64url_decode(payload_b64)),
    }


def decode(token, secret, now=None, leeway=0):
    parts = token.split(".")
    if len(parts) != 3:
        raise InvalidToken("token must have exactly 3 parts")
    header_b64, payload_b64, signature = parts

    try:
        header = json.loads(b64url_decode(header_b64))
        payload = json.loads(b64url_decode(payload_b64))
    except ValueError as exc:
        raise InvalidToken("malformed token") from exc
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise InvalidToken("malformed token")

    if header.get("alg") != "HS256":
        raise InvalidToken("unsupported alg: " + repr(header.get("alg")))

    expected = _sign(header_b64 + "." + payload_b64, secret)
    if not hmac.compare_digest(expected.encode(), signature.encode()):
        raise InvalidToken("bad signature")

    exp = payload.get("exp")
    if not isinstance(exp, (int, float)):
        raise InvalidToken("missing exp claim")
    current = time.time() if now is None else now
    if current > exp + leeway:
        raise ExpiredToken("token expired")

    return payload
