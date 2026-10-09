import json

import jwt_core

SECRET = "test-secret"


def test_b64url_roundtrip_for_all_padding_lengths():
    for raw in (b"", b"a", b"ab", b"abc", b"abcd", b"\xff\xfe\xfd"):
        text = jwt_core.b64url_encode(raw)
        assert "=" not in text
        assert jwt_core.b64url_decode(text) == raw


def test_roundtrip_returns_claims():
    token = jwt_core.encode({"sub": "7", "role": "admin"}, SECRET, expires_in=60, now=1000)
    payload = jwt_core.decode(token, SECRET, now=1010)
    assert payload["sub"] == "7"
    assert payload["role"] == "admin"
    assert payload["iat"] == 1000
    assert payload["exp"] == 1060
    assert payload["jti"]


def test_three_parts_and_header():
    token = jwt_core.encode({"a": 1}, SECRET)
    assert token.count(".") == 2
    assert jwt_core.peek(token)["header"] == {"alg": "HS256", "typ": "JWT"}


def test_jti_is_unique_per_token():
    first = jwt_core.peek(jwt_core.encode({}, SECRET))["payload"]["jti"]
    second = jwt_core.peek(jwt_core.encode({}, SECRET))["payload"]["jti"]
    assert first != second


def test_expired_token_is_rejected():
    token = jwt_core.encode({}, SECRET, expires_in=60, now=1000)
    try:
        jwt_core.decode(token, SECRET, now=1061)
    except jwt_core.ExpiredToken:
        return
    raise AssertionError("expected ExpiredToken")


def test_leeway_allows_small_clock_skew():
    token = jwt_core.encode({}, SECRET, expires_in=60, now=1000)
    assert jwt_core.decode(token, SECRET, now=1065, leeway=10)


def test_wrong_secret_is_rejected():
    token = jwt_core.encode({}, "other")
    try:
        jwt_core.decode(token, SECRET)
    except jwt_core.InvalidToken as exc:
        assert "signature" in str(exc)
        return
    raise AssertionError("expected InvalidToken")


def test_tampered_payload_is_rejected():
    token = jwt_core.encode({"role": "employee"}, SECRET)
    header, payload, signature = token.split(".")
    forged = json.loads(jwt_core.b64url_decode(payload))
    forged["role"] = "admin"
    new_payload = jwt_core.b64url_encode(json.dumps(forged).encode())
    try:
        jwt_core.decode(header + "." + new_payload + "." + signature, SECRET)
    except jwt_core.InvalidToken:
        return
    raise AssertionError("tampering was not detected")


def test_alg_none_is_rejected():
    header = jwt_core.b64url_encode(json.dumps({"alg": "none"}).encode())
    payload = jwt_core.b64url_encode(json.dumps({"role": "admin", "exp": 4102444800}).encode())
    try:
        jwt_core.decode(header + "." + payload + ".", SECRET)
    except jwt_core.InvalidToken as exc:
        assert "alg" in str(exc)
        return
    raise AssertionError("alg none must be rejected")


def test_malformed_tokens_are_rejected():
    for bad in ("", "abc", "a.b", "a.b.c.d", "!!!.???.***"):
        try:
            jwt_core.decode(bad, SECRET)
        except jwt_core.InvalidToken:
            continue
        raise AssertionError("accepted malformed token: " + repr(bad))


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_")]
    for name, func in tests:
        func()
        print("pass", name)
    print("%d tests passed" % len(tests))
