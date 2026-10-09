import json
import threading
import urllib.error
import urllib.request

import jwt_core
import server

httpd = server.make_server(0)
BASE = "http://127.0.0.1:%d" % httpd.server_address[1]
threading.Thread(target=httpd.serve_forever, daemon=True).start()

count = 0


def call(method, path, body=None, token=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        return exc.code, (json.loads(raw) if raw else None)


def check(title, got, expected_status):
    global count
    count += 1
    status, body = got
    mark = "ok  " if status == expected_status else "FAIL"
    print("[%2d] %s %s -> %s %s" % (count, mark, title, status, json.dumps(body)[:110]))
    assert status == expected_status, "expected %s for: %s" % (expected_status, title)
    return body


def login(username, password):
    return call("POST", "/login", {"username": username, "password": password})


def forge_payload(token, **changes):
    header_b64, payload_b64, signature = token.split(".")
    payload = json.loads(jwt_core.b64url_decode(payload_b64))
    payload.update(changes)
    new_payload = jwt_core.b64url_encode(json.dumps(payload).encode())
    return header_b64 + "." + new_payload + "." + signature


def alg_none_token(payload):
    header = jwt_core.b64url_encode(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    body = jwt_core.b64url_encode(json.dumps(payload).encode())
    return header + "." + body + "."


print("\n--- 1. Login and the anatomy of a token")
tokens = check("login as bob", login("bob", "bob-pass"), 200)
access = tokens["access_token"]
print("     token parts:", [len(p) for p in access.split(".")], "(header, payload, signature lengths)")
print("     anyone can read it, no secret needed:")
print("    ", json.dumps(jwt_core.peek(access)))

print("\n--- 2. Authentication (who are you?) vs authorization (what may you do?)")
check("GET /me with token", call("GET", "/me", token=access), 200)
check("GET /me without token", call("GET", "/me"), 401)
check("bob (employee) GET /admin", call("GET", "/admin", token=access), 403)
alice = check("login as alice", login("alice", "alice-pass"), 200)
check("alice (admin) GET /admin", call("GET", "/admin", token=alice["access_token"]), 200)
check("wrong password", login("bob", "nope"), 401)
check("unknown user (same error, no user leak)", login("mallory", "x"), 401)

print("\n--- 3. Multi-tenant scoping comes from the token's company_id")
body = check("bob's company", call("GET", "/company/employees", token=access), 200)
assert sorted(e["username"] for e in body["employees"]) == ["alice", "bob"]
carol = check("login as carol", login("carol", "carol-pass"), 200)
body = check("carol's company", call("GET", "/company/employees", token=carol["access_token"]), 200)
assert [e["username"] for e in body["employees"]] == ["carol"]

print("\n--- 4. Attacks that must fail")
check("tampered payload (role -> admin), old signature",
      call("GET", "/admin", token=forge_payload(access, role="admin")), 401)
check("alg=none token, empty signature",
      call("GET", "/admin", token=alg_none_token({"role": "admin", "company_id": 1, "exp": 4102444800})), 401)
wrong_key = jwt_core.encode({"role": "admin", "company_id": 1}, "some-other-secret")
check("signed with the wrong secret", call("GET", "/admin", token=wrong_key), 401)
expired = jwt_core.encode({"role": "admin", "company_id": 1}, server.SECRET, expires_in=-5)
check("expired token", call("GET", "/me", token=expired), 401)
check("garbage token", call("GET", "/me", token="not.a.jwt"), 401)

print("\n--- 5. Refresh tokens: rotation and logout")
old_refresh = tokens["refresh_token"]
fresh = check("refresh with bob's refresh token", call("POST", "/refresh", {"refresh_token": old_refresh}), 200)
check("new access token works", call("GET", "/me", token=fresh["access_token"]), 200)
check("reusing the OLD refresh token is rejected", call("POST", "/refresh", {"refresh_token": old_refresh}), 401)
check("logout", call("POST", "/logout", {"refresh_token": fresh["refresh_token"]}), 204)
check("refresh after logout is rejected", call("POST", "/refresh", {"refresh_token": fresh["refresh_token"]}), 401)

print("\nAll %d scenarios behaved as expected." % count)
