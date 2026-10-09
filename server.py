import hashlib
import hmac
import json
import os
import secrets
import sys
import threading
import time
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import jwt_core

SECRET = os.environ.get("JWT_SECRET", "dev-only-secret-change-me-in-real-life")
ACCESS_TTL = 15 * 60
REFRESH_TTL = 7 * 24 * 60 * 60
VERBOSE = bool(os.environ.get("VERBOSE"))


def _hash_password(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)


def _make_user(user_id, username, password, role, company_id):
    salt = secrets.token_bytes(16)
    return {
        "id": user_id,
        "username": username,
        "salt": salt,
        "password_hash": _hash_password(password, salt),
        "role": role,
        "company_id": company_id,
    }


USERS = {
    u["username"]: u
    for u in (
        _make_user(1, "alice", "alice-pass", "admin", 1),
        _make_user(2, "bob", "bob-pass", "employee", 1),
        _make_user(3, "carol", "carol-pass", "employee", 2),
    )
}
USERS_BY_ID = {u["id"]: u for u in USERS.values()}

_refresh_tokens = {}
_lock = threading.Lock()


def issue_tokens(user, access_ttl=ACCESS_TTL):
    access = jwt_core.encode(
        {
            "sub": str(user["id"]),
            "username": user["username"],
            "role": user["role"],
            "company_id": user["company_id"],
        },
        SECRET,
        expires_in=access_ttl,
    )
    refresh = secrets.token_urlsafe(32)
    with _lock:
        _refresh_tokens[refresh] = {
            "user_id": user["id"],
            "expires_at": time.time() + REFRESH_TTL,
            "access_ttl": access_ttl,
        }
    return {
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "Bearer",
        "expires_in": access_ttl,
        "refresh_expires_in": REFRESH_TTL,
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "JwtLab/1.0"

    def log_message(self, fmt, *args):
        if VERBOSE:
            super().log_message(fmt, *args)

    def _send(self, status, body=None):
        payload = b"" if body is None else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Cache-Control", "no-store")
        if body is not None:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if payload:
            self.wfile.write(payload)

    def _json_body(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            data = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return None
        return data if isinstance(data, dict) else None

    def _claims(self):
        header = self.headers.get("Authorization", "")
        scheme, _, token = header.partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            self._send(401, {"error": "missing bearer token"})
            return None
        try:
            return jwt_core.decode(token.strip(), SECRET)
        except jwt_core.ExpiredToken:
            self._send(401, {"error": "token expired"})
        except jwt_core.InvalidToken as exc:
            self._send(401, {"error": "invalid token: " + str(exc)})
        return None

    def do_GET(self):
        assets = {"/": ("index.html", "text/html"), "/app.js": ("app.js", "text/javascript"), "/style.css": ("style.css", "text/css")}
        if self.path in assets:
            name, content_type = assets[self.path]
            payload = (Path(__file__).parent / "static" / name).read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", content_type + "; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(payload)
        elif self.path == "/me":
            claims = self._claims()
            if claims:
                self._send(200, {"you_are": claims})
        elif self.path == "/admin":
            claims = self._claims()
            if not claims:
                return
            if claims.get("role") != "admin":
                return self._send(403, {"error": "admins only"})
            self._send(200, {"message": "welcome, admin"})
        elif self.path == "/company/employees":
            claims = self._claims()
            if not claims:
                return
            people = [
                {"id": u["id"], "username": u["username"], "role": u["role"]}
                for u in USERS.values()
                if u["company_id"] == claims["company_id"]
            ]
            self._send(200, {"company_id": claims["company_id"], "employees": people})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        body = self._json_body()
        if body is None:
            return self._send(400, {"error": "body must be a JSON object"})

        if self.path == "/login":
            access_ttl = body.get("access_ttl", ACCESS_TTL)
            if type(access_ttl) is not int or access_ttl not in (20, ACCESS_TTL):
                return self._send(400, {"error": "access_ttl must be 20 or 900 seconds"})
            user = USERS.get(str(body.get("username", "")))
            salt = user["salt"] if user else b"\x00" * 16
            candidate = _hash_password(str(body.get("password", "")), salt)
            if not user or not hmac.compare_digest(candidate, user["password_hash"]):
                return self._send(401, {"error": "invalid credentials"})
            self._send(200, issue_tokens(user, access_ttl))

        elif self.path == "/refresh":
            token = str(body.get("refresh_token", ""))
            with _lock:
                record = _refresh_tokens.pop(token, None)
            if record is None or record["expires_at"] < time.time():
                return self._send(401, {"error": "invalid or expired refresh token"})
            self._send(200, issue_tokens(USERS_BY_ID[record["user_id"]], record["access_ttl"]))

        elif self.path == "/logout":
            with _lock:
                _refresh_tokens.pop(str(body.get("refresh_token", "")), None)
            self._send(204)

        else:
            self._send(404, {"error": "not found"})


def make_server(port=0):
    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    print("JWT lab server on http://127.0.0.1:%d" % port)
    print("users: alice/alice-pass (admin, company 1), bob/bob-pass, carol/carol-pass (company 2)")
    print("Open the URL above in your browser for the interactive JWT lab.")
    make_server(port).serve_forever()
