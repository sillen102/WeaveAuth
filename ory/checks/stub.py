#!/usr/bin/env python3
"""Throwaway stand-in for the weaveauth container (bff, login, hooks) used by the behaviour checks.

Not shipped. Listens on the four ports the real image uses and logs every request as one JSON
line to stdout and /logs/requests.jsonl:

  8080  bff public      GET /callback, GET /health
  8081  login           pages (log only), /login?login_challenge -> Kratos, /self-service/* proxy
  8082  bff internal    POST /backchannel-logout, POST /internal/revoke
  1983  hooks           POST /hydra/token-hook, /kratos/* with canned responses

Hooks behaviour is steered by /logs/mode (one word per line, re-read per request):
  registration-fail   after-registration answers 400 with a Kratos `messages` payload
  registration-500    after-registration answers 500
  claims:<k>=<v>      token hook adds access_token claim k=v (several lines allowed)
  deny-token          token hook answers 403
  fail:<path>         that hooks path answers 500
  purge-sessions      after-recovery deletes all Kratos sessions of the identity via admin
"""
import http.client
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

KRATOS = ("kratos", 4433)
LOGS = "/logs"
LOGIN_HOST = os.environ.get("LOGIN_URL", "https://login.localhost:8443")
LOCK = threading.Lock()


def mode():
    try:
        return [l.strip() for l in open(f"{LOGS}/mode") if l.strip()]
    except OSError:
        return []


def log(port, h, body):
    hdrs = {k.lower(): v for k, v in h.headers.items()}
    # Only the API key is redacted; everything else is logged as received.
    if "authorization" in hdrs:
        hdrs["authorization"] = hdrs["authorization"][:12] + "..."
    entry = {
        "t": round(time.time(), 3),
        "port": port,
        "method": h.command,
        "path": h.path,
        "headers": hdrs,
        "body": body,
    }
    line = json.dumps(entry)
    with LOCK:
        print(line, flush=True)
        try:
            with open(f"{LOGS}/requests.jsonl", "a") as f:
                f.write(line + "\n")
        except OSError:
            pass


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    # -- helpers
    def read_body(self):
        n = int(self.headers.get("content-length") or 0)
        return self.rfile.read(n) if n else b""

    def reply(self, status, body=b"", ctype="text/plain", headers=()):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
            ctype = "application/json"
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def proxy_kratos(self, raw):
        conn = http.client.HTTPConnection(*KRATOS, timeout=20)
        fwd = {k: v for k, v in self.headers.items() if k.lower() not in ("host", "connection", "content-length")}
        if raw:
            fwd["Content-Length"] = str(len(raw))
        conn.request(self.command, self.path, body=raw or None, headers=fwd)
        r = conn.getresponse()
        data = r.read()
        self.send_response(r.status)
        for k, v in r.getheaders():
            if k.lower() in ("transfer-encoding", "connection", "content-length"):
                continue
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def handle_any(self):
        port = self.server.server_address[1]
        raw = self.read_body()
        try:
            body = json.loads(raw) if raw and "json" in (self.headers.get("content-type") or "") else raw.decode(errors="replace")
        except ValueError:
            body = raw.decode(errors="replace")
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if port == 8081 and (u.path.startswith("/self-service/") or u.path.startswith("/.well-known/ory/")):
            return self.proxy_kratos(raw)
        log(port, self, body)
        if u.path == "/health":
            return self.reply(200, "ok")
        if port == 8080:
            if u.path == "/callback":
                return self.reply(200, {"callback": {k: v[0] for k, v in q.items()}})
            if u.path == "/logged-out":
                return self.reply(200, "logged out")
            return self.reply(404)
        if port == 8081:
            if u.path == "/login" and "login_challenge" in q:
                loc = f"{LOGIN_HOST}/self-service/login/browser?login_challenge={q['login_challenge'][0]}"
                return self.reply(303, headers=[("Location", loc)])
            return self.reply(200, {"login_stub_page": u.path, "query": {k: v[0] for k, v in q.items()}})
        if port == 8082:
            return self.reply(204 if u.path in ("/backchannel-logout", "/internal/revoke") else 404)
        if port == 1983:
            return self.hooks(u.path, body)
        self.reply(404)

    def hooks(self, path, body):
        m = mode()
        if f"fail:{path}" in m:
            return self.reply(500, {"error": "boom"})
        if path == "/hydra/token-hook":
            if "deny-token" in m:
                return self.reply(403, {})
            extra = {}
            for l in m:
                if l.startswith("claims:"):
                    k, _, v = l[7:].partition("=")
                    extra[k] = v
            return self.reply(200, {"session": {"access_token": {"roles": ["user"], **extra}, "id_token": {"stub": "id"}}})
        if path == "/kratos/after-registration":
            probe_identity(body)
            if "registration-fail" in m:
                return self.reply(400, {"messages": [{"instance_ptr": "#/traits/email", "messages": [{"id": 4000001, "text": "stub hook says no", "type": "error"}]}]})
            if "registration-500" in m:
                return self.reply(500, {"error": "boom"})
            return self.reply(200, {})
        if path == "/kratos/after-recovery" and "purge-sessions" in m:
            # What the real hook does: end every Kratos session of the identity. The recovery session does not exist yet.
            iid = body["identity_id"]
            c = http.client.HTTPConnection("kratos", 4434, timeout=10)
            c.request("DELETE", f"/admin/identities/{iid}/sessions")
            r = c.getresponse(); r.read()
            with LOCK:
                print(json.dumps({"t": round(time.time(), 3), "probe": "purge sessions in after-recovery", "admin_status": r.status}), flush=True)
                open(f"{LOGS}/requests.jsonl", "a").write(json.dumps({"t": round(time.time(), 3), "probe": "purge sessions in after-recovery", "admin_status": r.status}) + "\n")
            return self.reply(200, {})
        if f"fail:{path}" in m:
            return self.reply(500, {"error": "boom"})
        if path in ("/kratos/after-recovery", "/kratos/after-password-change"):
            return self.reply(200, {})
        self.reply(404)

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = handle_any


def probe_identity(body):
    """Reads the new identity back from Kratos admin while the hook is still running (is it persisted? tokens there?)."""
    try:
        iid = body["identity_id"]
        c = http.client.HTTPConnection("kratos", 4434, timeout=10)
        c.request("GET", f"/admin/identities/{iid}?include_credential=oidc")
        r = c.getresponse()
        d = json.loads(r.read() or b"{}")
        provs = ((d.get("credentials") or {}).get("oidc") or {}).get("config", {}).get("providers", [])
        summary = {"admin_status": r.status, "provider": [p.get("provider") for p in provs],
                   "has_access_token": [bool(p.get("initial_access_token")) for p in provs],
                   "has_refresh_token": [bool(p.get("initial_refresh_token")) for p in provs],
                   "has_id_token": [bool(p.get("initial_id_token")) for p in provs],
                   "credential_types": sorted((d.get("credentials") or {}).keys())}
    except Exception as e:  # probe only
        summary = {"probe_error": repr(e)}
    with LOCK:
        line = json.dumps({"t": round(time.time(), 3), "probe": "after-registration admin read", **summary})
        print(line, flush=True)
        try:
            with open(f"{LOGS}/requests.jsonl", "a") as f:
                f.write(line + "\n")
        except OSError:
            pass


def serve(port):
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()


if __name__ == "__main__":
    os.makedirs(LOGS, exist_ok=True)
    for p in (8081, 8082, 1983):
        threading.Thread(target=serve, args=(p,), daemon=True).start()
    print("stub up", file=sys.stderr, flush=True)
    serve(8080)
