"""Minimal cookie-keeping, redirect-by-hand HTTP client for the behaviour checks (stdlib only).

Maps the stack's names to the published ports: login.localhost / bff.localhost -> caddy 127.0.0.1:8443
(verified against local-prod/certs/ca.crt), fakeidp:8080 -> 127.0.0.1:18080.
"""
import http.client
import json
import os
import socket
import ssl
from urllib.parse import urlencode, urljoin, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
CA = os.path.join(HERE, "..", "..", "local-prod", "certs", "ca.crt")
CTX = ssl.create_default_context(cafile=CA)
CTX.verify_flags &= ~ssl.VERIFY_X509_STRICT  # the throwaway CA has no Authority Key Identifier
HOSTS = {"login.localhost": ("127.0.0.1", 8443), "bff.localhost": ("127.0.0.1", 8443), "fakeidp": ("127.0.0.1", 18080)}


def _short(u, n=150):
    return u if len(u) <= n else u[:n] + f"...({len(u)} chars)"


class _TLS(http.client.HTTPSConnection):
    """Connects to `addr` but verifies the certificate (and sends SNI) for `host`."""

    def __init__(self, host, addr, port):
        super().__init__(host, port, timeout=30, context=CTX)
        self._addr = addr

    def connect(self):
        sock = socket.create_connection((self._addr, self.port), 30)
        self.sock = CTX.wrap_socket(sock, server_hostname=self.host)


class Resp:
    def __init__(self, status, headers, body, url):
        self.status, self.headers, self.url = status, headers, url
        self.body = body

    @property
    def location(self):
        return self.headers.get("location")

    def json(self):
        return json.loads(self.body)


class Browser:
    def __init__(self):
        self.cookies = {}  # host -> {name: value}
        self.trace = []

    def _conn(self, u):
        host = u.hostname
        addr, port = HOSTS.get(host, (host, u.port or (443 if u.scheme == "https" else 80)))
        if u.scheme != "https":
            return http.client.HTTPConnection(addr, port, timeout=30)
        return _TLS(host, addr, port)

    def request(self, method, url, data=None, headers=None, json_body=None, follow=False, max_redirects=15, quiet=False):
        headers = dict(headers or {})
        body = None
        if json_body is not None:
            body = json.dumps(json_body).encode()
            headers["Content-Type"] = "application/json"
        elif data is not None:
            body = urlencode(data).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        for _ in range(max_redirects + 1):
            u = urlparse(url)
            hostkey = u.hostname
            ck = self.cookies.get(hostkey, {})
            h = dict(headers)
            if ck:
                h["Cookie"] = "; ".join(f"{k}={v}" for k, v in ck.items())
            path = u.path or "/"
            if u.query:
                path += "?" + u.query
            c = self._conn(u)
            c.request(method, path, body=body, headers={**h, "Host": u.netloc})
            r = c.getresponse()
            raw = r.read().decode(errors="replace")
            c.close()
            for k, v in r.getheaders():
                if k.lower() == "set-cookie":
                    nv, _, rest = v.partition(";")
                    name, _, val = nv.partition("=")
                    jar = self.cookies.setdefault(hostkey, {})
                    if "max-age=0" in rest.lower() or "expires=thu, 01 jan 1970" in rest.lower() or val == "":
                        jar.pop(name, None)
                    else:
                        jar[name] = val
            resp = Resp(r.status, {k.lower(): v for k, v in r.getheaders()}, raw, url)
            self.trace.append((method, url, resp.status, resp.location))
            if not quiet:
                print(f"  {method} {_short(url)} -> {resp.status}" + (f" Location: {_short(resp.location)}" if resp.location else ""))
            if follow and resp.status in (301, 302, 303, 307, 308) and resp.location:
                url = urljoin(url, resp.location)
                method, body = "GET", None
                headers.pop("Content-Type", None)
                continue
            return resp
        raise RuntimeError("too many redirects")

    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def post(self, url, **kw):
        return self.request("POST", url, **kw)


def form_values(flow, method=None, **override):
    """Values of every input node of a Kratos flow (optionally only one group), with overrides."""
    vals = {}
    for n in flow["ui"]["nodes"]:
        a = n["attributes"]
        if n["type"] != "input" or not a.get("name"):
            continue
        if n["group"] not in ("default", method) and method:
            continue
        if a["type"] in ("submit", "button"):
            continue
        if "value" in a and a["value"] is not None:
            vals[a["name"]] = a["value"]
    vals.update(override)
    return vals


def node_names(flow):
    return [(n["group"], n["attributes"].get("name"), n["attributes"].get("type"), n["attributes"].get("value") if n["attributes"].get("type") in ("submit", "hidden") else None) for n in flow["ui"]["nodes"] if n["type"] == "input"]
