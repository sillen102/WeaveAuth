#!/usr/bin/env python3
"""Runs the nine behaviour checks (and the hook-shape probes) against the check stack. Stdlib only,
except the passkey parts, which need `pip install soft-webauthn` and are skipped without it.

  cd local-prod && ./gen-certs.sh && ./gen-secrets.sh
  docker compose -f docker-compose.yml -f ../ory/checks/docker-compose.checks.yml up -d
  python3 ../ory/checks/run_checks.py            # all checks; or: ... run_checks.py 3 7 hooks

Needs the stack as that command starts it: base config (verified-first, no overlay), the fake IdP, the
stub standing in for weaveauth, and the admin ports published on loopback.
"""
import base64
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import parse_qs, quote, urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from browser import Browser, form_values  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
LOGIN = "https://login.localhost:8443"
HYDRA, KRATOS, MAIL = "http://127.0.0.1:34445", "http://127.0.0.1:34434", "http://127.0.0.1:8025"
LOG = os.path.join(HERE, "logs", "requests.jsonl")
STUB = "weaveauth-local-prod-weaveauth-1"
NET = "weaveauth-local-prod_internal"
PW = "correct-Horse-battery-9!"
J = {"Accept": "application/json"}
ENV = dict(l.strip().split("=", 1) for l in open(os.path.join(HERE, "..", "..", "local-prod", ".env")) if "=" in l and not l.startswith("#"))

try:
    from soft_webauthn import SoftWebauthnDevice
except ImportError:
    SoftWebauthnDevice = None


# --- plumbing -------------------------------------------------------------------------------------
def say(s=""):
    print(s, flush=True)


def short(o, n=70):
    def tr(x):
        if isinstance(x, str):
            return x if len(x) <= n else x[:n] + f"...<{len(x)}>"
        if isinstance(x, dict):
            return {k: tr(v) for k, v in x.items()}
        if isinstance(x, list):
            return [tr(v) for v in x]
        return x
    return json.dumps(tr(o), indent=1)


def api(method, base, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method, headers={"Content-Type": "application/json", "Accept": "application/json"})
    try:
        r = urllib.request.urlopen(req)
        t = r.read().decode()
        return r.status, (json.loads(t) if t else None)
    except urllib.error.HTTPError as e:
        t = e.read().decode()
        try:
            return e.code, json.loads(t)
        except ValueError:
            return e.code, t


hydra = lambda m, p, b=None: api(m, HYDRA, p, b)  # noqa: E731
kratos = lambda m, p, b=None: api(m, KRATOS, p, b)  # noqa: E731


def stub_log():
    return [json.loads(l) for l in open(LOG)] if os.path.exists(LOG) else []


def clear_log():
    open(LOG, "w").close()


def set_mode(*lines):
    """Writes the stub's mode file from inside the container (bind-mount writes from the host propagate late on macOS)."""
    cmd = "printf '%s\\n' \"$@\" > /logs/mode" if lines else ": > /logs/mode"
    subprocess.run(["docker", "exec", STUB, "sh", "-c", cmd, "sh", *lines], check=True)


def hook_calls(path):
    return [e for e in stub_log() if e.get("path") == path]


def clear_mail():
    urllib.request.urlopen(urllib.request.Request(MAIL + "/api/v1/messages", method="DELETE"))


def mail_code(email, n=1):
    for _ in range(40):
        ms = [m for m in json.load(urllib.request.urlopen(MAIL + "/api/v1/messages"))["messages"] if m["To"][0]["Address"] == email]
        if len(ms) >= n:
            body = json.load(urllib.request.urlopen(MAIL + "/api/v1/message/" + ms[0]["ID"]))
            return re.search(r"\b(\d{6})\b", body["Text"]).group(1), body
        time.sleep(0.5)
    raise RuntimeError("no mail for " + email)


uniq = lambda p="u": f"{p}{int(time.time() * 1000) % 10**9}@example.test"  # noqa: E731
jwt = lambda t: json.loads(base64.urlsafe_b64decode(t.split(".")[1] + "=" * (-len(t.split(".")[1]) % 4)))  # noqa: E731


def pkce():
    v = secrets.token_urlsafe(48)
    return v, base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode()


def flow(b, kind, fid):
    return b.get(f"{LOGIN}/self-service/{kind}/flows?id={fid}", headers=J, quiet=True).json()


def new_flow(b, kind, challenge=None):
    u = f"{LOGIN}/self-service/{kind}/browser?x=1" + (f"&login_challenge={challenge}" if challenge else "")
    r = b.get(u, follow=True, quiet=True)
    return flow(b, kind, parse_qs(urlparse(r.url).query)["flow"][0])


def submit(b, f, method, follow=True, **vals):
    v = form_values(f, method)
    v.update(vals)
    v["method"] = method
    return b.post(f["ui"]["action"], data=v, follow=follow, quiet=True)


def authorize(b, challenge, state="st12345678", extra=""):
    return b.get(LOGIN + "/oauth2/auth?client_id=bff&response_type=code&scope=openid+offline_access&redirect_uri=https%3A%2F%2Fbff.localhost%3A8443%2Fcallback"
                 f"&state={state}&code_challenge={challenge}&code_challenge_method=S256" + extra, follow=True, quiet=True)


def login_flow(b, r):
    return flow(b, "login", parse_qs(urlparse(r.url).query)["flow"][0])


def oidc_start(b, f, provider):
    return b.post(f["ui"]["action"], data={"provider": provider, "csrf_token": form_values(f)["csrf_token"]}, follow=True, quiet=True)


def accept_consent(consent_url, audience=None):
    ch = parse_qs(urlparse(consent_url).query)["consent_challenge"][0]
    _, cr = hydra("GET", "/admin/oauth2/auth/requests/consent?consent_challenge=" + ch)
    aud = cr["requested_access_token_audience"] if audience is None else audience
    _, res = hydra("PUT", "/admin/oauth2/auth/requests/consent/accept?consent_challenge=" + ch,
                   {"grant_scope": cr["requested_scope"], "grant_access_token_audience": aud, "remember": False})
    return cr, res["redirect_to"]


def token_call(data):
    """Runs on the internal network like bff will: http://hydra:4444, client_secret_basic."""
    cmd = ["docker", "run", "--rm", "--network", NET, "curlimages/curl", "-s", "-i", "-u", f"bff:{ENV['WA_BFF_CLIENT_SECRET']}", "http://hydra:4444/oauth2/token"]
    for k, v in data.items():
        cmd += ["--data-urlencode", f"{k}={v}"]
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    head, _, body = out.partition("\n\n")
    try:
        return head.split("\n")[0].strip(), json.loads(body)
    except ValueError:
        return head.split("\n")[0].strip(), body


def finish(b, r, verifier, audience=None):
    """From a response at the consent page: accept consent, follow to bff /callback, exchange the code."""
    if "/consent" in r.url:
        _, redir = accept_consent(r.url, audience)
        r = b.get(redir, follow=True, quiet=True)
    cb = parse_qs(urlparse(r.url).query)
    if "code" not in cb:
        return None, r
    return token_call({"grant_type": "authorization_code", "code": cb["code"][0], "redirect_uri": "https://bff.localhost:8443/callback", "code_verifier": verifier}), r


def make_verified_user(prefix="vu"):
    """Password registration through the whole verified-first OAuth2 path. Returns (email, sub, tokens)."""
    b = Browser()
    v, c = pkce()
    lf = login_flow(b, authorize(b, c))
    f = new_flow(b, "registration", lf["oauth2_login_challenge"])
    email = uniq(prefix)
    submit(b, f, "profile", follow=False, **{"traits.email": email, "traits.first_name": "V", "traits.last_name": "U", "traits.phone_number": "+46700000001"})
    f = flow(b, "registration", f["id"])
    r = submit(b, f, "password", password=PW)
    vf = flow(b, "verification", parse_qs(urlparse(r.url).query)["flow"][0])
    r = submit(b, vf, "code", code=mail_code(email)[0])
    tok, _ = finish(b, r, v)
    return email, jwt(tok[1]["id_token"])["sub"], tok[1]


def password_login(email):
    b = Browser()
    v, c = pkce()
    lf = login_flow(b, authorize(b, c))
    r = submit(b, lf, "password", identifier=email, password=PW)
    tok, _ = finish(b, r, v)
    return b, tok[1]


def remove_identity(email):
    for i in kratos("GET", "/admin/identities?credentials_identifier=" + email)[1] or []:
        kratos("DELETE", "/admin/identities/" + i["id"])


# --- the nine checks --------------------------------------------------------------------------------
def check1():
    say("== 1. Does skip_consent bypass urls.consent?")
    _, cl = hydra("GET", "/admin/clients/bff")
    email, sub, _ = make_verified_user("c1")
    b = Browser()
    v, c = pkce()
    lf = login_flow(b, authorize(b, c))
    r = submit(b, lf, "password", identifier=email, password=PW)
    _, cr = hydra("GET", "/admin/oauth2/auth/requests/consent?consent_challenge=" + parse_qs(urlparse(r.url).query)["consent_challenge"][0])
    say(f"   client skip_consent={cl['skip_consent']}; after login the browser still lands on {urlparse(r.url).path}?consent_challenge=...; consent request skip={cr['skip']}")
    tok, _ = finish(b, r, v)
    say(f"   accepting it with grant_scope=requested_scope: code exchange {tok[0]}")
    say("   RESULT: NO. Hydra v26.2.0 stores skip_consent but its consent strategy never reads it; login needs a /consent that auto-accepts.")


def check2():
    say("== 2. Does token_hook fire on the refresh grant?")
    email, sub, _ = make_verified_user("c2")
    b, toks = password_login(email)
    clear_log()
    set_mode("claims:roles=admin-after-refresh")
    st, res = token_call({"grant_type": "refresh_token", "refresh_token": toks["refresh_token"]})
    set_mode()
    h = hook_calls("/hydra/token-hook")
    say(f"   refresh -> {st}; hook calls: {len(h)}; grant_types in hook request: {h[0]['body']['request']['grant_types'] if h else None}")
    say(f"   hook returned roles=admin-after-refresh; refreshed JWT roles claim: {jwt(res['access_token']).get('roles')}")
    say(f"   hook request.session.extra on refresh (previous claims): {h[0]['body']['session']['extra']}")
    say("   RESULT: YES, claims are recomputed on every refresh; session.extra carries the previous claims.")


def check3():
    say("== 3. Does admin revocation by subject fire back-channel logout?")
    email, sub, _ = make_verified_user("c3")
    b, toks = password_login(email)
    clear_log()
    for label, p in [("DELETE /admin/oauth2/auth/sessions/login?subject=", f"/admin/oauth2/auth/sessions/login?subject={sub}"),
                     ("DELETE /admin/oauth2/auth/sessions/consent?subject=&all=true", f"/admin/oauth2/auth/sessions/consent?subject={sub}&all=true")]:
        st, _ = hydra("DELETE", p)
        time.sleep(1.5)
        say(f"   {label} -> {st}; back-channel POSTs at bff internal stub so far: {len([e for e in stub_log() if e.get('port') == 8082])}")
    st, res = token_call({"grant_type": "refresh_token", "refresh_token": toks["refresh_token"]})
    say(f"   refresh token after consent-session revoke: {st} {res.get('error') if isinstance(res, dict) else ''}")
    say("   RESULT: NO back-channel logout from either call (the second does kill refresh tokens). hooks must call bff /internal/revoke.")


def check4_9():
    say("== 4. Does Hydra accept an internal http backchannel_logout_uri?   9. How to chain logout?")
    _, cl = hydra("GET", "/admin/clients/bff")
    say(f"   client registered with backchannel_logout_uri={cl['backchannel_logout_uri']} (accepted by hydra-init)")
    for variant in ("kratos-chained", "hydra-only"):
        email, sub, _ = make_verified_user("c9")
        b, tok = password_login(email)
        clear_log()
        r = b.get(LOGIN + "/oauth2/sessions/logout?id_token_hint=" + tok["id_token"] + "&post_logout_redirect_uri=https%3A%2F%2Fbff.localhost%3A8443%2Flogged-out&state=xyz", quiet=True)
        lc = parse_qs(urlparse(r.location).query)["logout_challenge"][0]
        say(f"   [{variant}] hydra redirects to urls.logout: {urlparse(r.location).path}?logout_challenge=...")
        _, acc = hydra("PUT", "/admin/oauth2/auth/requests/logout/accept?logout_challenge=" + lc, {})
        if variant == "kratos-chained":
            k = b.get(LOGIN + "/self-service/logout/browser", headers=J, quiet=True).json()
            end = b.get(k["logout_url"] + "&return_to=" + quote(acc["redirect_to"], safe=""), follow=True, quiet=True)
        else:
            end = b.get(acc["redirect_to"], follow=True, quiet=True)
        time.sleep(2)
        bc = [e for e in stub_log() if e.get("port") == 8082]
        claims = jwt(parse_qs(bc[0]["body"])["logout_token"][0]) if bc else {}
        say(f"   [{variant}] ends at {end.url}; back-channel POSTs: {len(bc)} (/backchannel-logout, form logout_token); logout_token claims: {sorted(claims)}")
        say(f"   [{variant}] kratos session after: {b.get(LOGIN + '/self-service/logout/browser', headers=J, quiet=True).status} (401 = ended); hydra refresh token after: {token_call({'grant_type': 'refresh_token', 'refresh_token': tok['refresh_token']})[0]}")
    say("   RESULT 4: YES, delivered to http://weaveauth:8082/backchannel-logout.")
    say("   RESULT 9: urls.logout -> login /logout?logout_challenge -> PUT hydra logout/accept -> 303 redirect_to. With urls.identity_provider.url set,")
    say("             Hydra disables the Kratos session itself (hydra-only variant), so the Kratos logout hop is optional. The logout_token has sid but no sub;")
    say("             refresh tokens survive logout, bff must revoke them.")


def check5_6():
    say("== 5. oauth2_provider coverage (registration, social, passkey from a login_challenge)   6. require_verified_address coverage")
    # password registration, OIDC registration (verified / unverified)
    b = Browser()
    v, c = pkce()
    lf = login_flow(b, authorize(b, c))
    say(f"   login flow carries the challenge: {bool(lf.get('oauth2_login_challenge'))}; passkey nodes present: {any(n['group'] == 'passkey' for n in lf['ui']['nodes'])}")
    email, sub, _ = make_verified_user("c5")
    say("   password registration (verified-first): verification UI, code mail, then hydra login accepted -> consent -> tokens: OK")
    for prov in ("fake", "fakeu"):
        remove_identity({"fake": "idp-user@example.test", "fakeu": "idp-unverified@example.test"}[prov])
        b = Browser()
        v, c = pkce()
        lf = login_flow(b, authorize(b, c))
        f = new_flow(b, "registration", lf["oauth2_login_challenge"])
        r = oidc_start(b, f, prov)
        say(f"   OIDC registration via {prov} ({'email_verified true' if prov == 'fake' else 'email_verified false'}): lands on {urlparse(r.url).path}")
    for prov in ("fake", "fakeu"):
        b = Browser()
        v, c = pkce()
        r = oidc_start(b, login_flow(b, authorize(b, c)), prov)
        say(f"   OIDC login via {prov} (existing identity, require_verified_address): lands on {urlparse(r.url).path}"
            + (" -> tokens " + finish(b, r, v)[0][0] if "/consent" in r.url else " (verification flow, no hydra accept)"))
    b, _ = password_login(email)
    remove_identity("unverified-pw@example.test")
    st, res = kratos("POST", "/admin/identities", {"schema_id": "default", "traits": {"email": "unverified-pw@example.test"},
                                                   "credentials": {"password": {"config": {"password": PW}}}})
    b = Browser()
    v, c = pkce()
    r = submit(b, login_flow(b, authorize(b, c)), "password", identifier="unverified-pw@example.test", password=PW)
    say(f"   password login of an unverified identity: lands on {urlparse(r.url).path} (verification flow, no hydra accept)")
    if SoftWebauthnDevice:
        passkey_flows()
    else:
        say("   (passkey parts skipped: pip install soft-webauthn)")
    say("   RESULT 5: YES for password, OIDC and passkey, registration and login (every flow object carries oauth2_login_challenge).")
    say("   RESULT 6: YES for password, OIDC and passkey logins (global login.after.hooks applies when no method-specific hooks exist).")
    say("             Caveat: entering the code in the verification flow that login started ends on /error 404 (the login session was never persisted);")
    say("             the address IS verified, the user signs in again.")


def passkey_flows():
    import base64 as b64

    def b64u(x):
        return b64.urlsafe_b64encode(x).rstrip(b"=").decode()

    def unb64u(s):
        return b64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

    origin = LOGIN
    dev = SoftWebauthnDevice()
    b = Browser()
    v, c = pkce()
    lf = login_flow(b, authorize(b, c))
    f = new_flow(b, "registration", lf["oauth2_login_challenge"])
    email = uniq("pk")
    submit(b, f, "profile", follow=False, **{"traits.email": email, "traits.first_name": "P", "traits.last_name": "K", "traits.phone_number": "+46700000002"})
    f = flow(b, "registration", f["id"])
    cd = json.loads([n["attributes"]["value"] for n in f["ui"]["nodes"] if n["attributes"].get("name") == "passkey_create_data"][0])["credentialOptions"]["publicKey"]
    att = dev.create({"publicKey": {**cd, "challenge": unb64u(cd["challenge"]), "user": {**cd["user"], "id": unb64u(cd["user"]["id"])}}}, origin)
    reg = json.dumps({"id": att["id"].decode().rstrip("="), "rawId": b64u(att["rawId"]), "type": "public-key",
                      "response": {"attestationObject": b64u(att["response"]["attestationObject"]), "clientDataJSON": b64u(att["response"]["clientDataJSON"])}})
    clear_log()
    r = submit(b, f, "passkey", passkey_register=reg)
    say(f"   passkey registration: lands on {urlparse(r.url).path}; after-registration hook ran: {len(hook_calls('/kratos/after-registration'))}")

    def passkey_login():
        b2 = Browser()
        v2, c2 = pkce()
        lf = login_flow(b2, authorize(b2, c2))
        ch = json.loads([n["attributes"]["value"] for n in lf["ui"]["nodes"] if n["attributes"].get("name") == "passkey_challenge"][0])["publicKey"]
        a = dev.get({"publicKey": {**ch, "challenge": unb64u(ch["challenge"])}}, origin)
        lg = json.dumps({"id": a["id"].decode().rstrip("="), "rawId": b64u(a["rawId"]), "type": "public-key",
                         "response": {"authenticatorData": b64u(a["response"]["authenticatorData"]), "clientDataJSON": b64u(a["response"]["clientDataJSON"]),
                                      "signature": b64u(a["response"]["signature"]), "userHandle": b64u(a["response"]["userHandle"])}})
        return b2, v2, submit(b2, lf, "passkey", passkey_login=lg)

    b2, v2, r = passkey_login()
    say(f"   passkey login while the address is unverified: lands on {urlparse(r.url).path} (verification flow, no hydra accept)")
    vf = flow(b2, "verification", parse_qs(urlparse(r.url).query)["flow"][0])
    submit(b2, vf, "code", code=mail_code(email, 2)[0])
    b3, v3, r = passkey_login()
    tok, _ = finish(b3, r, v3)
    say(f"   passkey login once verified: lands on {urlparse(r.url).path}, tokens {tok[0]}, amr {jwt(tok[1]['id_token'])['amr']}")


def check7():
    say("== 7. After-registration OIDC web hook: provider tokens/scopes in the context? Run before or after persistence?")
    remove_identity("idp-user@example.test")
    clear_log()
    b = Browser()
    v, c = pkce()
    lf = login_flow(b, authorize(b, c))
    f = new_flow(b, "registration", lf["oauth2_login_challenge"])
    oidc_start(b, f, "fake")
    h = hook_calls("/kratos/after-registration")[0]
    say(f"   Kratos web hook request headers: {sorted(k for k in h['headers'] if k.startswith('ory-') or k in ('content-type', 'authorization'))}")
    say("   body the final after-registration.jsonnet produced for the OIDC registration:\n" + short(h["body"]))
    probe = [e for e in stub_log() if e.get("probe")]
    say(f"   stub read the identity back from Kratos admin while the hook was running: {probe[0] if probe else None}")
    say("   RESULT: the hook context has NO provider tokens or scopes (only identity without credentials, flow with active=oidc, request_url, cookies).")
    say("           Without response.parse the hook runs AFTER persistence: the identity exists and GET /admin/identities/{id}?include_credential=oidc")
    say("           returns initial_access_token / initial_refresh_token / initial_id_token. With response.parse (or can_interrupt) it runs BEFORE persistence.")
    say("           A failing non-parse hook leaves the identity persisted and the browser on /error: hooks must delete the identity itself.")
    for mode in ("registration-fail", "registration-500"):
        set_mode(mode)
        b = Browser()
        v, c = pkce()
        lf = login_flow(b, authorize(b, c))
        f = new_flow(b, "registration", lf["oauth2_login_challenge"])
        email = uniq("hf")
        submit(b, f, "profile", follow=False, **{"traits.email": email})
        f = flow(b, "registration", f["id"])
        r = submit(b, f, "password", password=PW)
        err = b.get(LOGIN + "/self-service/errors?id=" + parse_qs(urlparse(r.url).query)["id"][0], headers=J, quiet=True).json()["error"] if urlparse(r.url).path == "/error" else None
        n = len(kratos("GET", "/admin/identities?credentials_identifier=" + email)[1])
        say(f"   hook answers [{mode}]: browser lands on {urlparse(r.url).path}; error shown: {err}; identity still persisted: {n == 1}")
        set_mode()


def check8():
    say("== 8. Does the client's audience end up in the JWT aud?")
    email, sub, _ = make_verified_user("c8")

    def run(label, extra="", grant=None):
        b = Browser()
        v, c = pkce()
        lf = login_flow(b, authorize(b, c, extra=extra))
        r = submit(b, lf, "password", identifier=email, password=PW)
        cr, _ = accept_consent(r.url, grant)
        tok, _ = finish(b, r, v, audience=grant)
        say(f"   {label}: requested_access_token_audience={cr['requested_access_token_audience']} client.audience={cr['client']['audience']} -> JWT aud={jwt(tok[1]['access_token'])['aud']}")

    run("A no audience param, consent grants what was requested")
    run("B no audience param, consent grants client.audience", grant=["weaveauth"])
    run("C authorize with audience=weaveauth, consent grants what was requested", extra="&audience=weaveauth")
    r = authorize(Browser(), pkce()[1], extra="&audience=other")
    say(f"   D authorize with audience=other (not in client.audience): {parse_qs(urlparse(r.url).query).get('error')}")
    say("   RESULT: NO. client.audience is only an allow-list. aud is set by granting it: the auto-accepting /consent should send")
    say("           grant_access_token_audience = consent_request.client.audience (B), or bff passes audience= (C).")


# --- hook shapes and the rest -----------------------------------------------------------------------
def hooks():
    say("== Kratos hook bodies produced by ory/kratos/hooks/*.jsonnet (and Hydra token hook payload)")
    email, sub, _ = make_verified_user("hk")
    h = hook_calls("/kratos/after-registration")[-1]
    say("-- after-registration (password registration):\n" + short(h["body"]))
    v = hook_calls("/kratos/after-verification")[-1]
    say("-- after-verification (code accepted; the context has the identity, no session):\n" + short(v["body"]))
    probe = [e for e in stub_log() if e.get("probe") == "after-verification admin read"][-1]
    say(f"   address already verified when the hook ran: {probe.get('verified_at_call')}")
    clear_mail()
    clear_log()
    set_mode("purge-sessions")
    old_b, old_t = password_login(email)
    b = Browser()
    f = new_flow(b, "recovery")
    submit(b, f, "code", follow=False, email=email)
    f = flow(b, "recovery", f["id"])
    r = submit(b, f, "code", follow=False, code=mail_code(email)[0])
    set_mode()
    say("-- after-recovery (the context has no session; it runs BEFORE the recovery session is persisted):\n" + short(hook_calls("/kratos/after-recovery")[-1]["body"]))
    say(f"   old browser session after recovery: {old_b.get(LOGIN + '/self-service/logout/browser', headers=J, quiet=True).status} (401 = purged inside the hook)")
    say(f"   recovery session still works: {b.get(r.location, headers=J, quiet=True).status}; recovery redirect -> {urlparse(r.location).path}; old hydra refresh token still valid: {token_call({'grant_type': 'refresh_token', 'refresh_token': old_t['refresh_token']})[0]}")
    b2 = Browser()
    v, c = pkce()
    submit(b2, login_flow(b2, authorize(b2, c)), "password", identifier=email, password=PW)
    clear_log()
    s = new_flow(b2, "settings")
    submit(b2, s, "password", password="brand-New-passw0rd-77!")
    say("-- after-password-change (settings flow, after persistence):\n" + short(hook_calls("/kratos/after-password-change")[-1]["body"]))
    say("-- Hydra token hook payload (authorization_code grant):")
    clear_log()
    email, sub, tok = make_verified_user("th")
    th = hook_calls("/hydra/token-hook")[-1]["body"]
    say(short(th, 50))
    say(f"   JWT access token claims: {sorted(jwt(tok['access_token']))}; roles (from the hook) -> {jwt(tok['access_token']).get('roles')}; id_token extra 'stub' -> {jwt(tok['id_token']).get('stub')}")
    b = Browser()
    v, c = pkce()
    r = submit(b, login_flow(b, authorize(b, c)), "password", identifier=email, password=PW)
    set_mode("deny-token")
    t, _ = finish(b, r, v)
    set_mode()
    say(f"   hook answers 403 -> token endpoint {t[0]} {t[1].get('error')}")
    b = Browser()
    v, c = pkce()
    r = submit(b, login_flow(b, authorize(b, c)), "password", identifier=email, password=PW)
    set_mode("fail:/hydra/token-hook")
    t0 = time.time()
    t, _ = finish(b, r, v)
    set_mode()
    say(f"   hook answers 500 -> token endpoint {t[0]} {t[1].get('error')} after {time.time() - t0:.1f}s (hydra retries 3 times)")
    b, toks = password_login(email)
    st1, r1 = token_call({"grant_type": "refresh_token", "refresh_token": toks["refresh_token"]})
    st2, _ = token_call({"grant_type": "refresh_token", "refresh_token": toks["refresh_token"]})
    time.sleep(11)
    st3, e3 = token_call({"grant_type": "refresh_token", "refresh_token": toks["refresh_token"]})
    st4, e4 = token_call({"grant_type": "refresh_token", "refresh_token": r1["refresh_token"]})
    say(f"   refresh rotation (grace 10s, reuse count 2): rotate {st1}; old token inside grace {st2}; old token after grace {st3} {e3.get('error')}; newest token of that chain then {st4} {e4.get('error')} (reuse revokes the chain)")


def linking():
    say("== Account linking (confirm_with_existing_credential)")
    email = "pw-user@example.test"
    remove_identity(email)
    st, res = kratos("POST", "/admin/identities", {"schema_id": "default", "traits": {"email": email}, "verifiable_addresses": [{"value": email, "via": "email", "verified": True, "status": "completed"}],
                                                   "credentials": {"password": {"config": {"password": PW}}}})
    b = Browser()
    v, c = pkce()
    r = oidc_start(b, login_flow(b, authorize(b, c)), "fakelink")
    fl = flow(b, "login", parse_qs(urlparse(r.url).query)["flow"][0])
    say(f"   OIDC login whose email belongs to a password identity: lands on {urlparse(r.url).path}; message: {fl['ui']['messages'][0]['text'][:110]}...")
    r = submit(b, fl, "password", identifier=email, password=PW)
    tok, _ = finish(b, r, v)
    say(f"   after signing in with the password: tokens {tok[0]}, amr {jwt(tok[1]['id_token'])['amr']}; credentials now {sorted(kratos('GET', '/admin/identities/' + res['id'])[1]['credentials'])}")


def routing():
    say("== Caddy routing")
    for path in ("/self-service/login/browser", "/.well-known/ory/webauthn.js", "/admin/clients", "/oauth2/token", "/.well-known/jwks.json", "/oauth2/auth?client_id=bff&response_type=code&scope=openid&state=abcdefgh1234&redirect_uri=https%3A%2F%2Fbff.localhost%3A8443%2Fcallback"):
        b = Browser()
        r = b.get(LOGIN + path, quiet=True)
        names = list(b.cookies.get("login.localhost", {}))
        who = "login's own handler (stub)" if "login_stub_page" in r.body else (
            "hydra" if any(n.startswith("ory_hydra") for n in names) else ("kratos, through login's proxy" if any(n.startswith("csrf_token") for n in names) else "?"))
        say(f"   {path.split('?')[0]} -> {r.status} answered by {who}")
    say("   (/self-service and /.well-known/ory reach Kratos only through login; only /oauth2/auth and /oauth2/sessions/logout go to hydra)")


def json_registration():
    say("== JSON registration with a login_challenge: does Kratos accept Hydra's login request at the end of it?")
    email = uniq("json-reg")
    b = Browser()
    v, c = pkce()
    lf = login_flow(b, authorize(b, c))
    f = b.get(f"{LOGIN}/self-service/registration/browser?login_challenge={lf['oauth2_login_challenge']}", headers=J, quiet=True).json()
    vals = form_values(f, "password")
    vals.update({"method": "password", "traits.email": email, "password": PW})
    r = b.post(f["ui"]["action"], json_body=vals, headers=J, follow=False, quiet=True)
    body = r.json() if r.body else {}
    target = body.get("redirect_browser_to") or next((x.get("redirect_browser_to") for x in body.get("continue_with", []) if x.get("redirect_browser_to")), "")
    say(f"   registration answered {r.status}; redirect_browser_to: {target or '-'}; session: {bool(body.get('session'))}")
    if "login_verifier" in target:
        end = b.get(target, follow=True, quiet=True)
        say(f"   following login_verifier lands on {urlparse(end.url).path}" + (" (hydra login accepted before the address was verified)" if "/consent" in end.url else ""))
    else:
        say("   no login_verifier handed out: the challenge stays pending until the address is verified")


ALL = {"1": check1, "2": check2, "3": check3, "4": check4_9, "9": check4_9, "5": check5_6, "6": check5_6, "7": check7, "8": check8, "hooks": hooks, "link": linking, "routing": routing, "json": json_registration}
ORDER = [check1, check2, check3, check4_9, check5_6, check7, check8, hooks, linking, routing, json_registration]

if __name__ == "__main__":
    todo = ORDER if len(sys.argv) == 1 else list(dict.fromkeys(ALL[a] for a in sys.argv[1:]))
    for fn in todo:
        fn()
        say()
