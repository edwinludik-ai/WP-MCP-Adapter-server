#!/usr/bin/env python3
"""End-to-end smoke test for the key-protected MCP endpoint (standard library only).

Start WordPress with this plugin and the MCP Adapter active (see README, "Development"), then:

    python3 tests/smoke.py [base-url]        # default http://127.0.0.1:9400

The script creates its own keys through the admin screen, so the site must log the first visitor in as an
administrator (Playground's --login) and have Application Passwords available (tests/blueprint.json does that).
"""
import base64
import http.cookiejar
import json
import re
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:9400").rstrip("/")
ROUTE = "/wp-json/mcp-keys/mcp"
DEFAULT_SERVER = "/wp-json/mcp/mcp-adapter-default-server"
PAGE = BASE + "/wp-admin/options-general.php?page=mcp-api-keys"
KEY_RE = r"mcpk_[0-9a-f]{8}_[A-Za-z0-9_-]{43}"

admin = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))  # the logged-in admin
fails = []


# --- admin session -----------------------------------------------------------------------------------------------

def admin_get(url):
    return admin.open(url, timeout=60).read().decode()


def admin_post(data, headers=None):
    req = urllib.request.Request(BASE + "/wp-admin/admin-post.php", urllib.parse.urlencode(data).encode(), headers or {})
    try:
        r = admin.open(req, timeout=60)
        return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def admin_rest(method, path, body=None):
    """A REST call as the logged-in administrator (cookie + nonce)."""
    nonce = admin_get(BASE + "/wp-admin/admin-ajax.php?action=rest-nonce")
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data, {"Content-Type": "application/json", "X-WP-Nonce": nonce}, method=method)
    return json.loads(admin.open(req, timeout=60).read().decode())


def wait_for_admin():
    """The first anonymous request to Playground logs us in; retry until the admin screen (with its nonce) loads."""
    for _ in range(60):
        try:
            if "_wpnonce" in admin_get(PAGE):
                return
        except OSError:
            pass
        time.sleep(2)
    sys.exit("could not load the admin screen as an administrator")


def create_key(label, ips="", user_id=1, headers=None):
    html = admin_get(PAGE)
    nonce = re.findall(r'name="_wpnonce" value="([a-z0-9]+)"', html)[-1]  # the create form comes after the revoke forms
    status, body = admin_post({"action": "mcpk_create", "_wpnonce": nonce, "label": label, "user_id": user_id, "ips": ips}, headers)
    m = re.search(KEY_RE, body)
    return status, (m.group(0) if m else None)


def revoke_key(key_id):
    html = admin_get(PAGE)
    m = re.search(r'name="id" value="%s">\s*<input[^>]*name="_wpnonce" value="([a-z0-9]+)"' % key_id, html)
    return admin_post({"action": "mcpk_revoke", "id": key_id, "_wpnonce": m.group(1)})[0] if m else None


# --- anonymous MCP requests (no admin cookies) -------------------------------------------------------------------

def call(path, body, headers=None):
    h = {
        "Content-Type": "application/json",
        "MCP-Protocol-Version": "2025-06-18",
        "Cookie": "playground_auto_login_already_happened=1",  # stops Playground logging anonymous requests in
    }
    h.update(headers or {})
    try:
        r = urllib.request.urlopen(urllib.request.Request(BASE + path, json.dumps(body).encode(), h), timeout=60)
        return r.status, r.read().decode(), r.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), e.headers


def check(name, got, want, also=True):
    ok = got == want and also
    print(("PASS " if ok else "FAIL ") + f"{name}  (http {got}, want {want})")
    if not ok:
        fails.append(name)


def rpc(method, id_=1, **params):
    return {"jsonrpc": "2.0", "id": id_, "method": method, "params": params}


INIT = rpc("initialize", 0, protocolVersion="2025-06-18", capabilities={}, clientInfo={"name": "smoke", "version": "1"})
LIST = rpc("tools/list")
CALL = rpc("tools/call", 2, name="mcp-keys-get-site-info", arguments={})
bearer = lambda k: {"Authorization": "Bearer " + k}  # noqa: E731
basic = lambda user, pw: {"Authorization": "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()}  # noqa: E731


def main():
    wait_for_admin()

    # keys, all created through the admin screen
    s, any_key = create_key("any ip")
    check("create key (any IP)", s, 200, any_key is not None)
    _, blocked_key = create_key("blocked", "203.0.113.0/24")
    _, local_key = create_key("loopback", "127.0.0.1\n::1\n::ffff:127.0.0.1")
    s, bad = create_key("bad rule", "10.0.0.0/33")
    check("invalid IP rule rejected at save", s, 400, bad is None)
    listing = admin_get(PAGE)
    check("key list never shows a full key", 200, 200, not any(k in listing for k in (any_key, blocked_key, local_key)))

    # the endpoint with a valid key
    s, b, h = call(ROUTE, INIT, bearer(any_key))
    check("initialize with Bearer key", s, 200, "serverInfo" in b)
    sid = {"Mcp-Session-Id": h.get("Mcp-Session-Id")} if h.get("Mcp-Session-Id") else {}
    s, b, _ = call(ROUTE, LIST, {**bearer(any_key), **sid})
    check("tools/list with Bearer key", s, 200, "mcp-keys-get-site-info" in b)
    s, b, _ = call(ROUTE, LIST, {"X-API-Key": any_key, **sid})
    check("tools/list with X-API-Key", s, 200)
    s, b, _ = call(ROUTE, CALL, {**bearer(any_key), **sid})
    check("tools/call get-site-info", s, 200, "site_name" in b)

    # rejected credentials
    s, b, _ = call(ROUTE, LIST)
    check("no auth header", s, 401, "mcpk_missing" in b)
    s, b, _ = call(ROUTE, LIST, bearer(any_key[:14] + "A" * 43))
    check("right id, wrong secret", s, 401, "mcpk_invalid" in b)
    s, b, _ = call(ROUTE, LIST, bearer("mcpk_00000000_" + "A" * 43))
    check("unknown id", s, 401, "mcpk_invalid" in b)
    s, b, _ = call(ROUTE, LIST, basic("admin", "wrong"))
    check("Basic auth header (junk)", s, 401, "mcpk_missing" in b)

    # a real Application Password and the admin cookie must not work on the key-only route
    nonce = admin_get(BASE + "/wp-admin/admin-ajax.php?action=rest-nonce")
    req = urllib.request.Request(
        BASE + "/wp-json/wp/v2/users/me/application-passwords",
        json.dumps({"name": "smoke"}).encode(),
        {"Content-Type": "application/json", "X-WP-Nonce": nonce},
    )
    app_pw = json.loads(admin.open(req, timeout=60).read().decode())["password"]
    s, b, _ = call(ROUTE, LIST, basic("admin", app_pw))
    check("Application Password on key-only route", s, 401, "mcpk_missing" in b)
    s, _, _ = call(DEFAULT_SERVER, INIT, basic("admin", app_pw))
    check("(control) same Application Password on default server", s, 200)
    s, _, _ = call(DEFAULT_SERVER, INIT, bearer(any_key))
    check("API key on default server", s, 401)
    req = urllib.request.Request(BASE + ROUTE, json.dumps(LIST).encode(), {"Content-Type": "application/json", "X-WP-Nonce": nonce})
    try:
        r = admin.open(req, timeout=60)
        s, b = r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        s, b = e.code, e.read().decode()
    check("admin cookie + nonce, no key", s, 401, "mcpk_missing" in b)

    # route spellings core still dispatches (case-insensitive, trailing newline)
    for label, path in (
        ("uppercase path", "/wp-json/MCP-KEYS/mcp"),
        ("mixed-case rest_route", "/?rest_route=/Mcp-Keys/MCP"),
        ("rest_route with trailing newline", "/?rest_route=/mcp-keys/mcp%0A"),
    ):
        s, b, _ = call(path, INIT, basic("admin", app_pw))
        check(f"Application Password, {label}", s, 401, "mcpk_" in b)
        s, b, _ = call(path, INIT, bearer(any_key[:14] + "A" * 43))
        check(f"wrong key, {label}", s, 401, "mcpk_invalid" in b)

    # IP allowlist
    s, b, _ = call(ROUTE, INIT, bearer(blocked_key))
    check("key limited to 203.0.113.0/24", s, 403, "mcpk_ip" in b)
    s, b, _ = call(ROUTE, INIT, bearer(local_key))
    check("key limited to loopback addresses", s, 200, "serverInfo" in b)

    # hardening: keys need HTTPS (the blueprint's test hook turns the requirement on per request with a header)
    s, b, _ = call(ROUTE, INIT, {**bearer(any_key), "X-Smoke-Require-Https": "1"})
    check("key refused over plain HTTP when HTTPS is required", s, 403, "mcpk_https" in b)
    s, refused = create_key("over http", headers={"X-Smoke-Require-Https": "1"})
    check("key creation refused over plain HTTP when HTTPS is required", s, 403, refused is None)

    # hardening: an error from an earlier REST auth filter (a firewall, say) is not overridden by a valid key
    s, b, _ = call(ROUTE, INIT, {**bearer(any_key), "X-Smoke-Block": "1"})
    check("earlier filter's refusal is honoured despite a valid key", s, 403, "smoke_block" in b)

    # hardening: key-authenticated responses must not be cached
    s, _, h = call(ROUTE, INIT, bearer(any_key))
    check("key-authenticated response is not cacheable", s, 200, "no-store" in (h.get("Cache-Control") or ""))

    # last-used time is shown (it is stored apart from the key records)
    key_id_any = re.match(r"mcpk_([0-9a-f]{8})_", any_key).group(1)
    row = re.search(r"<tr>(?:(?!</tr>).)*mcpk_%s_…(?:(?!</tr>).)*</tr>" % key_id_any, admin_get(PAGE), re.S)
    cells = [re.sub(r"<[^>]+>", "", c).strip() for c in re.findall(r"<td[^>]*>(.*?)</td>", row.group(0), re.S)] if row else []
    check("last-used time is listed after a key is used", 200, 200, len(cells) > 5 and cells[5] != "never")

    # hardening: deleting a user revokes their keys
    user = admin_rest("POST", "/wp-json/wp/v2/users", {"username": "smoke_user", "email": "smoke_user@example.com", "password": secrets.token_urlsafe(18), "roles": ["subscriber"]})
    s, user_key = create_key("subscriber key", user_id=user["id"])
    check("create a key for a subscriber", s, 200, user_key is not None)
    s, b, _ = call(ROUTE, INIT, bearer(user_key))
    check("subscriber's key works", s, 200, "serverInfo" in b)
    admin_rest("DELETE", f"/wp-json/wp/v2/users/{user['id']}?force=true&reassign=1")
    s, _, _ = call(ROUTE, INIT, bearer(user_key))
    check("deleted user's key is rejected", s, 401)
    user_key_id = re.match(r"mcpk_([0-9a-f]{8})_", user_key).group(1)
    check("deleted user's key is removed from the list", 200, 200, "mcpk_%s_" % user_key_id not in admin_get(PAGE))

    # revoke
    key_id = re.match(r"mcpk_([0-9a-f]{8})_", any_key).group(1)
    check("revoke redirects back to the list", revoke_key(key_id), 200)
    s, b, _ = call(ROUTE, LIST, {**bearer(any_key), **sid})
    check("revoked key rejected immediately", s, 401, "mcpk_invalid" in b)

    print("\nFAILED: " + ", ".join(fails) if fails else "\nALL PASS")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
