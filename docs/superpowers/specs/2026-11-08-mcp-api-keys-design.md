# MCP API Keys plugin: design (short)

## Intent
Site owners want AI clients (Claude Code, Cursor, etc.) to reach a WordPress site through the WordPress MCP Adapter using a revocable API key instead of a user's Application Password, with an optional IP allowlist (IPv4 and IPv6). The plugin also implements the adapter's getting-started Step 2 (register an ability) and Step 3 (create a custom MCP server).

## Goals
- Step 2: register `mcp-keys/get-site-info` exactly as the docs do.
- Step 3: create a custom server at `/wp-json/mcp-keys/mcp` exposing that ability as a tool.
- Generate API keys in wp-admin, shown once, stored only as a hash.
- Each key is bound to one existing WordPress user (picked at creation); requests act with that user's capabilities.
- Optional per-key IP allowlist: exact IPs and CIDR ranges, v4 and v6. Empty list = any IP.
- Revoke a key; see label, user, IPs, created and last-used.

## Non-goals
- OAuth (claude.ai / ChatGPT connectors cannot use API keys).
- Touching the adapter's default server or cookie/Application Password auth.
- Trusted-proxy / `X-Forwarded-For` handling (spoofable; add later behind an explicit setting).
- Rate limiting, key expiry, per-key ability scopes.

## Anti-goals
- Plaintext or reversibly-encrypted keys anywhere (DB, logs, admin pages after creation).
- An IP allowlist that can be bypassed by sending a cookie or Application Password to the same route.

## Constraints
- Needs the MCP Adapter plugin (class `WP\MCP\Core\McpAdapter`) and WordPress 6.9+. PHP 7.4+.
- Abilities check `current_user_can()`, so a key must resolve to a real user.

## Approaches
- **A. Authenticate in `rest_authentication_errors` on our route only (picked).** Look up the key, check the IP, `wp_set_current_user()`, return `true`; wrong/missing key or IP = 401/403. The custom server becomes key-only, so the allowlist cannot be skipped. Default server untouched.
- B. Transport permission callback that validates the key. The callback runs after core auth; a request with a cookie user would still pass unless re-checked, and the user must be switched by hand. Messier for the same result.
- C. Lean on WordPress Application Passwords and add an IP filter. Smallest diff and already hashed, but needs HTTPS, uses Basic auth, has no dedicated key screen, and some security plugins disable it. Doesn't match "API keys".

## Design
- **Key format:** `mcpk_<id>_<secret>`; `id` = 8 hex chars (lookup), `secret` = 32 random bytes, base64url. Sent as `Authorization: Bearer <key>` or `X-API-Key`.
- **Storage:** option `mcp_keys_keys` (autoload off), array keyed by `id`: `label, user_id, hash, ips[], created, last_used`. `hash = hash_hmac('sha256', key, wp_salt('auth'))`, compared with `hash_equals`. A leaked DB alone cannot reproduce a key.
- **IP match:** `REMOTE_ADDR` only. Normalise with `inet_pton`; IPv4-mapped IPv6 (`::ffff:1.2.3.4`) is treated as IPv4. CIDR compares masked bytes. Invalid allowlist entries are rejected at save time.
- **Errors:** no key on our route = 401; unknown key / hash mismatch = 401; IP not allowed = 403; user deleted = 401. Same message for unknown id and bad secret.
- **Last used:** updated at most once per hour per key, to avoid an option write per request.
- **Admin:** Settings > MCP API Keys. Create form (label, user dropdown, IPs one per line). The new key is rendered directly in the create-form POST response (no redirect, never persisted anywhere, not even a transient). List with Revoke. Capability `manage_options`, nonces on both actions.
- **Layout:** one plugin file `mcp-api-keys.php` plus `tests/check.php` (plain PHP asserts for key hashing, CIDR v4/v6, mapped addresses).

## Left to the builder
Exact admin markup, translation strings, plugin header text, whether the ability needs `meta.public` for explicit server tool lists (check against the installed adapter version).
