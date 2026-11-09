# MCP API Keys Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A WordPress plugin that registers the adapter docs' Step 2 ability and Step 3 custom server, and protects that server with hashed, revocable API keys bound to a WordPress user, each with an optional IPv4/IPv6 allowlist.

**Architecture:** One plugin file `mcp-api-keys.php` holds everything. Pure functions (no WordPress calls: key generation, HMAC, header parsing, IP/CIDR matching, request verification) are unit-checked by `tests/check.php`, which stubs `add_action`/`add_filter` and loads the plugin file. A thin WordPress layer (storage, `rest_authentication_errors` filter, ability, server, admin page) sits on top and is verified by a smoke test against a real WordPress.

**Tech Stack:** PHP 7.4+, WordPress 6.9+, MCP Adapter plugin, `@wp-playground/cli` for the smoke test.

**Spec:** `docs/superpowers/specs/2026-11-08-mcp-api-keys-design.md`

## Global Constraints

- PHP 7.4 syntax only: no `match`, union types, `str_contains`, named arguments, nullsafe `?->`.
- Plugin header: `Requires Plugins: mcp-adapter`, `Requires at least: 6.9`, `Requires PHP: 7.4`.
- Ability id `mcp-keys/get-site-info`, category `site`, **no `meta.public`** (so it is not exposed on the adapter's default server). Tool name becomes `mcp-keys-get-site-info`.
- Server: id `mcp-keys-server`, REST namespace `mcp-keys`, route `mcp` (`/wp-json/mcp-keys/mcp`), `HttpTransport`, `ErrorLogMcpErrorHandler`, created on `mcp_adapter_init`, exposes only that ability.
- Key format `mcpk_<id>_<secret>`: `id` = 8 lowercase hex chars; `secret` = base64url of 32 random bytes, no padding (43 chars). Accepted as `Authorization: Bearer <key>` or `X-API-Key: <key>`.
- Storage: option `mcp_keys_keys`, autoload off, array keyed by `id`: `label, user_id, hash, ips[], created, last_used`. `hash = hash_hmac('sha256', $key, wp_salt('auth'))`, compared with `hash_equals`. The plaintext key is never stored anywhere.
- IP source is `$_SERVER['REMOTE_ADDR']` only. Never read `X-Forwarded-For`. Empty allowlist = any IP; non-empty allowlist + missing/invalid address = deny.
- Errors on the `/mcp-keys/mcp` route: no key 401, unknown id or bad secret 401 (same message), IP not allowed 403, key's user deleted 401. Requests to other routes are untouched.
- Do not commit or push unless the user asks. Do not add `.idea/`.

## Review Focus

- `REMOTE_ADDR` arrives IPv4-mapped (`::ffff:203.0.113.7`) on dual-stack hosts and the rule is `203.0.113.0/24`: allowed. (Task 1)
- Allowlist is non-empty but `REMOTE_ADDR` is missing or garbage: denied, not allowed. (Task 1, Task 2)
- Rule typos (`10.0.0.0/33`, `::1/129`, `1.2.3`, `10.0.0.0/`, `abc`) are rejected at save; `10.0.0.5/24` (host bits set) is accepted and matches the whole /24. (Task 1)
- A request with `Authorization: Basic ...` (an Application Password) or a cookie on the key-only route gets 401, never falls through to normal auth. (Task 2, Task 5)
- IPs textarea with CRLF, commas, blank lines and duplicates yields a clean list. (Task 1)

---

### Task 1: IP rules (pure functions)

**Files:**
- Create: `mcp-api-keys.php` (header + these functions; `defined( 'ABSPATH' ) || exit;` at top)
- Create: `tests/check.php`

**Interfaces:**
- Produces:
  - `mcpk_ip_to_bin( string $ip ): ?string`: `inet_pton` result; IPv4-mapped IPv6 collapses to the 4-byte IPv4 form; `null` if not an IP.
  - `mcpk_rule_valid( string $rule ): bool`: a bare IP, or `IP/prefix` with prefix 0-32 (v4) or 0-128 (v6), digits only. A mapped-IPv6 literal is valid only without a prefix.
  - `mcpk_ip_allowed( ?string $ip, array $rules ): bool`: empty `$rules` → true; `$ip` null/invalid → false; otherwise true if any rule matches (same address family, masked bytes equal). Invalid rules in the array never match.
  - `mcpk_parse_rules( string $text ): array`: splits on whitespace and commas, drops blanks and duplicates, returns `[ 'rules' => string[], 'invalid' => string[] ]`.

- [ ] **Step 1: Write the failing checks**

`tests/check.php` starts with: `define( 'ABSPATH', '/' );`, no-op `function add_action() {}` and `function add_filter() {}`, a helper `function ok( $cond, $msg ) { if ( ! $cond ) { fwrite( STDERR, "FAIL: $msg\n" ); exit( 1 ); } }`, then `require __DIR__ . '/../mcp-api-keys.php';`, ends with `echo "OK\n";`. Assertions to add:

```php
ok( mcpk_ip_allowed( '203.0.113.7', array( '203.0.113.0/24' ) ), 'v4 cidr' );
ok( ! mcpk_ip_allowed( '203.0.114.7', array( '203.0.113.0/24' ) ), 'v4 cidr miss' );
ok( mcpk_ip_allowed( '::ffff:203.0.113.7', array( '203.0.113.0/24' ) ), 'mapped addr vs v4 rule' );
ok( mcpk_ip_allowed( '203.0.113.7', array( '::ffff:203.0.113.7' ) ), 'v4 addr vs mapped rule' );
ok( mcpk_ip_allowed( '2001:db8::1', array( '2001:db8::/32' ) ), 'v6 cidr' );
ok( ! mcpk_ip_allowed( '2001:db9::1', array( '2001:db8::/32' ) ), 'v6 cidr miss' );
ok( mcpk_ip_allowed( '::1', array( '::1' ) ), 'v6 exact' );
ok( ! mcpk_ip_allowed( '::1', array( '127.0.0.1' ) ), 'families never cross' );
ok( mcpk_ip_allowed( '10.0.0.200', array( '10.0.0.5/24' ) ), 'host bits set still masks' );
ok( mcpk_ip_allowed( '8.8.8.8', array( '0.0.0.0/0' ) ), '/0 allows all v4' );
ok( mcpk_ip_allowed( 'garbage', array() ) && mcpk_ip_allowed( null, array() ), 'empty rules allow anything' );
ok( ! mcpk_ip_allowed( null, array( '1.2.3.4' ) ) && ! mcpk_ip_allowed( 'garbage', array( '1.2.3.4' ) ), 'fail closed' );
foreach ( array( '10.0.0.0/33', '::1/129', '1.2.3', '10.0.0.0/', 'abc', '::ffff:1.2.3.4/120', '1.2.3.4/-1' ) as $bad ) { ok( ! mcpk_rule_valid( $bad ), "invalid: $bad" ); }
foreach ( array( '1.2.3.4', '1.2.3.4/32', '::1', '2001:db8::/64', '::ffff:1.2.3.4' ) as $good ) { ok( mcpk_rule_valid( $good ), "valid: $good" ); }
$p = mcpk_parse_rules( "1.2.3.4\r\n\r\n::1, 1.2.3.4 ,bad\n" );
ok( $p['rules'] === array( '1.2.3.4', '::1' ) && $p['invalid'] === array( 'bad' ), 'parse_rules crlf/commas/dupes' );
```

- [ ] **Step 2: Run to verify failure**

Run: `php tests/check.php`
Expected: fatal "Call to undefined function mcpk_ip_allowed()" (or file-not-found before the plugin file exists).

- [ ] **Step 3: Implement the four functions in `mcp-api-keys.php`**

Mask comparison on the binary strings from `mcpk_ip_to_bin`: compare whole bytes with `substr`, then the remaining bits with a byte mask. Rule family comes from the binary length (4 vs 16).

- [ ] **Step 4: Run to verify pass**

Run: `php tests/check.php`
Expected: prints `OK`, exit 0.

---

### Task 2: Key generation, hashing, header parsing, request verification (pure functions)

**Files:**
- Modify: `mcp-api-keys.php`
- Modify: `tests/check.php`

**Interfaces:**
- Consumes: `mcpk_ip_allowed` from Task 1.
- Produces:
  - `mcpk_generate_key(): array`: `[ 'id' => string, 'key' => string ]` in the Global Constraints format. Uses `random_bytes`.
  - `mcpk_hash( string $key, string $salt ): string`: lowercase hex HMAC-SHA256.
  - `mcpk_extract_key( array $server ): ?string`: `HTTP_X_API_KEY` if non-empty, else the token of `HTTP_AUTHORIZATION` when its scheme is `Bearer` (case-insensitive); also checks `REDIRECT_HTTP_AUTHORIZATION`. Returns trimmed token, or `null` (including for `Basic`).
  - `mcpk_verify( array $keys, ?string $presented, ?string $ip, string $salt )`: returns the matching record array with an added `'id'` on success, or the string `'missing'` (`$presented` null), `'invalid'` (unparsable, unknown id, hash mismatch), or `'ip'` (secret correct but `mcpk_ip_allowed` false). Never reveals which of unknown-id / bad-secret occurred. IP is checked only after the secret verifies.

- [ ] **Step 1: Write the failing checks** (append to `tests/check.php` before the final `echo`)

```php
$g = mcpk_generate_key();
ok( preg_match( '/^mcpk_[0-9a-f]{8}_[A-Za-z0-9_-]{43}$/', $g['key'] ) === 1, 'key format' );
ok( strpos( $g['key'], 'mcpk_' . $g['id'] . '_' ) === 0, 'id embedded' );
ok( $g['key'] !== mcpk_generate_key()['key'], 'keys differ' );
ok( mcpk_hash( $g['key'], 's1' ) === mcpk_hash( $g['key'], 's1' ) && mcpk_hash( $g['key'], 's1' ) !== mcpk_hash( $g['key'], 's2' ), 'hash deterministic and salted' );

ok( mcpk_extract_key( array( 'HTTP_AUTHORIZATION' => 'Bearer abc ' ) ) === 'abc', 'bearer' );
ok( mcpk_extract_key( array( 'HTTP_AUTHORIZATION' => 'bearer abc' ) ) === 'abc', 'bearer case' );
ok( mcpk_extract_key( array( 'HTTP_X_API_KEY' => 'abc' ) ) === 'abc', 'x-api-key' );
ok( mcpk_extract_key( array( 'REDIRECT_HTTP_AUTHORIZATION' => 'Bearer abc' ) ) === 'abc', 'redirect header' );
ok( mcpk_extract_key( array( 'HTTP_AUTHORIZATION' => 'Basic dXNlcjpwYXNz' ) ) === null, 'basic auth is not a key' );
ok( mcpk_extract_key( array() ) === null, 'no header' );

$keys = array( $g['id'] => array( 'label' => 't', 'user_id' => 1, 'hash' => mcpk_hash( $g['key'], 'salt' ), 'ips' => array( '203.0.113.0/24' ), 'created' => 0, 'last_used' => 0 ) );
$r = mcpk_verify( $keys, $g['key'], '203.0.113.9', 'salt' );
ok( is_array( $r ) && $r['id'] === $g['id'] && $r['user_id'] === 1, 'verify ok' );
ok( mcpk_verify( $keys, null, '203.0.113.9', 'salt' ) === 'missing', 'missing' );
ok( mcpk_verify( $keys, 'junk', '203.0.113.9', 'salt' ) === 'invalid', 'unparsable' );
ok( mcpk_verify( $keys, 'mcpk_00000000_' . str_repeat( 'A', 43 ), '203.0.113.9', 'salt' ) === 'invalid', 'unknown id' );
ok( mcpk_verify( $keys, 'mcpk_' . $g['id'] . '_' . str_repeat( 'A', 43 ), '203.0.113.9', 'salt' ) === 'invalid', 'bad secret' );
ok( mcpk_verify( $keys, $g['key'], '198.51.100.1', 'salt' ) === 'ip', 'ip denied' );
ok( mcpk_verify( $keys, $g['key'], null, 'salt' ) === 'ip', 'no REMOTE_ADDR fails closed' );
ok( mcpk_verify( $keys, 'mcpk_' . $g['id'] . '_' . str_repeat( 'A', 43 ), '198.51.100.1', 'salt' ) === 'invalid', 'bad secret from bad ip reveals nothing about ip' );
ok( mcpk_verify( $keys, $g['key'], '203.0.113.9', 'other-salt' ) === 'invalid', 'wrong salt' );
```

- [ ] **Step 2: Run to verify failure**

Run: `php tests/check.php`
Expected: fatal "Call to undefined function mcpk_generate_key()".

- [ ] **Step 3: Implement the four functions** in `mcp-api-keys.php`. base64url = `rtrim( strtr( base64_encode( $bytes ), '+/', '-_' ), '=' )`. Parse with the regex from the check; compare with `hash_equals`.

- [ ] **Step 4: Run to verify pass**

Run: `php tests/check.php`
Expected: `OK`, exit 0.

---

### Task 3: WordPress layer: storage, auth filter, ability, server

**Files:**
- Modify: `mcp-api-keys.php` (add the plugin header comment block at the very top if not yet complete)

**Interfaces:**
- Consumes: `mcpk_generate_key`, `mcpk_hash`, `mcpk_extract_key`, `mcpk_verify` (Task 2).
- Produces:
  - `mcpk_create_key( string $label, int $user_id, array $ips ): string`: stores the record (option `mcp_keys_keys`, autoload off, `created` = `time()`, `last_used` = 0) and returns the plaintext key.
  - `mcpk_revoke_key( string $id ): void`.
  - `mcpk_authenticate( $result )`: hooked on `rest_authentication_errors`, priority 5.

- [ ] **Step 1: Implement `mcpk_create_key` and `mcpk_revoke_key`** over `get_option` / `update_option( ..., false )`, hashing with `wp_salt( 'auth' )`.

- [ ] **Step 2: Implement `mcpk_authenticate( $result )`**
  - Route check: `$GLOBALS['wp']->query_vars['rest_route']` starts with `/mcp-keys/mcp`; otherwise return `$result` untouched.
  - Otherwise ignore any earlier `$result`, call `mcpk_verify( get_option(...), mcpk_extract_key( $_SERVER ), $_SERVER['REMOTE_ADDR'] ?? null, wp_salt( 'auth' ) )`.
  - Map to `WP_Error`: `'missing'` → `mcpk_missing`, 401, "API key required"; `'invalid'` → `mcpk_invalid`, 401, "Invalid API key"; `'ip'` → `mcpk_ip`, 403, "IP address not allowed". Pass `array( 'status' => N )` as error data.
  - Success: `get_userdata( $record['user_id'] )` false → the `mcpk_invalid` 401 error. Else `wp_set_current_user( $id )`; if `time() - last_used > HOUR_IN_SECONDS`, write `last_used` back; return `true`.
  - Mark the unthrottled single-option write with a `// ponytail:` comment (concurrent requests can lose a last-used update).

- [ ] **Step 3: Register the Step 2 ability** on `wp_abilities_api_init`: copy the docs' `get-site-info` example with id `mcp-keys/get-site-info`, category `site`, `permission_callback` = `current_user_can( 'read' )`. No `meta.public`.

- [ ] **Step 4: Create the Step 3 server** on `mcp_adapter_init` (`$adapter->create_server( 'mcp-keys-server', 'mcp-keys', 'mcp', 'MCP API Keys Server', 'WordPress MCP server protected by API keys', '1.0.0', array( \WP\MCP\Transport\HttpTransport::class ), \WP\MCP\Infrastructure\ErrorHandling\ErrorLogMcpErrorHandler::class, null, array( 'mcp-keys/get-site-info' ) )`). No custom transport permission callback: the default (logged-in user) is satisfied by `mcpk_authenticate`.

- [ ] **Step 5: Verify syntax and that pure checks still pass**

Run: `php -l mcp-api-keys.php && php tests/check.php`
Expected: `No syntax errors detected` then `OK`. (End-to-end behaviour is verified in Task 5.)

---

### Task 4: Admin screen

**Files:**
- Modify: `mcp-api-keys.php`

**Interfaces:**
- Consumes: `mcpk_parse_rules`, `mcpk_create_key`, `mcpk_revoke_key`, option `mcp_keys_keys`.
- Produces: Settings > MCP API Keys page (slug `mcp-api-keys`, capability `manage_options`), and `admin_post_mcpk_create` / `admin_post_mcpk_revoke` handlers.

- [ ] **Step 1: Settings page** via `add_options_page` on `admin_menu`. Table of keys: label, `mcpk_<id>_…`, user login, allowed IPs (or "any"), created, last used ("never" when 0; format with `wp_date`), a Revoke form per row. Create form: label (text, required), user (`wp_dropdown_users( array( 'name' => 'user_id' ) )`), IPs textarea (one per line, v4/v6, CIDR ok; empty = any IP). Show the endpoint URL `rest_url( 'mcp-keys/mcp' )` at the top. Escape all output.

- [ ] **Step 2: Create handler.** Check `manage_options` and nonce `mcpk_create`. Label empty, user missing, or any entry in `mcpk_parse_rules()['invalid']` → `wp_die` 400 naming the problem and listing the bad entries. Otherwise `mcpk_create_key`, `nocache_headers()`, then `wp_die` with 200 containing the key once in `<code>`, a "copy it now, it cannot be shown again" note and a link back to the page. The key is not stored or redirected anywhere.

- [ ] **Step 3: Revoke handler.** Check `manage_options` and nonce `mcpk_revoke_<id>`, call `mcpk_revoke_key`, redirect back with `wp_safe_redirect`.

- [ ] **Step 4: Verify syntax**

Run: `php -l mcp-api-keys.php && php tests/check.php`
Expected: `No syntax errors detected` then `OK`. (Behaviour is verified in Task 5.)

---

### Task 5: Smoke test against real WordPress, and README

**Files:**
- Create: `tests/blueprint.json`
- Modify: `README.md`

- [ ] **Step 1: Blueprint** `tests/blueprint.json`: WordPress `latest` (must be 6.9+), PHP 8.3, `login: true`, `landingPage` `/wp-admin/options-general.php?page=mcp-api-keys`, one `installPlugin` step for `https://github.com/WordPress/mcp-adapter/releases/latest/download/mcp-adapter.zip` with `activate: true`.

- [ ] **Step 2: Start WordPress with this plugin mounted**

Run: `npx @wp-playground/cli@latest server --blueprint=tests/blueprint.json --auto-mount` (check `--help` if flag names differ). Expected: a local URL; both plugins active; the Settings > MCP API Keys page loads.

- [ ] **Step 3: Create a key in the admin page** (label "smoke", user admin, IPs empty) using the built-in browser. Expected: key shown once; reloading the page shows only `mcpk_<id>_…` in the list.

- [ ] **Step 4: Exercise the endpoint** with curl against `<url>/wp-json/mcp-keys/mcp`. POST JSON-RPC `initialize`, then `tools/list` (send `Mcp-Session-Id` if `initialize` returns one). Expected results:

  | Request | Expected |
  |---|---|
  | Bearer key, `tools/list` | 200, tool `mcp-keys-get-site-info` listed |
  | `X-API-Key` header | 200 |
  | `tools/call` `mcp-keys-get-site-info` | 200, `site_name` present |
  | no auth header | 401 |
  | right id, wrong secret | 401 |
  | `Authorization: Basic ...` for a real Application Password | 401 |
  | default server `/wp-json/mcp/mcp-adapter-default-server` with the key | not authenticated by this plugin (401) |

- [ ] **Step 5: IP allowlist.** Create a second key with IPs `203.0.113.0/24`: request → 403. Create a third with `127.0.0.1` and `::1` (and `::ffff:127.0.0.1`): request → 200. Revoke the first key in the admin: its next request → 401 immediately.

- [ ] **Step 6: README.md**: what the plugin does, requirements (MCP Adapter plugin, WP 6.9+), endpoint, how to create a key, the IP rule syntax (v4, v6, CIDR, empty = any), `REMOTE_ADDR`-only caveat behind proxies, a curl example, and `claude mcp add --transport http <name> <url> --header "Authorization: Bearer <key>"`. Note that web chat connectors (claude.ai, ChatGPT) need OAuth and cannot use API keys.

- [ ] **Step 7: Final run**

Run: `php -l mcp-api-keys.php && php tests/check.php`
Expected: `No syntax errors detected` then `OK`.
