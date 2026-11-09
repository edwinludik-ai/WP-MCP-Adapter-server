# MCP API Keys

A WordPress plugin for the [WordPress MCP Adapter](https://github.com/WordPress/mcp-adapter) that puts an MCP server behind **hashed, revocable API keys**, each with an optional **IPv4/IPv6 allowlist**.

It implements the adapter's getting-started steps:

- **Step 2:** registers the `mcp-keys/get-site-info` ability.
- **Step 3:** creates a custom MCP server at `/wp-json/mcp-keys/mcp` that exposes only that ability.

The adapter's default server (`/wp-json/mcp/mcp-adapter-default-server`) is untouched. The `get-site-info` ability is not marked public, so it is not exposed there.

## Requirements

WordPress 6.9+, PHP 7.4+, and the [MCP Adapter plugin](https://github.com/WordPress/mcp-adapter/releases/latest) active.

## Use

1. Install and activate this plugin (and MCP Adapter).
2. Go to **Settings > MCP API Keys**, enter a label, pick the user the key acts as (use the lowest role that does the job), optionally list allowed IPs, and click **Create key**.
3. Copy the key. **It is shown once** and only a hash is stored.
4. Point your client at the endpoint shown on that page and send the key as `Authorization: Bearer <key>` or `X-API-Key: <key>`:

```bash
claude mcp add --transport http my-site https://example.com/wp-json/mcp-keys/mcp \
  --header "Authorization: Bearer mcpk_xxxxxxxx_..."
```

Revoke a key on the same page; it stops working immediately.

### Allowed IPs

One rule per line (or comma-separated): an IPv4 or IPv6 address, optionally with a `/prefix` (`203.0.113.7`, `198.51.100.0/24`, `2001:db8::/32`). Leave empty to allow any IP. A key with rules rejects every other address with a 403.

The address checked is the connection's `REMOTE_ADDR`; `X-Forwarded-For` and similar headers are **ignored** (they can be spoofed). Behind a proxy or CDN, `REMOTE_ADDR` is the proxy, so an allowlist will not do what you want there.

### Behaviour

| Request to `/wp-json/mcp-keys/mcp` | Result |
|---|---|
| valid key, allowed IP | acts as the key's user |
| no key (including cookie or Application Password auth) | 401 |
| unknown id or wrong secret | 401 |
| valid key, IP not allowed | 403 |
| key's user deleted | 401 |

Web chat connectors (claude.ai, ChatGPT) sign in with OAuth and cannot use API keys; use a desktop or CLI client.

## Development

```bash
php tests/check.php        # key hashing, header parsing, IP/CIDR matching (no WordPress needed)
```

End-to-end check against a real WordPress (Playground, with the adapter preinstalled by the blueprint):

```bash
npx @wp-playground/cli@latest server --blueprint=tests/blueprint.json --auto-mount --login --port=9400
```
