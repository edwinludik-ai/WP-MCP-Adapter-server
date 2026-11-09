# MCP API Keys

A WordPress plugin for the [WordPress MCP Adapter](https://github.com/WordPress/mcp-adapter) that puts an MCP server behind **hashed, revocable API keys**, each with an optional **IPv4/IPv6 allowlist**.

It implements the adapter's getting-started steps:

- **Step 2:** registers the `mcp-keys/get-site-info` ability.
- **Step 3:** creates a custom MCP server at `/wp-json/mcp-keys/mcp` that exposes only that ability.

The adapter's default server (`/wp-json/mcp/mcp-adapter-default-server`) is untouched. The `get-site-info` ability is not marked public, so it is not exposed there.

## Requirements

WordPress 6.9+, PHP 7.4+, and the [MCP Adapter plugin](https://github.com/WordPress/mcp-adapter/releases/latest) active.

## Install

Download `mcp-api-keys.zip` from the [latest release](../../releases/latest) and upload it under **Plugins > Add New Plugin > Upload Plugin** (or `wp plugin install mcp-api-keys.zip --activate`). Install and activate the MCP Adapter first; this plugin declares it as a required plugin. Deleting the plugin from wp-admin also deletes the stored key hashes.

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
bin/build-zip.sh           # builds dist/mcp-api-keys.zip, the installable plugin
```

End-to-end check against a real WordPress (Playground, with the adapter preinstalled by the blueprint). In one terminal:

```bash
npx @wp-playground/cli@latest server --blueprint=tests/blueprint.json --auto-mount --login --port=9400
```

and in another, once it prints `Ready!`:

```bash
python3 tests/smoke.py
```

### CI and releases

`.github/workflows/ci.yml` runs on pushes to `main`, pull requests and tags:

1. **test:** lint plus `tests/check.php` on PHP 7.4, 8.1, 8.3 and 8.4.
2. **build:** `bin/build-zip.sh`, uploading `mcp-api-keys.zip` as a workflow artifact.
3. **smoke:** unpacks that zip into a real WordPress with the MCP Adapter and runs `tests/smoke.py` against it, so the packaged files are what gets tested.
4. **release:** on a `v*` tag, after the above pass, creates a GitHub release with the zip attached. The tag must match the plugin header's `Version:` (tag `v1.0.1` needs `Version: 1.0.1`).

To cut a release: bump `Version:` in `mcp-api-keys.php`, merge, then `git tag v1.0.1 && git push origin v1.0.1`.
