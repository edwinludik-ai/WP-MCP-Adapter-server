=== MCP API Keys ===
Contributors: REPLACE_WITH_WPORG_USERNAME
Tags: mcp, api, ai, authentication, security
Requires at least: 6.9
Tested up to: 7.1
Requires PHP: 7.4
Requires Plugins: mcp-adapter
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Protect a WordPress MCP server with hashed, revocable API keys and an optional IPv4/IPv6 allowlist.

== Description ==

MCP API Keys adds an MCP server to your site, built on the [MCP Adapter](https://wordpress.org/plugins/mcp-adapter/), that only accepts requests carrying an API key you created. Use it to let tools such as Claude Code or Cursor reach your site without handing them a user's password or an Application Password.

* **Hashed keys.** Keys look like `mcpk_<id>_<secret>`, are shown once when you create them, and only an HMAC-SHA256 hash is stored. A copy of the database alone cannot reproduce a key.
* **Acts as a user you choose.** Each key is bound to one WordPress user, so requests get exactly that user's capabilities. Use the lowest role that does the job.
* **Optional IP allowlist per key.** Allow exact IPs or CIDR ranges, IPv4 and IPv6 (for example `203.0.113.7`, `198.51.100.0/24`, `2001:db8::/32`). Leave it empty to allow any IP.
* **Revoke any time.** A revoked key stops working immediately. The list shows when each key was last used.
* **Key-only endpoint.** The server at `/wp-json/mcp-keys/mcp` rejects cookies and Application Passwords. The MCP Adapter's default server is left untouched.

The plugin registers one simple ability, `mcp-keys/get-site-info`, and exposes it on its own server, following the MCP Adapter's getting-started guide. It is a starting point: the key protection applies to everything exposed on that server.

Send a key as `Authorization: Bearer <key>` or `X-API-Key: <key>`.

= Requirements =

* The MCP Adapter plugin, active.
* WordPress 6.9 or later and PHP 7.4 or later.

== Installation ==

1. Install and activate the MCP Adapter plugin.
2. Install this plugin from the Plugins screen, or upload the zip under Plugins > Add New Plugin > Upload Plugin, then activate it.
3. Go to Settings > MCP API Keys, enter a label, choose the user the key acts as, optionally list allowed IPs, and click Create key.
4. Copy the key. It is shown once.
5. Point your MCP client at the endpoint shown on that screen and send the key as `Authorization: Bearer <key>`.

== Frequently Asked Questions ==

= Can claude.ai or ChatGPT connect with a key? =

No. Their web connectors sign in with OAuth and have no field for an API key. Use a desktop or command-line client, such as Claude Code or Cursor.

= How does the IP allowlist work behind a proxy or CDN? =

The plugin checks the connection's `REMOTE_ADDR` and ignores `X-Forwarded-For` and similar headers, because clients can forge them. Behind a proxy or CDN, `REMOTE_ADDR` is the proxy, so an allowlist will not do what you want there.

= Where are the keys stored? =

In one option, `mcp_keys_keys`, as hashes only. Deleting the plugin removes it.

= I rotated my WordPress salts and every key stopped working. =

Keys are hashed with your site's `auth` salt, so changing the salts invalidates all of them. Create new keys.

= A key got a 403. =

The key has an IP allowlist and the request came from an address that is not on it. A 401 means the key is missing, wrong or revoked.

== Changelog ==

= 1.0.0 =
* Initial release.
