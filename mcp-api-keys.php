<?php
/**
 * Plugin Name:       MCP API Keys
 * Plugin URI:        https://github.com/edwinludik-ai/WP-MCP-Adapter-server
 * Description:       A WordPress MCP Adapter server protected by hashed API keys, each with an optional IPv4/IPv6 allowlist.
 * Version:           1.0.0
 * Requires at least: 6.9
 * Requires PHP:      7.4
 * Requires Plugins:  mcp-adapter
 * Author:            Edwin Ludik
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       mcp-api-keys
 */

defined( 'ABSPATH' ) || exit;

/* ---------------------------------------------------------------------------
 * IP rules (pure functions: no WordPress calls)
 * ------------------------------------------------------------------------- */

/**
 * Binary form of an IP; IPv4-mapped IPv6 (::ffff:a.b.c.d) collapses to the 4-byte IPv4 form.
 * Returns null if $ip is not an IP address.
 */
function mcpk_ip_to_bin( string $ip ): ?string {
	// filter_var is strict and behaves the same everywhere; inet_pton alone accepts leading zeros and zone ids on some platforms.
	if ( false === filter_var( $ip, FILTER_VALIDATE_IP ) ) {
		return null;
	}
	$bin = inet_pton( $ip );
	if ( false === $bin ) {
		return null;
	}
	if ( 16 === strlen( $bin ) && 0 === strncmp( $bin, str_repeat( "\0", 10 ) . "\xff\xff", 12 ) ) {
		return substr( $bin, 12 );
	}
	return $bin;
}

/** Parses "IP" or "IP/prefix" into [ binary address, prefix bits ], or null if invalid. */
function mcpk_parse_rule( string $rule ): ?array {
	$parts = explode( '/', $rule, 2 );
	$bin   = mcpk_ip_to_bin( $parts[0] );
	if ( null === $bin ) {
		return null;
	}
	$max = strlen( $bin ) * 8;
	if ( ! isset( $parts[1] ) ) {
		return array( $bin, $max );
	}
	// A mapped-IPv6 literal (collapsed to v4) with a prefix would mean different things per family.
	if ( 4 === strlen( $bin ) && false !== strpos( $parts[0], ':' ) ) {
		return null;
	}
	if ( ! ctype_digit( $parts[1] ) || (int) $parts[1] > $max ) {
		return null;
	}
	return array( $bin, (int) $parts[1] );
}

function mcpk_rule_valid( string $rule ): bool {
	return null !== mcpk_parse_rule( $rule );
}

/** True if the first $bits bits of $a and $b are equal (same length binary addresses). */
function mcpk_prefix_match( string $a, string $b, int $bits ): bool {
	$bytes = intdiv( $bits, 8 );
	if ( 0 !== strncmp( $a, $b, $bytes ) ) {
		return false;
	}
	$rem = $bits % 8;
	if ( ! $rem ) {
		return true;
	}
	$mask = ( 0xFF << ( 8 - $rem ) ) & 0xFF;
	return ( ord( $a[ $bytes ] ) & $mask ) === ( ord( $b[ $bytes ] ) & $mask );
}

/** Empty $rules = any IP. Non-empty rules + missing/invalid $ip = denied. Address families never cross. */
function mcpk_ip_allowed( ?string $ip, array $rules ): bool {
	if ( ! $rules ) {
		return true;
	}
	$bin = null === $ip ? null : mcpk_ip_to_bin( $ip );
	if ( null === $bin ) {
		return false;
	}
	foreach ( $rules as $rule ) {
		$r = mcpk_parse_rule( (string) $rule );
		if ( $r && strlen( $r[0] ) === strlen( $bin ) && mcpk_prefix_match( $bin, $r[0], $r[1] ) ) {
			return true;
		}
	}
	return false;
}

/** Splits textarea input on whitespace/commas into unique valid and invalid rules. */
function mcpk_parse_rules( string $text ): array {
	$out = array(
		'rules'   => array(),
		'invalid' => array(),
	);
	foreach ( preg_split( '/[\s,]+/', $text, -1, PREG_SPLIT_NO_EMPTY ) as $rule ) {
		$k = mcpk_rule_valid( $rule ) ? 'rules' : 'invalid';
		if ( ! in_array( $rule, $out[ $k ], true ) ) {
			$out[ $k ][] = $rule;
		}
	}
	return $out;
}

/* ---------------------------------------------------------------------------
 * Keys (pure functions: no WordPress calls)
 * ------------------------------------------------------------------------- */

/** New key: 'mcpk_<8 hex id>_<43-char base64url secret>'. Returns [ 'id' => ..., 'key' => ... ]. */
function mcpk_generate_key(): array {
	$id = bin2hex( random_bytes( 4 ) );
	// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- encodes random bytes into a URL-safe secret; not obfuscation.
	$secret = rtrim( strtr( base64_encode( random_bytes( 32 ) ), '+/', '-_' ), '=' );
	return array(
		'id'  => $id,
		'key' => 'mcpk_' . $id . '_' . $secret,
	);
}

function mcpk_hash( string $key, string $salt ): string {
	return hash_hmac( 'sha256', $key, $salt );
}

/** Key from 'X-API-Key' or 'Authorization: Bearer'; anything else (e.g. Basic) is not a key. */
function mcpk_extract_key( array $server ): ?string {
	$key = trim( (string) ( $server['HTTP_X_API_KEY'] ?? '' ) );
	if ( '' !== $key ) {
		return $key;
	}
	$auth = (string) ( $server['HTTP_AUTHORIZATION'] ?? '' );
	if ( '' === $auth ) {
		$auth = (string) ( $server['REDIRECT_HTTP_AUTHORIZATION'] ?? '' );
	}
	return preg_match( '/^Bearer\s+(\S+)\s*$/i', $auth, $m ) ? $m[1] : null;
}

/**
 * Checks a presented key against the stored records.
 * Returns the record (plus 'id') on success, else 'missing' | 'invalid' | 'ip'.
 * Unknown id and wrong secret are both 'invalid'; the IP is only checked once the secret is right.
 *
 * @return array|string
 */
function mcpk_verify( array $keys, ?string $presented, ?string $ip, string $salt ) {
	if ( null === $presented ) {
		return 'missing';
	}
	if ( ! preg_match( '/^mcpk_([0-9a-f]{8})_[A-Za-z0-9_-]{43}$/', $presented, $m ) || ! isset( $keys[ $m[1] ] ) ) {
		return 'invalid';
	}
	$rec = $keys[ $m[1] ];
	if ( ! hash_equals( (string) ( $rec['hash'] ?? '' ), mcpk_hash( $presented, $salt ) ) ) {
		return 'invalid';
	}
	if ( ! mcpk_ip_allowed( $ip, (array) ( $rec['ips'] ?? array() ) ) ) {
		return 'ip';
	}
	$rec['id'] = $m[1];
	return $rec;
}

/* ---------------------------------------------------------------------------
 * WordPress layer: storage, authentication, ability, server
 * ------------------------------------------------------------------------- */

const MCPK_OPTION = 'mcp_keys_keys';
const MCPK_ROUTE  = '/mcp-keys/mcp';

/** Stores a new key (hash only) and returns the plaintext key. It cannot be retrieved again. */
function mcpk_create_key( string $label, int $user_id, array $ips ): string {
	$keys = (array) get_option( MCPK_OPTION, array() );
	do {
		$k = mcpk_generate_key();
	} while ( isset( $keys[ $k['id'] ] ) );
	$keys[ $k['id'] ] = array(
		'label'     => $label,
		'user_id'   => $user_id,
		'hash'      => mcpk_hash( $k['key'], wp_salt( 'auth' ) ),
		'ips'       => array_values( $ips ),
		'created'   => time(),
		'last_used' => 0,
	);
	update_option( MCPK_OPTION, $keys, false );
	return $k['key'];
}

function mcpk_revoke_key( string $id ): void {
	$keys = (array) get_option( MCPK_OPTION, array() );
	unset( $keys[ $id ] );
	update_option( MCPK_OPTION, $keys, false );
}

/**
 * True if a REST route belongs to our server. Mirrors how core matches routes (case-insensitive, and `$`
 * also matches before a trailing newline) so no spelling of the route that core dispatches can slip past.
 */
function mcpk_is_our_route( string $route ): bool {
	return 1 === preg_match( '@^' . preg_quote( MCPK_ROUTE, '@' ) . '(?:/|$)@i', $route );
}

/** Whether this request was authenticated by an API key. Set by mcpk_authenticate(), read by the server's permission callback. */
function mcpk_authed( ?bool $set = null ): bool {
	static $authed = false;
	if ( null !== $set ) {
		$authed = $set;
	}
	return $authed;
}

/**
 * Makes the MCP route key-only: a valid key (and allowed IP) logs in the key's user for this request;
 * everything else on that route is rejected, including cookie and Application Password auth.
 * Other REST routes are untouched. The server's transport permission callback re-checks the
 * mcpk_authed() flag, so a route spelling this filter fails to recognise is still denied.
 *
 * @param WP_Error|true|null $result
 * @return WP_Error|true|null
 */
function mcpk_authenticate( $result ) {
	mcpk_authed( false );
	if ( ! mcpk_is_our_route( (string) ( $GLOBALS['wp']->query_vars['rest_route'] ?? '' ) ) ) {
		return $result;
	}
	$errors = array(
		'missing' => array( 'mcpk_missing', 'API key required.', 401 ),
		'invalid' => array( 'mcpk_invalid', 'Invalid API key.', 401 ),
		'ip'      => array( 'mcpk_ip', 'IP address not allowed.', 403 ),
	);

	$keys = (array) get_option( MCPK_OPTION, array() );
	$rec  = mcpk_verify( $keys, mcpk_extract_key( $_SERVER ), $_SERVER['REMOTE_ADDR'] ?? null, wp_salt( 'auth' ) );
	$user = is_array( $rec ) ? get_userdata( (int) $rec['user_id'] ) : false;
	if ( is_array( $rec ) && ! $user ) {
		$rec = 'invalid'; // The key's user was deleted.
	}
	if ( ! is_array( $rec ) ) {
		list( $code, $message, $status ) = $errors[ $rec ];
		return new WP_Error( $code, $message, array( 'status' => $status ) );
	}
	wp_set_current_user( $user->ID );
	mcpk_authed( true );
	// ponytail: unlocked read-modify-write of one option; concurrent requests can drop a last-used update. Per-key rows/table if that matters.
	if ( time() - (int) $rec['last_used'] > HOUR_IN_SECONDS ) {
		$keys[ $rec['id'] ]['last_used'] = time();
		update_option( MCPK_OPTION, $keys, false );
	}
	return true;
}
add_filter( 'rest_authentication_errors', 'mcpk_authenticate', 5 );

// Step 2: register a simple ability. No meta.public, so it is not exposed on the adapter's default server.
add_action(
	'wp_abilities_api_init',
	function () {
		wp_register_ability(
			'mcp-keys/get-site-info',
			array(
				'label'               => 'Get Site Information',
				'description'         => 'Retrieves basic information about the current WordPress site',
				'category'            => 'site',
				'input_schema'        => array(
					'type'       => 'object',
					'properties' => array(
						'include_stats' => array(
							'type'        => 'boolean',
							'description' => 'Whether to include post/page statistics',
							'default'     => false,
						),
					),
				),
				'execute_callback'    => function ( $input ) {
					$result = array(
						'site_name'   => get_bloginfo( 'name' ),
						'site_url'    => get_site_url(),
						'description' => get_bloginfo( 'description' ),
					);
					if ( $input['include_stats'] ?? false ) {
						$result['stats'] = array(
							'post_count' => wp_count_posts( 'post' )->publish,
							'page_count' => wp_count_posts( 'page' )->publish,
						);
					}
					return $result;
				},
				'permission_callback' => function () {
					return current_user_can( 'read' );
				},
			)
		);
	}
);

// Step 3: create the custom server at /wp-json/mcp-keys/mcp, exposing only that ability.
add_action(
	'mcp_adapter_init',
	function ( $adapter ) {
		$adapter->create_server(
			'mcp-keys-server',
			'mcp-keys',
			'mcp',
			'MCP API Keys Server',
			'WordPress MCP server protected by API keys',
			'1.0.0',
			array( \WP\MCP\Transport\HttpTransport::class ),
			\WP\MCP\Infrastructure\ErrorHandling\ErrorLogMcpErrorHandler::class,
			null,
			array( 'mcp-keys/get-site-info' ),
			array(),
			array(),
			// Only requests that mcpk_authenticate() accepted get in, however the route was spelled.
			function () {
				return mcpk_authed() && current_user_can( 'read' );
			}
		);
	}
);

/* ---------------------------------------------------------------------------
 * Admin screen: Settings > MCP API Keys
 * ------------------------------------------------------------------------- */

add_action(
	'admin_menu',
	function () {
		add_options_page( 'MCP API Keys', 'MCP API Keys', 'manage_options', 'mcp-api-keys', 'mcpk_render_page' );
	}
);

function mcpk_render_page(): void {
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}
	$keys   = (array) get_option( MCPK_OPTION, array() );
	$action = esc_url( admin_url( 'admin-post.php' ) );
	$format = get_option( 'date_format' ) . ' ' . get_option( 'time_format' );
	?>
	<div class="wrap">
		<h1>MCP API Keys</h1>
		<p>Endpoint: <code><?php echo esc_html( rest_url( 'mcp-keys/mcp' ) ); ?></code><br>
		Send a key as <code>Authorization: Bearer &lt;key&gt;</code> or <code>X-API-Key: &lt;key&gt;</code>. Requests act as the key's user.</p>

		<table class="widefat striped">
			<thead><tr><th>Label</th><th>Key</th><th>User</th><th>Allowed IPs</th><th>Created</th><th>Last used</th><th></th></tr></thead>
			<tbody>
			<?php if ( ! $keys ) : ?>
				<tr><td colspan="7">No keys yet.</td></tr>
			<?php endif; ?>
			<?php foreach ( $keys as $id => $k ) : ?>
				<?php
				$id   = (string) $id; // All-digit hex ids come back as int array keys.
				$user = get_userdata( (int) $k['user_id'] );
				?>
				<tr>
					<td><?php echo esc_html( $k['label'] ); ?></td>
					<td><code><?php echo esc_html( 'mcpk_' . $id . '_…' ); ?></code></td>
					<td><?php echo $user ? esc_html( $user->user_login ) : '<em>deleted user</em>'; ?></td>
					<td><?php echo $k['ips'] ? esc_html( implode( ', ', $k['ips'] ) ) : 'any'; ?></td>
					<td><?php echo esc_html( wp_date( $format, (int) $k['created'] ) ); ?></td>
					<td><?php echo $k['last_used'] ? esc_html( wp_date( $format, (int) $k['last_used'] ) ) : 'never'; ?></td>
					<td>
						<form method="post" action="<?php echo $action; // phpcs:ignore WordPress.Security.EscapeOutput -- escaped above. ?>">
							<input type="hidden" name="action" value="mcpk_revoke">
							<input type="hidden" name="id" value="<?php echo esc_attr( $id ); ?>">
							<?php wp_nonce_field( 'mcpk_revoke_' . $id, '_wpnonce', false ); ?>
							<button class="button" onclick="return confirm('Revoke this key? Clients using it stop working immediately.')">Revoke</button>
						</form>
					</td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>

		<h2>Create key</h2>
		<form method="post" action="<?php echo $action; // phpcs:ignore WordPress.Security.EscapeOutput -- escaped above. ?>">
			<input type="hidden" name="action" value="mcpk_create">
			<?php wp_nonce_field( 'mcpk_create' ); ?>
			<table class="form-table" role="presentation">
				<tr><th><label for="mcpk-label">Label</label></th><td><input id="mcpk-label" name="label" type="text" class="regular-text" required></td></tr>
				<tr>
					<th><label for="mcpk-user">Acts as user</label></th>
					<td>
						<?php
						wp_dropdown_users(
							array(
								'name' => 'user_id',
								'id'   => 'mcpk-user',
							)
						);
						?>
						<p class="description">Use the lowest role that can do the job.</p>
					</td>
				</tr>
				<tr><th><label for="mcpk-ips">Allowed IPs</label></th><td><textarea id="mcpk-ips" name="ips" rows="4" class="large-text code" placeholder="203.0.113.7&#10;198.51.100.0/24&#10;2001:db8::/32"></textarea><p class="description">One per line (or comma-separated): IPv4 or IPv6, optional /prefix. Leave empty to allow any IP. Matched against the connection's address, not forwarded headers.</p></td></tr>
			</table>
			<?php submit_button( 'Create key' ); ?>
		</form>
	</div>
	<?php
}

/** Ends an admin-post request with a message page and a link back to the keys screen. $html must already be escaped. */
function mcpk_die( string $html, string $title, int $status ): void {
	wp_die(
		$html, // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- every caller passes escaped HTML.
		esc_html( $title ),
		array(
			'response'  => absint( $status ),
			'link_url'  => esc_url( admin_url( 'options-general.php?page=mcp-api-keys' ) ),
			'link_text' => esc_html__( 'Back to API keys', 'mcp-api-keys' ),
		)
	);
}

function mcpk_handle_create(): void {
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( 'Forbidden', '', array( 'response' => 403 ) );
	}
	check_admin_referer( 'mcpk_create' );
	$label   = sanitize_text_field( wp_unslash( $_POST['label'] ?? '' ) );
	$user_id = absint( $_POST['user_id'] ?? 0 );
	$ips     = mcpk_parse_rules( sanitize_textarea_field( wp_unslash( $_POST['ips'] ?? '' ) ) );
	// The dropdown only lists this site's users, but the POST body can name anyone: on multisite that would
	// let a site admin mint a key that acts as a super admin.
	if ( '' === $label || ! get_userdata( $user_id ) || ! current_user_can( 'edit_user', $user_id ) || ! is_user_member_of_blog( $user_id ) ) {
		mcpk_die( 'A label and a user you can manage on this site are required.', 'Invalid input', 400 );
	}
	if ( $ips['invalid'] ) {
		mcpk_die( 'Invalid IP rule(s): ' . esc_html( implode( ', ', $ips['invalid'] ) ), 'Invalid input', 400 );
	}
	$key = mcpk_create_key( $label, $user_id, $ips['rules'] );
	nocache_headers();
	// Shown once, in this response only: the key is never stored or redirected.
	mcpk_die( '<p>Copy this key now. It cannot be shown again.</p><p><code>' . esc_html( $key ) . '</code></p>', 'API key created', 200 );
}
add_action( 'admin_post_mcpk_create', 'mcpk_handle_create' );

function mcpk_handle_revoke(): void {
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( 'Forbidden', '', array( 'response' => 403 ) );
	}
	$id = sanitize_key( wp_unslash( $_POST['id'] ?? '' ) );
	check_admin_referer( 'mcpk_revoke_' . $id );
	mcpk_revoke_key( $id );
	wp_safe_redirect( admin_url( 'options-general.php?page=mcp-api-keys' ) );
	exit;
}
add_action( 'admin_post_mcpk_revoke', 'mcpk_handle_revoke' );
