<?php
// Run: php tests/check.php  (pure-function checks; WordPress is stubbed out)
define( 'ABSPATH', '/' );
function add_action() {}
function add_filter() {}
function ok( $cond, $msg ) {
	if ( ! $cond ) {
		fwrite( STDERR, "FAIL: $msg\n" );
		exit( 1 );
	}
}

require __DIR__ . '/../mcp-api-keys.php';

// --- Task 1: IP rules ---
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
foreach ( array( '10.0.0.0/33', '::1/129', '1.2.3', '10.0.0.0/', 'abc', '::ffff:1.2.3.4/120', '1.2.3.4/-1' ) as $bad ) {
	ok( ! mcpk_rule_valid( $bad ), "invalid: $bad" );
}
foreach ( array( '1.2.3.4', '1.2.3.4/32', '::1', '2001:db8::/64', '::ffff:1.2.3.4' ) as $good ) {
	ok( mcpk_rule_valid( $good ), "valid: $good" );
}
$p = mcpk_parse_rules( "1.2.3.4\r\n\r\n::1, 1.2.3.4 ,bad\n" );
ok( $p['rules'] === array( '1.2.3.4', '::1' ) && $p['invalid'] === array( 'bad' ), 'parse_rules crlf/commas/dupes' );

// --- Task 2: keys ---
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

$keys = array(
	$g['id'] => array(
		'label'     => 't',
		'user_id'   => 1,
		'hash'      => mcpk_hash( $g['key'], 'salt' ),
		'ips'       => array( '203.0.113.0/24' ),
		'created'   => 0,
		'last_used' => 0,
	),
);
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

// --- Final review fix: route matching must mirror core (case-insensitive, `$` allows a trailing newline) ---
foreach ( array( '/mcp-keys/mcp', '/mcp-keys/mcp/', '/mcp-keys/mcp/x', '/MCP-KEYS/mcp', '/Mcp-Keys/MCP/', "/mcp-keys/mcp\n" ) as $route ) {
	ok( mcpk_is_our_route( $route ), 'our route: ' . json_encode( $route ) );
}
foreach ( array( '', '/', '/mcp-keys', '/mcp-keys/mcpx', '/mcp-keys/mcp-x', '/other/mcp-keys/mcp', '/mcp/mcp-adapter-default-server', '/batch/v1' ) as $route ) {
	ok( ! mcpk_is_our_route( $route ), 'not our route: ' . json_encode( $route ) );
}

// --- Same answer on every platform: no inet_pton quirks (leading zeros, zone ids) ---
ok( ! mcpk_rule_valid( '010.0.0.1' ), 'leading-zero IPv4 is not an IP' );
ok( ! mcpk_rule_valid( 'fe80::1%en0' ), 'zone id is not an IP' );
ok( ! mcpk_ip_allowed( '010.0.0.1', array( '10.0.0.1' ) ), 'leading-zero address is denied' );

echo "OK\n";
