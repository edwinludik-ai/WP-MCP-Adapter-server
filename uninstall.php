<?php
/**
 * Runs when the plugin is deleted from wp-admin: removes the stored key hashes.
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

// ponytail: clears the option on the site this runs for; on multisite, other sites' options stay until their own cleanup.
delete_option( 'mcp_keys_keys' );
