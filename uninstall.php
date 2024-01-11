<?php
/**
 * Copyright (C) 2019-2024 Paladin Business Solutions
 * 
 */
/* ============================================= */
/* if the constant is not defined then get out ! */
/* ============================================= */
if (!defined('WP_UNINSTALL_PLUGIN')) exit() ;

/* ======================================== */
// Drop the DB tables related to the plugin */
/* ======================================== */
global $wpdb;
$wpdb->query('DROP TABLE ringcentral_call_requests');
$wpdb->query('DROP TABLE ringcentral_contacts');
$wpdb->query('DROP TABLE ringcentral_control');
$wpdb->query('DROP TABLE ringcentral_help');
$wpdb->query('DROP TABLE ringcentral_queue');
?>