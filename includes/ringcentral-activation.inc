<?php 
/*
 * Copyright (C) 2019-2023 Paladin Business Solutions
 *
 */

global $wpdb;

require_once (ABSPATH . 'wp-admin/includes/upgrade.php');

/* ================================= */
/* Create ringcentral_control table  */
/* ================================= */
$ringcentral_sql = "CREATE TABLE `ringcentral_control` (
  `ringcentral_control_id` int(11) NOT NULL AUTO_INCREMENT,
  `embedded_phone` tinyint(4) NOT NULL,
  `client_id` varchar(50) NOT NULL,
  `client_secret` varchar(50) NOT NULL,
  `ringcentral_user_name` varchar(50) NOT NULL,
  `ringcentral_extension` tinyint(4) NOT NULL,
  `ringcentral_password` varchar(50) NOT NULL,
  `ringcentral_sandbox` TINYINT NOT NULL,
  `embed_width` SMALLINT(4) NOT NULL,
  `embed_height` SMALLINT(4) NOT NULL,		
  `enable_glip` tinyint(4) NOT NULL,
  `email_updates` tinyint(4) NOT NULL,
  `mobile_updates` tinyint(4) NOT NULL,
  `token_prefix` varchar(10) NOT NULL,
  `grc_site_key` VARCHAR(75) NOT NULL,
  `grc_secret_key` VARCHAR(75) NOT NULL,
  `oauth_client` varchar(75) NOT NULL,
  `oauth_secret` varchar(75) NOT NULL,  
  PRIMARY KEY (`ringcentral_control_id`)
) ";
dbDelta($ringcentral_sql);
/* ====================================== */
/* seed table with control row and basic  */
/* data if there is no existing row       */
/* ====================================== */
$row_exists = $wpdb->get_var($wpdb->prepare("SELECT `ringcentral_control_id` 
    FROM `ringcentral_control` WHERE `ringcentral_control_id` = %d", 1) );
if (!$row_exists) {
    $wpdb->insert('ringcentral_control', 
        array(
            'ringcentral_control_id' => 1,
            'embedded_phone' => 0,
            'ringcentral_sandbox' => 1,            
            'embed_width' => 300,            
            'embed_height' => 600,            
            'email_updates' => 1,            
            'mobile_updates' => 0,            
            )
        );
}
/* ================================= */
/* Create ringcentral_contacts table */
/* ================================= */
$ringcentral_sql = "CREATE TABLE `ringcentral_contacts` (
  `ringcentral_contacts_id` int(11) NOT NULL AUTO_INCREMENT,
  `ringcentral_token` varchar(33) NOT NULL,
  `full_name` varchar(100) NOT NULL,
  `email` varchar(100) NOT NULL,
  `email_confirmed` tinyint(4) NOT NULL DEFAULT '0',
  `email_optin_ip` varchar(50) NOT NULL,
  `email_optin_date` varchar(10) NOT NULL,
  `mobile` varchar(25) NOT NULL,
  `mobile_confirmed` tinyint(4) NOT NULL DEFAULT '0',
  `mobile_optin_ip` varchar(50) NOT NULL,
  `mobile_optin_date` varchar(10) NOT NULL,
  PRIMARY KEY (`ringcentral_contacts_id`)
) ";
dbDelta($ringcentral_sql);
/* =======================================*/
/* Create ringcentral_call_requests table */
/* =======================================*/
$ringcentral_sql = "CREATE TABLE `ringcentral_call_requests` (
  `ringcentral_call_requests_id` int(11) NOT NULL AUTO_INCREMENT,
  `full_name` varchar(100) NOT NULL,
  `mobile` varchar(25) NOT NULL,  
  `requested_date` varchar(10) NOT NULL,
  `call_reason` varchar(500) NOT NULL,
  PRIMARY KEY (`ringcentral_call_requests_id`)
) ";
dbDelta($ringcentral_sql);
/* ==============================*/
/* Create ringcentral_queue table */
/* ==============================*/
$ringcentral_sql = "CREATE TABLE `ringcentral_queue` (
`ringcentral_queue_id` INT NOT NULL AUTO_INCREMENT ,
`ringcentral_post_id` INT NOT NULL ,
`ringcentral_post_title` VARCHAR(255) NOT NULL ,
`ringcentral_post_url` VARCHAR(255) NOT NULL ,
`ringcentral_queue_complete` TINYINT(1) NOT NULL DEFAULT 0,
PRIMARY KEY (`ringcentral_queue_id`))";
dbDelta($ringcentral_sql);
/* ==============================*/
/* Create ringcentral_help table */
/* ==============================*/
$ringcentral_sql = "CREATE TABLE `ringcentral_help` ( 
`ringcentral_help_id` INT NOT NULL AUTO_INCREMENT , 
`ringcentral_help_field` VARCHAR(75) NULL , 
`ringcentral_help_help` TEXT NULL , 
PRIMARY KEY (`ringcentral_help_id`))";
dbDelta($ringcentral_sql);
/* ====================================== */
/* seed table with control row and basic  */
/* data if there is no existing row       */
/* ====================================== */
$row_exists = $wpdb->get_var($wpdb->prepare("SELECT `ringcentral_help_id` FROM `ringcentral_help`
        WHERE `ringcentral_help_id` = %d", 1) );
// should check all rows individually.
if (!$row_exists) {
    $wpdb->query( $wpdb->prepare("INSERT INTO `ringcentral_help`
      (`ringcentral_help_id`, `ringcentral_help_field`, `ringcentral_help_help`)
      VALUES (%d, %s, %s)",
        1, "username", "Main Company Phone Number" ) );
    $wpdb->query( $wpdb->prepare("INSERT INTO `ringcentral_help`
      (`ringcentral_help_id`, `ringcentral_help_field`, `ringcentral_help_help`)
      VALUES (%d, %s, %s)",
        2, "token_prefix", "Your installations unique prefix to a link token that will be added to the opt-in email and SMS confirmation URLs" ) );
    $wpdb->query( $wpdb->prepare("INSERT INTO `ringcentral_help`
      (`ringcentral_help_id`, `ringcentral_help_field`, `ringcentral_help_help`)
      VALUES (%d, %s, %s)",
        3, "ringcentral_sandbox", "Turn this checkbox ON if you want to use the Ring Central SANDBOX SDK, leave it off for Production use." ) );
    $wpdb->query( $wpdb->prepare("INSERT INTO `ringcentral_help`
      (`ringcentral_help_id`, `ringcentral_help_field`, `ringcentral_help_help`)
      VALUES (%d, %s, %s)",
    	4, "embedded_phone", "Use this checkbox to turn on the Embedded Phone tool, note it cannot be on at the same time as embedded Team Messaging" ) );
    $wpdb->query( $wpdb->prepare("INSERT INTO `ringcentral_help`
      (`ringcentral_help_id`, `ringcentral_help_field`, `ringcentral_help_help`)
      VALUES (%d, %s, %s)",
    	5, "enable_glip", "Use this checkbox to turn on embedded Team Messaging, note it cannot be on at the same time as the Embedded Phone" ) );
    $wpdb->query( $wpdb->prepare("INSERT INTO `ringcentral_help`
      (`ringcentral_help_id`, `ringcentral_help_field`, `ringcentral_help_help`)
      VALUES (%d, %s, %s)",
    	6, "embed_width", "Set the width in pixels for embedded Team Messaging; this should be a number greater than 300" ) );
    $wpdb->query( $wpdb->prepare("INSERT INTO `ringcentral_help`
      (`ringcentral_help_id`, `ringcentral_help_field`, `ringcentral_help_help`)
      VALUES (%d, %s, %s)",
   		7, "embed_height", "Set the height in pixels for embedded Team Messaging; this should be a number greater than 500" ) );
    
}
/* ======================================= */
/* build email confirmation page if needed */
/* permainks must be set to "Post name"    */
/* ======================================= */
$new_page_title = 'eMail Confirmation';
$new_page_content = 'email-confirmed ... thanks for that !';
$new_page_template = '';
$page_check = get_page_by_title($new_page_title);
$new_page = array(
    'post_type' => 'page',
    'post_title' => $new_page_title,
    'post_content' => $new_page_content,
    'post_status' => 'publish',
    'post_author' => 1,
);
if(!isset($page_check->ID)){
    $new_page_id = wp_insert_post($new_page);
    if(!empty($new_page_template)){
        update_post_meta($new_page_id, '_wp_page_template', $new_page_template);
    }
}
/* =================================================== */
/* build email unsubscribe confirmation page if needed */
/* =================================================== */
$new_page_title = 'eMail Unsubscribe';
$new_page_content = 'You have been unsubscribed from the email list ... Sorry to see you go.';
$new_page_template = '';
$page_check = get_page_by_title($new_page_title);
$new_page = array(
    'post_type' => 'page',
    'post_title' => $new_page_title,
    'post_content' => $new_page_content,
    'post_status' => 'publish',
    'post_author' => 1,
);
if(!isset($page_check->ID)){
    $new_page_id = wp_insert_post($new_page);
    if(!empty($new_page_template)){
        update_post_meta($new_page_id, '_wp_page_template', $new_page_template);
    }
}
/* ======================================== */
/* build mobile confirmation page if needed */
/* ======================================== */
$new_page_title = 'Mobile Confirmation';
$new_page_content = 'Your mobile device has been confirmed ... thanks for that !';
$new_page_template = '';
$page_check = get_page_by_title($new_page_title);
$new_page = array(
    'post_type' => 'page',
    'post_title' => $new_page_title,
    'post_content' => $new_page_content,
    'post_status' => 'publish',
    'post_author' => 1,
);
if(!isset($page_check->ID)){
    $new_page_id = wp_insert_post($new_page);
    if(!empty($new_page_template)){
        update_post_meta($new_page_id, '_wp_page_template', $new_page_template);
    }
}
/* ==================================================== */
/* build mobile unsubscribe confirmation page if needed */
/* ==================================================== */
$new_page_title = 'Mobile Unsubscribe';
$new_page_content = 'You have been unsubscribed from the mobile list ... Sorry to see you go.';
$new_page_template = '';
$page_check = get_page_by_title($new_page_title);
$new_page = array(
    'post_type' => 'page',
    'post_title' => $new_page_title,
    'post_content' => $new_page_content,
    'post_status' => 'publish',
    'post_author' => 1,
);
if(!isset($page_check->ID)){
    $new_page_id = wp_insert_post($new_page);
    if(!empty($new_page_template)){
        update_post_meta($new_page_id, '_wp_page_template', $new_page_template);
    }
}
?>