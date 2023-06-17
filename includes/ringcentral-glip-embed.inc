<?php 
/**
 * Copyright (C) 2019-2023 Paladin Business Solutions
 *
 */

/* ============================ */
/* Build TM Embed iFrame string */
/* ============================ */

require('vendor/autoload.php');
	
// get control data
global $wpdb;

$result_rc = $wpdb->get_row( $wpdb->prepare("SELECT * FROM `ringcentral_control` WHERE `ringcentral_control_id` = %d", 1) );

$ringcentral_sandbox   		= $result_rc->ringcentral_sandbox ;
$ringcentral_embed_width		= $result_rc->embed_width ;
$ringcentral_embed_height	= $result_rc->embed_height ;
$ringcentral_glip_on		= $result_rc->enable_glip ;	

if ($ringcentral_glip_on == 1) {

	$server_URL = "https://ringcentral.github.io/ringcentral-embeddable/app.html?" ;
	
	if ($ringcentral_sandbox == 1) {
		// test environment
		$server_URL .= "appServer=" . RingCentral\SDK\SDK::SERVER_SANDBOX ;
	} else if ($ringcentral_sandbox == 0) {
		// production
		$server_URL .= RingCentral\SDK\SDK::SERVER_PRODUCTION ;
	}
	
 	$server_URL .= "&disableGlip=false";
//  $server_URL .= "&disableGlip=false&disableCall=true&disableMessages=true";
 	
// 	echo "Server URL: " . $server_URL;
	
	$iFrame_string = "<iframe id='rc-widget' allow='microphone' ";
	$iFrame_string .= "width='$ringcentral_embed_width' ";
	$iFrame_string .= "height='$ringcentral_embed_height' ";
	$iFrame_string .= "src='$server_URL'";	
	$iFrame_string .= " ></iframe>";
		
	echo "<br/><br/>" . $iFrame_string ;

} else {
	echo "<br/><br/><br/><h2>Embeded Team Messaging is not turned on, go the the settings page to change options.</h2>" ;
}
?>

















