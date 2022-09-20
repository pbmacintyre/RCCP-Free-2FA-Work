<?php
/**
 * Copyright (C) 2019-2022 Paladin Business Solutions
 *
 */

$sdk = ringcentral_sdk() ;
$from = ringcentral_get_from_phone();

$mobile_list = $wpdb->get_results( $wpdb->prepare("SELECT `ringcentral_token`, `full_name`, `mobile` 
    FROM `ringcentral_contacts` WHERE `mobile` <> %s AND `mobile_confirmed` = %d", "", 1 ) ); 

foreach ( $mobile_list as $mobile_contact ) {	
	$unsub_url = add_query_arg(array('rcunsubscribe'=>$mobile_contact->ringcentral_token, 'rcformat'=>'2'), get_site_url());
    
    $message = "hi $mobile_contact->full_name : A new post has been added to:  $siteName \n\n";
    $message .= $postTitle . ": " . $postUrl . "\n\n";
    $message .= "To unsubscribe follow this link: " ;
    $message .= "$unsub_url ";
    
    try {
        $apiResponse = $sdk->platform()->post('/account/~/extension/~/sms',
            array('from' => array('phoneNumber' => $from),
                'to'   => array( array('phoneNumber' => $mobile_contact->mobile) ),
                'text' => $message ) );
        
    } catch (\RingCentral\SDK\Http\ApiException $e) {
        
        // In order to get Request and Response used to perform transaction:
        $apiResponse = $e->apiResponse();

        // craft a friendly message here.
        $return_message = "There was an error broadcasting to the mobile list => " . $apiResponse;
    }
	// Sleep for 1.8 seconds to prevent 40/min penalty
	usleep(1800000);
}

?>