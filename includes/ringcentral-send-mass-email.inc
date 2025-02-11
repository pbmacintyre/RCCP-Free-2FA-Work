<?php
/**
 * Copyright (C) 2019-2025 Paladin Business Solutions
 *
 */

// send email(s) to signed up client(s)

$email_list = $wpdb->get_results( $wpdb->prepare("SELECT `ringcentral_token`, `full_name`, `email`
    FROM `ringcentral_contacts` WHERE `email` <> %s AND `email_confirmed` = %d", "", 1 ) );  

foreach ( $email_list as $email_contact ) {
	$unsub_url = add_query_arg(array('rcunsubscribe'=>$mobile_contact->ringcentral_token, 'rcformat'=>'1'), get_site_url());
    
    $subject = 'A new post has been added to: ' . $siteName;
    
    $message = "hi $email_contact->full_name : A new post has been added to:  $siteName <br/>";
    $message .= "email: $email_contact->email <br/>";
    $message .= $postTitle . ": " . $postUrl;
    $message .= "<br/><br/><br/><br/>To unsubscribe click here: " ;
    $message .= "<a href='" . $unsub_url . "'>Unsubscribe eMail</a>";
    
    $recipient = '"' . $email_contact->full_name . '" <' . $email_contact->email . '>' ;
    $headers = array('Content-Type: text/html; charset=UTF-8');
    wp_mail( $recipient, $subject, $message, $headers );
}
?>