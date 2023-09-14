<?php 
/**
 * Copyright (C) 2019-2023 Paladin Business Solutions
 *
 */

if ($method == 1) { // email unsubscription coming in
    $unsub_confirm_page = site_url() . "/ringcentral-email-unsubscribe";
    $sql = $wpdb->prepare("UPDATE `ringcentral_contacts` 
        SET `email` = %s, `email_confirmed` = %d,`email_optin_ip` = %s, `email_optin_date` = %s  
        WHERE `ringcentral_token` = %s",
        "", 0, "", "", $token_id);
}
//} elseif ($method == 2) { // sms unsubscription coming in
//    $unsub_confirm_page = site_url() . "/mobile-unsubscribe" ;
//    $sql = $wpdb->prepare("UPDATE `ringcentral_contacts`
//        SET `mobile` = %s, `mobile_confirmed` = %d,`mobile_optin_ip` = %s, `mobile_optin_date` = %s
//        WHERE `ringcentral_token` = %s",
//        "", 0, "", "", $token_id) ;
//}

$wpdb->query($sql);

// then re-direct to public page confirming the email removal.
wp_redirect($unsub_confirm_page); exit();
?>