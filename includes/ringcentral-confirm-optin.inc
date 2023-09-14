<?php 
/**
 * Copyright (C) 2019-2023 Paladin Business Solutions
 *
 */

// locate the email address to be updated.
$opt_in_date = date('Y-m-d'); // YYYY-MM-DD
$opt_in_ip = $_SERVER['REMOTE_ADDR']?:($_SERVER['HTTP_X_FORWARDED_FOR']?:$_SERVER['HTTP_CLIENT_IP']);  ;

if ($method == 1) { // email confirmation coming in
    $confirmation_page = $_SERVER['HTTP_HOST'] . "/ringcentral-email-confirmation";
    $sql = $wpdb->prepare("UPDATE `ringcentral_contacts` 
        SET `email_confirmed` = %d, `email_optin_ip` = %s, `email_optin_date` = %s 
        WHERE `ringcentral_token` = %s",
        1, $opt_in_ip, $opt_in_date, $token_id);
}
//} elseif ($method == 2) { // mobile confirmation coming in
//    $confirmation_page = $_SERVER['HTTP_HOST'] . "/mobile-confirmation" ;
//    $sql = $wpdb->prepare("UPDATE `ringcentral_contacts`
//        SET `mobile_confirmed` = %d, `mobile_optin_ip` = %s, `mobile_optin_date` = %s
//        WHERE `ringcentral_token` = %s",
//        1, $opt_in_ip, $opt_in_date, $token_id ) ;
//}

$wpdb->query($sql);

// then re-direct to public page confirming the appropriate opt-in method.
wp_redirect($confirmation_page); exit();
?>