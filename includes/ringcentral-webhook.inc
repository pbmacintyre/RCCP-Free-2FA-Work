<?php
/**
 * Copyright (C) 2019-2024 Paladin Business Solutions
 *
 */

$hvt = isset($_SERVER['HTTP_VALIDATION_TOKEN']) ? $_SERVER['HTTP_VALIDATION_TOKEN'] : '';
if (strlen($hvt) > 0) {
    header("Validation-Token: {$hvt}");
}

$incoming = file_get_contents("php://input");
if (empty($incoming)) {
    http_response_code(200);
    echo json_encode(array('responseType'=>'error', 'responseDescription'=>'No data was provided'));
    exit();
}

$incoming_data = json_decode($incoming);

if (!$incoming_data) {
	http_response_code(200);
    echo json_encode(array('responseType'=>'error', 'responseDescription'=>'Media type not supported.  Please use JSON.'));
    exit();
}

$in_to = $incoming_data->body->to[0]->phoneNumber;
$in_from = $incoming_data->body->from->phoneNumber;

$text = $incoming_data->body->subject;

$sdk = ringcentral_sdk() ;
$from = ringcentral_get_from_phone();

if (preg_match('/(STOP)|(END)|(CANCEL)|(UNSUBSCRIBE)|(QUIT)/i', $text) && $in_to == $from) {
	$sql = $wpdb->prepare("UPDATE `ringcentral_contacts`
		SET `mobile` = %s, `mobile_confirmed` = %d,`mobile_optin_ip` = %s, `mobile_optin_date` = %s
		WHERE `mobile` = %s",
		"", 0, "", "", $in_from) ;

	$wpdb->query($sql);
	
	$message = 'You have successfully been unsubscribed';
	$sdk->platform()->post('/account/~/extension/~/sms',
            array('from' => array('phoneNumber' => $from),
                'to'   => array( array('phoneNumber' => $in_from) ),
                'text' => $message ) );
	
} elseif (preg_match('/(HELP)|(INFO)/i', $text) && $in_to == $from) {
	$message = 'Please call '.$from.' for more information, or text STOP to stop these messages. Msg&Data rates may apply.';
	$sdk->platform()->post('/account/~/extension/~/sms',
            array('from' => array('phoneNumber' => $from),
                'to'   => array( array('phoneNumber' => $in_from) ),
                'text' => $message ) );

} elseif (preg_match('/(START)|(SUBSCRIBE)|(RESUME)|(CONTINUE)|(UNSTOP)/i', $text) && $in_to == $from) {
    $message = 'You have Opted IN to our SMS Service, welcome! Text STOP anytime to stop recieving future messages. Msg & Data rates may apply.';
    $sdk->platform()->post('/account/~/extension/~/sms',
        array('from' => array('phoneNumber' => $from),
            'to'   => array( array('phoneNumber' => $in_from) ),
            'text' => $message ) );

    $opt_in_date = date('Y-m-d'); // YYYY-MM-DD
    $opt_in_ip = $_SERVER['REMOTE_ADDR']?:($_SERVER['HTTP_X_FORWARDED_FOR']?:$_SERVER['HTTP_CLIENT_IP']);  ;

    // locate the mobile # to be updated.
    $sql = $wpdb->prepare("UPDATE `ringcentral_contacts`
		SET `mobile_confirmed` = %d,`mobile_optin_ip` = %s, `mobile_optin_date` = %s
		WHERE `mobile` = %s",
        1, $opt_in_ip, $opt_in_date, $in_from) ;

    $wpdb->query($sql);
}

http_response_code(200);
echo json_encode(array('responseType'=>'success', 'responseDescription'=>'Action accepted.'));
exit();