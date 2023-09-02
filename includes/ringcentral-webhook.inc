<?php
/**
 * Copyright (C) 2019-2023 Paladin Business Solutions
 *
 */

$v = isset($_SERVER['HTTP_VALIDATION_TOKEN']) ? $_SERVER['HTTP_VALIDATION_TOKEN'] : '';
if (strlen($v) > 0) {
    header("Validation-Token: {$v}");
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
}

http_response_code(200);
echo json_encode(array('responseType'=>'success', 'responseDescription'=>'Action accepted.'));
exit();