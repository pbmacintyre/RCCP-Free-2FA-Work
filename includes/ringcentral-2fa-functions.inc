<?php
/**
 * Copyright (C) 2019-2023 Paladin Business Solutions
 *
 */

function user_has_role($user_id, $role_name = 'administrator')
{
    // get selected users roles
    $user_meta = get_userdata($user_id);
    $user_roles = $user_meta->roles;
    return in_array($role_name, $user_roles);
}

function ringcentral_2fa_user_settings ($selected_user_obj) {
    ringcentral_2fa_edit_profile ($selected_user_obj);
}
function ringcentral_2fa_save_settings ($user_id) {
    // Profile update button was pressed,
    if (!current_user_can('edit_user', $user_id)) return false;

}
function ringcentral_2fa_form_settings_validation (&$errors, $update, &$user ) {
    // validate RingCentral form data, called on "Update Profile" button click
    $isUserAdmin = user_has_role($user->ID) ;
    $enabled = filter_var(isset($_POST['RingCentral_2fa_user_enabled']), FILTER_SANITIZE_NUMBER_INT);

    if (!$enabled) {
        $current_enabled_state = get_the_author_meta('RingCentral_2fa_user_enabled', $user->ID);
//        echo_spaces("current enabled state", $current_enabled_state);
//        echo_spaces("enabled checkbox value", $enabled);
//        echo_spaces("user access level", $selected_user_access_lvl);

        if ($current_enabled_state == 1 && $enabled == "" && $isUserAdmin) {
            $errors->add('RingCentral_2fa_settings_update_error',
                'You have disabled the 2FA feature, you will have to re-validate your mobile number when this is reactivated');

        }
        // 2FA is off, so clean out the settings
        update_user_meta($user->ID, 'RingCentral_2fa_user_enabled', 0);
        update_user_meta($user->ID, 'RingCentral_2fa_user_mobile_validated', 0);
        update_user_meta($user->ID, 'RingCentral_2fa_user_2fa_code', 0);
        update_user_meta($user->ID, 'RingCentral_2fa_user_mobile', "");
        return ;
    }

    $mobile = filter_var($_POST['RingCentral_2fa_user_mobile'], FILTER_SANITIZE_NUMBER_INT);
    $mobile = ringcentral_2fa_valid_mobile($mobile) ;  // get the digits only

    $validated = get_the_author_meta('RingCentral_2fa_user_mobile_validated', $user->ID);
    $fresh_code = get_the_author_meta('RingCentral_2fa_fresh_code_sent', $user->ID);

    // if enabled and mobile is lacking
    if ($enabled && strlen($mobile) !== 10) {
        $errors->add('RingCentral_2fa_settings_update_error',
            'The mobile number does not have enough digits, US and Canada numbers are 10 digits');
        update_user_meta($user->ID, 'RingCentral_2fa_user_enabled', 0);
        return ;
    }
    // check to see if the number is not already in the database
    if ($mobile && $enabled && ringcentral_2fa_mobile_number_exists($user->ID, $mobile)) {
        $errors->add('RingCentral_2fa_settings_update_error', 'Mobile number already in use.');
        update_user_meta($user->ID, 'RingCentral_2fa_user_mobile', "");
        return ;
    }

    if ($enabled && strlen($mobile) == 10) { //save the digits of the phone number & enabled state
        update_user_meta($user->ID, 'RingCentral_2fa_user_mobile', ringcentral_2fa_valid_mobile($mobile));
        update_user_meta($user->ID, 'RingCentral_2fa_user_enabled', 1);
        if ($isUserAdmin) { // if active user is an admin
            if ($validated) { // if number was already validated, just make sure RingCentral_2fa_fresh_code_sent is off
                update_user_meta($user->ID, 'RingCentral_2fa_fresh_code_sent', 0);
            } else {  // if enabled, good number length, but not validated
                if ($fresh_code) { // if a fresh code is true, this means that a 6 digit code was sent, so test them
                    $two_fa_code = $_POST['RingCentral_2fa_validation'];  // form entered code
                    $two_fa_code_db = get_the_author_meta('RingCentral_2fa_user_2fa_code', $user->ID);  // DB code
                    if ($two_fa_code !== $two_fa_code_db) {
                        $errors->add('RingCentral_2fa_settings_update_error',
                            'The 2FA Code you entered does not match the system generated code.');
                        // question: turn off the 2FA check box to force sending out new codes?
                    } else {  // the codes match
                        // so send 1 to validated field in DB
                        update_user_meta($user->ID, 'RingCentral_2fa_user_mobile_validated', 1);
                        // remove the 6 digit code from the DB
                        update_user_meta($user->ID, 'RingCentral_2fa_user_2fa_code', "");
                        // "fresh code" toggle should also be turned off
                        update_user_meta($user->ID, 'RingCentral_2fa_fresh_code_sent', 0);
                    }
                } else { // send the 6 digit code
                    ringcentral_gen_six_digit_code($user, 0);
                }
            }
        } else {
            // they are not admin but number and enabled are good, so validate account anyway
            update_user_meta($user->ID, 'RingCentral_2fa_user_mobile_validated', 1);
        }
    }

}

function ringcentral_2fa_valid_mobile ($mobile) {
    // only take the digits, strip out brackets and dashes if they are there
    $digits_only = preg_replace('/[^0-9]/', '', $mobile);

    return $digits_only ;
}

function ringcentral_2fa_mobile_number_exists ($user_id, $mobile) {
    $users_found = get_users(
        [
            'meta_key' => 'RingCentral_2fa_user_mobile',
            'meta_value' => $mobile,
        ]
    );

    return 0 < count($users_found) && $user_id !== $users_found[0]->ID;
}

function ringcentral_gen_six_digit_code ($user, $login = 1) {
    // login = 1 means that the WP Admin login form is being used.
    // 0 = code sent via user profile edit page
    // generate a random 6 digit code
    $six_digit_code = rand(100000, 999999);
    // put code in the session
    $_SESSION['six_digit_code'] = $six_digit_code;
    $website_name = get_option('blogname');

    if (!$login) {  // user profile edit page is being used
        // put in wp_usermeta if updating / adding a user profile to admin system
        update_user_meta($user->ID, 'RingCentral_2fa_user_2fa_code', $six_digit_code);
        update_user_meta($user->ID, 'RingCentral_2fa_fresh_code_sent', 1);
        $message = "\nTo continue your login for '$website_name' use the following six-digit code. We will never call or email for this code: $six_digit_code";
    } else { // WP Admin login form is being used
        // make sure fresh code is 0
        update_user_meta($user->ID, 'RingCentral_2fa_fresh_code_sent', 0);
        $message = "\nTo continue your login for '$website_name' use the following six-digit code. We will never call or email for this code: $six_digit_code";
    }

    // connect to SDK with credentials in the DB
    $sdk = ringcentral_sdk();
    $from = ringcentral_get_from_phone();
    $to = ringcentral_2fa_valid_mobile(get_user_meta($user->ID, 'RingCentral_2fa_user_mobile', true)) ;


    try {
        // echo "in try... <br/>";
        $apiResponse = $sdk->platform()->post('/account/~/extension/~/sms',
            array('from' => array('phoneNumber' => $from),
                'to' => array(array('phoneNumber' => $to)),
                'text' => $message ),
        );
    }
    catch (\RingCentral\SDK\Http\ApiException $e) {
        // Getting error messages using PHP native interface
        $apiResponse = $e->apiResponse();
        $message = '  Message: ' . $e->apiResponse->response()->error() . PHP_EOL;
        // craft a friendly message here.
        $return_message = "There was an error sending the validation code, Please try again later <br/>" . $message;
    }

}

require_once("ringcentral-2fa-profile-functions.inc");

?>