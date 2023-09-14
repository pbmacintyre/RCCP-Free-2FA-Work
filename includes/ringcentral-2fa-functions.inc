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

    if ($login == 0) {  // user profile edit page is being used
        // put in wp_usermeta if updating / adding a user profile to admin system
        update_user_meta($user, 'RingCentral_2fa_user_2fa_code', $six_digit_code);
        update_user_meta($user, 'RingCentral_2fa_fresh_code_sent', 1);

        $message = "You or another person has requested to use this number for '$website_name' two-factor authentication. To enable 2FA please enter the following code on the admin user page: $six_digit_code";
    }
    if ($login == 1) { // wp-dmin login form is being used
        // make sure fresh code is 0
        update_user_meta($user, 'RingCentral_2fa_fresh_code_sent', 0);
        $message = "\nTo continue your login for '$website_name' use the following six-digit code. We will never call 
        or email for this code: $six_digit_code";
    }

    // connect to SDK with credentials in the DB

    $sdk = ringcentral_sdk();
    $from = ringcentral_get_from_phone();
    $to = ringcentral_2fa_valid_mobile(get_user_meta($user, 'RingCentral_2fa_user_mobile', true)) ;

    try {
        $apiResponse = $sdk->platform()->post('/account/~/extension/~/sms',
            array('from' => array('phoneNumber' => $from),
                'to' => array(array('phoneNumber' => $to)),
                'text' => $message ),
        );
//        echo_spaces("API response text", $apiResponse->text() ) ;
    }
    catch (\RingCentral\SDK\Http\ApiException $e) {
        // Getting error messages using PHP native interface
        // $message = "Unable to authenticate to platform. Check credentials. " . $e->message . PHP_EOL);
        // craft a friendly message here.
        $return_message = "There was an error sending the validation code, Please try again later <br/>" . $e ;
        echo_spaces("Catch message", $return_message) ;
    }

}

function ringcentral_2fa_edit_profile ($selected_user_obj) { ?>
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.6.4/jquery.min.js"></script>
    <script>
        $(document).ready(function() {
            $("#TwoFAEnabledAdmin").click(function() {
                if($("#TwoFAEnabledAdmin").is(":checked") ) {
                   goodPhone();
                 }
                if($("#TwoFAEnabledAdmin").is(":checked") == false ) {
                    $("#v-code").hide();
                    $("#send-code").hide();
                }
            });
            $('#RingCentralMobile').on('keyup keypress blur change', function(e) {
                goodPhone();
            });
            $('#enterPinCode').on('keyup keypress change', function(e) {
                goodPIN();
            });
        });
        function goodPIN(){
            if (validatePIN('enterPinCode')) {
                $('#pinCode').css('display', 'inline');
                $("#pinCode").show();
            } else {
                $("#pinCode").hide();
            }
        }
        function validatePIN(enterPinCode) {
            var a = document.getElementById(enterPinCode).value;
            var len = a.length ;
            var filter = /^\d+$/; // only numbers
            if (len === 6) {
                return filter.test(a);
            } else {
                return false ;
            }
        }
        function goodPhone(){
            $("#v-code").show();
            if (validatePhone('RingCentralMobile')) {
                $('#v-code').html('Valid phone number format');
                $('#v-code').css('color', 'green');
                if($("#TwoFAEnabledAdmin").is(":checked") ) {
                    $('#send-code').css('display', 'inline');
                    $("#send-code").show();
                }
            } else {
                $('#v-code').html('Invalid phone number format');
                $('#v-code').css('color', 'red');
                $("#send-code").hide();
            }
        }
        function validatePhone(RingCentralMobile) {
            var a = document.getElementById(RingCentralMobile).value;
            var filter = /^(\+\d{1,2}\s?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}$/;
            return filter.test(a);
        }
        function sendPin() {
            var fromPhone = document.getElementById('RingCentralFromMobile').value ;
            var userid = document.getElementById('RingCentralUserID').value ;
            var toPhone = document.getElementById('RingCentralMobile').value;

            var URL_String = '/wp-admin/user-edit.php?user_id=' + userid
                + '&to_phone="' + toPhone + '"'
                + '/#TwoFAAnchor';
            // + '&validator=1'
            URL_String = "<?php echo get_site_url(null, null, 'https'); ?>" + URL_String ;

            window.open(URL_String, "_self");
        }
        function validateUser() {
            var enteredPIN = document.getElementById('enterPinCode').value ;
            var userid = document.getElementById('RingCentralUserID').value ;
            var URL_String = '/wp-admin/user-edit.php?user_id=' + userid
                + '&MFAPIN="' + enteredPIN + '"'
                + '/#TwoFAAnchor';
            URL_String = "<?php echo get_site_url(null, null, 'https'); ?>" + URL_String ;

            window.open(URL_String, "_self");
        }

    </script>
    <?php

    $loggedin_user_obj = wp_get_current_user();
    $loggedin_user_id = $loggedin_user_obj->data->ID ;

    $selected_user_access_lvl = $selected_user_obj->roles[0]; //access level (admin, contributor, etc.)
    $selected_user_id = $selected_user_obj->data->ID ;

    $mobileValue = ringcentral_2fa_valid_mobile(get_the_author_meta('RingCentral_2fa_user_mobile', $selected_user_obj->ID));

    $enabled = get_the_author_meta('RingCentral_2fa_user_enabled', $selected_user_obj->ID);
    $validated = get_the_author_meta('RingCentral_2fa_user_mobile_validated', $selected_user_obj->ID);
    // Could be the first time editing the profile and therefore validated will be an empty string
    strlen($validated) == 0 ? $validated = 0 : $validated ;
    // whatever the case, send it back to db to ensure usermeta record exists
    update_user_meta($selected_user_obj->ID, 'RingCentral_2fa_user_mobile_validated', $validated);

    // check the query string for a phone number then send out a code.
    $toPhone = preg_replace('/[^0-9]/', '', $_GET['to_phone'] );
//    $validator = $_GET['validator'] ;

    $get_user_id = $_GET['user_id'] ;

    if ($toPhone) {
        // store the phone number of the user in the DB
        update_user_meta($get_user_id, 'RingCentral_2fa_user_mobile', $toPhone);
        update_user_meta($get_user_id, 'RingCentral_2fa_fresh_code_sent', 1);
        update_user_meta($get_user_id, 'RingCentral_2fa_user_enabled', 1);
        $mobileValue = ringcentral_2fa_valid_mobile(get_the_author_meta('RingCentral_2fa_user_mobile', $get_user_id));
        $enabled = get_the_author_meta('RingCentral_2fa_user_enabled', $get_user_id);

        // send out a 6 digit code to the valid phone number.
        ringcentral_gen_six_digit_code($get_user_id, 0);
    } else {
        update_user_meta($get_user_id, 'RingCentral_2fa_fresh_code_sent', 0);
    }

    /* =============================================================================== */

    // pick up form submitted pin from query string
    $mfapin =  preg_replace('/[^0-9]/', '', $_GET['MFAPIN'] );

    if ($mfapin) {
        // if query string PIN exists ... get code from DB to test match
        $sentPIN = get_the_author_meta('RingCentral_2fa_user_2fa_code', $get_user_id);
        $pinValidated = $mfapin == $sentPIN ? 1 : 0;
        if( $pinValidated) {
            update_user_meta($get_user_id, 'RingCentral_2fa_fresh_code_sent', 0);
            update_user_meta($get_user_id, 'RingCentral_2fa_user_mobile_validated', 1);
            update_user_meta($get_user_id, 'RingCentral_2fa_user_2fa_code', "");

            $enabled = get_the_author_meta('RingCentral_2fa_user_enabled', $get_user_id);
            $validated = get_the_author_meta('RingCentral_2fa_user_mobile_validated', $get_user_id);
            $mfapin = 0 ;
        } else {
            // PINs don't match
            update_user_meta($get_user_id, 'RingCentral_2fa_user_mobile_validated', 0);
        }
    }
    // test if a fresh 6 digit code was sent
    $fresh_code = get_the_author_meta('RingCentral_2fa_fresh_code_sent', $selected_user_obj->ID);

    $checkedString = $enabled === '1' ? 'checked' : '';

    $from = ringcentral_get_from_phone();
    ?>
    <input type='hidden' name='RingCentral_from_mobile' id='RingCentralFromMobile' value="<?php echo $from; ?>" >
    <input type='hidden' name='RingCentral_user_id' id='RingCentralUserID' value="<?php echo $selected_user_id; ?>" >

    <?php if ($loggedin_user_id == $selected_user_id) { // editing your own profile ?>
        <h3 id="RC_2FA">SMS Two-Factor Authentication Settings </h3>
        <div style="margin-top: 5px; width: 45%; border: 1px solid #004F6D; padding: 5px; background: #DAF0F8;">
            When enabling 2FA you are agreeing to be sent a pin code via SMS which will be required to complete the
            login process.</div>
    <?php } else { ?>
        <img src="<?php echo RINGCENTRAL_FULL_LOGO ?>">
        <h3>RingCentral Two-Factor Authentication Settings </h3>
        <div style="margin-top: 5px; width: 45%; border: 1px solid #004F6D; padding: 5px; background: #DAF0F8;">
            Use RingCentral to send an SMS message with a pin code in order to complete login. By turning on
            RingCentral 2FA you are agreeing that the owner of the mobile number has consented to receive these
            types of SMS messages from you</div>
    <?php } ?>

    <table class='form-table'>
        <tr >
            <th>
                <p id="TwoFAAnchor"></p>
                <label for='RingCentral_2fa_user_enabled'>Turn on 2FA ?</label></th>
            <td>
                <?php if ($selected_user_access_lvl == "administrator") { ?>
                    <input id="TwoFAEnabledAdmin" type='checkbox' name='RingCentral_2fa_user_enabled' <?php echo $checkedString; ?> value='<?php echo $enabled; ?>' />
                <?php } else { ?>
                    <input id="TwoFAEnabled" type='checkbox' name='RingCentral_2fa_user_enabled' <?php echo $checkedString; ?> value='<?php echo $enabled; ?>' />
                <?php } ?>
            </td>
        </tr>
        <tr >
            <th style="vertical-align: middle;"><label for='RingCentralMobile' >Mobile Phone Number</label></th>
            <td>
                +1 <input type='text' name='RingCentral_2fa_user_mobile' id='RingCentralMobile'
                          value='<?php echo $mobileValue; ?>' />
                <div style="display: none" id="send-code">
                    <a href="javascript:void(0);" onclick="sendPin();" >Send 6 digit validation code</a>
                </div>
                <br />
                <span class='description'>US and Canadian mobile numbers only. </span>
                <p id="v-code" style="display: none"></p>
                <?php
                if ($selected_user_access_lvl == "administrator") {
                    if ($enabled && $validated) {
                        echo "<p id='validatedText' style='color: green; '>Entered mobile number has been 2FA validated</p>";
                    }
                    if ($toPhone) {
                        echo "<p id='code-sent' style='color: green; '>a 6 digit code has been sent, enter it below to validate your mobile number</p>";
                    };
                }
                ?>
            </td>
        </tr>
        <?php if ($toPhone || $mfapin) { ?>
            <tr >
                <th style="vertical-align: middle;"><label for='RingCentral_2fa_validation' >Validation Code</label></th>
                <td>
                    <input type='text' name='RingCentral_2fa_validation' id="enterPinCode" value='' />
                    <div style="display: none" id="pinCode">
                        <a href="javascript:void(0);" onclick="validateUser();" >Verify 6 digit code</a>
                    </div>
                    <?php
                    if (!$pinValidated) { ?>
                        <p style='color: red; '>PIN was NOT yet validated!</p>
                    <?php  } ?>
                </td>
            </tr>
        <?php  } ?>
    </table>
<?php } ?>
