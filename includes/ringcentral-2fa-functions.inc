<?php
/**
 * Copyright (C) 2019-2022 9 Paladin Business Solutions
 *
 */

function ringcentral_2fa_save_settings ($user_id) {

    $mobile = filter_var($_POST['RingCentral_2fa_user_mobile'], FILTER_SANITIZE_NUMBER_INT);

    $mobile = preg_replace('/[^0-9]/', '', $mobile);
    if (substr($mobile, 0, 1) == "1") {
        $mobile = substr($mobile, 1);
    }
    $enabled = filter_var(isset($_POST['RingCentral_2fa_user_enabled']), FILTER_SANITIZE_NUMBER_INT);

    if (!current_user_can('edit_user', $user_id)) {
        return false;
    }

    update_user_meta($user_id, 'RingCentral_2fa_user_mobile', $mobile);
    update_user_meta($user_id, 'RingCentral_2fa_user_enabled', $enabled);
}

function ringcentral_2fa_user_settings ($user) {
    $mobileValue = get_the_author_meta('RingCentral_2fa_user_mobile', $user->ID);
    $enabled = get_the_author_meta('RingCentral_2fa_user_enabled', $user->ID);
    $checkedString = $enabled === '1' ? 'checked' : '';
    ?>
    <br/>
    <img id='page_title_img' title="RingCentral Plugin" src="<?php echo RINGCENTRAL_LOGO; ?>">
    <?php
    echo "<h3>RingCentral Two-Factor Authentication Settings</h3>

    <table class='form-table'>
    <tr>
        <th><label for='RingCentral_2fa_user_mobile'>Phone Number</label></th>
    <td>        
        <input type='tel' name='RingCentral_2fa_user_mobile' id='RingCentral_2fa_user_mobile' 
            value='$mobileValue' placeholder='9999999999' required />
        <br />
        <span class='description'>North American mobile numbers only. Format: 9999999999</span>
    </td></tr>

    <tr>
        <th><label for='RingCentral_2fa_user_enabled'>Turn on 2FA ?</label></th>
    <td>
        <input type='checkbox' name='RingCentral_2fa_user_enabled' $checkedString value='$enabled'>
    </td></tr>
    </table>
    ";
}

function ringcentral_2fa_form_settings_validation (&$errors, $update, &$user) {

    $mobile = filter_var($_POST['RingCentral_2fa_user_mobile'], FILTER_SANITIZE_NUMBER_INT);
    $enabled = filter_var(isset($_POST['RingCentral_2fa_user_enabled']), FILTER_SANITIZE_NUMBER_INT);

    // check that the number is in the right format, call the valid_mobile function
    if ($user && $enabled && !ringcentral_2fa_valid_mobile($mobile)) {
        $errors->add('vonage_2fa_settings_update_error',
            'Phone number provided is invalid, please make sure it is a valid North American formatted number');
        update_user_meta($user->ID, 'vonage_2fa_user_mobile_number_data', "");
    }

    // check to see if the number is not already in the database
    if ($user && $mobile && ringcentral_2fa_mobile_number_taken($user->ID, $mobile)) {
        $errors->add('vonage_2fa_settings_update_error', 'Mobile number already in use.');
        update_user_meta($user->ID, 'vonage_2fa_user_mobile_number_data', "");
    }
}

function ringcentral_2fa_valid_mobile ($mobile) {
    // $validMatch = preg_match('/^\+(?:[0-9]?){6,14}[0-9]$/', $mobile);

    // only take the mobile numbers, strip out brackets and dashes if they are there
    $validMatch = preg_replace('/[^0-9]/', '', $mobile);
//     strlen($mobile) !== 10
    if (substr($mobile, 0, 1) == "1") {
        $mobile = substr($mobile, 1);
    }
    $validTrim = trim($mobile) !== "";

    return $validMatch && $validTrim;
}

function ringcentral_2fa_mobile_number_taken ($user_id, $mobile) {

    if (!$mobile) {
        return false;
    }

    $users = get_users(
        [
            'meta_key' => 'RingCentral_2fa_user_mobile',
            'meta_value' => $mobile,
            'number' => 1
        ]
    );

    return 0 < count($users) && $user_id !== $users[0]->ID;
}

?>