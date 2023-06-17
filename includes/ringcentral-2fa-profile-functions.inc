<?php
/**
 * Copyright (C) 2019-2023 Paladin Business Solutions
 *
 */

/* ================ */
/* Edit own profile */
/* ================ */
function ringcentral_2fa_edit_profile ($selected_user_obj) {

    $loggedin_user_obj = wp_get_current_user();
    $loggedin_user_id = $loggedin_user_obj->data->ID ;

    $selected_user_access_lvl = $selected_user_obj->roles[0]; //access level (admin, contributor, etc.)
    $selected_user_id = $selected_user_obj->data->ID ;

    $mobileValue = get_the_author_meta('RingCentral_2fa_user_mobile', $selected_user_obj->ID);
    $mobileValue = ringcentral_2fa_valid_mobile($mobileValue) ;

    $enabled = get_the_author_meta('RingCentral_2fa_user_enabled', $selected_user_obj->ID);
    $validated = get_the_author_meta('RingCentral_2fa_user_mobile_validated', $selected_user_obj->ID);
    // Could be the first time editing the profile and therefore validated will be an empty string
    strlen($validated) == 0 ? $validated = 0 : $validated ;
    // whatever the case, send it back to db to ensure usermeta record exists
    update_user_meta($selected_user_obj->ID, 'RingCentral_2fa_user_mobile_validated', $validated);

    // test if a fresh 6 digit code was sent
    $fresh_code = get_the_author_meta('RingCentral_2fa_fresh_code_sent', $selected_user_obj->ID);

    $checkedString = $enabled === '1' ? 'checked' : '';
//    $selected_user = $selected_user_obj->user_login;  //username

//if ($loggedin_user_id == $selected_user_id) { // editing your own profile
//
//    } else {
//    // editing someone else's profile
//}
    ?>

    <br/>
    <?php if ($loggedin_user_id == $selected_user_id) { // editing your own profile ?>
        <h3>SMS Two-Factor Authentication Settings </h3>
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
        <tr>
            <th><label for='RingCentral_2fa_user_enabled'>Turn on 2FA ?</label></th>
            <td>
                <input id="TwoFAEnabled" type='checkbox' name='RingCentral_2fa_user_enabled' <?php echo $checkedString; ?> value='<?php echo $enabled; ?>' />
            </td>
        </tr>
        <tr >
            <th style="vertical-align: middle;"><label for='RingCentral_2fa_user_mobile' >Mobile Phone Number</label></th>
            <td>
                +1 <input type='text' name='RingCentral_2fa_user_mobile' id='RingCentral_2fa_user_mobile'
                          value='<?php echo $mobileValue; ?>' />

                <br />
                <span class='description'>US and Canadian mobile numbers only. </span>
                <?php
                if ($selected_user_access_lvl == "administrator") {
                    if ($enabled && $validated) {
                    echo "<p id='validatedText' style='color: red; '>Entered mobile number has been 2FA validated</p>";
                    }
                    if ($fresh_code) {
                        echo "<p style='color: red; '>a 6 digit code has been sent, enter it below to validate your mobile number</p>";
                    };

                            ?>
                        </td>
                    </tr>
                    <?php if (!$validated && $fresh_code) { ?>
                    <tr >
                        <th style="vertical-align: middle;"><label for='RingCentral_2fa_validation' >Validation Code</label></th>
                        <td>
                            <input type='text' name='RingCentral_2fa_validation' value='' />
                        </td>
                    </tr>
        <?php       }
                }?>

    </table>
<?php
}
/*
function ringcentral_2fa_edit_admin_profile ($selected_user) {

    $mobileValue =  get_the_author_meta('RingCentral_2fa_user_mobile', $selected_user);
    $enabled =      get_the_author_meta('RingCentral_2fa_user_enabled', $selected_user);
    $validated =    get_the_author_meta('RingCentral_2fa_user_mobile_validated', $selected_user);
    // Could be the first time editing the profile and therefore validated will be an empty string
    strlen($validated) == 0 ? $validated = 0 : $validated ;
    // whatever the case, send it back to db to ensure usermeta record exists
    update_user_meta($selected_user, 'RingCentral_2fa_user_mobile_validated', $validated);

    $checkedString = $enabled === '1' ? 'checked' : '';
    // $selected_user = $selected_user_obj->user_login;  //username

    ?>
    <br/>
    <h3>SMS Two-Factor Authentication Settings (other admin profile)</h3>
    <div style="margin-top: 5px; width: 45%; border: 1px solid #004F6D; padding: 5px; background: #DAF0F8;">
        When enabling 2FA you are agreeing to be sent a pin code via SMS which will be required
        to complete the login process.</div>
    <table class='form-table'>
        <tr>
            <th><label for='RingCentral_2fa_user_enabled'>Turn on 2FA ?</label></th>
            <td>
                <input type='checkbox' name='RingCentral_2fa_user_enabled' <?php echo $checkedString; ?> value='<?php echo $enabled; ?>'>
            </td>
        </tr>
        <tr >
            <th style="vertical-align: middle;"><label for='RingCentral_2fa_user_mobile' >Mobile Phone Number</label></th>
            <td>
                +1 <input type='text' name='RingCentral_2fa_user_mobile' id='RingCentral_2fa_user_mobile'
                          value='<?php echo $mobileValue; ?> ' placeholder='9999999999' required />
                <?php //request validation code if validated is null
                if ($validated == 0 ) { ?>
                    <a href="?user_id=<?php echo $selected_user; ?>&sendcode=true#RCanchor" >Validate Mobile Number</a>
                    <?php
                    if(isset($_GET['sendcode'])){
                        ringcentral_gen_six_digit_code_for_selected_user ($selected_user);
                    }
                }
                if ($validated == 1 ) {
                    echo "<p style='color: #0074cc; display: inline'>Entered mobile number has been 2FA validated</p>" ;
                } ?>
                <br />
                <span class='description'>US and Canadian mobile numbers only. </span>
            </td></tr>
        <?php  if (isset($_GET['sendcode']) && $validated == 0 ) {  ?>
            <tr >
                <th style="vertical-align: middle;"><label for='RingCentral_2fa_validation' >Validation Code</label></th>
                <td>
                    <input type='text' name='RingCentral_2fa_validation' value='' />
                </td></tr>
        <?php } ?>

    </table>
<?php }
*/ ?>