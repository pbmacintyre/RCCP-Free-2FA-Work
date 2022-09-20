<?php

/*
  Plugin Name: Vonage 2FA
  Plugin URI: http://wordpress.org/plugins/vonage-2fa
  Description: Use Vonage's APIs for 2FA
  Author: Vonage
  Version: 1.0.2
  Author URI: https://developer.vonage.com/
*/

const PLUGIN_VERSION = '1.0.2';
const RESPONSE_PIN_OK = "0";
const RESPONSE_PIN_INVALID = "16";
const RESPONSE_VERIFICATION_PASSED = 'SUCCESS';
const RESPONSE_REQUEST_FAILED = '3';
const RESPONSE_REQUEST_INSUFFICIENT_FUNDS = '9';

global $wp_version;
define("VONAGE_USER_AGENT_STRING", 'vonage-wordpress/' . $wp_version . '/' . PLUGIN_VERSION);

function vonage_2fa_setup_menu () {
    add_menu_page(
        'Vonage 2FA Plugin Page',
        'Vonage 2FA',
        'manage_options',
        'vonage_2fa_plugin',
        'vonage_2fa_load_admin_settings',
        'data:image/svg+xml;base64,' . base64_encode('<svg version="1.0" xmlns="http://www.w3.org/2000/svg"
             width="300.000000pt" height="261.000000pt" viewBox="0 0 300.000000 261.000000"
             preserveAspectRatio="xMidYMid meet">

            <g transform="translate(0.000000,261.000000) scale(0.100000,-0.100000)"
            fill="#000000" stroke="none">
            <path d="M10 2588 c375 -850 841 -1883 850 -1883 6 0 77 146 156 324 l144 324
            -282 628 -283 628 -297 1 -298 0 10 -22z"/>
            <path d="M1975 1662 c-544 -1227 -601 -1341 -747 -1497 -70 -75 -137 -120
            -216 -146 l-57 -18 326 2 325 2 76 38 c141 69 266 231 407 528 47 97 813 1814
            892 1997 l18 42 -302 0 -302 -1 -420 -947z"/>
            </g>
            </svg>
            ')
    );
}

function vonage_2fa_register_settings () {
    register_setting('vonage_api_settings_options', 'vonage_api_settings_options', 'vonage_api_settings_options_validate');
    add_settings_section('api_credentials', 'Vonage API Credentials', 'vonage_2fa_plugin_text_helper', 'vonage_2fa_plugin');

    add_settings_field('api_credentials_key', 'API Key', 'vonage_2fa_api_credentials_key', 'vonage_2fa_plugin', 'api_credentials');
    add_settings_field('api_credentials_secret', 'API Secret', 'vonage_2fa_api_credentials_secret', 'vonage_2fa_plugin', 'api_credentials');
}

function vonage_2fa_plugin_text_helper () {
    echo '<p>You will need your master API Key/Secret credentials from your Vonage Dashboard.</p>';
}

function vonage_2fa_api_credentials_key () {
    $options = get_option('vonage_api_settings_options');
    echo "<input id='api_credentials_key' name='vonage_api_settings_options[api_credentials_key]' type='text' value='" . esc_attr($options['api_credentials_key']) . "' />";
}

function vonage_2fa_api_credentials_secret () {
    $options = get_option('vonage_api_settings_options');
    echo "<input id='api_credentials_secret' name='vonage_api_settings_options[api_credentials_secret]' type='text' value='" . esc_attr($options['api_credentials_secret']) . "' />";
}

function vonage_2fa_load_admin_settings () {
    echo "
    <img src='" . plugin_dir_url(__FILE__) . "assets/logo-large.png' alt='Vonage logo'>
    <h1>Built in 2FA</h1>
    <p>A text is sent out with a 2FA code to the user's provided mobile number.</p>
    <p>This plugin requires a Vonage Developer Account to work.<br>
    <p>If you don't have a Developer Account, you can follow the instructions below the settings fields.</p>
    <strong>If you run out of credit on your Vonage account,
    your users may be locked out if they are unable to complete the 2FA process.</strong><br>
    <div>
        <form action='options.php' method='post'>";
    settings_fields('vonage_api_settings_options');
    do_settings_sections('vonage_2fa_plugin');
    submit_button();
    echo "
        </form>
    </div>
    <h2>Setup Tutorial</h2>
    <p>1. Head to <a target=\'_blank\' href=\'https://dashboard.nexmo.com/sign-up\'>https://dashboard.nexmo.com/sign-up</a> to create a new Vonage API Account.
    <p>2. Once you have an account with credit, you\'ll need the following keys:</p>
    <img src='" . plugin_dir_url(__FILE__) . "assets/vonage-api-screenshot.png' alt='Vonage logo'>";
    echo "
    <p>Paste these two values into the corresponding fields above, and you're all set.</p>";
}

function vonage_2fa_user_settings ($user) {
    $mobileValue = get_the_author_meta('vonage_2fa_user_mobile_number_data', $user->ID);
    $enabled = get_the_author_meta('vonage_2fa_user_enabled_data', $user->ID);
    $checkedString = $enabled === '1' ? 'checked' : '';

    echo "
        <br />
        <h3>Vonage Two-Factor Authentication Settings</h3>
        
        <table class='form-table'>
            <tr>
                <th><label for='vonage_2fa_user_mobile_number'>Phone Number</label></th>
                <td>
                    <input type='text' name='vonage_2fa_user_mobile_number' id='vonage_2fa_user_mobile_number' value='$mobileValue' class='regular-text' /><br />
                    <span class='description'>Your mobile number needs to have the international dialling code (e.g. +44770XXXXXXX).</span>
                </td>
            </tr>

            <tr>
                <th>  <label for='vonage_2fa_user_enabled'>Enable 2FA</label></th>
                <td>
                    <input type='checkbox' name='vonage_2fa_user_enabled' $checkedString value='$enabled'>
                </td>
            </tr>
        </table>
    ";
}

function vonage_2fa_mobile_number_taken ($user_id, $mobile) {

    if (!$mobile) {
        return false;
    }

    $users = get_users(
        [
            'meta_key' => 'vonage_2fa_user_mobile_number',
            'meta_value' => $mobile,
            'number' => 1
        ]
    );

    return 0 < count($users) && $user_id !== $users[0]->ID;
}

function vonage_2fa_valid_mobile ($mobile) {
    $validMatch = preg_match('/^\+(?:[0-9]?){6,14}[0-9]$/', $mobile);
    $validTrim = trim($mobile) !== "";

    return $validMatch && $validTrim;
}

function vonage_2fa_form_settings_validation (&$errors, $update, &$user) {
    $mobile = filter_var($_POST['vonage_2fa_user_mobile_number'], FILTER_SANITIZE_NUMBER_INT);
    $enabled = filter_var(isset($_POST['vonage_2fa_user_enabled']), FILTER_SANITIZE_NUMBER_INT);

    if ($user && $enabled && !vonage_2fa_valid_mobile($mobile)) {
        $errors->add('vonage_2fa_settings_update_error', 'Phone number provided is invalid, please make sure it includes international dialling code with plus sign.');
        update_user_meta($user->ID, 'vonage_2fa_user_mobile_number_data', "");
    }

    if ($user && $mobile && vonage_2fa_mobile_number_taken($user->ID, $mobile)) {
        $errors->add('vonage_2fa_settings_update_error', 'Mobile number already in use.');
        update_user_meta($user->ID, 'vonage_2fa_user_mobile_number_data', "");
    }
}

function vonage_2fa_save_settings ($user_id) {

    $mobile = filter_var($_POST['vonage_2fa_user_mobile_number'], FILTER_SANITIZE_NUMBER_INT);
    $enabled = filter_var(isset($_POST['vonage_2fa_user_enabled']), FILTER_SANITIZE_NUMBER_INT);

    if (!current_user_can('edit_user', $user_id)) {
        return false;
    }

    update_user_meta($user_id, 'vonage_2fa_user_mobile_number_data', $mobile);
    update_user_meta($user_id, 'vonage_2fa_user_enabled_data', $enabled);
}

function vonage_2fa_auth_intercept ($user, $username, $password) {
    if (!session_id()) {
        session_start();
    }

    $wpUser = get_user_by('login', $username);
    $enabled_2fa = get_user_meta($wpUser->ID, 'vonage_2fa_user_enabled_data', true);

    if (!$enabled_2fa) {
        return;
    }

    $options = get_option('vonage_api_settings_options');
    $apiKey = $options['api_credentials_key'];
    $apiSecret = $options['api_credentials_secret'];

    $errors = [];
    $redirect_to = sanitize_url($_POST['redirect_to']) ?? admin_url();
    $remember_me = isset($_POST['rememberme']) && $_POST['rememberme'] === 'forever';

    $savedRequestId = sanitize_text_field($_SESSION['vonage_2fa_request_id']);
    $pin = isset($_POST['vonage_2fa_pin']) ? sanitize_text_field($_POST['vonage_2fa_pin']) : false;
    $requestId = isset($_POST['vonage_2fa_request_id']) ? sanitize_text_field($_POST['vonage_2fa_request_id']) : false;

    // You have submitted a PIN
    if ($requestId && $pin && $savedRequestId === $requestId) {

        $url = "https://api.nexmo.com/verify/check/json?&api_key=$apiKey&api_secret=$apiSecret&request_id=$requestId&code=$pin";
        $response = wp_remote_get($url, [
            'user-agent' => VONAGE_USER_AGENT_STRING
        ]);
        $responseBody = json_decode($response['body'], true);

        if ($responseBody['status'] === RESPONSE_PIN_OK) {
            wp_set_auth_cookie($wpUser->ID, $remember_me);
            wp_safe_redirect($redirect_to);
            exit;
        }

        if ($responseBody['status'] === RESPONSE_PIN_INVALID) {
            $errors[] = "Invalid PIN code";
        }
    }

    // Or you have a request ID saved that needs to be checked
    if ($savedRequestId) {
        $url = "https://api.nexmo.com/verify/search/json?&api_key=$apiKey&api_secret=$apiSecret&request_id=$savedRequestId";
        $response = wp_remote_get($url, [
            'user-agent' => VONAGE_USER_AGENT_STRING
        ]);
        $responseBody = json_decode($response['body'], true);

        if ($responseBody['status'] === RESPONSE_VERIFICATION_PASSED) {
            wp_set_auth_cookie($wpUser->ID, $remember_me);
            wp_safe_redirect($redirect_to);
            exit;
        }

        // The saved request ID has expired or failed
        $errors[] = 'Your verification has expired or there was an error logging in.';
        $_SESSION['vonage_2fa_request_id'] = '';
    }

    // You are trying to log in for the first time or have requested a PIN or have an invalid exiting verify
    if ($wpUser) {
        vonage_2fa_verify_user($wpUser, $redirect_to, $remember_me, $errors);
    }

    return $user;
}

function vonage_2fa_verify_user ($user, $redirect_to, $remember_me, $errors = []) {
    $options = get_option('vonage_api_settings_options');
    $apiKey = $options['api_credentials_key'];
    $apiSecret = $options['api_credentials_secret'];
    $phoneNumber = get_user_meta($user->ID, 'vonage_2fa_user_mobile_number_data', true);

    // You are requesting a PIN with a phone number
    $url = "https://api.nexmo.com/verify/json?&api_key=$apiKey&api_secret=$apiSecret&number=$phoneNumber&workflow_id=6&brand=Wordpress2FA";
    $response = wp_remote_post($url, [
        'user-agent' => VONAGE_USER_AGENT_STRING
    ]);
    $responseBody = json_decode($response['body'], true);

    // Attempt to send number has been rejected
    if ($responseBody['status'] === RESPONSE_REQUEST_FAILED) {
        $errors[] = $responseBody['error_text'];
    }

    if ($responseBody['status'] === RESPONSE_REQUEST_INSUFFICIENT_FUNDS) {
        $errors[] = 'Your Vonage account does not have enough balance to perform this authorisation request. 
        Please contact your website administrator';
    }

    $requestId = $responseBody['request_id'];
    $_SESSION['vonage_2fa_request_id'] = $requestId;

    wp_logout();
    nocache_headers();
    header('Content-Type: ' . get_bloginfo('html_type') . '; charset=' . get_bloginfo('charset'));
    login_header('Vonage Two-Factor Authentication', '<p class="message">' . sprintf('Enter the PIN code sent to your 2FA phone number ending in <strong>%1$s</strong>', substr($phoneNumber, -5)) . '</p>');

    if (!empty($errors)) { ?>
        <div id="login_error"><?php echo esc_html(implode('<br />', $errors)) ?></div>
    <?php } ?>

    <form name="loginform" id="loginform" action="<?php echo esc_url(site_url('wp-login.php', 'login_post')) ?>"
          method="post" autocomplete="off">
        <p>
            <label for="vonage_2fa_pin">PIN code
                <br/>
                <input type="number" name="vonage_2fa_pin" id="vonage_2fa_pin" class="input" value="" size="6"/>
            </label>
        </p>
        <p class="submit">
            <input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large"
                   value="Verify"/>
            <input type="hidden" name="log" value="<?php echo esc_attr($user->user_login) ?>"/>
            <input type="hidden" name="vonage_2fa_request_id" value="<?php echo esc_attr($requestId) ?>"/>
            <input type="hidden" name="redirect_to" value="<?php echo esc_attr($redirect_to) ?>"/>

            <?php if ($remember_me) : ?>
                <input type="hidden" name="rememberme" value="forever"/>
            <?php endif; ?>
        </p>
    </form>

    <?php

    login_footer('vonage_2fa_pin');

    exit;
}

add_action('admin_menu', 'vonage_2fa_setup_menu');
add_action('admin_init', 'vonage_2fa_register_settings');
add_action('show_user_profile', 'vonage_2fa_user_settings');
add_action('edit_user_profile', 'vonage_2fa_user_settings');
add_action('user_profile_update_errors', 'vonage_2fa_form_settings_validation', 10, 3);
add_action('personal_options_update', 'vonage_2fa_save_settings');
add_action('edit_user_profile_update', 'vonage_2fa_save_settings');
add_action('authenticate', 'vonage_2fa_auth_intercept', 10, 3);