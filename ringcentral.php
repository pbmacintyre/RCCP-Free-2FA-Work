<?php
/*
Plugin Name: RingCentral
Plugin URI:  https://paladin-bs.com
Description: RingCentral Communications Plugin - FREE
Author:      Peter MacIntyre
Version:     1.7.0
Author URI:  https://paladin-bs.com/about
Details URI: https://paladin-bs.com
License:     GPL2
License URI: https://www.gnu.org/licenses/gpl-2.0.html

RingCentral is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
any later version.
 
RingCentral is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.
 
See License URI for full details.

Copyright (C) 2019-2025 Paladin Business Solutions
*/

/* ============================== */
/* Set RingCentral Constant values */
/* ============================== */
if (!defined('RINGCENTRAL_PLUGIN_VERSION')) {
    define('RINGCENTRAL_PLUGIN_VERSION', "1.7.0");
}
if (!defined('RINGCENTRAL_PLUGINDIR')) {
    define('RINGCENTRAL_PLUGINDIR', plugin_dir_path(__FILE__));
}
if (!defined('RINGCENTRAL_PLUGINURL')) {
    define('RINGCENTRAL_PLUGINURL', plugin_dir_url(__FILE__));
    //  http path returned
}
if (!defined('RINGCENTRAL_PLUGIN_INCLUDES')) {
    define('RINGCENTRAL_PLUGIN_INCLUDES', plugin_dir_path(__FILE__) . "includes/");
}
if (!defined('RINGCENTRAL_PLUGIN_FILENAME')) {
    define('RINGCENTRAL_PLUGIN_FILENAME', plugin_basename(dirname(__FILE__) . '/ringcentral.php'));
}
if (!defined('RINGCENTRAL_PRO_URL')) {
    define('RINGCENTRAL_PRO_URL', 'https://paladin-bs.com/product/rccp-pro/');
}
if (!defined('RINGCENTRAL_LOGO')) {
    define('RINGCENTRAL_LOGO', RINGCENTRAL_PLUGINURL . 'images/rc_logo_60_60.jpg');
}
if (!defined('RINGCENTRAL_FULL_LOGO')) {
    define('RINGCENTRAL_FULL_LOGO', RINGCENTRAL_PLUGINURL . 'images/rc-logo.png');
}
/* ============================== */
/* bring in PHP utility functions */
/* ============================== */
require_once("includes/ringcentral-php-functions.inc");

/* ====================================== */
/* bring in generic RingCentral functions */
/* ====================================== */
require_once("includes/ringcentral-functions.inc");

/* ================================== */
/* bring in RingCentral 2FA functions */
/* ================================== */
require_once("includes/ringcentral-2fa-functions.inc");

/* ================================= */
/* set RingCentral supporting cast  */
/* ================================= */
function ringcentral_js_add_script() {
    $js_path = RINGCENTRAL_PLUGINURL . 'js/ringcentral-scripts.js';
    wp_enqueue_script('ringcentral-js', $js_path);
}

add_action('init', 'ringcentral_js_add_script');

function ringcentral_js_add_admin_script() {
    $js_path = RINGCENTRAL_PLUGINURL . 'js/ringcentral-admin-scripts.js';
    wp_enqueue_script('ringcentral-admin-js', $js_path);
}

add_action('admin_enqueue_scripts', 'ringcentral_js_add_admin_script');

function ringcentral_load_custom_admin_css() {
    wp_register_style('ringcentral_custom_admin_css',
            RINGCENTRAL_PLUGINURL . 'css/ringcentral-custom.css',
            false, '1.0.0');
    wp_enqueue_style('ringcentral_custom_admin_css');
}

add_action('admin_print_styles', 'ringcentral_load_custom_admin_css');

/* ========================================= */
/* Make top level menu                       */
/* ========================================= */
function ringcentral_menu() {
    add_menu_page(
            'RingCentral: Configurations',    // Page & tab title
            'RingCentral',                                // Menu title
            'manage_options',                           // Capability option
            'ringcentral_Admin',                        // Menu slug
            'ringcentral_config_page',                  // menu destination function call
            RINGCENTRAL_PLUGINURL . 'images/rc_logo_20_20.jpg', // menu icon path
            25                                       // menu position level
    );
    add_submenu_page(
            'ringcentral_Admin',                   // parent slug
            'RingCentral: Configurations', // page title
            'Settings',                            // menu title - can be different than parent
            'manage_options',                      // options
            'ringcentral_Admin'                    // menu slug to match top level (go to the same link)
    );
    add_submenu_page(
            'ringcentral_Admin',                // parent menu slug
            'RingCentral: Add a New Subscriber', // page title
            'Add Subscribers',                  // menu title
            'manage_options',                   // capability
            'ringcentral_add_subs',             // menu slug
            'ringcentral_add_subscribers'       // callable function
    );
    add_submenu_page(
            'ringcentral_Admin',                   // parent menu slug
            'RingCentral: Manage Subscribers', // page title
            'List Subscribers',                    // menu title
            'manage_options',                      // capability
            'ringcentral_list_subs',               // menu slug
            'ringCentral_list_subscribers'         // callable function
    );
    add_submenu_page(
            'ringcentral_Admin',                // parent menu slug
            'RingCentral: CallMe Requests', // page title
            'Call Me Requests',                 // menu title
            'manage_options',                   // capability
            'ringcentral_list_callme',          // menu slug
            'ringCentral_list_callme_requests'  // callable function
    );
//    add_submenu_page(
//        'ringcentral_Admin',                // parent menu slug
//        'RingCentral: Send a Team Message', // page title
//        'Send a Team Message',                  // menu title
//        'manage_options',                   // capability
//        'ringcentral_glip',             // menu slug
//        'ringcentral_glip_send'       // callable function
//    );
//    add_submenu_page(
//        'ringcentral_Admin',                // parent menu slug
//        'RingCentral: Team Messaging Embed ', // page title
//        'Embedded Team Messaging',                  // menu title
//        'manage_options',                   // capability
//        'ringcentral_glip_embed',             // menu slug
//        'ringcentral_glip_embed'       // callable function
//    );
}

/* ========================================= */
/* page / menu calling functions             */
/* ========================================= */

// call add action func on menu building function above.
add_action('admin_menu', 'ringcentral_menu');

// function for default Admin page
function ringcentral_config_page() {
    // check user capabilities
    if (!current_user_can('manage_options')) {
        return;
    }
    ?>
    <div class="wrap">
        <?php ringcentral_admin_page_top();
        require_once(RINGCENTRAL_PLUGINDIR . "includes/ringcentral-config-page.inc"); ?>

    </div>
    <?php
}

// function for adding new subscribers page
function ringcentral_add_subscribers() {
    // check user capabilities
    if (!current_user_can('manage_options')) {
        return;
    }
    ?>
    <div class="wrap">
        <?php ringcentral_admin_page_top();
        require_once(RINGCENTRAL_PLUGINDIR . "includes/ringcentral-add-subscribers.inc"); ?>

    </div>
    <?php
}

// function for editing existing subscribers page
function ringCentral_list_subscribers() {
    // check user capabilities
    if (!current_user_can('manage_options')) {
        return;
    }
    ?>
    <div class="wrap">
        <?php ringcentral_admin_page_top();
        require_once(RINGCENTRAL_PLUGINDIR . "includes/ringcentral-list-subscribers.inc"); ?>

    </div>
    <?php
}

// function for editing existing subscribers page
function ringCentral_list_callme_requests() {
    // check user capabilities
    if (!current_user_can('manage_options')) {
        return;
    }
    ?>
    <div class="wrap">
        <?php ringcentral_admin_page_top();
        require_once(RINGCENTRAL_PLUGINDIR . "includes/ringcentral-list-callme.inc"); ?>

    </div>
    <?php
}

// function for calling GLIP send
function ringcentral_glip_send() {
    // check user capabilities
    if (!current_user_can('manage_options')) {
        return;
    }
    ?>
    <div class="wrap">
        <?php ringcentral_admin_page_top();
        require_once(RINGCENTRAL_PLUGINDIR . "includes/ringcentral-glip.inc"); ?>

    </div>
    <?php
}

// function for calling GLIP Embed settings page
function ringcentral_glip_embed() {
    // check user capabilities
    if (!current_user_can('manage_options')) {
        return;
    }
    ?>
    <div class="wrap">
        <?php ringcentral_admin_page_top();
        require_once(RINGCENTRAL_PLUGINDIR . "includes/ringcentral-glip-embed.inc"); ?>

    </div>
    <?php
}

/* ========================================================== */
/* Add action for the ringcentral Embedded Phone app toggle   */
/* ========================================================== */
add_action('admin_footer', 'ringcentral_embed_phone');

/* =============================================== */
/* Add custom footer action                        */
/* This toggles the ringcentral Embedded Phone app */
/* =============================================== */
function ringcentral_embed_phone() {
    global $wpdb;
    $result_rc = $wpdb->get_row($wpdb->prepare("SELECT * FROM `ringcentral_control`
        WHERE `ringcentral_control_id` = %d", 1)
    );
    if ($result_rc->embedded_phone == 1) {

        $embed_url = "https://apps.ringcentral.com/integration/ringcentral-embeddable/latest/adapter.js?enablePopup=1&multipleTabsSupport=1";

        $embed_url .= ($result_rc->disable_glip == 1) ? "&disableGlip=true" : "&disableGlip=false";
        $embed_url .= ($result_rc->enable_sms_template == 1) ? "&enableSMSTemplate=1" : "";
        $embed_url .= ($result_rc->disable_calls == 1) ? "&disableCall=true" : "";
        $embed_url .= ($result_rc->disable_call_history == 1) ? "&disableCallHistory=true" : "";
        $embed_url .= ($result_rc->disable_contacts == 1) ? "&disableContacts=true" : "";

        $embed_url .= ($result_rc->disable_messages == 1) ? "&disableMessages=true" : "";
        $embed_url .= ($result_rc->disable_meetings == 1) ? "&disableMeeting=true" : "";

        ?>
        <script src=" <?= $embed_url ?>"></script>
    <?php }
}

/* ================================== */
/* Add action for the contacts widget */
/* ================================== */
add_action('widgets_init', 'ringcentral_register_contacts_widget');

/* ============================================== */
/* Add contacts widget function                   */
/* This registers the ringcentral_contacts_widget */
/* ============================================== */
function ringcentral_register_contacts_widget() {
    register_widget('ringcentral_contacts_widget');
}

require_once(RINGCENTRAL_PLUGINDIR . "includes/ringcentral-contacts-widget.inc");

/* ================================= */
/* Add action for the Call Me widget */
/* ================================= */
add_action('widgets_init', 'ringcentral_register_callme_widget');

/* ============================================ */
/* Add Call Me widget function                  */
/* This registers the ringcentral_callme_widget */
/* ============================================ */
function ringcentral_register_callme_widget() {
    register_widget('ringcentral_callme_widget');
}

require_once(RINGCENTRAL_PLUGINDIR . "includes/ringcentral-callme-widget.inc");

/* ============================================== */
/* Add action hook for correspondence on new post */
/* ============================================== */
add_action('pending_to_publish', 'ringcentral_new_post_set_queue');
add_action('draft_to_publish', 'ringcentral_new_post_set_queue');

function ringcentral_new_post_set_queue($post) {
    global $wpdb;

    if (wp_is_post_revision($post->ID) || get_post_type($post->ID) !== 'post') {
        return;
    }

    $post_url = get_permalink($post->ID);
    $title = $post->post_title;

    $wpdb->query($wpdb->prepare("INSERT INTO `ringcentral_queue` 
        (`ringcentral_post_id`, `ringcentral_post_title`, `ringcentral_post_url`) 
        VALUES (%d, %s, %s)", $post->ID, $title, $post_url));
}

/* ============================================== */
/* Setup CRON to do SMS messages and emails .     */
/* ============================================== */
function ringcentral_cron_schedules($schedules) {
    if (!isset($schedules["5min"])) {
        $schedules["5min"] = array(
                'interval' => 5 * 60,
                'display' => __('Once every 5 minutes'));
    }
    if (!isset($schedules["30min"])) {
        $schedules["30min"] = array(
                'interval' => 30 * 60,
                'display' => __('Once every 30 minutes'));
    }
    return $schedules;
}

add_filter('cron_schedules', 'ringcentral_cron_schedules');

if (!wp_next_scheduled('ringcentral_send_notifications')) {
    wp_schedule_event(time(), '5min', 'ringcentral_send_notifications');
}

add_action('ringcentral_send_notifications', 'ringcentral_check_queue');

function ringcentral_check_queue() {
    global $wpdb;

    $result_queue = $wpdb->get_row($wpdb->prepare("SELECT `ringcentral_queue_id` AS `id`, 
        `ringcentral_post_title` AS `title`, `ringcentral_post_url` AS `url`
        FROM `ringcentral_queue`
        WHERE `ringcentral_queue_complete` = %d LIMIT 1", 0)
    );

    if ($result_queue) {
        $siteName = get_bloginfo('name');
        $queueId = $result_queue->id;
        $postTitle = $result_queue->title;
        $postUrl = $result_queue->url;

        $wpdb->query($wpdb->prepare("UPDATE `ringcentral_queue` 
            SET `ringcentral_queue_complete` = 1 WHERE `ringcentral_queue_id` = %d", $queueId));

        $result_rc = $wpdb->get_row($wpdb->prepare("SELECT `email_updates`, `mobile_updates`
			FROM `ringcentral_control` WHERE `ringcentral_control_id` = %d", 1)
        );

        if ($result_rc->email_updates) {
            require_once(RINGCENTRAL_PLUGINDIR . "includes/ringcentral-send-mass-email.inc");
        }

        if ($result_rc->mobile_updates) {
            require_once(RINGCENTRAL_PLUGINDIR . "includes/ringcentral-send-mass-mobile.inc");
        }
    }
}

/* ================================= */
/* Add filter hook for subscriptions */
/* ================================= */
function ringcentral_vars($vars) {
    $vars[] = 'rcsubscribe';
    $vars[] = 'rcunsubscribe';
    $vars[] = 'rcformat';
    $vars[] = 'rcwebhook';
    $vars[] = 'confirmmfa';
    return $vars;
}

add_filter('query_vars', 'ringcentral_vars');

function ringcentral_handle_vars() {
    global $wpdb;
    $subscribe = get_query_var('rcsubscribe');
    $unsubscribe = get_query_var('rcunsubscribe');
    $method = get_query_var('rcformat');

    if (!empty($subscribe)) {
        $token_id = $subscribe;
        require_once(RINGCENTRAL_PLUGINDIR . "includes/ringcentral-confirm-optin.inc");
    } elseif (!empty($unsubscribe)) {
        $token_id = $unsubscribe;
        require_once(RINGCENTRAL_PLUGINDIR . "includes/ringcentral-unsubscribe.inc");
    } elseif (!empty(get_query_var('rcwebhook'))) {
        // Check for opt out keywords
        require_once(RINGCENTRAL_PLUGINDIR . "includes/ringcentral-webhook.inc");
    }
}

add_action('parse_query', 'ringcentral_handle_vars');

/* ============================================= */
/* Add registration hook for plugin installation */
/* ============================================= */
function ringcentral_install() {
    require_once(RINGCENTRAL_PLUGINDIR . "includes/ringcentral-install.inc");
}

/* ========================================= */
/* Create default pages on plugin activation */
/* ========================================= */
function ringcentral_install_default_pages() {
    require_once(RINGCENTRAL_PLUGINDIR . "includes/ringcentral-activation.inc");
}

register_activation_hook(__FILE__, 'ringcentral_install');
register_activation_hook(__FILE__, 'ringcentral_install_default_pages');

/* ===================================== */
/* Check if the pro version is available */
/* ===================================== */
//if (ringcentral_CheckPro()) {
//    /* ====================================================== */
//    /* add link on plugin details line for buying Pro Version */
//    /* ====================================================== */
//    add_filter('plugin_row_meta', 'rc_get_pro', 10, 2);
//
//    //Add a link on the plugin control line after 'visit plugin site'
//    function rc_get_pro ($links, $file) {
//        if ($file == RINGCENTRAL_PLUGIN_FILENAME) {
//            $link_string = RINGCENTRAL_PRO_URL;
//            $links[] = "<a href='$link_string' style='color: red' target='_blank'>" . esc_html__('Get Pro Version', 'RingCentral') . '</a>';
//        }
//        return $links;
//    }
//}

// function for sending out 6 digit authorization code to admin for login validation
function RingCentral_2fa_intercept($user, $username, $password) {

    if (is_wp_error($user) || empty($username)) {
        return $user;
    }

    // Only handle initial login (not our 2FA form submission)
    if (!isset($_POST['RC_Validate_submit'])) {
        // generate + send the PIN
        ringcentral_gen_six_digit_code($user->ID);

        // Show the custom 2FA form instead of continuing login
        ringcentral_render_2fa_form($user);
        exit;
    }

    // if RC_Validate_submit is set, let WordPress continue normally
    return $user;
}

function ringcentral_handle_2fa_submit() {
    if (isset($_POST['RC_Validate_submit'])) {
        $username = $_POST['log'] ?? '';
        $enteredPIN = $_POST['entered_2fa_code'] ?? '';

        $user = get_user_by('login', $username);
        if (!$user) {
            return;
        }

        $sms_sentPIN = get_user_meta($user->ID, 'RingCentral_2fa_user_2fa_code', true);

        if ($enteredPIN == $sms_sentPIN) {
            // success: log in
            $remember = !empty($_POST['remember_me']) && $_POST['remember_me'] === 'forever';
            wp_set_auth_cookie($user->ID, $remember);
            wp_safe_redirect($_POST['redirect_to'] ?? admin_url());
            exit;
        } else {
            // fail → redisplay form with error
            ringcentral_render_2fa_form($user, ['Invalid 2FA Validation code']);
            exit;
        }
    }
}

function ringcentral_render_2fa_form($wpUser, $errors = []) {
    // Phone partial
    $phone_number = trim(get_user_meta($wpUser->ID, 'RingCentral_2fa_user_mobile', true));
    $phone_partial = substr($phone_number, -4);

    login_header('RingCentral 2FA',
            empty($errors)
                    ? '<p class="message">' . sprintf('We have sent you a 6 digit
                validation code to the number we have on file ending in <strong>%1$s</strong>', $phone_partial) . '</p>'
                    : '<div id="login_error">' . esc_html(implode('<br />', $errors)) . '</div>'
    );
    ?>
    <div style="display: flex; justify-content: center; align-items: center; flex-direction: column;">
        <form method="post" action="<?php echo esc_url(site_url('wp-login.php', 'login_post')); ?>"
              style="text-align: center; max-width: 300px; width: 100%;">
            <p>
                <label for="entered_2fa_code">Enter the validation code:</label><br/><br/>
                <input type="number" name="entered_2fa_code" size="6"/>

                <input type="submit" name="RC_Validate_submit" class="button button-primary" value="Validate Code"/>
                <input type="hidden" name="log" value="<?php echo esc_attr($wpUser->user_login); ?>"/>
                <input type="hidden" name="redirect_to" value="<?php echo esc_attr(admin_url()); ?>"/>
                <?php if (!empty($_POST['remember_me'])) { ?>
                    <input type="hidden" name="remember_me" value="forever"/>
                <?php } ?>
            </p>
        </form>
    </div>
    <?php
    login_footer();
}

add_filter('plugin_row_meta', 'ringcentral_add_plugin_links', 10, 2);

//Add a link on the plugin control line after 'view details'
function ringcentral_add_plugin_links($links, $file) {
    if ($file == plugin_basename(dirname(__FILE__) . '/ringcentral.php')) {
        $links[] = '<a href="https://paladin-bs.com/wp-content/uploads/2025/02/RingCentral_user_guide_1_6_8.pdf" target="_blank">' . esc_html__('User Guide', 'ringcentral') . '</a>';
    }
    return $links;
}

add_filter('authenticate', 'RingCentral_2fa_intercept', 30, 3);
add_action('login_init', 'ringcentral_handle_2fa_submit');

add_action('show_user_profile', 'ringcentral_2fa_user_settings');  // other users
add_action('edit_user_profile', 'ringcentral_2fa_user_settings');   // your own profile

add_action('personal_options_update', 'ringcentral_2fa_save_settings');
add_action('edit_user_profile_update', 'ringcentral_2fa_save_settings');

add_action('user_profile_update_errors', 'ringcentral_2fa_form_settings_validation', 10, 3);

?>