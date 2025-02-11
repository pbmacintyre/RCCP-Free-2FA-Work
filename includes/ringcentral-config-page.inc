<?php
/**
 * Copyright (C) 2019-2025 Paladin Business Solutions
 *
 */

/* ========= */
/* show_form */
/* ========= */
Function show_form($message, $label = "", $color = "#008EC2") {

	global $print_again, $wpdb, $valid_sdk;

	if (ringcentral_CheckPro()) { ?>
        <form action="<?php echo RINGCENTRAL_PRO_URL ?>" target="_blank" style="padding-left: 15%;">
            <?php 
            $btn_attributes = array( "style" => "background: red; border-color: #006799; color: #fff;" ); 
            submit_button("Get Pro Version","","submit","",$btn_attributes);
            ?>        
        </form>
    <?php } ?>

	<?php if (empty($_SERVER['HTTPS']) || $_SERVER['HTTPS'] == 'off') { ?>
	<div style="margin-top: 5px; width: 93%; max-width: 786px; border: 1px solid #900; padding: 10px; background: #ffe6e6; font-weight: bold; text-align: center;">
		To comply with CTIA guidelines, please enable HTTPS and save your settings<br />(this will allow for your users to opt out with the STOP keyword).
	</div>	
	<?php } ?>

	<form action="" method="post" >
	<table class="TableOverride" >
		<tr class="TableOverride">
			<td colspan="2" align="center">
<?php	
	if ($print_again == true) {
		echo "<font color='$color'><strong>" . esc_html($message) . "</strong></font>";
	} else {
	    echo "<font color='$color'><strong>" . esc_html($message) . "</strong></font>";	    
	}
	
	$result_rc = $wpdb->get_row( $wpdb->prepare("SELECT * FROM `ringcentral_control` WHERE `ringcentral_control_id` = %d", 1) );

	?></td>
	</tr>	
	<tr class="TableOverride">
		<td class="left_col">
			<p style='display: inline; <?php if ($label == "embedded_phone") echo "color:red"; ?>' >Use Embedded Phone?</p>
			
			<?php echo ringcentral_build_help("embedded_phone") ; ?>
						
		</td>
		<td class="right_col">
            <input type="checkbox" name="embedded_phone" id="embedded" onclick="embedd_options()" <?php
		if ($print_again) { 
		    if ($_POST['embedded_phone'] == "on") {
		      echo 'CHECKED';
		    } 
          } else {             
              if ($result_rc->embedded_phone == 1) {
                  echo 'CHECKED' ;
                }
          }
            ?>></td>
	</tr>
    <tr class="TableOverride" id="embeddRow">
        <td class="left_col">
            Manage the display options:
        </td>
        <td class="right_col">
            <table  >
                <tr class="inner_borders">
                    <td class="inner_borders">
                        Disable Team Messaging?
                        <input type="checkbox" name="disable_glip" <?php
						if ($print_again) {
							if ($_POST['disable_glip'] == "on") {
								echo 'CHECKED';
							}
						} else {
							if ($result_rc->disable_glip == 1) {
								echo 'CHECKED' ;
							}
						}
						?>>
                    </td>
                    <td class="inner_borders">
                        Enable SMS Template?
                        <input type="checkbox" name="enable_sms_template" <?php
						if ($print_again) {
							if ($_POST['enable_sms_template'] == "on") {
								echo 'CHECKED';
							}
						} else {
							if ($result_rc->enable_sms_template == 1) {
								echo 'CHECKED' ;
							}
						}
						?>>
                    </td>
                </tr>
                <tr class="inner_borders">
                    <td class="inner_borders">
                        Disable Calls?
                        <input type="checkbox" name="disable_calls" <?php
						if ($print_again) {
							if ($_POST['disable_calls'] == "on") {
								echo 'CHECKED';
							}
						} else {
							if ($result_rc->disable_calls == 1) {
								echo 'CHECKED' ;
							}
						}
						?>>
                    </td>
                    <td class="inner_borders">
                        Disable Call History?
                        <input type="checkbox" name="disable_call_history" <?php
						if ($print_again) {
							if ($_POST['disable_call_history'] == "on") {
								echo 'CHECKED';
							}
						} else {
							if ($result_rc->disable_call_history == 1) {
								echo 'CHECKED' ;
							}
						}
						?>>
                    </td>
                </tr>
                <tr class="inner_borders">
                    <td class="inner_borders">
                        Disable Contacts?
                        <input type="checkbox" name="disable_contacts" <?php
						if ($print_again) {
							if ($_POST['disable_contacts'] == "on") {
								echo 'CHECKED';
							}
						} else {
							if ($result_rc->disable_contacts == 1) {
								echo 'CHECKED' ;
							}
						}
						?>>
                    </td>
                    <td class="inner_borders">
                        Disable Voicemail Messages?
                        <input type="checkbox" name="disable_messages" <?php
						if ($print_again) {
							if ($_POST['disable_messages'] == "on") {
								echo 'CHECKED';
							}
						} else {
							if ($result_rc->disable_messages == 1) {
								echo 'CHECKED' ;
							}
						}
						?>>
                    </td>
                </tr>
                <tr class="inner_borders">
                    <td class="inner_borders">
                        Disable Video Meetings?
                        <input type="checkbox" name="disable_meetings" <?php
						if ($print_again) {
							if ($_POST['disable_meetings'] == "on") {
								echo 'CHECKED';
							}
						} else {
							if ($result_rc->disable_meetings == 1) {
								echo 'CHECKED' ;
							}
						}
						?>>
                    </td>
                    <td class="inner_borders"> &nbsp; </td>
                </tr>
            </table>
        </td>
    </tr>
	<tr class="TableOverride">
		<td class="left_col">
			<p style='display: inline; <?php if ($label == "email_updates") echo "color:red"; ?>' >Send Post Updates by eMail?</p>			
		</td>
		<td class="right_col"><input type="checkbox" name="email_updates" <?php 
		if ($print_again) { 
		    if ($_POST['email_updates'] == "on") {
		      echo 'CHECKED';
		    } 
          } else {             
              if ($result_rc->email_updates == 1) {
                  echo 'CHECKED' ;
                }
          }
            ?>></td>
	</tr>    
	<tr class="TableOverride">
		<td class="left_col">
			<p style='display: inline; <?php if ($label == "mobile_updates") echo "color:red"; ?>' >Send Post Updates over SMS Text?</p>			
		</td>
		<td class="right_col"><input type="checkbox" name="mobile_updates" <?php 
		if ($print_again) { 
		    if ($_POST['mobile_updates'] == "on") {
		      echo 'CHECKED';
		    } 
          } else {             
              if ($result_rc->mobile_updates == 1) {
                  echo 'CHECKED' ;
                }
          }
            ?>></td>
	</tr>
    <tr>
        <td colspan=2>
            <hr>
        </td>
    </tr>
	<?php /* ============================================== */ ?>
    <tr class="TableOverride">
        <td class="left_col">
            <p style='display: inline; <?php if ($label == "jwt_key") echo "color:red"; ?>' >JWT Key:</p>
            <p style='color: red; display: inline'>*</p>
        </td>
        <td class="right_col"><textarea name="jwt_key" rows="5"><?php
            if ($print_again) {
                if ($valid_sdk == 0) {
                    echo ' ';
                } else {
                    echo sanitize_text_field($_POST['jwt_key']);
                }
            } else {
                if ($result_rc->jwt_key) {
                    echo $result_rc->jwt_key ;
                }
            }
                ?></textarea>
        </td>
    </tr>
	<tr class="TableOverride">
		<td class="left_col" >
		<p style='display: inline; <?php if ($label == "ringcentral_user_name") echo "color:red"; ?>' >RingCentral Number:</p>
		<p style='color: red; display: inline'>*</p>
        
        <?php echo ringcentral_build_help("username") ; ?>
              
		</td>
		<td class="right_col" ><input type="text" name="ringcentral_user_name" value="<?php
		  if ($print_again) {
		      if ($valid_sdk == 0) {
                    echo ' ';
                } else {
                  echo sanitize_text_field($_POST['ringcentral_user_name']);
              }
          } else {             
              if ($result_rc->ringcentral_user_name != "") {
                echo $result_rc->ringcentral_user_name ;
              } else {
                echo "" ;
              }
          }
            ?>"><br />
			<div style="margin-top: 5px; width: 93%; border: 1px solid #004F6D; padding: 5px; background: #DAF0F8;">Please ensure you have completed TCR registration within the RingCentral Admin portal for an automated use case,
                and that this number is linked to your automated campaign.
                [<a href="https://support.ringcentral.com/sms-registration" target="_blank">Learn More</a>]</div>
		
		</td>
	</tr>
    <tr>
        <td colspan=2>
            <hr>
        </td>
    </tr>
	<tr class="TableOverride">
		<td class="left_col">
			<p style='display: inline; <?php if ($label == "token_prefix") echo "color:red"; ?>' >Token Prefix:</p>
            <!--  <p style='color: red; display: inline'>*</p>   -->
             
            <?php echo ringcentral_build_help("token_prefix") ; ?>
                         
		</td>
		<td class="right_col"><input type="text" name="token_prefix" style="width: 25%;" value="<?php 
		  if ($print_again) {
		      echo sanitize_text_field($_POST['token_prefix']);
          } else {             
              if ($result_rc->token_prefix) {
                  echo $result_rc->token_prefix ;
              } 
          }
            ?>"></td>
	</tr>
	<?php /* ========= Google ReCaptcha Section =================== */ ?>
    <tr>
        <td colspan=2>
            <hr>
        </td>
    </tr>
    <tr class="TableOverride">
        <td class="left_col">
            &nbsp;
        </td>
        <td class="right_col">
            <button type="button" onmouseout="hide_it();" onmousedown="reveal_it();" onmouseup="hide_it();">Reveal Keys</button>
        </td>
    </tr>
    <tr class="TableOverride">
        <td class="left_col">
            <p style='display: inline; <?php if ($label == "recaptcha_site") echo "color:red"; ?>' >Google ReCaptcha Site Key:</p>
            <p style='color: red; display: inline'>*</p>
        </td>
        <td class="right_col"><input type="password" name="recaptcha_site" id="myGRCSite" value="<?php 
          if ($print_again) {
              echo sanitize_text_field($_POST['recaptcha_site']);
          } else {             
              if ($result_rc->grc_site_key != "") {
                echo $result_rc->grc_site_key ;
              } 
          }
            ?>" > 
            </td>
    </tr>       
    <tr class="TableOverride">
        <td class="left_col">
            <p style='display: inline; <?php if ($label == "recaptcha_secret") echo "color:red"; ?>' >Google ReCaptcha Secret Key:</p>
            <p style='color: red; display: inline'>*</p>
        </td>
        <td class="right_col"><input type="password" name="recaptcha_secret" id="myGRCSecret" value="<?php 
          if ($print_again) {
              echo sanitize_text_field($_POST['recaptcha_secret']);
          } else {             
              if ($result_rc->grc_secret_key) {
                echo $result_rc->grc_secret_key ;
              } 
          }
            ?>" ><br />
            <div style="margin-top: 5px; width: 93%; border: 1px solid #004F6D; padding: 5px; background: #DAF0F8;">
            You need to register your site with Google ReCaptcha. Be sure to set up using the ReCaptcha Version 2 checkbox option. 
            To do that go here: [<a href="https://developers.google.com/recaptcha/" 
            target="_blank">Google ReCaptcha Version 2 Checkbox</a>]</div> 
            </td>
    </tr>     
	<tr class="TableOverride">
		<td colspan="2" align="center">			
			<br/>
			<?php 
			$btn_attributes = array( "style" => "background: #008ec2; border-color: #006799; color: #fff;" );
			submit_button("Save Settings","","submit","",$btn_attributes); ?>
			<br/><br/>
		</td>
	</tr>
	</table>
	</form>
<?php
    ringcentral_plugin_version () ;
}
/* ========== */
/* check_form */
/* ========== */
Function check_form() {
	
	global $print_again, $wpdb;

    $print_again = false;
    $label = "" ;
	$message = "" ;
	
	$form_data = array(
	    "jwt_key"          => sanitize_text_field($_POST['jwt_key']),
	);
    $givenPhone = sanitize_text_field( $_POST['ringcentral_user_name'] ) ;

	$GRCSite   = $_POST["recaptcha_site"] ;
	$GRCSecret = $_POST["recaptcha_secret"] ;

    /* SDK setup for testing and validation */
    $valid_SDK = ringcentral_sdk($form_data) ;
    $SmsSender = sms_enabled_phone_number($valid_SDK, $givenPhone ) ;

    /* data integrity checks */
    if (!$SmsSender) {
        $print_again = true;
        $message = "The entered phone number does not have SMS sending permission, please verify and try again";
    }
    if ($valid_SDK == 0 ) {
	    $print_again = true;
	    $message = "There was an error validating your RingCentral JWT key credentials, please verify and try again";
	}
    /* =============================================================================== */
    /* save JWT, SmsSender Phone number to DB if validated */
    /* =============================================================================== */
    if (!$print_again) {
        $jwt_sql = $wpdb->prepare("UPDATE `ringcentral_control` SET `jwt_key` = %s, `ringcentral_user_name` = %s, 
            WHERE `ringcentral_control_id` = %d", $form_data['jwt_key'], $_POST['ringcentral_user_name'], 1);
        $wpdb->query($jwt_sql);
    } else {
        // blank this data so old values are not kept
        $jwt_sql = $wpdb->prepare("UPDATE `ringcentral_control` SET `jwt_key` = %s, `ringcentral_user_name` = %s
            WHERE `ringcentral_control_id` = %d", "", "", 1);
        $wpdb->query($jwt_sql);
    }
    /* =============================================================================== */
    if ($form_data["jwt_key"] == "") {
        $print_again = true;
        $label = "jwt_key";
        $message = "The JWT Key cannot be blank.";
    }
	if (sanitize_text_field($_POST['ringcentral_user_name']) == "") {
	    $print_again = true;
	    $label = "ringcentral_user_name";
	    $message = "RingCentral Number cannot be blank.";
	}
	if ($GRCSite == "") {
	    $print_again = true;
	    $label = "recaptcha_site";
	    $message = "Google ReCaptcha Site Key cannot be blank.";
	}	
	if ($GRCSecret == "") {
	    $print_again = true;
	    $label = "recaptcha_secret";
	    $message = "Google ReCaptcha Secret Key cannot be blank.";
	}
	/* end data integrity checking */

	if ($print_again == true) {
		$color = "red" ;
	    show_form($message, $label, $color);
	} else {	    
	    /* convert and / or sanitize any needed form POST values */
	    if ($_POST['embedded_phone'] == "on") { 
	        $embedded_phone = 1;
			$disable_glip = ($_POST['disable_glip'] == "on") ? 1 : 0;
			$enable_sms_template = ($_POST['enable_sms_template'] == "on") ? 1 : 0;
			$disable_calls = ($_POST['disable_calls'] == "on") ? 1 : 0;
			$disable_call_history = ($_POST['disable_call_history'] == "on") ? 1 : 0;
			$disable_contacts = ($_POST['disable_contacts'] == "on") ? 1 : 0;
			$disable_messages = ($_POST['disable_messages'] == "on") ? 1 : 0;
			$disable_meetings = ($_POST['disable_meetings'] == "on") ? 1 : 0;
		} else {
            $embedded_phone = 0;
            // turn off all the sub controls for embeddable
            $disable_glip = 0;
            $enable_sms_template = 0;
            $disable_calls = 0;
            $disable_call_history = 0;
            $disable_contacts = 0;
            $disable_messages = 0;
            $disable_meetings = 0;
        }
        if ($_POST['email_updates'] == "on") {
            $email_updates = 1;
        } else {
            $email_updates = 0;
        }        
        if ($_POST['mobile_updates'] == "on") {
            $mobile_updates = 1;
        } else {
            $mobile_updates = 0;
        }

        $token_prefix = sanitize_text_field($_POST['token_prefix']) ;

        // pick up existing record before any changes are committed.
        $result_rc = $wpdb->get_row( $wpdb->prepare("SELECT * FROM `ringcentral_control` WHERE `ringcentral_control_id` = %d", 1) );
        
        $config_sql = $wpdb->prepare("UPDATE `ringcentral_control` SET `jwt_key` = %s, `embedded_phone` = %d, 
            `disable_glip` = %d, `enable_sms_template` = %d, `disable_calls` = %d, `disable_call_history` = %d,
            `disable_contacts` = %d, `disable_messages` = %d, `disable_meetings` = %d, `email_updates` = %d, `mobile_updates` = %d, 
            `ringcentral_user_name` = %s, `grc_site_key` = %s, `grc_secret_key` = %s, `token_prefix` = %s
            WHERE `ringcentral_control_id` = %d", $form_data['jwt_key'], $embedded_phone,
			$disable_glip, $enable_sms_template, $disable_calls, $disable_call_history, $disable_contacts, $disable_messages, $disable_meetings,
            $email_updates, $mobile_updates, $_POST['ringcentral_user_name'], $GRCSite, $GRCSecret, $token_prefix, 1) ;

        if($form_data['jwt_key'] != $result_rc->jwt_key ) {
            if(!empty($result_rc->webhook_token)) {
                // Make call to delete webhook
                $sdk = ringcentral_sdk() ;
                $sdk->platform()->delete("/subscription/{$result_rc->webhook_token}");
            }
        }
        // save any updated information on the submitted form to the database
        $wpdb->query( $config_sql );

        // now re-create the webhook token for the new credentials
        if($form_data['jwt_key'] != $result_rc->jwt_key ) {

            // Create subscription
            // SDK should now be using any new credentials just saved to DB ~2 lines above
            $sdk = ringcentral_sdk() ;
            $api_call = $sdk->platform()->post('/subscription',
                array(
                    "eventFilters" => array(
                        "/restapi/v1.0/account/~/extension/~/message-store/instant?type=SMS",
                    ),
                    "expiresIn" => "315360000",
                    "deliveryMode" => array(
                        "transportType" => "WebHook",
                        "address" => get_site_url(null, null, "https").'?rcwebhook=1'
                    )
                )
            );

            // Save webhook ID in database
            $webhook_sql = $wpdb->prepare("UPDATE `ringcentral_control` SET `webhook_token` = %s 
            WHERE `ringcentral_control_id` = %d", $api_call->json()->id, 1) ;
            $wpdb->query( $webhook_sql );
        }
        
	    $color = "#53DF00";
	    $message = "Configuration Changes have been saved";	   
	    show_form($message, $label, $color) ;	    
	}
}

/* ============= */
/*  --- MAIN --- */
/* ============= */
if(isset($_POST['submit'])) {
	check_form();
} else {
	$message = "Adjust settings to your preferences";
	show_form($message);
} 
?>