<?php
/**
 * Copyright (C) 2019-2023 Paladin Business Solutions
 *
 */

/* ========= */
/* show_form */
/* ========= */
Function show_form($message, $label = "", $color = "#008EC2") {

	global $print_again, $wpdb;

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
		<td class="right_col"><input type="checkbox" name="embedded_phone" <?php 
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
    
    <tr class="TableOverride">
        <td class="left_col">
            <p style='display: inline; <?php if ($label == "ringcentral_sandbox") echo "color:red"; ?>' >Use the RingCentral SANDBOX Environment?</p>
            
            <?php echo ringcentral_build_help("ringcentral_sandbox") ; ?>
                      
        </td>
        <td class="right_col"><input type="checkbox" name="ringcentral_sandbox" <?php 
        if ($print_again) { 
            if ($_POST['ringcentral_sandbox'] == "on") {
              echo 'CHECKED';
            } 
          } else {             
              if ($result_rc->ringcentral_sandbox  == 1) {
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
                echo sanitize_text_field($_POST['jwt_key']);
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
		      echo sanitize_text_field($_POST['ringcentral_user_name']);
          } else {             
              if ($result_rc->ringcentral_user_name) {
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
              if ($result_rc->grc_site_key) {
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
}
/* ========== */
/* check_form */
/* ========== */
Function check_form() {
	
	global $print_again, $wpdb;

	$label = "" ;
	$message = "" ;
	
	if ($_POST['ringcentral_sandbox'] == "on") {
	    $sandbox = 1;
	} else {
	    $sandbox = 0;
	}    
	
	$form_data = array(
	    "jwt_key"          => sanitize_text_field($_POST['jwt_key']),
	    "sandbox"          => $sandbox 	    
	);

	$GRCSite   = $_POST["recaptcha_site"] ;
	$GRCSecret = $_POST["recaptcha_secret"] ;

// 	/* data integrity checks */	
	if (!ringcentral_sdk($form_data) ) {
	    $print_again = true;
	    $label = "";
	    $message = "There was an error validating your RingCentral account credentials, please verify and try again";
	}
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

	// end data integrity checking

	if ($print_again == true) {
		$color = "red" ;
	    show_form($message, $label, $color);
	} else {	    
	    /* convert and / or sanitize any needed form POST values */
	    if ($_POST['embedded_phone'] == "on") { 
	        $embedded_phone = 1;	        
        } else {
            $embedded_phone = 0;
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
        
        $config_sql = $wpdb->prepare("UPDATE `ringcentral_control` SET `jwt_key` = %s, `embedded_phone` = %d, `email_updates` = %d, `mobile_updates` = %d, 
            `ringcentral_user_name` = %s, `ringcentral_sandbox` = %d, `grc_site_key` = %s, `grc_secret_key` = %s, `token_prefix` = %s
            WHERE `ringcentral_control_id` = %d", $form_data['jwt_key'], $embedded_phone, $email_updates, $mobile_updates,
            $_POST['ringcentral_user_name'], $sandbox, $GRCSite, $GRCSecret, $token_prefix, 1) ;

        if($form_data['jwt_key'] != $result_rc->jwt_key || $sandbox != $result_rc->ringcentral_sandbox) {
            if(!empty($result_rc->webhook_token)) {
                // Make call to delete webhook
                $sdk = ringcentral_sdk() ;
                $sdk->platform()->delete("/subscription/{$result_rc->webhook_token}");
            }
        }
        // save any updated information on the submitted form to the database
        $wpdb->query( $config_sql );

        // now re-create the webhook token for the new credentials
        if($form_data['jwt_key'] != $result_rc->jwt_key || $sandbox != $result_rc->ringcentral_sandbox) {

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