<?php
/**
 * Copyright (C) 2019-2023 Paladin Business Solutions
 *
 */

/* ========= */
/* show_form */
/* ========= */
Function show_form($message, $label = "", $color = "green") {	
	global $print_again, $wpdb;  ?>		
	<form action="" method="post" >
	<table class="TableOverride" >
		<tr class="TableOverride">
			<td colspan="2" style="text-align: center;">
<?php	
	if ($print_again == true) {
	    echo "<font color='$color'><strong>" . esc_html($message) . "</strong></font>";
	} else {
	    echo "<font color='$color'><strong>" . esc_html($message) . "</strong></font>";
	}	
	?></td>
	</tr>	
	<tr class="TableOverride">
		<td class="left_col">
			<p style='display: inline; <?php if ($label == "full_name") echo "color:red"; ?>' >Full Name:</p>
			<p style='color: red; display: inline'>*</p>
		</td>
		<td class="right_col">
			<input type="text" name="full_name" value="<?php if ($print_again) { echo sanitize_text_field($_POST['full_name']) ; } ?>">
		</td>
	</tr>
	<tr class="TableOverride">
		<td class="left_col">
			<p style='display: inline; <?php if ($label == "email") echo "color:red"; ?>' >email:</p>			
		</td>
		<td class="right_col">
			<input type="text" name="email" value="<?php if ($print_again) { echo sanitize_email($_POST['email']); } ?>">
		</td>
	</tr>
    <tr class="TableOverride">
		<td class="left_col">
			<p style='display: inline; <?php if ($label == "mobile") echo "color:red"; ?>' >mobile:</p>			
		</td>
		<td class="right_col">
			<input type="text" name="mobile" onkeydown="return isNumberKey(event)"
                   value="<?php if ($print_again) { echo sanitize_text_field($_POST['mobile']) ; } ?>">
		</td>
	</tr>
    <tr class="TableOverride">
        <td>&nbsp;</td>
        <td >
            <div style="margin-top: 5px; width: 93%; border: 1px solid #004F6D; padding: 5px; background: #DAF0F8;">I agree that the subscriber has opted in to receive SMS messages and/ or email communications.
                I understand in order to send SMS the subscriber must specifically have opted into SMS.</div>
        </td>
    </tr>
	<tr class="TableOverride">
		<td colspan="2" align="center">			
			<br/>
			<?php 
			$other_attributes = array( "style" => "background: #008ec2; border-color: #006799; color: #fff;" );
			submit_button("Save Settings","","submit","",$other_attributes); ?>
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
	
	$full_name  = sanitize_text_field($_POST['full_name']) ;
	$email      = sanitize_email($_POST['email']) ;
	$mobile     = sanitize_text_field($_POST['mobile']) ;	
	
	/* =================================== */
    /* data integrity checks, data massage */
    /* =================================== */        
	// only take the mobile numbers
	$mobile = preg_replace("/[^0-9]/", '', $mobile);
	// remove leading digit if it is a 1
	if (substr($mobile, 0, 1) == "1") { $mobile = substr($mobile, 1) ; }
	
    if ($email == "" && $mobile == "") {        
        $print_again = true;
        $label = "email";
        $return_message = "eMail and Mobile cannot both be blank.";
    }
    if ($email !== "" && filter_var($email, FILTER_VALIDATE_EMAIL) == FALSE){
        $print_again = true;
        $label = "email";
        $return_message = "eMail is malformed";
    }
    if ($mobile != "" && strlen($mobile) !== 10) {
        $print_again = true;
        $label = "mobile";
        $return_message = "Mobile number must be 10 digits";
    }
    if ($full_name == "") { 
        $print_again = true;
        $label = "full_name";
        $return_message = "Full Name cannot be blank."; 
    }    
    /* ========================== */
    /* end data integrity checks  */
    /* ========================== */	
    
    //   echo "</br> Trimmed mobile: [" . $mobile ."]";
    
	if ($print_again == true) {
	    show_form($return_message, $label, 'red');
	} else {	    
	    /* ========================== */
	    /* prep for saving the data   */
	    /* ========================== */
	    // add the country code prefix
	    if ($mobile != "" ) $mobile = "+1" . $mobile ; 
	    
	    // generate unique token with control prefix.
	    $uniq_token = ringcentral_unique_token() ;
	    
	    // if only given an email, check to see if we already have it
	    if ($email != "" && $mobile == "") {
	        $result_rc = $wpdb->get_row( $wpdb->prepare("SELECT `ringcentral_contacts_id`
                    FROM `ringcentral_contacts`
                    WHERE `email` = %s",
	            $email )
	            );
	        if ($result_rc->ringcentral_contacts_id) {
	            $return_message = "<br/><center>That email is already on file.</center>" ;
	        } else {
	            // save with name
	            $wpdb->query( $wpdb->prepare("INSERT INTO
                        `ringcentral_contacts` (`ringcentral_token`, `full_name`, `email`)
                        VALUES (%s, %s, %s )",
                        $uniq_token, $full_name, $email )
	            );
	            ringcentral_send_welcome_email($email, $uniq_token, $full_name );
	            $return_message = "Contact Information saved...the new member will still have to opt-in" ;
	        }
	    }
	    // if only given an mobile, check to see if we already have it
	    if ($email == "" && $mobile != "") {
	        $result_rc = $wpdb->get_row( $wpdb->prepare("SELECT `ringcentral_contacts_id`
                    FROM `ringcentral_contacts`
                    WHERE `mobile` = %s",
	            $mobile )
	            );
	        if ($result_rc->ringcentral_contacts_id) {
	            $return_message = "<br/><center>That mobile number is already on file.</center>" ;
	        } else {
	            // save with name
	            $wpdb->query( $wpdb->prepare("INSERT INTO
                        `ringcentral_contacts` (`ringcentral_token`,`full_name`, `mobile`)
                        VALUES (%s, %s, %s )",
                        $uniq_token, $full_name, $mobile )
	            );
	            ringcentral_send_welcome_mobile($mobile, $uniq_token, $full_name) ;
	            $return_message = "Contact Information saved...the new member will still have to opt-in" ;
	        }
	    }
	    // if given both an email and mobile, check to see if we already have them
	    if ($email != "" && $mobile != "") {
	        // Check to see if we already have both email and mobile on file.
	        $result_rc = $wpdb->get_row( $wpdb->prepare("SELECT `ringcentral_contacts_id`
                    FROM `ringcentral_contacts`
                    WHERE `email` = %s OR `mobile` = %s",
                    $email, $mobile )
	        );
	        if ($result_rc->ringcentral_contacts_id) {
	            $return_message = "Contact Information already on file..." ;
	        } else { // save new data
	            $wpdb->query( $wpdb->prepare("INSERT INTO
                        `ringcentral_contacts` (`ringcentral_token`, `full_name`, `email`, `mobile`)
                        VALUES (%s, %s, %s, %s )",
                        $uniq_token, $full_name, $email, $mobile )
	            );
	            // send both welcome output
	            ringcentral_send_welcome_email($email, $uniq_token, $full_name );
	            ringcentral_send_welcome_mobile($mobile, $uniq_token, $full_name) ;
	            $return_message = "Contact Information saved...the new member will still have to opt-in" ;
	        }
	    }  //end if already exists test
	    $color = "red";	    
	    show_form($return_message,'',$color) ;	
	}	    
}

/* ============= */
/*  --- MAIN --- */
/* ============= */
if(isset($_POST['submit'])) {
	check_form();
} else {
	$message = "Provide the data for the new subscriber";
	show_form($message);
} 
?>