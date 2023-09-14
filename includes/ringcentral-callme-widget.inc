<?php
/**
 * Copyright (C) 2019-2023 Paladin Business Solutions
 *
 */
class ringcentral_callme_widget extends WP_Widget {
    // instantiate the class
    function __construct() {
        $widget_ops = array(
            'classname' => 'ring_central_callme_widget_class',
            'description' => 'Use this widget to allow someone to request a call from your website admin'
        );
        $this->WP_Widget(
            'ring_central_callme_widget',
            'RingCentral Free Call Me Widget',
            $widget_ops );
    }    
    // build the widget settings form
    function form($instance) {
        $defaults = array('title' => 'Call Me Request' );
        $instance = wp_parse_args( (array) $instance, $defaults );
        $title = $instance['title']; ?>
        <p>Title: <input type="text" class="widefat" 
        	name="<?php echo $this->get_field_name( 'title' ); ?>" 
        	value="<?php echo esc_attr($title) ; ?>" /></p>          
<?php 
    }    
    // save widget settings function on admin widget
    function update($new_instance, $old_instance) {
        $instance = $old_instance ;
        $instance['title'] = strip_tags($new_instance['title']) ;
        return $instance ;
    }

    // display the widget
    function widget ($args, $instance) {
        global $wpdb ;
        
        extract($args);
        echo $before_widget;
        $title = apply_filters ('widget_title', $instance['title']);        
        if (!empty($title) ) { echo $before_title . $title . $after_title; } ;
        ringcentral_build_recaptcha_top();
        ?>
        <form action="" method="post" id="callme_id" name="callme" >        		
        <p>Full Name: <input type="text" class="widefat" style="color: black;" name="call_full_name" value="" /></p>           
                                
        <p>Mobile No: <input type="text" class="widefat" style="color: black;" name="call_mobile" value="" onkeypress="return isNumberKey(event)" /></p>

        <p>Call Reason: <textarea name="call_reason" style="color: black;" value="" maxlength="500" ></textarea>
                         
		<br/>
        <?php ringcentral_build_recaptcha_main(); ?>
        <br/>
		<center>
		<input type="submit" name="call_submit" value="Call Me" style="background: #008ec2; border-color: #006799; color: #fff;">
		</center>
        </form>
<?php           
        // check that the form was submitted
        if(isset($_POST['call_submit']) && $_POST['call_submit'] == "Call Me" ) {
            echo $this->public_save($_POST);
        }
        
        echo $after_widget ;  
    }
    /* ===================== */
    /* save public form data */
    /* ===================== */
    function public_save($FormData) {
        global $wpdb;
        $callme_widget_return_message = "";
        
        $full_name      = sanitize_text_field($FormData['call_full_name']) ;
        $mobile         = sanitize_text_field($FormData['call_mobile']) ;
        $call_reason    = sanitize_text_field($FormData['call_reason']) ;
        $request_date   = date('Y-m-d', strtotime("now"));
              
        /* =================================== */
        /* data integrity checks, data massage */
        /* =================================== */        
        if ($call_reason == "") {
            $print_again = true;
            $label = "call_reason";
            $callme_widget_return_message = "Please provide a summary of your call request.";
        }   
        if ($mobile == "") {
            $print_again = true;
            $label = "mobile";
            $callme_widget_return_message = "Mobile number cannot be blank";
        }    	
    	// only take the mobile numbers
    	$mobile = preg_replace("/[^0-9]/", '', $mobile);
    	// remove leading digit if it is a 1
    	if (substr($mobile, 0, 1) == "1") { $mobile = substr($mobile, 1) ; }
    	// remove 900 toll free numbers
    	if (substr($mobile, 0, 3) == "900") { 
    	    $print_again = true;
    	    $label = "mobile";
    	    $callme_widget_return_message = "Toll free 900 Mobile numbers are not allowed";
    	}    	    
        if ($mobile != "" && strlen($mobile) !== 10) {
            $print_again = true;
            $label = "mobile";
            $callme_widget_return_message = "Mobile number must be 10 digits";
        }
        if ($full_name == "") { 
            $print_again = true;
            $label = "full_name";
            $callme_widget_return_message = "Full Name cannot be blank."; 
        }    
        if (ringcentral_verify_recaptcha($_POST['g-recaptcha-response']) == false) {
            $print_again = true;
            $label = "recaptcha";
            $contacts_widget_return_message = "Invalid ReCaptcha answer, are you a bot?";
        } 
        /* future consideration - only allow one call request per day? */
        
        /* ========================== */
        /* end data integrity checks  */
        /* ========================== */	
        if (!$print_again) {
            
            /* ========================== */
            /* prep for saving the data   */
            /* ========================== */
            // add the country code prefix
            if ($mobile != "" ) $mobile = "+1" . $mobile ; 
            
            // if given a mobile # save the request
            if ($mobile != "") {                
                // save with name
                $wpdb->query( $wpdb->prepare("INSERT INTO `ringcentral_call_requests` 
                    (`full_name`, `mobile`, `requested_date`, `call_reason`)
                    VALUES (%s, %s, %s, %s)",
                    $full_name, $mobile, $request_date, $call_reason)
                );                
                $callme_widget_return_message = "<br/><center><font color='green'>Call Request Information saved...<br/>Keep your phone close!</font></center>" ;
                ringcentral_ringout($mobile) ;
            }                        
        } else {
            // end data intergity fail tests
            $callme_widget_return_message = "<br/><center><font color='red'>" . $callme_widget_return_message . "</font></center>";            
        }
        
        // show message on widget area
        return $callme_widget_return_message ;
    } // end public_save method
    
} // end of class definition

?>