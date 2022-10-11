<?php
unset($_POST['RC_Validate_submit']);
ringcentral_2fa_verify($wpUser, $redirect_to, $remember_me);
?>