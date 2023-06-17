<?php
/**
 * Copyright (C) 2019-2023 Paladin Business Solutions
 *
 */

/* ================== */
/* Turn on Error codes */
/* ================== */
function show_errors($toggle = 1) {
    error_reporting(E_ALL);
    ini_set('display_errors', $toggle);
}

/* ======================== */
/* Dump the provided object */
/* ======================== */
function ringcentral_dump_obj($object) {
    echo "<pre>";
    var_dump($object);
    echo "</pre>";
}
function echo_spaces($text, $value="", $count = 50) {
    for ($i = 1; $i <= $count; $i++) echo "&nbsp;" ;
    if (is_string($value)) echo "<br /><strong><p style='color: red; display: inline'>$text:</p></strong> " . $value . "<br />";
    if (is_object($value)) {
        echo "<strong><p style='color: red;'>" . $text . " </p></strong><br/>" ;
        ringcentral_dump_obj($value) ;
    }
}
?>