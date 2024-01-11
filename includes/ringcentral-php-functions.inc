<?php
/**
 * Copyright (C) 2019-2024 Paladin Business Solutions
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
function echo_spaces($text, $value="") {
    $count = 50;
    for ($i = 1; $i <= $count; $i++) echo "&nbsp;" ;
    echo "<br /><strong><p style='color: red; display: inline'>$text:</p></strong> " ;
    if (is_string($value))  { echo $value; }
    if (is_object($value) || is_array($value)) { ringcentral_dump_obj($value); }
    echo "<br /><br />" ;
}
?>