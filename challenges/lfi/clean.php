<?php
// CLEAN — basename() strips any directory component from user input.
function load_partial() {
    $partial = basename($_GET['partial']);
    include "partials/" . $partial . ".php";
}
