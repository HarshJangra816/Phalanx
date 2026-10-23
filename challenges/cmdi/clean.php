<?php
// CLEAN — argument escaped for the shell before use.
function check_port() {
    $target = escapeshellarg($_GET['target']);
    system("nc -z -w 2 " . $target . " 443");
}
