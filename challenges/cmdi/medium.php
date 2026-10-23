<?php
// MEDIUM — request input flows through a chained command variable.
function run_lookup() {
    $domain = $_REQUEST['domain'];
    $cmd = "nslookup " . $domain;
    $out = shell_exec($cmd);
    echo htmlspecialchars($out, ENT_QUOTES, 'UTF-8');
}
