<?php
// EASY — request input passed straight to a shell command.
function resolve_host() {
    $host = $_GET['host'];
    system("ping -c 1 " . $host);
}
