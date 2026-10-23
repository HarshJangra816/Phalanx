<?php
// INTENTIONALLY VULNERABLE LAB APP — local testing only. Never deploy.
// Each function demonstrates one of the five Phase-1 vuln classes.

// 1) SQL injection (sqli) — string-concatenated query
function get_user($db, $username) {
    $query = "SELECT * FROM users WHERE name = '" . $username . "'";
    return mysqli_query($db, $query);
}

// 2) Reflected XSS — unescaped echo of user input
function greet() {
    echo "Hello " . $_GET['name'];
}

// 3) Command injection (cmdi) — user input into shell
function ping_host() {
    $host = $_GET['host'];
    system("ping -c 1 " . $host);
}

// 4) Unsafe file upload — no type/extension validation
function save_upload() {
    $file = $_FILES['upload'];
    move_uploaded_file($file['tmp_name'], "uploads/" . $file['name']);
}

// 5) Path traversal / LFI — user input in include path
function load_page() {
    include "pages/" . $_GET['page'];
}
