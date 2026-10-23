<?php
// CLEAN — server-side generated name; client filename never used.
function save_image() {
    $img = $_FILES['photo'];
    $ext = ".jpg"; // extension decided by server allowlist, not the client
    $dest = "uploads/" . bin2hex(random_bytes(16)) . $ext;
    move_uploaded_file($img['tmp_name'], $dest);
}
