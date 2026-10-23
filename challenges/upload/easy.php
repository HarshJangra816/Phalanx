<?php
// EASY — upload stored under the client-supplied filename.
function handle_avatar() {
    move_uploaded_file($_FILES['avatar']['tmp_name'],
                       "uploads/" . $_FILES['avatar']['name']);
}
