<?php
// MEDIUM — client filename reaches the destination via a chained variable.
function store_document() {
    $doc = $_FILES['document'];
    $dest = "uploads/" . $doc['name'];
    move_uploaded_file($doc['tmp_name'], $dest);
}
