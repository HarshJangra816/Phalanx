<?php
// EASY — direct user input concatenated into a SQL query.
function lookup_user($db) {
    $id = $_GET['id'];
    $query = "SELECT * FROM users WHERE id = " . $id;
    return mysqli_query($db, $query);
}
