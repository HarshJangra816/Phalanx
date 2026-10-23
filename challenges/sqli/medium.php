<?php
// MEDIUM — user input flows through an interpolated string variable.
function search_orders($db) {
    $term = $_REQUEST['q'];
    $status = "active";
    $sql = "SELECT * FROM orders WHERE term LIKE '%$term%' AND status = '$status'";
    return mysqli_query($db, $sql);
}
