<?php
// MEDIUM — user input embedded in HTML via a chained variable.
function render_comment() {
    $body = $_POST['comment'];
    $html = "<div class='comment'>" . $body . "</div>";
    echo $html;
}
