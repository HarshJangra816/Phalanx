<?php
// MEDIUM — request input reaches include through a prefixed variable.
function render_view() {
    $view = $_REQUEST['view'];
    $path = "views/" . $view . ".php";
    include $path;
}
