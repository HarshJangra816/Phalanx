<?php
// EASY — raw request input used as an include path.
function open_page() {
    include $_GET['page'];
}
