<?php
// CLEAN — output escaping applied before echo.
function show_name() {
    echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
}
