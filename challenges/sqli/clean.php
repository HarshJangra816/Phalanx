<?php
// CLEAN — parameterized query; user input never enters SQL text.
function load_user($pdo, $id_param) {
    $id = intval($id_param);
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->execute([$id]);
    return $stmt->fetch();
}
