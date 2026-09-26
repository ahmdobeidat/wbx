<?php
// parameterized query, escaped output, strict compare -> should be clean
$id = (int)($_GET['id'] ?? 0);
$conn = new PDO("mysql:host=localhost;dbname=app", "app", "pw");
$stmt = $conn->prepare("SELECT username FROM users WHERE id = ?");
$stmt->execute([$id]);
$row = $stmt->fetch();
echo htmlspecialchars($row['username'] ?? '', ENT_QUOTES);

$token = $_POST['token'] ?? '';
if (hash_equals($_SESSION['csrf'] ?? '', $token)) {   // constant-time, strict
    echo "ok";
}
?>
