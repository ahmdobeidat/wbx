<?php
$next = $_GET['next'] ?? '/';
header("Location: " . $next);   // header injection / open redirect
?>
