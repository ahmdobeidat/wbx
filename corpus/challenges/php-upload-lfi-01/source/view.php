<?php
// viewer with LFI
$f = $_GET['file'] ?? '';
include("uploads/" . $f);   // include user-controlled path
?>
