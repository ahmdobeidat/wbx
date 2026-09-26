<?php
$id = $_GET['id'] ?? '1';
$conn = mysqli_connect("localhost", "root", "", "app");
$q = "SELECT username, about FROM users WHERE id = " . $id;
$res = mysqli_query($conn, $q);   // SQLi sink
?>
