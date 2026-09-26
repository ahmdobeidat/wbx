<?php
$page = $_GET['page'] ?? 'home';
include($page . ".php");   // LFI sink
// flag stored at /flag.txt
?>
