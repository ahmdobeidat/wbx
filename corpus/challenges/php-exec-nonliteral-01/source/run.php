<?php
$parts = array("echo", $_GET['a'], $_GET['b']);
$cmd = implode(" ", $parts);
system($cmd);   // command sink on a non-literal built from input (indirect)
?>
