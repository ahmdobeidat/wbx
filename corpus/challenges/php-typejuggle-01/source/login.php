<?php
$flag = "flag{placeholder_type_juggle}";
$secret_hash = "0e462097431906509019562988736854"; // md5 that is 0e...
$pass = $_POST['password'] ?? '';
if (md5($pass) == $secret_hash) {   // loose compare -> magic hash bypass
    echo $flag;
}
?>
