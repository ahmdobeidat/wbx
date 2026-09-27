<?php
$is_admin = false;
extract($_GET);          // variable override: attacker sets &is_admin=1
if ($is_admin) {
    echo file_get_contents("/flag.txt");
}
?>
