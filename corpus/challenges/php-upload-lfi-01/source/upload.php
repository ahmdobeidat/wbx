<?php
// upload endpoint: no content check
if (isset($_FILES['f'])) {
    $name = basename($_FILES['f']['name']);
    move_uploaded_file($_FILES['f']['tmp_name'], "uploads/" . $name);
    echo "uploaded to uploads/" . $name;
}
?>
