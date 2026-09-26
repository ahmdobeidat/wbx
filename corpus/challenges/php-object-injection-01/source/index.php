<?php
// FLAG is read from /flag.txt by the Logger gadget
class Logger {
    public $file = "/tmp/app.log";
    public $msg = "";
    public function __destruct() {
        file_put_contents($this->file, $this->msg);
    }
}

$data = $_GET['data'] ?? '';
if ($data) {
    $obj = unserialize($data);   // object injection sink
    echo "processed";
}
?>
