<?php
class Model {
    public function search($needle) {
        $q = "SELECT body FROM quotes WHERE body LIKE '%" . $needle . "%' LIMIT 50";
        return mysqli_query($this->conn, $q);
    }
}
?>
