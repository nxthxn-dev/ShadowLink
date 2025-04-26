<?php
$database = new SQLite3('\public_keys.db');

$result = $database->query("SELECT * FROM public_keys");

while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
    echo "Username: " . $row['username'] . "\n";
    echo "Public Key: " . $row['public_key'] . "\n\n";
}

$database->close();
?>
