<?php
$conn = mysqli_connect("localhost", "root", "", "vulnerable_db");

if (!$conn) {
    die("Connection failed: " . mysqli_connect_error());
}

$id = $_GET['id'];
$sql = "SELECT * FROM users WHERE id = '$id'";
$result = mysqli_query($conn, $sql);

if (mysqli_num_rows($result) > 0) {
    while ($row = mysqli_fetch_assoc($result)) {
        echo "Username: " . $row["username"] . " - Password: " . $row["password"] . "<br>";
    }
} else {
    echo "No results found.";
}

mysqli_close($conn);
?>
