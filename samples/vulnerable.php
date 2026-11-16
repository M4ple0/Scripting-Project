<?php
// Deliberately insecure demo - input for the scanner.
$result = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_GET['id']);
echo $_GET['name'];
system("ping " . $_GET['host']);
$obj = unserialize($_COOKIE['data']);
include($_GET['page'] . ".php");
eval($_POST['code']);
$hash = md5($_POST['password']);
