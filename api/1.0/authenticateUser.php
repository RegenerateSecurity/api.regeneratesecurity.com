<?php
// Output on this page will be JSON, so let the requester know
header('Content-Type: application/json');
include_once $_SERVER['DOCUMENT_ROOT'] .  '/hmac.php';          // Load the HMAC key ($apiHMAC) to validate frontend requests
include_once $_SERVER['DOCUMENT_ROOT'] .  '/auth.php';          // Load a connection to the DB
include_once $_SERVER['DOCUMENT_ROOT'] .  '/functions.php';     // functoin abstractions to clean up code

if (!isset($_SERVER['HTTP_SIGNATURE'])) {
  print '{"error":"Signature missing"}';
  exit();
}

$inputJSON = file_get_contents('php://input');
if ($_SERVER['HTTP_SIGNATURE'] != hash_hmac('sha3-512' , $inputJSON , $apiHMAC)) {
  print '{"error":"Signature mismatch"}';
  exit();
}

// Decode after the signature has been checked...just in case
$input = json_decode($inputJSON, TRUE); //convert JSON into array
if ($input === null) {
  print '{"error":"JSON Decode error"}';
  exit();
}

if (!isset($input['username']) or $input['username'] == "") {
  print '{"error":"Expected username"}';
  exit();
}

if (!isset($input['password']) or $input['password'] == "") {
  print '{"error":"Expected password"}';
  exit();
}

$token    = hash('sha3-512', random_bytes(128));
$email    = $input['email'];
$password = $input['password'];

// TODO: Consider using numPrepare then execPrepare?
$result = execPrepare($mysqli, "SELECT * FROM users WHERE email = ?;", array("s", $email));
$row = $result->fetch_assoc();
if ($row['email'] != $email) {
  print '{"error":"Invalid credentials"}';
  exit();
}

$algo      = $row['algo'];
$salt      = $row['salt'];
$iter      = $row['iterations'];
$hash      = $row['hash'];
$privs     = $row['privs'];
$checkhash = hash_pbkdf2('sha3-512', $_POST['password'], $salt , $iter);
$activity  = time();

if ($hash == $checkhash) {
  $result = execPrepare($mysqli, "UPDATE users SET session = ?, activity = ? WHERE email = ?;", array("sis", $token, $activity, $email));
  print '{"token":"' . $token . '"}';
  exit();
}
else {
  print '{"error":"Invalid credentials"}';
  exit();
}
?>
