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

// TODO: Fix, impose password policy
if (!isset($input['password']) or $input['password'] == "") {
  print '{"error":"Expected password"}';
  exit();
}

if (!filter_var($input['username'], FILTER_VALIDATE_EMAIL)) {
  print '{"error":"Invalid email"}';
  exit();
}

$email      = $input['username'];
$password   = $input['password'];
$salt       = openssl_random_pseudo_bytes(64);
$iterations = 10000;
$algo       = 'sha3-512';
$hash       = hash_pbkdf2($algo, $password, $salt , $iterations);
$privs      = 0;

// this is overkill but safe; in case of a race condition between checking if the user exists and creating the user.
if (numPrepare($mysqli, "SELECT email FROM users WHERE email = ?;", array("s", $email)) > 0) {
  print '{"result":"taken"}';
  exit();
}

// TODO: Split this for readability
$result = execPrepare($mysqli, "INSERT INTO users (email, algo, salt, iterations, hash, privs) VALUES (?, ?, ?, ?, ?, ?);", array("sssisi", $email, $algo, $salt, $iterations, $hash, $privs));
print '{"result":"created"}';
?>
