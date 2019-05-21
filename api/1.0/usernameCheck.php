<?php
// Output on this page will be JSON, so let the requester know
header('Content-Type: application/json');
include_once $_SERVER['DOCUMENT_ROOT'] .  '/hmac.php';		// Load the HMAC key ($apiHMAC) to validate frontend requests
include_once $_SERVER['DOCUMENT_ROOT'] .  '/auth.php';		// Load a connection to the DB
include_once $_SERVER['DOCUMENT_ROOT'] .  '/functions.php';	// functoin abstractions to clean up code

// If no signature was supplied then refuse to respond.
if (!isset($_SERVER['HTTP_SIGNATURE'])) {
  print '{"error":"Signature missing"}';
  exit();
}

$inputJSON = file_get_contents('php://input');
$inputSignature = hash_hmac('sha3-512' , $inputJSON , $apiHMAC);
$input = json_decode($inputJSON, TRUE); //convert JSON into array

// Check if supplied signature and generated signature match
if ($_SERVER['HTTP_SIGNATURE'] == hash_hmac('sha3-512', $inputJSON, $apiHMAC)) {
  print '{"error":"Signature mismatch"}';
  exit();
}

// Check is supplied input is JSON
if ($input === null) {
  print '{"error":"JSON Decode error"}';
  exit()
}

// Check is username to test was supplied
if (!isset($input['username'])) {
  print '{"error":"Expected username parameter"}';
  exit();
}

// Check if number of rows wth username is greater than zero, in case some how
// two accounts with the same username were created
if (numPrepare($mysqli, "SELECT email FROM users WHERE email = ?;", array("s", $input['username'])) > 0) {
  print '{"result":"taken"}';
}
else {
  print '{"result":"available"}';
}
?>
