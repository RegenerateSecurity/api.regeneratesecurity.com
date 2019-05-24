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

if (!isset($input['token']) or $input['token'] == "") {
  print '{"error":"Expected token"}';
  exit();
}

if (numPrepare($mysqli, "SELECT email,session,activity FROM users WHERE session = ?;", array("s", $input['token'])) == 1) {
  $result = execPrepare($mysqli, "SELECT email,session,activity FROM users WHERE session = ?;", array("s", $input['token']));
  // TODO: Clean up data out of the db
  $row = $result->fetch_assoc();
  // TODO: check time against activity for validity
  $t = time();
  if ($t - $row['activity'] < 21600) {
    // TODO: build JSON properly
    print '{"result":"valid", "email":"' . $row['email'] . '","activity":"' . $row['activity'] . '"}';
    // TODO: update activity
  }
  else {
    print '{"result":"expired"}';
  }
}
else {
  print '{"result":"invalid"}';
}


?>
