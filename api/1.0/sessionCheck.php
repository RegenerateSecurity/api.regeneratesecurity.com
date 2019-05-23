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

$t = time();
// TODO: Consider using numPrepare then execPrepare?
$result = execPrepare($mysqli, "SELECT email,session,activity FROM users WHERE session = ?;", array("s", $input['token']));
$row = $result->fetch_assoc();
print "<br>Session Check<br>";
print 'email: '    . htmlspecialchars($row['email']);
print 'session: '  . htmlspecialchars($row['session']);
print 'activity: ' . htmlspecialchars($row['activity']);
print 'time:' . time();
?>
