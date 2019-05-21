<?php
header('Content-Type: application/json');
include_once $_SERVER['DOCUMENT_ROOT'] .  '/hmac.php';
include_once $_SERVER['DOCUMENT_ROOT'] .  '/auth.php';
include_once $_SERVER['DOCUMENT_ROOT'] .  '/functions.php';

if (isset($_SERVER['HTTP_SIGNATURE'])) {
  $inputJSON = file_get_contents('php://input');
  $signature = hash_hmac('sha3-512' , $inputJSON , $apiHMAC);
  if ($signature == $_SERVER['HTTP_SIGNATURE']) {
    $input = json_decode($inputJSON, TRUE); //convert JSON into array
    if ($input === null) {
      print '{"error":"JSON Decode error"}';
    }
    else if (isset($input['username'])) {
      if (numPrepare($mysqli, "SELECT email FROM users WHERE email = ?;", array("s", $input['username'])) > 0) {
        print '{"username":"taken"}';
      }
      else {
        print '{"username":"available"}';
      }
    }
    else {
      print '{"error":"unexpected message"}';
    }
  }
  else {
    print '{"error":"Signature mismatch"}';
  }
}
else {
  print '{"error":"Signature missing."}';
}
?>
