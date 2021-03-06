<?php
header('Content-Type: application/json');
include_once $_SERVER['DOCUMENT_ROOT'] .  '/hmac.php';

if (isset($_SERVER['HTTP_SIGNATURE'])) {
  $inputJSON = file_get_contents('php://input');
  $signature = hash_hmac('sha3-512' , $inputJSON , $apiHMAC);
  if ($signature == $_SERVER['HTTP_SIGNATURE']) {
    $input = json_decode($inputJSON, TRUE); //convert JSON into array
    if ($input === null) {
      print '{"error":"JSON Decode error"}';
    }
    else if (isset($input['ping']) and $input['ping'] == "hello") {
      print '{"ping":"olleh"}';
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
