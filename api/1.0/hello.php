<?php
include_once $_SERVER['DOCUMENT_ROOT'] .  '/hmac.php';

if (isset($_SERVER['HTTP_SIGNATURE'])) {
  $inputJSON = file_get_contents('php://input');
  $signature = hash_hmac('sha3-512' , $inputJSON , $apiHMAC);
  if ($signature == $_SERVER['HTTP_SIGNATURE']) {
    print '{"signature":"match"}';
  }
  else {
    print '{"signature":"no dice"}';
    print $signature . '<br/>' . $_SERVER['HTTP_SIGNATURE'];
  }
  //$input = json_decode($inputJSON, TRUE); //convert JSON into array

  //if ($input === null) {
  //  print '{"error":"Error decoding json."}';
  //}
  //else {
  //  print '{"error":"false"}';
  //}
}
else {
  print '{"error":"Signature missing."}';
}
?>
