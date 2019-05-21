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
    else if (isset($input['username'] and isset($input["password"]))) {
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
      }
      else {
        // TODO: Split this for readability
        $result = execPrepare($mysqli, "INSERT INTO users (email, algo, salt, iterations, hash, privs) VALUES (?, ?, ?, ?, ?, ?);", array("sssisi", $email, $algo, $salt, $iterations, $hash, $privs)
        print '{"result":"created"}';
      }
    }
    else {
      print '{"error":"incorrectly formatted request"}';
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
