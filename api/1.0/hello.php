<?php
if (isset($_SERVER['Signature'])) {
  $inputJSON = file_get_contents('php://input');
  $input = json_decode($inputJSON, TRUE); //convert JSON into array

  if ($input === null) {
    print '{"error":"Error decoding json."}';
  }
  else {
    print '{"error":"false"}';
  }
}
else {
  print '{"error":"Signature missing."}';
}
?>
