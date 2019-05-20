<?php
if (isset($_SERVER['Signature'])) {
  print 'Hello';
}
else {
  print '{"error":"Signature missing."}'
}
?>
