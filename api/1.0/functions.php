<?php
// A function to execute a prepared query against an array of vars
function execPrepare($mysqli, $query, $param) {
  $stmt = $mysqli->prepare($query);
  call_user_func_array(array($stmt, 'bind_param'), $param);
  $stmt->execute();
  $result = $stmt->get_result();
  return $result;
}
function numPrepare($mysqli, $query, $param) {
  $stmt = $mysqli->prepare($query);
  call_user_func_array(array($stmt, 'bind_param'), $param);
  $stmt->execute();
  $stmt->store_result();
  $result = $stmt->get_result();
  return $stmt->num_rows;
}
?>
