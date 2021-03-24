<?php

$db = new SQLite3('./blades.db');
$res = $db->query('SELECT * FROM "blades_data"');
while ($row = $res->fetchArray()) {
	$results["data"][] = $row ;
}
echo json_encode($results);

?>
