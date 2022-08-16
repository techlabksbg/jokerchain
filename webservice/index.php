<?php

header('Content-Type: text/plain; charset=utf8-8');

$DATADIR = "data/";
$CHAIN = "joker-chain.md";
$TEMP = "tempblock.md";

if ($_SERVER["REQUEST_METHOD"] == "GET") {
	$handle = fopen($DATADIR.$CHAIN, "r") or die("Server Error: Unable to open file!");
	$size = filesize($DATADIR.$CHAIN);
	echo fread($handle,$size);

} else if ($_SERVER["REQUEST_METHOD"] == "POST") {
	if (isset($_POST['block'])) {
		chdir($DATADIR);
		$fp = fopen($TEMP,"wb");
		fwrite($fp, $_POST['block']);
		fclose($fp);
		$output=null;
		$retval=null;
		exec("python3 jokerchain.py -b ".$TEMP." 2>&1", $output, $retval);
		echo "Returned with status $retval and output:\n";
		print_r($output);
	} else {
		echo("Server Error: Wrong request");
	}
}


?>
