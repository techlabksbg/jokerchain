<?php

header('Content-Type: text/plain; charset=utf8-8');

$DATADIR = "data/";
$CHAIN = "joker-chain.md";
$TEMP = "tempblock.md";
$LOCK = "lockfile";

if ($_SERVER["REQUEST_METHOD"] == "GET") {
	$handle = fopen($DATADIR.$CHAIN, "r") or die("Server Error: Unable to open file!");
	$size = filesize($DATADIR.$CHAIN);
	echo fread($handle,$size);

} else if ($_SERVER["REQUEST_METHOD"] == "POST") {
	if (isset($_POST['block'])) {
		chdir($DATADIR);

		$sem = sem_get(12345,1);
		if (sem_acquire($sem,1)) {
			$lockfile = fopen($LOCK, "w+");
			if (flock($lockfile, LOCK_EX)) {
				$fp = fopen($TEMP,"wb");
				fwrite($fp, $_POST['block']);
				fclose($fp);
				$output=null;
				$retval=null;
				exec("python3 jokerchain.py -b ".$TEMP." 2>&1", $output, $retval);
				if ($retval==0) {
					usleep(100000);  // 0.1s to make sure, next process will read new file
					echo("OK\n");
				} else {
					echo("ERROR\n");
				}
				echo("Returned with status $retval and output:\n");
				print_r($output);
			} else {
				echo("Error\n");
				echo("System busy, try again later...");
			}
			sem_release($sem);
		} else {
			echo("Error\n");
			echo("System busy, try again later...");
		}
		flock($fp,$lockfile);
		fclose($lockfile);
	} else {
		echo("Error\n");
		echo("Server Error: Wrong request");
	}
}

?>
