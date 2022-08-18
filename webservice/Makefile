DEST=root@mx:/var/www/html/jokerchain/.
DATA=${DEST}/data/.

all:
	rsync -vu index.php ${DEST}
	rsync -vu ../public-key-joker.pem ../secret-private-key-joker.pem ../jokerchain.py ${DATA}


chain:	all
	rsync -vu ../joker-chain.md ${DATA}
	ssh root@mx chown -R www-data:www-data /var/www/html/jokerchain

