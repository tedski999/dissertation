LD_LIBRARY_PATH=/mnt/openssl/lib64 /mnt/openssl/bin/openssl req -x509 \
	-newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -days 3650 -nodes \
	-keyout /keys/root.key -out /keys/root.crt -subj '/CN=example.com'
