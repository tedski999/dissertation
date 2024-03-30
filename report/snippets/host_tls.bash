LD_LIBRARY_PATH=/mnt/openssl/lib64 /mnt/openssl/bin/openssl ech \
	-public_name tcd.example.com -pemout /keys/tcd/key.ech

LD_LIBRARY_PATH=/mnt/openssl/lib64 /mnt/openssl/bin/openssl req \
	-newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -nodes \
	-keyout /keys/tcd/tcd.key -out /keys/tcd/tcd.csr -subj '/CN=tcd.example.com'

LD_LIBRARY_PATH=/mnt/openssl/lib64 /mnt/openssl/bin/openssl x509 -req \
	-CA /keys/root.crt -CAkey /keys/root.key -days 3650 -CAcreateserial \
	-extfile <(printf 'subjectAltName=DNS:tcd.example.com') \
	-in /keys/tcd/tcd.csr -out /keys/tcd/tcd.crt
