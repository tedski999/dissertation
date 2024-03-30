LD_LIBRARY_PATH=/mnt/openssl/lib64 /mnt/openssl/bin/openssl req \
	-newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -nodes \
	-keyout /keys/dns.key -out /keys/dns.csr -subj '/CN=ns.example.com'

LD_LIBRARY_PATH=/mnt/openssl/lib64 /mnt/openssl/bin/openssl x509 -req \
	-CA /keys/root.crt -CAkey /keys/root.key -days 3650 -CAcreateserial \
	-extfile <(printf 'subjectAltName=DNS:ns.example.com') \
	-in /keys/dns.csr -out /keys/dns.crt
