LD_LIBRARY_PATH=/mnt/openssl/lib64 /mnt/curl/bin/curl \
	--verbose --cacert /keys/root.crt --ech hard \
	--doh-url https://ns.example.com/dns-query https://tcd.example.com
