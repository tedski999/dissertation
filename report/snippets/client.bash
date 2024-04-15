while true; do
	sleep 0.$(( $RANDOM % 999 ))
	LD_LIBRARY_PATH=/mnt/openssl/lib64 /mnt/curl/bin/curl \
		--verbose --cacert /keys/root.crt --ech hard \
		--doh-url https://dns.example.com/dns-query \
		https://$(shuf -n 1 -e dcu.example.com tcd.example.com ucd.example.com)
done
