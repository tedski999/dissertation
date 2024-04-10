tc qdisc replace dev enp0s6 root netem slot 100ms 200ms

tcpdump -i wg0 -nnqlt ip and udp and src 172.0.1.5 and not dst port 1234 \
		| while read _ _ _ dst _ len; do
	[ "172.0.1.2" != "${dst%.*}" ] &&
		dd if=/dev/urandom bs=$len count=1 >/dev/udp/172.0.1.2/1234 &
	[ "172.0.1.8" != "${dst%.*}" ] &&
		dd if=/dev/urandom bs=$len count=1 >/dev/udp/172.0.1.8/1234 &
done
