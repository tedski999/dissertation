tc qdisc replace dev enp0s6 root netem slot 100ms 200ms

tcpdump -i wg0 -nnqt ip and src 172.0.1.5 | while read _ _ _ dst _ len; do
	if [ "172.0.1.2" != "$\textdollar${dst\%.*}" ]; then
		dd if=/dev/urandom bs=$\textdollar$len count=1 >/dev/udp/172.0.1.2/12345 &
	fi
done
