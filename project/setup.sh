#!/bin/bash

hash sudo ssh ssh-keygen debvm-create debvm-run debvm-waitssh openssl || exit 1

msg() { printf "\n\033[1;33m$@\033[0m\n"; }

config=$(<"$1") || exit 1

[ -f ssh.key ] && [ -f ssh.key.pub ] || {
	msg "Generating ssh keypair..."
	ssh-keygen -N "" -t ed25519 -f ssh.key || exit 1
}

sudo ip link show br0 1>/dev/null 2>&1 || {
	msg "Creating network bridge br0..."
	sudo ip link add name br0 type bridge || exit 1
	sudo ip addr add 172.0.0.1/24 dev br0 || exit 1
}

[ -z "$(ip link show br0 up)" ] && {
	msg "Bringing up network bridge br0..."
	sudo ip link set dev br0 up || exit 1
}

[ -f base.img ] || {
	msg "Generating base VM image..."
	debvm-create \
		-h base -o base.img -r unstable -z 3GB -k ssh.key.pub \
		-- "http://deb.debian.org/debian" "deb [trusted=yes] https://defo.ie/debian ./" \
		--include libcurl4=8.4.0-2.1~1.gbp221d8f,curl=8.4.0-2.1~1.gbp221d8f \
		--include ca-certificates,iproute2,iputils-ping,dnsutils || exit 1
}

[ -f client.img ] || {
	msg "Configuring client VM image..."
	cp base.img "client.img" || exit 1
	debvm-run --image "client.img" --sshport 2222 --graphical -- -display none &
	debvm-waitssh --timeout 10 2222 || exit 1
	ssh -o NoHostAuthenticationForLocalhost=yes -i ssh.key -p 2222 root@127.0.0.1 "
		hostnamectl set-hostname client && sed -i 's/base/client/g' /etc/hosts || sleep infinity
		echo '
			[Match]
			MACAddress=42:ee:ee:ee:ee:ee
			[Network]
			DNS=172.0.0.254
			Address=172.0.0.253/24
			[Route]
			Gateway=0.0.0.0
			Destination=0.0.0.0/0
			Metric=9999' > /etc/systemd/network/00-debvm.network
		shutdown now
	" || exit 1
	wait
}

[ -f dns.img ] || {
	msg "Configuring dns VM image..."
	cp base.img "dns.img" || exit 1
	debvm-run --image "dns.img" --sshport 2222 --graphical -- -display none &
	debvm-waitssh --timeout 10 2222 || exit 1
	ssh -o NoHostAuthenticationForLocalhost=yes -i ssh.key -p 2222 root@127.0.0.1 "
		hostnamectl set-hostname dns &&
			sed -i 's/base/dns/g' /etc/hosts ||
			sleep infinity
		echo '
			[Match]
			MACAddress=42:ff:ff:ff:ff:ff
			[Network]
			DNS=8.8.8.8
			Address=172.0.0.254/24
			[Route]
			Gateway=0.0.0.0
			Destination=0.0.0.0/0
			Metric=9999' > /etc/systemd/network/00-debvm.network
		shutdown now
	" || exit 1
	wait
}

msg "Booting up VMs..."
while IFS=, read -r host mac _; do
	$TERMINAL -e $SHELL -c "TERM=xterm-256color debvm-run --image $host.img -- \
		-device virtio-net-pci,netdev=net1,mac=$mac \
		-netdev bridge,id=net1,br=br0" &
done < $config || exit 1
