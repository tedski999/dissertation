#!/bin/bash

hash sudo ssh ssh-keygen debvm-create debvm-run debvm-waitssh ip || exit 1
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

# TODO: run prefixed installs
[ -f base.img ] || {
	msg "Generating base VM image..."
	debvm-create -h base -o base.img -r unstable -z 5GB -k ssh.key.pub -- \
		--include ca-certificates,build-essential,dh-autoreconf,git,openssl \
		--include libpsl-dev,libpcre3-dev,libz-dev || exit 1
	debvm-run --image base.img --sshport 2222 --graphical -- -display none &
	debvm-waitssh --timeout 10 2222 || exit 1
	ssh -o NoHostAuthenticationForLocalhost=yes -i ssh.key -p 2222 root@127.0.0.1 "
		git clone -b ECH-draft-13c https://github.com/sftcd/openssl.git ~/openssl &&
			cd ~/openssl &&
			./config &&
			make -j8 ||
			sleep infinity
		git clone -b ECH-experimental https://github.com/sftcd/curl.git ~/curl &&
			cd ~/curl &&
			autoreconf -fi &&
			LD_LIBRARY_PATH=~/openssl LDFLAGS=-L~/openssl ./configure --with-ssl=\$HOME/openssl --enable-ech --enable-httpsrr &&
			LD_LIBRARY_PATH=~/openssl make -j8 ||
			sleep infinity
		git clone -b v9.18.25-release https://gitlab.isc.org/isc-projects/bind9 ~/bind9 &&
			cd ~/bind9 &&
			autoreconf -fi &&
			LD_LIBRARY_PATH=~/openssl LDFLAGS=-L~/openssl ./configure --with-ssl=\$HOME/openssl &&
			LD_LIBRARY_PATH=~/openssl make -j8 ||
			sleep infinity
		git clone -b ECH-experimental https://github.com/sftcd/nginx.git ~/nginx &&
			cd ~/nginx &&
			./auto/configure --with-http_ssl_module --with-stream --with-stream_ssl_module --with-stream_ssl_preread_module --with-http_v2_module --with-cc-opt=-I\$HOME/openssl/include --with-ld-opt=-L\$HOME/openssl &&
			make -j8 ||
			sleep infinity
		LD_LIBRARY_PATH=~/openssl ~/openssl/apps/openssl req -x509 \
			-newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -days 3650 -nodes \
			-keyout /root.key -out /root.crt -subj '/CN=root.example.com' &&
			chmod +r /root.key ||
			sleep infinity
		# TODO: mount directory would let ossl certs+ech keys gen here then only config on host needed for mounts
		shutdown now
	" || exit 1
	wait
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
		LD_LIBRARY_PATH=~/openssl ~/openssl/apps/openssl req -x509 \
			-newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -days 3650 -nodes \
			-keyout /dns.key -out /dns.crt -subj '/CN=dns.example.com' \
			-CA /root.crt -CAkey /root.key -addext 'subjectAltName=DNS:dns.example.com,IP:172.0.0.254' &&
			chmod +r /dns.key ||
			sleep infinity
		echo '
			tls local-tls { key-file \"/dns.key\"; cert-file \"/dns.crt\"; };
			options { directory \"/var/cache/bind\"; listen-on { any; }; listen-on port 443 tls local-tls http default { any; }; dnssec-validation auto; };
			zone \"example.com\" { type master; file \"db.example.com\"; };' > /named.conf
		echo '\$TTL 3600' > /db.example.com
		echo '@ IN SOA dns.example.com. root.dns.example.com. ( 2007010401 3600 600 86400 600 )' >> /db.example.com
		echo '@ IN NS dns.example.com.' >> /db.example.com
	" || exit 1
	while IFS=, read -r host mac ip score vhosts; do
		for vhost in ${vhosts//,/ }; do
			ssh -o NoHostAuthenticationForLocalhost=yes -i ssh.key -p 2222 root@127.0.0.1 "
				echo '$vhost.$host IN A $ip' >> /db.example.com
			" || exit 1
		done
	done < $config || exit 1
	ssh -o NoHostAuthenticationForLocalhost=yes -i ssh.key -p 2222 root@127.0.0.1 "
		shutdown now
	" || exit 1
	wait
}

while IFS=, read -r host mac ip score vhosts; do
	[ -f "$host.img" ] || {
		msg "Configuring $host VM image..."
		cp base.img "$host.img" || exit 1
		debvm-run --image "$host.img" --sshport 2222 --graphical -- -display none &
		debvm-waitssh --timeout 10 2222 || exit 1
		ssh -o NoHostAuthenticationForLocalhost=yes -i ssh.key -p 2222 root@127.0.0.1 "
			hostnamectl set-hostname $host &&
				sed -i 's/base/$host/g' /etc/hosts ||
				sleep infinity
			echo '
				[Match]
				MACAddress=$mac
				[Network]
				DNS=172.0.0.254
				Address=$ip/24
				[Route]
				Gateway=0.0.0.0
				Destination=0.0.0.0/0
				Metric=9999' > /etc/systemd/network/00-debvm.network
			mkdir -p ~/site/nginx/logs || sleep infinity
			# TODO: ech keys in ssl_echkeydir ech;
			# TODO: configure ECH nginx split mode
			echo '
				worker_processes 1;
				error_log logs/error.log info;
				events { worker_connections 1024; }
				http {
					access_log logs/access.log combined;' > ~/site/nginx.conf
		" || exit 1
		for vhost in ${vhosts//,/ }; do
			vhost=${vhost%:*}
			ssh -o NoHostAuthenticationForLocalhost=yes -i ssh.key -p 2222 root@127.0.0.1 "
				mkdir -p ~/site/nginx/$vhost &&
					echo 'Welcome to $vhost' > ~/site/nginx/$vhost/index.html ||
					sleep infinity
				LD_LIBRARY_PATH=~/openssl ~/openssl/apps/openssl req -x509 \
					-newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -days 3650 -nodes \
					-keyout /$vhost.key -out /$vhost.crt -subj '/CN=$vhost.$host.example.com' \
					-CA /root.crt -CAkey /root.key -addext 'subjectAltName=DNS:$vhost.$host.example.com,IP:$ip' &&
					chmod +r /$vhost.key ||
					sleep infinity
				echo '
					server {
						listen 443 ssl;
						http2 on;
						ssl_certificate /$vhost.crt;
						ssl_certificate_key /$vhost.key;
						ssl_protocols TLSv1.3;
						server_name $vhost.$host.example.com;
						location / { root $vhost; index index.html index.htm; }
					}' >> ~/site/nginx.conf
			" || exit 1
		done
		ssh -o NoHostAuthenticationForLocalhost=yes -i ssh.key -p 2222 root@127.0.0.1 "
			echo '}' >> ~/site/nginx.conf
			shutdown now
		" || exit 1
		wait
	}
done < $config || exit 1

# TODO: slow
msg "Booting up VMs..."
while IFS=, read -r host mac _; do
	$TERMINAL -e $SHELL -c "TERM=xterm-256color debvm-run --image $host.img -- \
		-device virtio-net-pci,netdev=net1,mac=$mac \
		-netdev bridge,id=net1,br=br0" &
done < $config || exit 1

# TODO: autostart in background
# cd $HOME/site && $HOME/nginx/objs/nginx -c $HOME/site/nginx.conf
# LD_LIBRARY_PATH=$HOME/openssl $HOME/curl/src/curl --cacert /root.crt https://a.ucd.example.com
