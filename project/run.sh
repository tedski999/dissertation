#!/bin/bash

hash sudo ip ssh ssh-keygen debvm-create debvm-run debvm-waitssh || exit 1
msg() { printf "\n\033[1;33m$@\033[0m\n"; }
pkill qemu-system-x86

# Parse provided config
dir="$1"
network_cfg="$(<"$2")" || exit 1
server_cfgs="$(<"$3")" || exit 1
read -d "" domain dns_host dns_mac dns_ip <<< "$network_cfg"
mkdir -p "$dir" || exit 1

# List of additional hosts useful for interactive testing and evaluation purposes
client_cfgs="tls-client,00:00:00:00:00:01,172.0.0.100"

# Generate SSH keypair
[ -f "$dir/ssh.key" ] && [ -f "$dir/ssh.key.pub" ] || {
	msg "Generating ssh keypair for VMs..."
	ssh-keygen -N "" -t ed25519 -f "$dir/ssh.key" || exit 1
}

# Setup host network bridge
sudo ip link show br0 1>/dev/null 2>&1 || {
	msg "Creating network bridge br0..."
	sudo ip link add name br0 type bridge || exit 1
	sudo ip addr add 172.0.0.1/24 dev br0 || exit 1
}
[ -z "$(ip link show br0 up)" ] && {
	msg "Bringing up network bridge br0..."
	sudo ip link set dev br0 up || exit 1
}

# Generate build with builder
[ -f "$dir/builder.img" ] || {
	msg "Generating builder.img..."
	debvm-create -h builder -o "$dir/builder.img" -r unstable -z 2GB -k "$dir/ssh.key.pub" -- \
		--include ca-certificates,build-essential,dh-autoreconf,git,e2fsprogs \
		--include libpsl-dev,libpcre3-dev,libz-dev,libnghttp2-dev || exit 1
}
[ -f "$dir/build.img" ] || {
	msg "Generating build.img:"

	cmds="
	# Format and mount build.img
	mkfs.ext4 -L build /dev/vdb || exit 1
	mount /dev/vdb /mnt || exit 1

	# Build OpenSSL patched with ECH support
	git clone -b ECH-draft-13c https://github.com/sftcd/openssl.git /mnt/src/openssl \
		&& cd /mnt/src/openssl || exit 1
	./config --prefix=/mnt/openssl --openssldir=/mnt/openssl || exit 1
	make -j8 || exit 1
	make -j8 install || exit 1

	# Build curl patched with ECH support
	git clone -b ECH-experimental https://github.com/sftcd/curl.git /mnt/src/curl \
		&& cd /mnt/src/curl || exit 1
	autoreconf -fi || exit 1
	CPPFLAGS=-I/mnt/openssl/include LDFLAGS=-L/mnt/openssl/lib64 ./configure \\
		--prefix=/mnt/curl --with-openssl --enable-ech --enable-httpsrr || exit 1
	LD_LIBRARY_PATH=/mnt/openssl/lib64 make -j8 || exit 1
	make -j8 install || exit 1

	# Build NGINX patched with ECH support
	git clone -b ECH-experimental https://github.com/sftcd/nginx.git /mnt/src/nginx \
		&& cd /mnt/src/nginx || exit 1
	./auto/configure --prefix=/mnt/nginx \\
		--with-cc-opt=-I/mnt/openssl/include --with-ld-opt=-L/mnt/openssl/lib64 \\
		--with-stream --with-stream_ssl_module --with-stream_ssl_preread_module \\
		--with-http_ssl_module --with-http_v2_module || exit 1
	LD_LIBRARY_PATH=/mnt/openssl/lib64 make -j8 || exit 1
	make -j8 install || exit 1
	sed 's/\\/usr\\/sbin\\/nginx/\\/mnt\\/nginx\\/sbin\\/nginx -c \\/site\\/nginx.conf -p \\/site\\/nginx/' \\
		/mnt/src/nginx/debian/nginx-common.nginx.service > /mnt/nginx/nginx.service || exit 1
	>>/mnt/nginx/nginx.service echo '
	[Service]
	Environment=LD_LIBRARY_PATH=/mnt/openssl/lib64' || exit 1

	# Graceful shutdown
	cd / && umount /mnt || exit 1
	shutdown now"

	echo "$cmds"
	qemu-img create "$dir/build.img" 2G || exit 1
	debvm-run --image "$dir/builder.img" --sshport 2222 --graphical -- \
		-display none -drive file="$dir/build.img",format=raw,if=virtio,readonly=off &
	debvm-waitssh 2222 || exit 1
	ssh -o NoHostAuthenticationForLocalhost=yes -i "$dir/ssh.key" -p 2222 root@127.0.0.1 "$cmds" || exit 1
	wait
}

# Generate base VM image
[ -f "$dir/base.img" ] || {
	msg "Generating base.img:"

	cmds="
	# Mount build.img
	mount -o ro /dev/disk/by-label/build /mnt || exit 1

	# Install some debugging tools
	apt-get --yes install vim dnsutils iproute2 || exit 1

	# Generate CA root and DNS key+certificate
	mkdir -p /keys || exit 1
	LD_LIBRARY_PATH=/mnt/openssl/lib64 /mnt/openssl/bin/openssl req -x509 \\
		-newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -days 3650 -nodes \\
		-keyout /keys/root.key -out /keys/root.crt -subj '/CN=root.$domain' || exit 1
	LD_LIBRARY_PATH=/mnt/openssl/lib64 /mnt/openssl/bin/openssl req \\
		-newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -nodes \\
		-keyout /keys/$dns_host.key -out /keys/$dns_host.csr -subj '/CN=$dns_host.$domain' || exit 1
	LD_LIBRARY_PATH=/mnt/openssl/lib64 /mnt/openssl/bin/openssl x509 -req \\
		-CA /keys/root.crt -CAkey /keys/root.key -days 3650 -CAcreateserial \\
		-extfile <(printf 'subjectAltName=DNS:$dns_host.$domain,IP:$dns_ip') \\
		-in /keys/$dns_host.csr -out /keys/$dns_host.crt || exit 1
	chmod +r /keys/{root,$dns_host}.key || exit 1"

	for server_cfg in $server_cfgs; do IFS=, read host _ ip _ sites <<< $server_cfg
		cmds="$cmds
		# Generate $host WireGuard and ECH keypair
		mkdir -p /keys/$host || exit 1
		wg genkey | tee /keys/$host/wg.key | wg pubkey > /keys/$host/wg.key.pub || exit 1
		LD_LIBRARY_PATH=/mnt/openssl/lib64 /mnt/openssl/bin/openssl ech \\
			-public_name $host.$domain -pemout /keys/$host/key.ech"
		for site in ${sites//,/ }; do
			cmds="$cmds
			# Generate $site.$domain key+certificate
			LD_LIBRARY_PATH=/mnt/openssl/lib64 /mnt/openssl/bin/openssl req \\
				-newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -nodes \\
				-keyout /keys/$host/$site.key -out /keys/$host/$site.csr -subj '/CN=$site.$domain' || exit 1
			LD_LIBRARY_PATH=/mnt/openssl/lib64 /mnt/openssl/bin/openssl x509 -req \\
				-CA /keys/root.crt -CAkey /keys/root.key -days 3650 -CAcreateserial \\
				-extfile <(printf 'subjectAltName=DNS:$site.$domain,IP:$ip') \\
				-in /keys/$host/$site.csr -out /keys/$host/$site.crt || exit 1
			chmod +r /keys/$host/$site.key || exit 1"
		done
	done

	cmds="$cmds
	# Graceful shutdown
	cd && umount /mnt || exit 1
	shutdown now"

	echo "$cmds"
	debvm-create -h base -o "$dir/base.img" -r unstable -z 1GB -k "$dir/ssh.key.pub" -- \
		--include ca-certificates,wireguard,libpsl5,libpcre3,libnghttp2-14 || exit 1
	debvm-run --image "$dir/base.img" --sshport 2222 --graphical -- \
		-display none -drive file="$dir/build.img",format=raw,if=virtio,readonly=on &
	debvm-waitssh 2222 || exit 1
	ssh -o NoHostAuthenticationForLocalhost=yes -i "$dir/ssh.key" -p 2222 root@127.0.0.1 "$cmds" || exit 1
	wait
}

# Set DNS server configuration
cmds="
# Install dependencies
apt-get --yes install bind9 || exit 1

# Configure BIND9 for DoH usage
>/etc/bind/named.conf.options echo '
tls tlspair {
	key-file \"/keys/$dns_host.key\";
	cert-file \"/keys/$dns_host.crt\";
};
options {
	directory \"/var/cache/bind\";
	recursion no;
	dnssec-validation auto;
	allow-transfer { none; };
	listen-on { any; };
	listen-on port 443 tls tlspair http default { any; };
};' || exit 1

# Configure BIND9 to be dns.example.com
>/etc/bind/named.conf.local echo '
zone \"$domain\" {
	type master;
	update-policy local;
	file \"/var/lib/bind/db.$domain\";
};' || exit 1

# Configure BIND9 with static RRs for dns.example.com
>/var/lib/bind/db.$domain echo '
\$ORIGIN ${domain}.
\$TTL 60
@ IN SOA $dns_host root.$dns_host 2024040100 3600 600 86400 600
@ IN NS $dns_host
$dns_host IN A $dns_ip' || exit 1

# Dynamic DNS service
>/ddns.sh echo '#!/bin/bash
servers=\""
for server_cfg in $server_cfgs; do IFS=, read host _ ip _ _ <<< $server_cfg
	cmds="$cmds $ip,\$(tail -2 /keys/$host/key.ech | head -1)"
done
cmds="$cmds\"
while true; do"
for server_cfg in $server_cfgs; do IFS=, read _ _ _ _ sites <<< $server_cfg
	for site in ${sites//,/ }; do
		cmds="$cmds
		server=\$(shuf -n 1 -e \$servers)
		input=\"\$input
		update delete $site.$domain
		update add $site.$domain 60 A \${server%%,*}
		update add $site.$domain 60 HTTPS 1 . ech=\${server#*,}
		\""
	done
done
cmds="$cmds
	echo \"\$input
	send\" | nsupdate -l
	sleep 1
done' || exit 1
>/ddns.service echo '
[Unit]
After=named.service
[Service]
ExecStart=/ddns.sh
Restart=always
[Install]
WantedBy=multi-user.target' || exit 1
chmod +x /ddns.sh || exit 1

# Install service
cp /ddns.service /etc/systemd/system || exit 1
systemctl daemon-reload && systemctl enable ddns || exit 1"

declare "${dns_host}_cmds=$cmds"

# Set TLS servers configuration
for server_cfg in $server_cfgs; do IFS=, read host _ ip wg sites <<< $server_cfg
	cmds="
	# Install dependencies
	apt-get --yes install wireguard socat || exit 1

	# Configure WireGuard
	>/etc/systemd/network/00-wg0.netdev echo '
	[NetDev]
	Name=wg0
	Kind=wireguard
	[WireGuard]
	ListenPort=51820
	PrivateKey='\"\$(cat /keys/$host/wg.key)\"'"
	for p_server_cfg in $server_cfgs; do IFS=, read p_host _ p_ip p_wg _ <<< $p_server_cfg
		[ "$host" != "$p_host" ] && {
			cmds="$cmds
			[WireGuardPeer]
			PublicKey='\"\$(cat /keys/$p_host/wg.key.pub)\"'
			AllowedIPs=$p_wg/32
			Endpoint=$p_ip:51820"
		}
	done
	cmds="$cmds' || exit 1
	>/etc/systemd/network/00-wg0.network echo '
	[Match]
	Name=wg0
	[Network]
	Address=$wg/24' || exit 1

	# Configure NGINX
	mkdir -p /site/nginx/logs || exit 1
	>/site/nginx.conf echo '
	pid /run/nginx.pid;
	worker_processes 1;
	events { worker_connections 1024; }

	# ECH client-facing server as proxy for each WireGuard peer
	stream {
		log_format basic \"\$remote_addr [\$time_local] \$protocol \$status \$bytes_sent \$bytes_received \$session_time\";
		access_log logs/access.log basic;
		ssl_preread on;
		ssl_echkeydir /keys/$host;
		server { listen $ip:443; proxy_pass \$backend; }
		map \$ssl_preread_server_name \$backend {"
	for p_server_cfg in $server_cfgs; do IFS=, read p_host _ _ _ p_sites <<< $p_server_cfg
		for p_site in ${p_sites//,/ }; do
			cmds="$cmds $p_site.$domain unix:/tmp/socat_$p_host.sock;"
		done
	done
	cmds="$cmds
		}
	}

	# ECH backend server listening only through WireGuard
	http {"
	for site in ${sites//,/ }; do
		cmds="$cmds
		server {
			root /site/$site;
			server_name $site.$domain;
			listen $wg:443 ssl;
			http2 on;
			ssl_certificate /keys/$host/$site.crt;
			ssl_certificate_key /keys/$host/$site.key;
			ssl_protocols TLSv1.3;
			location / { ssi on; index index.html index.htm; }
		}"
	done
	cmds="$cmds
	}' || exit 1"

	for site in ${sites//,/ }; do
		cmds="$cmds
		# Generate $site index.html
		mkdir -p /site/$site || exit 1
		>/site/$site/index.html echo '\
		<!doctype html>
		<html lang=en>
			<head>
				<meta charset=utf-8>
				<title>$site.$domain</title>
			</head>
			<body>
				<img src=\"/image.png\" width=\"300\" height=\"300\">
				<p>
					Welcome to <b>$site.$domain</b><br/>
					Got here via <i><!--# echo var=\"remote_addr\" --></i>
				</p>
				<ul>
					<li>SNI: <!--# echo var=\"ssl_server_name\" --></li>
					<li>HTTP host: <!--# echo var=\"http_host\" --></li>
					<li>ALPN protocol: <!--# echo var=\"ssl_alpn_protocol\" --></li>
				</ul>
				<form action=\"/pkglist\">
					<input type=\"submit\" value=\"Download pkglist\" />
				</form>"
		for p_server_cfg in $server_cfgs; do IFS=, read p_host _ p_ip _ p_sites <<< $p_server_cfg
			cmds="$cmds<p>Sites on $p_host ($p_ip):"
			for p_site in ${p_sites//,/ }; do
				cmds="$cmds<br/><a href=\"https://$p_site.$domain\">$p_site.$domain</a>"
				[ "$site" = "$p_site" ] && cmds="$cmds *" || true
			done
			cmds="$cmds</p>"
		done
		cmds="$cmds
			</body>
		</html>' || exit 1
		ln -s /mnt/src/openssl/doc/images/openssl-square-nontransparent.png /site/$site/image.png || exit 1
		ln -s /var/lib/apt/lists/deb.debian.org_debian_dists_unstable_main_binary-amd64_Packages /site/$site/pkglist || exit 1"
	done

	cmds="$cmds
	# WireGuard traffic padding service
	>/site/padding.sh echo '#!/bin/bash
	tc qdisc replace dev enp0s6 root netem slot 10ms 20ms"
	for p_server_cfg in $server_cfgs; do IFS=, read p_host _ _ p_wg _ <<< $p_server_cfg
		cmds="$cmds
		socat -x UNIX-LISTEN:/tmp/socat_$p_host.sock,fork,umask=0 TCP:$p_wg:443 2>&1 | grep --line-buffered ^\\> | while read _ _ _ len _ _; do"
		for pp_server_cfg in $server_cfgs; do IFS=, read _ _ _ pp_wg _ <<< $pp_server_cfg
			[ "$p_wg" != "$pp_wg" ] && {
				cmds="$cmds
				dd if=/dev/urandom bs=\${len#*=} count=1 >/dev/udp/$pp_wg/12345 &"
			}
		done
		cmds="$cmds
		done &"
	done
	cmds="$cmds
	wait' || exit 1
	>/site/padding.service echo '
	[Unit]
	Before=nginx.service
	[Service]
	ExecStart=/site/padding.sh
	Restart=always
	[Install]
	WantedBy=multi-user.target' || exit 1
	chmod +x /site/padding.sh || exit 1

	# Install services
	cp /site/padding.service /mnt/nginx/nginx.service /etc/systemd/system || exit 1
	systemctl daemon-reload && systemctl enable padding nginx || exit 1"

	declare "${host}_cmds=$cmds"
done

# Generate all VM images in parallel
port=2222
for cfg in "$dns_host,$dns_mac,$dns_ip" $server_cfgs $client_cfgs; do IFS=, read host mac ip _ <<< $cfg
	port="$((port+1))"
	[ -f "$dir/$host.img" ] || {
		msg "Generating $host.img:"

		cmds_var="${host}_cmds"
		cmds="
		# Mount build.img
		>>/etc/fstab echo 'LABEL=build /mnt ext4 defaults 0 0' || exit 1
		mount -o ro /dev/disk/by-label/build /mnt || exit 1

		# Useful aliases
		>~/.profile echo '
		alias openssl=\"LD_LIBRARY_PATH=/mnt/openssl/lib64 /mnt/openssl/bin/openssl\"
		alias curl=\"LD_LIBRARY_PATH=/mnt/openssl/lib64 /mnt/curl/bin/curl\"
		echo \"dig +https @dns.example.com tcd.example.com https\"
		echo \"curl --verbose --cacert /keys/root.crt --ech hard --doh-url https://dns.example.com/dns-query https://tcd.example.com\"
		' || exit 1

		# Configure networking
		hostnamectl set-hostname $host || exit 1
		sed -i 's/base/$host/g' /etc/hosts || exit 1
		>/etc/systemd/network/00-br0.network echo '
		[Match]
		MACAddress=$mac
		[Network]
		DNS=$dns_ip
		Address=$ip/24
		[Route]
		Gateway=0.0.0.0
		Destination=0.0.0.0/0
		Metric=9999' || exit 1

		# Execute $host-specific commands
		${!cmds_var}

		# Graceful shutdown
		cd && umount /mnt || exit 1
		shutdown now"

		echo "$cmds"
		cp "$dir/base.img" "$dir/$host.img" || exit 1
		debvm-run --image "$dir/$host.img" --sshport "$port" --graphical -- \
			-display none -drive file="$dir/build.img",format=raw,if=virtio,readonly=on &
		debvm-waitssh "$port" || exit 1
		ssh -o NoHostAuthenticationForLocalhost=yes -i "$dir/ssh.key" -p "$port" root@127.0.0.1 "$cmds" || exit 1
	} &
done
wait

port=2222
for cfg in "$dns_host,$dns_mac" $server_cfgs $client_cfgs; do IFS=, read host mac _ <<< $cfg
	sleep 1
	port="$((port+1))"
	{
		msg "Booting up host $host..."
		debvm-run --image "$dir/$host.img" --sshport "$port" --graphical -- \
			-display none -drive file="$dir/build.img",format=raw,if=virtio,readonly=on \
			-device virtio-net-pci,netdev=net1,mac=$mac -netdev bridge,id=net1,br=br0 &
		debvm-waitssh "$port" || exit 1
		msg "Host $host is up and running"
		echo "ssh -o NoHostAuthenticationForLocalhost=yes -i '$dir/ssh.key' -p $port root@127.0.0.1"
		wait
		msg "Host $host has shutdown"
	} &
done


wait
killall debvm-run qemu-system-x86_64
