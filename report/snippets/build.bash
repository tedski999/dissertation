ssh-keygen -N "" -t ed25519 -f ssh.key
debvm-create -h builder -o builder.img -r unstable -z 2GB -k ssh.key.pub -- \
	--include ca-certificates,build-essential,dh-autoreconf,git,e2fsprogs \
	--include libpsl-dev,libpcre3-dev,libz-dev,libnghttp2-dev

qemu-img create build.img 2G
debvm-run --image builder.img --sshport 2222 --graphical -- \
	-display none -drive file=build.img,format=raw,if=virtio,readonly=off &
debvm-waitssh 2222

ssh -o NoHostAuthenticationForLocalhost=yes -i ssh.key -p 2222 root@127.0.0.1 "
	mkfs.ext4 -L build /dev/vdb
	mount /dev/vdb /mnt

	git clone -b ECH-draft-13c https://github.com/sftcd/openssl.git /mnt/src/openssl
	cd /mnt/src/openssl
	./config --prefix=/mnt/openssl --openssldir=/mnt/openssl
	make -j8
	make -j8 install

	cd / && umount /mnt
	shutdown now"
wait
