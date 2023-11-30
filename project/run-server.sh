#!/bin/sh

IMG=images/server.ext4
KTMP=$(mktemp)
ITMP=$(mktemp)
/sbin/debugfs "$IMG" -R "cat boot/vmlinuz-6.5.0-3-cloud-amd64" > "$KTMP"
/sbin/debugfs "$IMG" -R "cat boot/initrd.img-6.5.0-3-cloud-amd64" > "$ITMP"

#-device "e1000,netdev=net0"
#-netdev "user,id=net0,hostfwd=tcp::5555-:22"

#-netdev "user,id=net0" \
#-device "virtio-net-pci,netdev=net0" \

qemu-system-x86_64 \
	-append "root=LABEL=debvm rw console=ttyS0 TERM=xterm-256color" \
	-net "nic,model=virtio,macaddr=52:54:00:00:00:01" \
	-net "bridge,br=virtbr0" \
	-nographic \
	-device "virtio-rng-pci,rng=rng0" \
	-smp "8" \
	-cpu "host" \
	-machine "type=q35,accel=kvm:tcg" \
	-no-user-config \
	-name "debvm-run $IMG" \
	-m "1G" \
	-kernel "$KTMP" \
	-initrd "$ITMP" \
	-drive "media=disk,format=raw,discard=unmap,file=$IMG,if=virtio,cache=unsafe" \
	-object "rng-random,filename=/dev/urandom,id=rng0"
