sudo ip link add name br0 type bridge
sudo ip addr add 172.0.0.1/24 dev br0
sudo ip link set dev br0 up

debvm-run --image host.img -- \
	-device virtio-net-pci,netdev=net1,mac=00:00:00:00:00:01 \
	-netdev bridge,id=net1,br=br0
