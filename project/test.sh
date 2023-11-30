sudo brctl addbr virtbr0
sudo brctl addif virtbr0 enp2s0
sudo ip addr add 172.168.0.20/24 dev virtbr0
sudo ip link set virtbr0 up
sudo iptables -I FORWARD -m physdev --physdev-is-bridged -j ACCEPT


ip addr add 172.168.0.22/24 dev enp0s2



sudo ip link set virtbr0 down
sudo brctl delbr virtbr0
