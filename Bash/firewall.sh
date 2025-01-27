#!/bin/bash

echo -n "Restarting Network..."
systemctl restart wg-quick@wg0.service
systemctl restart networking.service
/usr/bin/ip rule del not from all fwmark 0xca6c lookup 51820
echo "[completed]"

echo -n "Removing ip rules if exists ... "
/usr/bin/ip rule del fwmark 0x500 lookup wg0
/usr/bin/ip rule del fwmark 0x100 lookup wan1
/usr/bin/ip rule del fwmark 0x200 lookup wan2

# Rule Traffic only for wg0
/usr/bin/ip rule del fwmark 0x500 table 202
/usr/bin/ip route del default dev wg0 table 202
# Rule Traffic only for ens192 (wan1)
/usr/bin/ip rule del fwmark 0x100 table 200
/usr/bin/ip route del default via 100.100.1.1 dev ens192 table 200
# Rule Traffic only for ens224 (wan2)
/usr/bin/ip rule del fwmark 0x200 table 201
/usr/bin/ip route del default via 200.200.1.1 dev ens224 table 201


echo "[done]"

echo -n "adding ip route rules ... "
/usr/bin/ip rule add fwmark 0x500 lookup wg0
/usr/bin/ip rule add fwmark 0x100 lookup wan1
/usr/bin/ip rule add fwmark 0x200 lookup wan2

# Rule Traffic only for wg0
/usr/bin/ip rule add fwmark 0x500 table 202
/usr/bin/ip route add default dev wg0 table 202
# Rule Traffic only for ens224
/usr/bin/ip rule add fwmark 0x200 table 201
/usr/bin/ip route add default via 200.200.1.1 dev ens224 table 201
# Rule Traffic only for ens192
/usr/bin/ip rule add fwmark 0x100 table 200
/usr/bin/ip route add default via 100.100.1.1 dev ens192 table 200

echo "[done]"

echo -n "Showing ip rules ... "
/usr/bin/ip rule show
echo "[done]"

echo -n "Loading traffic shaping kernel modules ... "
/usr/sbin/modprobe sch_htb
/usr/sbin/modprobe sch_sfq
echo "[done]"

echo -n "Remove current QoS ... "
/usr/sbin/tc qdisc del dev ens192 root
/usr/sbin/tc qdisc del dev ens224 root
echo "[done]"


echo -n "Loading QoS priorities and rules ... "
echo -n "ens192 -> "
# For ens192
/usr/sbin/tc qdisc add dev ens192 root handle 1: htb default 30
/usr/sbin/tc class add dev ens192 parent 1: classid 1:1 htb rate 100mbit burst 15k
/usr/sbin/tc class add dev ens192 parent 1:1 classid 1:10 htb rate 70mbit ceil 100mbit prio 1 # High Priority
/usr/sbin/tc class add dev ens192 parent 1:1 classid 1:20 htb rate 20mbit ceil 100mbit prio 2 # Normal Priority
/usr/sbin/tc class add dev ens192 parent 1:1 classid 1:30 htb rate 10mbit ceil 100mbit prio 3 # Low Priority

/usr/sbin/tc qdisc add dev ens192 parent 1:10 handle 10: sfq perturb 10
/usr/sbin/tc qdisc add dev ens192 parent 1:20 handle 20: sfq perturb 10
/usr/sbin/tc qdisc add dev ens192 parent 1:30 handle 30: sfq perturb 10

/usr/sbin/tc filter add dev ens192 parent 1: protocol ip prio 1 handle 0x100 fw flowid 1:10
/usr/sbin/tc filter add dev ens192 parent 1: protocol ip prio 2 handle 0x200 fw flowid 1:20
/usr/sbin/tc filter add dev ens192 parent 1: protocol ip prio 3 handle 0x300 fw flowid 1:30
echo -n "OK"

# For ens224
echo -n " | ens224 -> "
/usr/sbin/tc qdisc add dev ens224 root handle 1: htb default 30
/usr/sbin/tc class add dev ens224 parent 1: classid 1:1 htb rate 100mbit burst 15k
/usr/sbin/tc class add dev ens224 parent 1:1 classid 1:10 htb rate 70mbit ceil 100mbit prio 1 # High Priority
/usr/sbin/tc class add dev ens224 parent 1:1 classid 1:20 htb rate 20mbit ceil 100mbit prio 2 # Normal Priority
/usr/sbin/tc class add dev ens224 parent 1:1 classid 1:30 htb rate 10mbit ceil 100mbit prio 3 # Low Priority

/usr/sbin/tc qdisc add dev ens224 parent 1:10 handle 10: sfq perturb 10
/usr/sbin/tc qdisc add dev ens224 parent 1:20 handle 20: sfq perturb 10
/usr/sbin/tc qdisc add dev ens224 parent 1:30 handle 30: sfq perturb 10

/usr/sbin/tc filter add dev ens224 parent 1: protocol ip prio 1 handle 0x100 fw flowid 1:10
/usr/sbin/tc filter add dev ens224 parent 1: protocol ip prio 2 handle 0x200 fw flowid 1:20
/usr/sbin/tc filter add dev ens224 parent 1: protocol ip prio 3 handle 0x300 fw flowid 1:30
echo -n "OK | ... "
echo "[completed]"


echo -n "Executing nftable firewall ... "
/usr/sbin/nft -f /etc/nftables.conf
echo "[done]"