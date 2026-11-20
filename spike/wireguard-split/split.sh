#!/bin/bash
# Feasibility of the wg0 split: two wg links with ONE private key (server + outbound),
# then moving the listen port between them. Three netns: fw, provider, laptop.
set -u
apt-get -qq update >/dev/null 2>&1 && apt-get -qq install -y wireguard-tools iproute2 iputils-ping >/dev/null 2>&1 || { echo "apt failed"; exit 2; }
ok(){ echo "PASS: $*"; }; bad(){ echo "FAIL: $*"; FAILED=1; }; FAILED=0
for ns in fw provider laptop; do ip netns add $ns; done
# fw <-> provider (WAN) and fw <-> laptop (another WAN client)
ip link add v-fw-p type veth peer name v-p-fw; ip link set v-fw-p netns fw; ip link set v-p-fw netns provider
ip link add v-fw-l type veth peer name v-l-fw; ip link set v-fw-l netns fw; ip link set v-l-fw netns laptop
ip -n fw addr add 203.0.113.1/24 dev v-fw-p; ip -n provider addr add 203.0.113.2/24 dev v-p-fw
ip -n fw addr add 198.51.100.1/24 dev v-fw-l; ip -n laptop addr add 198.51.100.2/24 dev v-l-fw
for ns in fw provider laptop; do ip -n $ns link set lo up; done
ip -n fw link set v-fw-p up; ip -n provider link set v-p-fw up; ip -n fw link set v-fw-l up; ip -n laptop link set v-l-fw up

K=$(wg genkey); KPUB=$(echo "$K" | wg pubkey)            # the firewall's single identity
P=$(wg genkey); PPUB=$(echo "$P" | wg pubkey)            # provider
L=$(wg genkey); LPUB=$(echo "$L" | wg pubkey)            # laptop (road warrior)

# Provider: knows the firewall only by KPUB, gave it 10.64.0.2.
ip -n provider link add wgP type wireguard
echo "$P" > /tmp/p.key; ip netns exec provider wg set wgP private-key /tmp/p.key listen-port 51821 peer "$KPUB" allowed-ips 10.64.0.2/32
ip -n provider addr add 10.64.0.1/24 dev wgP; ip -n provider link set wgP up

# Laptop: road warrior of the firewall's server, endpoint fw:51820, server key KPUB.
ip -n laptop link add wgC type wireguard
echo "$L" > /tmp/l.key; ip netns exec laptop wg set wgC private-key /tmp/l.key peer "$KPUB" allowed-ips 10.10.0.0/24 endpoint 198.51.100.1:51820 persistent-keepalive 1
ip -n laptop addr add 10.10.0.2/32 dev wgC; ip -n laptop link set wgC up; ip -n laptop route add 10.10.0.0/24 dev wgC

# ── BEFORE: legacy dual-role wg0 (listens 51820 AND dials the provider) ──
echo "$K" > /tmp/k.key
ip -n fw link add wg0 type wireguard
ip netns exec fw wg set wg0 private-key /tmp/k.key listen-port 51820 \
  peer "$PPUB" allowed-ips 10.64.0.0/24 endpoint 203.0.113.2:51821 persistent-keepalive 1 \
  peer "$LPUB" allowed-ips 10.10.0.2/32
ip -n fw addr add 10.64.0.2/32 dev wg0; ip -n fw addr add 10.10.0.1/24 dev wg0; ip -n fw link set wg0 up
ip -n fw route add 10.64.0.0/24 dev wg0
sleep 2
ip netns exec fw ping -c1 -W2 10.64.0.1 >/dev/null && ok "before: dual wg0 reaches the provider" || bad "before: provider"
ip netns exec laptop ping -c3 -W2 10.10.0.1 >/dev/null && ok "before: laptop reaches the server on wg0" || bad "before: laptop"

# ── SPLIT (advisor's direction): wg0 stays the OUTBOUND link; the server role moves to wg1 ──
# 1. wg0 gives up the listen port (kernel picks an ephemeral one) and the laptop peer + server address.
ip netns exec fw wg set wg0 listen-port 0 peer "$LPUB" remove
ip -n fw addr del 10.10.0.1/24 dev wg0
# 2. wg1 takes the SAME private key, the port and the laptop.
ip -n fw link add wg1 type wireguard
ip netns exec fw wg set wg1 private-key /tmp/k.key listen-port 51820 peer "$LPUB" allowed-ips 10.10.0.2/32 \
  && ok "port 51820 handed over to wg1" || bad "port handover (bind failed)"
ip -n fw addr add 10.10.0.1/24 dev wg1; ip -n fw link set wg1 up
sleep 3
ip netns exec fw wg show wg0 listen-port | grep -qv '^51820$' && ok "wg0 no longer listens on 51820 ($(ip netns exec fw wg show wg0 listen-port))" || bad "wg0 still on 51820"
ip netns exec fw ping -c2 -W2 10.64.0.1 >/dev/null && ok "after: wg0 still reaches the provider (same key, new port)" || bad "after: provider"
# An ACTIVE session was keyed to wg0: wg1 drops it until the laptop re-handshakes. Measure how long.
start=$(date +%s); back=""
for i in $(seq 1 60); do ip netns exec laptop ping -c1 -W1 10.10.0.1 >/dev/null && { back=$(( $(date +%s) - start )); break; }; done
[ -n "$back" ] && ok "after: laptop back on wg1 with its UNCHANGED config after ${back}s (re-handshake)" || bad "after: laptop never came back (60 s)"
ip netns exec fw wg show wg1 latest-handshakes | awk '{print $2}' | grep -qv '^0$' && ok "wg1 has a fresh handshake with the laptop" || bad "wg1 handshake"
ip netns exec provider wg show wgP endpoints
echo "RESULT: $([ $FAILED = 0 ] && echo ALL PASS || echo FAILURES)"
