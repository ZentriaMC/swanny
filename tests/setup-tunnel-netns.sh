#!/bin/sh
# Set up two network namespaces with XFRM interfaces for tunnel-mode testing.
#
# Topology:
#   ns1: 10.0.1.{1,10,100}/32 on xfrm0 ──┐
#        192.168.1.1/24 on veth           ├─ veth pair (underlay)
#   ns2: 10.0.2.{1,10,100}/32 on xfrm0 ──┘
#        192.168.1.2/24 on veth
#
# Traffic from 10.0.1.0/24 → 10.0.2.0/24 is routed through xfrm0,
# which triggers XFRM policy lookup (by if_id) and IPsec encapsulation.
#
# Each namespace gets its own if_id: NS1 uses IF_ID, NS2 uses IF_ID+1.
#
# Usage: setup-tunnel-netns.sh NS1 NS2 IF_ID

set -xe

if test $# -lt 3; then
    echo "Usage: $0 NS1 NS2 IF_ID" 1>&2
    exit 1
fi

NS1="$1"
NS2="$2"
IF_ID1="$3"
IF_ID2=$(( IF_ID1 + 1 ))

VETH1="$NS1-veth"
VETH2="$NS2-veth"

# Underlay: veth pair between namespaces
ip link add "$VETH1" type veth peer "$VETH2"

ip netns add "$NS1"
ip netns add "$NS2"

ip link set "$VETH1" netns "$NS1"
ip link set "$VETH2" netns "$NS2"

ip netns exec "$NS1" ip addr add 192.168.1.1/24 dev "$VETH1"
ip netns exec "$NS2" ip addr add 192.168.1.2/24 dev "$VETH2"

ip netns exec "$NS1" ip link set "$VETH1" up
ip netns exec "$NS2" ip link set "$VETH2" up

ip netns exec "$NS1" ip link set lo up
ip netns exec "$NS2" ip link set lo up

# Overlay: XFRM interfaces bound to the underlay veths (unique if_id per ns)
ip -n "$NS1" link add xfrm0 type xfrm dev "$VETH1" if_id "$IF_ID1"
ip -n "$NS1" addr add 10.0.1.1/32 dev xfrm0
ip -n "$NS1" addr add 10.0.1.10/32 dev xfrm0
ip -n "$NS1" addr add 10.0.1.100/32 dev xfrm0
ip -n "$NS1" link set xfrm0 up
ip -n "$NS1" route add 10.0.2.0/24 dev xfrm0 src 10.0.1.1

ip -n "$NS2" link add xfrm0 type xfrm dev "$VETH2" if_id "$IF_ID2"
ip -n "$NS2" addr add 10.0.2.1/32 dev xfrm0
ip -n "$NS2" addr add 10.0.2.10/32 dev xfrm0
ip -n "$NS2" addr add 10.0.2.100/32 dev xfrm0
ip -n "$NS2" link set xfrm0 up
ip -n "$NS2" route add 10.0.1.0/24 dev xfrm0 src 10.0.2.1

# Disable reverse-path filtering on XFRM interfaces so decapsulated
# packets with inner-subnet source addresses are not dropped.
ip netns exec "$NS1" sysctl -w net.ipv4.conf.xfrm0.rp_filter=0
ip netns exec "$NS2" sysctl -w net.ipv4.conf.xfrm0.rp_filter=0
