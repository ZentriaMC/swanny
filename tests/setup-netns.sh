#!/bin/sh

set -xe

if test $# -ne 2; then
    echo "Usage: $0 NS1 NS2" 1>&2
    exit 1
fi

NS1="$1"
shift
NS2="$1"
shift

VETH1="$NS1-veth"
VETH2="$NS2-veth"

ip netns add "$NS1"
ip netns add "$NS2"

ip link add "$VETH1" type veth peer "$VETH2"
ip link set "$VETH1" netns "$NS1"
ip link set "$VETH2" netns "$NS2"

ip netns exec "$NS1" ip addr add 192.168.1.1/24 dev "$VETH1"
ip netns exec "$NS2" ip addr add 192.168.1.2/24 dev "$VETH2"

ip netns exec "$NS1" ip link set "$VETH1" up
ip netns exec "$NS2" ip link set "$VETH2" up

ip netns exec "$NS1" ip link set lo up
ip netns exec "$NS2" ip link set lo up
