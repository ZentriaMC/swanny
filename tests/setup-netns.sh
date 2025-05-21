#!/bin/sh

set -xe

if test $# -lt 2; then
    echo "Usage: $0 NS1 NS2 [BRIDGE]" 1>&2
    exit 1
fi

NS1="$1"
shift
NS2="$1"
shift

if test $# -gt 0; then
    BRIDGE="$1"
    shift
fi

VETH1="$NS1-veth"
VETH2="$NS2-veth"

if test -n "$BRIDGE"; then
    VETH1BR="$VETH1-br"
    VETH2BR="$VETH2-br"

    ip link add "$BRIDGE" type bridge
    ip link set "$BRIDGE" up
    ip addr add 192.168.1.0/24 dev "$BRIDGE"

    ip link add "$VETH1" type veth peer name "$VETH1BR"
    ip link add "$VETH2" type veth peer name "$VETH2BR"
    ip link set "$VETH1BR" master "$BRIDGE" up
    ip link set "$VETH2BR" master "$BRIDGE" up
else
    ip link add "$VETH1" type veth peer "$VETH2"
fi

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
