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

ip netns exec "$NS1" ip xfrm policy add \
   src 192.168.1.2/32 dst 192.168.1.1/32 \
   proto icmp \
   dir fwd \
   priority 1000 \
   tmpl src 192.168.1.2 dst 192.168.1.1 proto "esp" reqid "42" \
   mode transport

ip netns exec "$NS1" ip xfrm policy add \
   src 192.168.1.1/32 dst 192.168.1.2/32 \
   proto icmp \
   dir out \
   priority 1000 \
   tmpl src 192.168.1.1 dst 192.168.1.2 proto "esp" reqid "42" \
   mode transport

ip netns exec "$NS1" ip xfrm policy add \
   src 192.168.1.2/32 dst 192.168.1.1/32 \
   proto icmp \
   dir in \
   priority 1000 \
   tmpl src 192.168.1.2 dst 192.168.1.1 proto "esp" reqid "42" \
   mode transport

ip netns exec "$NS2" ip xfrm policy add \
   src 192.168.1.1/32 dst 192.168.1.2/32 \
   proto icmp \
   dir fwd \
   priority 1000 \
   tmpl src 192.168.1.1 dst 192.168.1.2 proto "esp" reqid "42" \
   mode transport

ip netns exec "$NS2" ip xfrm policy add \
   src 192.168.1.2/32 dst 192.168.1.1/32 \
   proto icmp \
   dir out \
   priority 1000 \
   tmpl src 192.168.1.2 dst 192.168.1.1 proto "esp" reqid "42" \
   mode transport

ip netns exec "$NS2" ip xfrm policy add \
   src 192.168.1.1/32 dst 192.168.1.2/32 \
   proto icmp \
   dir in \
   priority 1000 \
   tmpl src 192.168.1.1 dst 192.168.1.2 proto "esp" reqid "42" \
   mode transport
