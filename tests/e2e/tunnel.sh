#!/usr/bin/env bash
# Tunnel mode E2E test.
# Expects lib.sh to be sourced and fh_ssh/scp_opts available.

test_tunnel() {
    echo ">>> [tunnel] Stopping previous swanny instances..."
    swanny_stop

    echo ">>> [tunnel] Setting up tunnel-mode network namespaces..."
    fh_ssh -- "sudo /tmp/setup-tunnel-netns.sh tun1 tun2 1337"

    echo ">>> [tunnel] Starting swanny responder in tun2..."
    swanny_start tun2 \
        --address 192.168.1.2 --peer-address 192.168.1.1 --psk secret \
        --mode tunnel --if-id 1338 \
        --local-ts 10.0.2.0/24 --remote-ts 10.0.1.0/24 \
        --identity fqdn:tun2.swanny.test --remote-identity fqdn:tun1.swanny.test

    sleep 1

    echo ">>> [tunnel] Starting swanny initiator in tun1..."
    swanny_start tun1 \
        --address 192.168.1.1 --peer-address 192.168.1.2 --psk secret \
        --mode tunnel --if-id 1337 \
        --local-ts 10.0.1.0/24 --remote-ts 10.0.2.0/24 \
        --identity fqdn:tun1.swanny.test --remote-identity fqdn:tun2.swanny.test

    echo ">>> [tunnel] Verifying 10.0.1.1 → 10.0.2.1..."
    if ! swanny_ping tun1 10.0.2.1 10 10; then
        swanny_fail "ping 10.0.1.1 → 10.0.2.1 failed" tun1 tun2
    fi
    echo ">>> [tunnel] PASS: 10.0.1.1 → 10.0.2.1"

    echo ">>> [tunnel] Verifying cross-subnet: 10.0.1.10 → 10.0.2.10..."
    if ! swanny_ping tun1 10.0.2.10 5 5 10.0.1.10; then
        swanny_fail "ping 10.0.1.10 → 10.0.2.10 failed" tun1 tun2
    fi
    echo ">>> [tunnel] PASS: 10.0.1.10 → 10.0.2.10"

    echo ">>> [tunnel] Verifying cross-subnet: 10.0.1.100 → 10.0.2.100..."
    if ! swanny_ping tun1 10.0.2.100 5 5 10.0.1.100; then
        swanny_fail "ping 10.0.1.100 → 10.0.2.100 failed" tun1 tun2
    fi
    echo ">>> [tunnel] PASS: 10.0.1.100 → 10.0.2.100"

    echo ">>> [tunnel] Verifying reverse direction: 10.0.2.1 → 10.0.1.10..."
    if ! swanny_ping tun2 10.0.1.10 5 5 10.0.2.1; then
        swanny_fail "ping 10.0.2.1 → 10.0.1.10 failed" tun1 tun2
    fi
    echo ">>> [tunnel] PASS: 10.0.2.1 → 10.0.1.10"
}
