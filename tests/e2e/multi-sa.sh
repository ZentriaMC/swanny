#!/usr/bin/env bash
# Multi-SA + INITIAL_CONTACT E2E test.
# Simulates a peer crash and reconnect: the responder should tear down
# the stale SA when the new initiator sends INITIAL_CONTACT.
# Expects lib.sh to be sourced and fh_ssh/scp_opts available.

test_multi_sa() {
    echo ">>> [multi-sa] Stopping previous swanny instances..."
    swanny_stop

    echo ">>> [multi-sa] Setting up network namespaces..."
    fh_ssh -- "sudo /tmp/setup-netns.sh ms1 ms2"

    echo ">>> [multi-sa] Starting swanny responder in ms2..."
    swanny_start ms2 \
        --tunnel-id multi-ms2 \
        --address 192.168.1.2 --peer-address 192.168.1.1 --psk secret \
        --mode transport --local-ts 192.168.1.2/32 --remote-ts 192.168.1.1/32 \
        --local-identity fqdn:ms2.swanny.test --remote-identity fqdn:ms1.swanny.test
    dataplane_start ms2

    sleep 1

    echo ">>> [multi-sa] Starting swanny initiator in ms1 (first SA)..."
    swanny_start ms1 \
        --tunnel-id multi-ms1 --initiate \
        --address 192.168.1.1 --peer-address 192.168.1.2 --psk secret \
        --mode transport --local-ts 192.168.1.1/32 --remote-ts 192.168.1.2/32 \
        --local-identity fqdn:ms1.swanny.test --remote-identity fqdn:ms2.swanny.test
    dataplane_start ms1

    echo ">>> [multi-sa] Verifying first SA with ping..."
    if ! swanny_ping ms1 192.168.1.2 10 10; then
        swanny_fail "first SA ping failed" ms1 ms2
    fi
    echo ">>> [multi-sa] First SA established"

    echo ">>> [multi-sa] Killing initiator (simulating crash)..."
    fh_ssh -- "sudo ip netns pids ms1 | xargs -r sudo kill" || true
    sleep 1

    # Flush XFRM state in ms1 so the new initiator starts clean
    fh_ssh -- "sudo ip netns exec ms1 ip xfrm state flush" || true
    fh_ssh -- "sudo ip netns exec ms1 ip xfrm policy flush" || true

    echo ">>> [multi-sa] Starting new swanny initiator in ms1 (second SA)..."
    swanny_start ms1 \
        --tunnel-id multi-ms1 --initiate \
        --address 192.168.1.1 --peer-address 192.168.1.2 --psk secret \
        --mode transport --local-ts 192.168.1.1/32 --remote-ts 192.168.1.2/32 \
        --local-identity fqdn:ms1.swanny.test --remote-identity fqdn:ms2.swanny.test
    dataplane_start ms1

    echo ">>> [multi-sa] Verifying second SA with ping..."
    if ! swanny_ping ms1 192.168.1.2 10 10; then
        swanny_fail "second SA ping failed" ms1 ms2
    fi
    echo ">>> [multi-sa] Second SA established"

    sleep 2

    echo ">>> [multi-sa] Responder log (last 30 lines):"
    fh_ssh -- "tail -30 /tmp/swanny-ms2.log" || true

    echo ">>> [multi-sa] Checking responder log for INITIAL_CONTACT teardown..."
    if ! fh_ssh -- "grep -q 'INITIAL_CONTACT received' /tmp/swanny-ms2.log"; then
        swanny_fail "responder did not receive INITIAL_CONTACT" ms1 ms2
    fi
    if ! fh_ssh -- "grep -q 'tore down stale IKE SA' /tmp/swanny-ms2.log"; then
        swanny_fail "responder did not tear down stale SA" ms1 ms2
    fi

    echo ">>> [multi-sa] PASS"
}
