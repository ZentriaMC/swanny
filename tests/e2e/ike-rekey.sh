#!/usr/bin/env bash
# IKE SA rekey E2E test.
# Expects lib.sh to be sourced and fh_ssh/scp_opts available.

test_ike_rekey() {
    echo ">>> [ike-rekey] Stopping previous swanny instances..."
    swanny_stop

    echo ">>> [ike-rekey] Setting up network namespaces..."
    fh_ssh -- "sudo /tmp/setup-netns.sh rk1 rk2"

    echo ">>> [ike-rekey] Starting swanny responder in rk2..."
    swanny_start rk2 \
        --address 192.168.1.2 --peer-address 192.168.1.1 --psk secret \
        --mode transport --local-ts 192.168.1.2/32 --remote-ts 192.168.1.1/32 \
        --identity fqdn:rk2.swanny.test --remote-identity fqdn:rk1.swanny.test

    sleep 1

    echo ">>> [ike-rekey] Starting swanny initiator in rk1 (--ike-lifetime 5)..."
    swanny_start rk1 \
        --address 192.168.1.1 --peer-address 192.168.1.2 --psk secret \
        --mode transport --local-ts 192.168.1.1/32 --remote-ts 192.168.1.2/32 \
        --ike-lifetime 5 \
        --identity fqdn:rk1.swanny.test --remote-identity fqdn:rk2.swanny.test

    echo ">>> [ike-rekey] Initial ping to establish SA..."
    if ! swanny_ping rk1 192.168.1.2 5 10; then
        swanny_fail "initial ping failed" rk1 rk2
    fi

    echo ">>> [ike-rekey] Waiting 8s for IKE SA rekey..."
    sleep 8

    echo ">>> [ike-rekey] Verifying traffic still works after rekey..."
    if ! swanny_ping rk1 192.168.1.2 5 5; then
        swanny_fail "ping after rekey failed" rk1 rk2
    fi

    echo ">>> [ike-rekey] Checking initiator log for rekey confirmation..."
    if ! fh_ssh -- "grep -q 'IKE SA rekeyed' /tmp/swanny-rk1.log"; then
        swanny_fail "IKE SA rekey did not occur (no 'IKE SA rekeyed' in log)" rk1 rk2
    fi

    echo ">>> [ike-rekey] PASS"
}
