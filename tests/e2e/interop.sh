#!/usr/bin/env bash
# strongSwan interop E2E test (transport mode).
# Tests both directions: swanny→strongSwan and strongSwan→swanny.
# Expects lib.sh to be sourced and fh_ssh/scp_opts available.

strongswan_start() {
    local ns="$1"
    local conf="$2"

    # Deploy config before starting
    scp "${scp_opts[@]}" "${conf}" core@127.0.0.1:/tmp/swanny-interop.conf
    fh_ssh -- "sudo mkdir -p /etc/strongswan/swanctl/conf.d && \
        sudo cp /tmp/swanny-interop.conf /etc/strongswan/swanctl/conf.d/swanny.conf"

    # Start charon inside the namespace
    fh_ssh -- "sudo ip netns exec ${ns} strongswan start"
    sleep 2

    # Load connections and secrets
    fh_ssh -- "sudo ip netns exec ${ns} swanctl --load-all 2>&1"
}

strongswan_stop() {
    fh_ssh -- "sudo strongswan stop" || true
    fh_ssh -- "sudo rm -f /etc/strongswan/swanctl/conf.d/swanny.conf" || true
    sleep 1
}

strongswan_initiate() {
    local ns="$1"
    fh_ssh -- "sudo ip netns exec ${ns} swanctl --initiate --child swanny 2>&1"
}

test_interop_swanny_initiator() {
    echo ">>> [interop] Setting up network namespaces..."
    fh_ssh -- "sudo /tmp/setup-netns.sh sw1 sw2"

    echo ">>> [interop] Starting strongSwan responder in sw2..."
    strongswan_start sw2 "${root}/tests/e2e/strongswan-responder.conf"

    echo ">>> [interop] Starting swanny initiator in sw1..."
    swanny_start sw1 \
        --address 192.168.1.1 --peer-address 192.168.1.2 --psk secret \
        --local-ts 192.168.1.1/32 --remote-ts 192.168.1.2/32

    echo ">>> [interop] Verifying IPsec SA with ping..."
    if ! swanny_ping sw1 192.168.1.2 10 10; then
        echo ">>> --- strongSwan status ---"
        fh_ssh -- "sudo ip netns exec sw2 swanctl --list-sas" || true
        swanny_fail "ping failed — swanny→strongSwan negotiation failed" sw1 sw2
    fi
    echo ">>> [interop] PASS: swanny initiator → strongSwan responder"

    echo ">>> [interop] Cleaning up..."
    swanny_stop
    strongswan_stop
    fh_ssh -- "sudo ip netns del sw1; sudo ip netns del sw2" || true
}

test_interop_strongswan_initiator() {
    echo ">>> [interop] Setting up network namespaces..."
    fh_ssh -- "sudo /tmp/setup-netns.sh sw1 sw2"

    echo ">>> [interop] Starting swanny responder in sw2..."
    swanny_start sw2 \
        --address 192.168.1.2 --peer-address 192.168.1.1 --psk secret \
        --local-ts 192.168.1.2/32 --remote-ts 192.168.1.1/32

    sleep 1

    echo ">>> [interop] Starting strongSwan initiator in sw1..."
    strongswan_start sw1 "${root}/tests/e2e/strongswan-initiator.conf"
    strongswan_initiate sw1

    echo ">>> [interop] Verifying IPsec SA with ping..."
    if ! swanny_ping sw1 192.168.1.2 10 10; then
        echo ">>> --- strongSwan status ---"
        fh_ssh -- "sudo ip netns exec sw1 swanctl --list-sas" || true
        swanny_fail "ping failed — strongSwan→swanny negotiation failed" sw1 sw2
    fi
    echo ">>> [interop] PASS: strongSwan initiator → swanny responder"

    echo ">>> [interop] Cleaning up..."
    swanny_stop
    strongswan_stop
    fh_ssh -- "sudo ip netns del sw1; sudo ip netns del sw2" || true
}
