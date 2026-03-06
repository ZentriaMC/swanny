#!/usr/bin/env bash
# Transport mode E2E test.
# Expects lib.sh to be sourced and fh_ssh/scp_opts available.

test_transport() {
    echo ">>> [transport] Setting up network namespaces..."
    fh_ssh -- "sudo /tmp/setup-netns.sh ns1 ns2"

    echo ">>> [transport] Starting swanny responder in ns2..."
    swanny_start ns2 \
        --tunnel-id transport-ns2 \
        --address 192.168.1.2 --peer-address 192.168.1.1 --psk secret \
        --mode transport --local-ts 192.168.1.2/32 --remote-ts 192.168.1.1/32 \
        --local-identity fqdn:ns2.swanny.test --remote-identity fqdn:ns1.swanny.test
    dataplane_start ns2

    sleep 1

    echo ">>> [transport] Starting swanny initiator in ns1..."
    swanny_start ns1 \
        --tunnel-id transport-ns1 --initiate \
        --address 192.168.1.1 --peer-address 192.168.1.2 --psk secret \
        --mode transport --local-ts 192.168.1.1/32 --remote-ts 192.168.1.2/32 \
        --local-identity fqdn:ns1.swanny.test --remote-identity fqdn:ns2.swanny.test
    dataplane_start ns1

    echo ">>> [transport] Verifying IPsec SA with ping..."
    if ! swanny_ping ns1 192.168.1.2 10 10; then
        swanny_fail "ping failed — IKE negotiation or SA installation may have failed" ns1 ns2
    fi
    echo ">>> [transport] PASS"
}
