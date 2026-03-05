#!/usr/bin/env bash
# strongSwan interop E2E test (transport mode).
# Tests both directions: swanny→strongSwan and strongSwan→swanny.
# Expects lib.sh to be sourced and fh_ssh/scp_opts available.

strongswan_start() {
    local conf="$1"

    # Deploy config before starting
    scp "${scp_opts[@]}" "${conf}" core@127.0.0.1:/tmp/swanny-interop.conf
    fh_ssh -- "sudo mkdir -p /etc/strongswan/swanctl/conf.d && \
        sudo cp /tmp/swanny-interop.conf /etc/strongswan/swanctl/conf.d/swanny.conf"

    # Enable verbose charon-systemd logging to journal
    fh_ssh -- "sudo tee /etc/strongswan/strongswan.d/zz-logging.conf > /dev/null" <<'LOGGING'
charon-systemd {
    journal {
        default = 2
        ike = 4
        cfg = 3
        knl = 3
        net = 3
        enc = 4
        esp = 3
        lib = 2
        mgr = 2
        tls = 4
    }
}
LOGGING

    # Grab journalctl cursor before starting so we can dump logs later
    strongswan_journal_cursor=$(fh_ssh -- "journalctl -u strongswan -n 0 --show-cursor 2>/dev/null \
        | sed -n 's/^-- cursor: //p'")

    fh_ssh -- "sudo systemctl start strongswan"
    sleep 2

    # Load connections and secrets
    fh_ssh -- "sudo swanctl --load-all 2>&1"
}

strongswan_dump_logs() {
    echo ">>> --- strongSwan journal ---"
    if [ -n "${strongswan_journal_cursor:-}" ]; then
        fh_ssh -- "journalctl -u strongswan --after-cursor='${strongswan_journal_cursor}' --no-pager" || true
    else
        fh_ssh -- "journalctl -u strongswan -n 50 --no-pager" || true
    fi
}

strongswan_stop() {
    fh_ssh -- "sudo systemctl stop strongswan" || true
    fh_ssh -- "sudo rm -f /etc/strongswan/swanctl/conf.d/swanny.conf \
        /etc/strongswan/strongswan.d/zz-logging.conf" || true
    sleep 1
}

strongswan_initiate() {
    fh_ssh -- "sudo swanctl --initiate --child swanny 2>&1"
}

# Set up a veth pair with one end in a namespace (for swanny) and the
# other in the default namespace (for strongSwan).
interop_setup_netns() {
    local ns="$1"
    local ns_addr="$2"
    local host_addr="$3"

    fh_ssh -- "sudo ip netns add ${ns} && \
        sudo ip link add ${ns}-veth type veth peer ss-veth && \
        sudo ip link set ${ns}-veth netns ${ns} && \
        sudo ip netns exec ${ns} ip addr add ${ns_addr}/24 dev ${ns}-veth && \
        sudo ip netns exec ${ns} ip link set ${ns}-veth up && \
        sudo ip netns exec ${ns} ip link set lo up && \
        sudo ip addr add ${host_addr}/24 dev ss-veth && \
        sudo ip link set ss-veth up"
}

interop_cleanup_netns() {
    local ns="$1"
    fh_ssh -- "sudo ip netns del ${ns}" || true
}

test_interop_swanny_initiator() {
    echo ">>> [interop] Setting up network..."
    interop_setup_netns sw1 192.168.1.1 192.168.1.2

    echo ">>> [interop] Starting strongSwan responder..."
    strongswan_start "${root}/tests/e2e/strongswan-responder.conf"

    echo ">>> [interop] Starting swanny initiator in sw1..."
    swanny_start sw1 \
        --address 192.168.1.1 --peer-address 192.168.1.2 --psk secret \
        --mode transport --local-ts 192.168.1.1/32 --remote-ts 192.168.1.2/32 \
        --local-identity keyid:swannywashere --remote-identity ipv4:192.168.1.2

    echo ">>> [interop] Verifying IPsec SA with ping..."
    if ! swanny_ping sw1 192.168.1.2 10 10; then
        echo ">>> --- strongSwan status ---"
        fh_ssh -- "sudo swanctl --list-sas" || true
        strongswan_dump_logs
        swanny_fail "ping failed — swanny→strongSwan negotiation failed" sw1
    fi
    echo ">>> [interop] PASS: swanny initiator → strongSwan responder"

    strongswan_dump_logs

    echo ">>> [interop] Cleaning up..."
    swanny_stop
    strongswan_stop
    interop_cleanup_netns sw1
}

test_interop_strongswan_initiator() {
    echo ">>> [interop] Setting up network..."
    interop_setup_netns sw2 192.168.1.2 192.168.1.1

    echo ">>> [interop] Starting swanny responder in sw2..."
    swanny_start sw2 \
        --address 192.168.1.2 --peer-address 192.168.1.1 --psk secret \
        --mode transport --local-ts 192.168.1.2/32 --remote-ts 192.168.1.1/32 \
        --local-identity keyid:swannywashere --remote-identity ipv4:192.168.1.1

    sleep 1

    echo ">>> [interop] Starting strongSwan initiator..."
    strongswan_start "${root}/tests/e2e/strongswan-initiator.conf"
    strongswan_initiate

    echo ">>> [interop] Verifying IPsec SA with ping..."
    if ! swanny_ping sw2 192.168.1.1 10 10; then
        echo ">>> --- strongSwan status ---"
        fh_ssh -- "sudo swanctl --list-sas" || true
        swanny_fail "ping failed — strongSwan→swanny negotiation failed" sw2
    fi
    echo ">>> [interop] PASS: strongSwan initiator → swanny responder"

    echo ">>> [interop] Cleaning up..."
    swanny_stop
    strongswan_stop
    interop_cleanup_netns sw2
}
