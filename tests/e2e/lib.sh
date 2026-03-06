#!/usr/bin/env bash
# Shared helpers for E2E tests.
# Expects fh_ssh() and scp_opts to be defined by the orchestrator.

swanny_fail() {
    local msg="$1"
    shift
    local namespaces=("$@")

    echo ">>> FAIL: ${msg}"
    for ns in "${namespaces[@]}"; do
        echo ">>> --- ${ns} swanny log ---"
        fh_ssh -- "cat /tmp/swanny-${ns}.log" || true
        echo ">>> --- ${ns} dataplane log ---"
        fh_ssh -- "cat /tmp/dataplane-${ns}.log" || true
        echo ">>> --- XFRM state (${ns}) ---"
        fh_ssh -- "sudo ip netns exec ${ns} ip xfrm state" || true
        echo ">>> --- XFRM policy (${ns}) ---"
        fh_ssh -- "sudo ip netns exec ${ns} ip xfrm policy" || true
    done
    exit 1
}

swanny_start() {
    local ns="$1"
    shift
    fh_ssh -- "sudo RUST_LOG=info ip netns exec ${ns} /tmp/swanny $* \
        </dev/null >/tmp/swanny-${ns}.log 2>&1 &"
}

dataplane_start() {
    local ns="$1"
    fh_ssh -- "sudo RUST_LOG=info ip netns exec ${ns} /tmp/swanny-dataplane \
        </dev/null >/tmp/dataplane-${ns}.log 2>&1 &"
}

swanny_stop() {
    fh_ssh -- "sudo killall swanny swanny-dataplane" || true
    sleep 1
}

swanny_ping() {
    local ns="$1"
    local target="$2"
    local count="${3:-5}"
    local timeout="${4:-10}"
    local source="${5:-}"

    local src_flag=""
    if [ -n "${source}" ]; then
        src_flag="-I ${source}"
    fi

    fh_ssh -- "sudo ip netns exec ${ns} ping ${src_flag} -c ${count} -W ${timeout} ${target}"
}
