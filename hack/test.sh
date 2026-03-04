#!/usr/bin/env bash
# E2E test: boot a FCOS VM, set up two network namespaces, run swanny in each,
# and verify IKEv2 negotiation by pinging between namespaces over IPsec.
# Uses QEMU savevm/loadvm to cache a booted VM snapshot for fast restarts.
#
# Env vars:
#   TEST_SSH_PORT      SSH port forward (default: 2223)
#   REBUILD_SNAPSHOT   Set to 1 to force snapshot recreation
#   KEEP_VM            Set to 1 to keep VM running after tests
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
work_dir="${root}/tmp/vm"
ssh_port="${TEST_SSH_PORT:-2223}"
ssh_key="${root}/hack/dev/dev_ed25519"

snapshot_disk="${work_dir}/fcos-snapshot.qcow2"
snapshot_name="ssh-ready"
snapshot_hash_file="${work_dir}/snapshot.hash"
monitor_sock="${work_dir}/qemu-monitor.sock"
pid_file="${work_dir}/qemu.pid"

fh() {
    fcos-harness --work-dir "${work_dir}" "$@"
}
fh_ssh() {
    fh ssh --ssh-key "${ssh_key}" --ssh-port "${ssh_port}" "$@"
}

scp_opts=(
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o LogLevel=ERROR
    -P "${ssh_port}"
    -i "${ssh_key}"
)

# ---------------------------------------------------------------------------
# Detect arch (needed for cross-compile target)
# ---------------------------------------------------------------------------
case "$(uname -s).$(uname -m)" in
    Linux.x86_64)   cargo_target="x86_64-unknown-linux-gnu"   ;;
    Darwin.arm64)   cargo_target="aarch64-unknown-linux-gnu"   ;;
    Linux.aarch64)  cargo_target="aarch64-unknown-linux-gnu"   ;;
    *) echo >&2 "Unsupported platform: $(uname -s).$(uname -m)"; exit 1 ;;
esac

# ---------------------------------------------------------------------------
# Build Ignition config
# ---------------------------------------------------------------------------
make -C "${root}/hack/init" config.ign
ign="${root}/hack/init/config.ign"

# ---------------------------------------------------------------------------
# Cross-compile swanny server
# ---------------------------------------------------------------------------
echo ">>> Building swanny for ${cargo_target}..."
cargo zigbuild --release --target "${cargo_target}" -p swanny-server --features vendored-openssl 2>&1

swanny_bin="${root}/target/${cargo_target}/release/swanny"
if ! [ -f "${swanny_bin}" ]; then
    echo >&2 ">>> Build failed: swanny binary not found at ${swanny_bin}"
    exit 1
fi

# ---------------------------------------------------------------------------
# Ensure FCOS base image
# ---------------------------------------------------------------------------
fh image

# ---------------------------------------------------------------------------
# Check if a valid VM snapshot exists
# ---------------------------------------------------------------------------
sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

current_hash="$(sha256 "${ign}")"
use_snapshot=false

if [ "${REBUILD_SNAPSHOT:-}" != "1" ] \
    && [ -f "${snapshot_disk}" ] \
    && [ -f "${snapshot_hash_file}" ] \
    && [ "$(cat "${snapshot_hash_file}")" = "${current_hash}" ] \
    && qemu-img snapshot -l "${snapshot_disk}" 2>/dev/null | grep -q "${snapshot_name}"; then
    use_snapshot=true
    echo ">>> Valid VM snapshot found, skipping boot+goss"
fi

# ---------------------------------------------------------------------------
# Create snapshot if needed: boot fresh, wait for SSH, goss, savevm, quit
# ---------------------------------------------------------------------------
if [ "${use_snapshot}" = false ]; then
    echo ">>> Creating VM snapshot (first run or config changed)..."
    rm -f "${snapshot_disk}" "${snapshot_hash_file}"
    fh disk --base "${work_dir}/fcos.qcow2" --overlay "${snapshot_disk}"

    fh start \
        --disk "${snapshot_disk}" \
        --ignition "${ign}" \
        --ssh-port "${ssh_port}" \
        --hostname swanny-test \
        --serial-log "${work_dir}/serial-test.log" \
        --qmp "${monitor_sock}" \
        --pid-file "${pid_file}"

    cleanup_snapshot() {
        fh stop --pid-file "${pid_file}" 2>/dev/null || true
        rm -f "${monitor_sock}"
    }
    trap cleanup_snapshot EXIT

    echo ">>> Waiting for SSH..."
    fh_ssh --wait 180 -- true

    echo ">>> Running goss validation..."
    fh goss "${root}/hack/goss.yaml" \
        --ssh-key "${ssh_key}" \
        --ssh-port "${ssh_port}" \
        --retry-timeout-secs 30

    echo ">>> Saving VM snapshot '${snapshot_name}'..."
    fh qmp --socket "${monitor_sock}" savevm "${snapshot_name}"

    echo ">>> Stopping snapshot VM..."
    fh qmp --socket "${monitor_sock}" quit
    sleep 1
    fh stop --pid-file "${pid_file}" 2>/dev/null || true
    rm -f "${monitor_sock}"
    trap - EXIT

    echo "${current_hash}" > "${snapshot_hash_file}"
    echo ">>> Snapshot created"
fi

# ---------------------------------------------------------------------------
# Boot VM from snapshot (instant restore, ephemeral writes)
# ---------------------------------------------------------------------------
echo ">>> Booting test VM from snapshot..."
fh start \
    --disk "${snapshot_disk}" \
    --ignition "${ign}" \
    --ssh-port "${ssh_port}" \
    --hostname swanny-test \
    --serial-log "${work_dir}/serial-test.log" \
    --loadvm "${snapshot_name}" \
    --pid-file "${pid_file}"

cleanup() {
    echo ">>> Shutting down test VM..."
    fh stop --pid-file "${pid_file}" 2>/dev/null || true
}
trap cleanup EXIT

echo ">>> Waiting for SSH (should be instant from snapshot)..."
fh_ssh --wait 30 -- true

# ---------------------------------------------------------------------------
# Deploy swanny binary and test scripts
# ---------------------------------------------------------------------------
echo ">>> Deploying swanny and test scripts..."
scp "${scp_opts[@]}" "${swanny_bin}" core@127.0.0.1:/tmp/swanny
scp "${scp_opts[@]}" "${root}/tests/setup-netns.sh" core@127.0.0.1:/tmp/setup-netns.sh
scp "${scp_opts[@]}" "${root}/tests/setup-tunnel-netns.sh" core@127.0.0.1:/tmp/setup-tunnel-netns.sh

fh_ssh -- "chmod +x /tmp/swanny /tmp/setup-netns.sh /tmp/setup-tunnel-netns.sh"

# ---------------------------------------------------------------------------
# Set up network namespaces
# ---------------------------------------------------------------------------
echo ">>> Setting up network namespaces..."
fh_ssh -- "sudo /tmp/setup-netns.sh ns1 ns2"

# ---------------------------------------------------------------------------
# Start swanny in both namespaces
# ---------------------------------------------------------------------------
echo ">>> Starting swanny responder in ns2..."
fh_ssh -- "sudo ip netns exec ns2 /tmp/swanny \
    --address 192.168.1.2 --peer-address 192.168.1.1 --psk secret \
    --local-ts 192.168.1.2/32 --remote-ts 192.168.1.1/32 \
    </dev/null >/tmp/swanny-ns2.log 2>&1 &"

sleep 1

echo ">>> Starting swanny initiator in ns1..."
fh_ssh -- "sudo ip netns exec ns1 /tmp/swanny \
    --address 192.168.1.1 --peer-address 192.168.1.2 --psk secret \
    --local-ts 192.168.1.1/32 --remote-ts 192.168.1.2/32 \
    </dev/null >/tmp/swanny-ns1.log 2>&1 &"

fh_ssh -- "ip -c -d a"

# ---------------------------------------------------------------------------
# Validate with ping (first packet triggers XFRM acquire + IKE negotiation,
# so we send enough packets with a long enough timeout for the SA to be
# established mid-stream)
# ---------------------------------------------------------------------------
echo ">>> Verifying IPsec SA with ping..."
if fh_ssh -- "sudo ip netns exec ns1 ping -c 10 -W 10 192.168.1.2"; then
    echo ">>> PASS: ping succeeded over IPsec"
else
    echo ">>> FAIL: ping failed — IKE negotiation or SA installation may have failed"
    echo ">>> --- ns1 swanny log ---"
    fh_ssh -- "cat /tmp/swanny-ns1.log" || true
    echo ">>> --- ns2 swanny log ---"
    fh_ssh -- "cat /tmp/swanny-ns2.log" || true
    echo ">>> --- XFRM state (ns1) ---"
    fh_ssh -- "sudo ip netns exec ns1 ip xfrm state" || true
    echo ">>> --- XFRM state (ns2) ---"
    fh_ssh -- "sudo ip netns exec ns2 ip xfrm state" || true
    exit 1
fi

# ===========================================================================
# Test 2: Tunnel mode with XFRM interfaces and subnet forwarding
# ===========================================================================
echo ">>> Stopping transport-mode swanny instances..."
fh_ssh -- "sudo killall swanny" || true
sleep 1

echo ">>> Setting up tunnel-mode network namespaces..."
fh_ssh -- "sudo /tmp/setup-tunnel-netns.sh tun1 tun2 1337"

echo ">>> Starting swanny responder in tun2 (tunnel mode)..."
fh_ssh -- "sudo ip netns exec tun2 /tmp/swanny \
    --address 192.168.1.2 --peer-address 192.168.1.1 --psk secret \
    --mode tunnel --if-id 1338 \
    --local-ts 10.0.2.0/24 --remote-ts 10.0.1.0/24 \
    </dev/null >/tmp/swanny-tun2.log 2>&1 &"

sleep 1

echo ">>> Starting swanny initiator in tun1 (tunnel mode)..."
fh_ssh -- "sudo ip netns exec tun1 /tmp/swanny \
    --address 192.168.1.1 --peer-address 192.168.1.2 --psk secret \
    --mode tunnel --if-id 1337 \
    --local-ts 10.0.1.0/24 --remote-ts 10.0.2.0/24 \
    </dev/null >/tmp/swanny-tun1.log 2>&1 &"

tunnel_fail() {
    echo ">>> FAIL: $1"
    echo ">>> --- tun1 swanny log ---"
    fh_ssh -- "cat /tmp/swanny-tun1.log" || true
    echo ">>> --- tun2 swanny log ---"
    fh_ssh -- "cat /tmp/swanny-tun2.log" || true
    echo ">>> --- XFRM state (tun1) ---"
    fh_ssh -- "sudo ip netns exec tun1 ip xfrm state" || true
    echo ">>> --- XFRM policy (tun1) ---"
    fh_ssh -- "sudo ip netns exec tun1 ip xfrm policy" || true
    echo ">>> --- XFRM state (tun2) ---"
    fh_ssh -- "sudo ip netns exec tun2 ip xfrm state" || true
    echo ">>> --- XFRM policy (tun2) ---"
    fh_ssh -- "sudo ip netns exec tun2 ip xfrm policy" || true
    exit 1
}

echo ">>> Verifying tunnel-mode IPsec SA with ping (10.0.1.1 → 10.0.2.1)..."
if ! fh_ssh -- "sudo ip netns exec tun1 ping -c 10 -W 10 10.0.2.1"; then
    tunnel_fail "ping 10.0.1.1 → 10.0.2.1 failed"
fi
echo ">>> PASS: 10.0.1.1 → 10.0.2.1"

echo ">>> Verifying cross-subnet: 10.0.1.10 → 10.0.2.10..."
if ! fh_ssh -- "sudo ip netns exec tun1 ping -I 10.0.1.10 -c 5 -W 5 10.0.2.10"; then
    tunnel_fail "ping 10.0.1.10 → 10.0.2.10 failed"
fi
echo ">>> PASS: 10.0.1.10 → 10.0.2.10"

echo ">>> Verifying cross-subnet: 10.0.1.100 → 10.0.2.100..."
if ! fh_ssh -- "sudo ip netns exec tun1 ping -I 10.0.1.100 -c 5 -W 5 10.0.2.100"; then
    tunnel_fail "ping 10.0.1.100 → 10.0.2.100 failed"
fi
echo ">>> PASS: 10.0.1.100 → 10.0.2.100"

echo ">>> Verifying reverse direction: 10.0.2.1 → 10.0.1.10..."
if ! fh_ssh -- "sudo ip netns exec tun2 ping -I 10.0.2.1 -c 5 -W 5 10.0.1.10"; then
    tunnel_fail "ping 10.0.2.1 → 10.0.1.10 failed"
fi
echo ">>> PASS: 10.0.2.1 → 10.0.1.10"

echo ">>> All E2E tests passed!"

# ---------------------------------------------------------------------------
# Keep VM running if requested
# ---------------------------------------------------------------------------
if [ "${KEEP_VM:-}" = "1" ]; then
    echo ">>> VM is still running (ssh -p ${ssh_port} core@127.0.0.1)"
    echo ">>> Press Ctrl-C to stop..."
    trap cleanup INT
    wait "$(cat "${pid_file}")"
fi
