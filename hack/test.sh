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

    echo ">>> Waiting for strongswan install..."
    fh_ssh -- "sudo systemctl start rpm-ostree-install-strongswan.service"

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
# Source test helpers and test scripts
# ---------------------------------------------------------------------------
source "${root}/tests/e2e/lib.sh"
source "${root}/tests/e2e/transport.sh"
source "${root}/tests/e2e/tunnel.sh"
source "${root}/tests/e2e/ike-rekey.sh"
source "${root}/tests/e2e/interop.sh"

# ---------------------------------------------------------------------------
# Deploy swanny binary and test scripts
# ---------------------------------------------------------------------------
echo ">>> Deploying swanny and test scripts..."
scp "${scp_opts[@]}" "${swanny_bin}" core@127.0.0.1:/tmp/swanny
scp "${scp_opts[@]}" "${root}/tests/setup-netns.sh" core@127.0.0.1:/tmp/setup-netns.sh
scp "${scp_opts[@]}" "${root}/tests/setup-tunnel-netns.sh" core@127.0.0.1:/tmp/setup-tunnel-netns.sh

fh_ssh -- "chmod +x /tmp/swanny /tmp/setup-netns.sh /tmp/setup-tunnel-netns.sh"

# ---------------------------------------------------------------------------
# Run tests
# ---------------------------------------------------------------------------
test_transport
test_tunnel
test_ike_rekey
test_interop_swanny_initiator
test_interop_strongswan_initiator

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
