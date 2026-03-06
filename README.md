# swanny

An experimental IKEv2 (RFC 7296) implementation in Rust with a split
dataplane architecture: the IKE server handles protocol negotiation while
a separate daemon manages Linux XFRM kernel IPsec.

## Crates

| Crate | Binary | Description | License |
|---|---|---|---|
| `ikev2` | — | Protocol library: parsing, crypto, SA state machine | LGPL-2.1-or-later |
| `server` | `swanny` | Async IKEv2 server (Tokio, clap, gRPC control plane) | GPL-3.0-or-later |
| `dataplane-linux` | `swanny-dataplane` | XFRM netlink daemon, connects to `swanny` via gRPC | GPL-3.0-or-later |
| `proto` | — | Protobuf/tonic definitions shared between server and dataplane | — |

## Building

```console
$ cargo build
```

The server and dataplane require Linux. For cross-compilation (e.g. from
macOS):

```console
$ cargo zigbuild --release --target aarch64-unknown-linux-gnu \
    -p swanny-server --features vendored-openssl \
    -p swanny-dataplane-linux
```

## Usage

### Transport mode

Set up two network namespaces connected by a veth pair:

```console
$ sudo tests/setup-netns.sh ns1 ns2 bridge
```

```
                          bridge
                      192.168.1.0/24
       +------------------------------------------+
       |                                          |
      ns1                                        ns2
  192.168.1.1                                192.168.1.2
```

Start the dataplane daemon in each namespace, then the IKE server:

```console
# ns1 (responder)
$ sudo ip netns exec ns1 swanny-dataplane &
$ RUST_LOG=info sudo -E ip netns exec ns1 swanny \
    --address 192.168.1.1 --peer-address 192.168.1.2 \
    --psk secret --tunnel-id test --mode transport

# ns2 (initiator)
$ sudo ip netns exec ns2 swanny-dataplane --grpc-connect [::1]:50052 &
$ RUST_LOG=info sudo -E ip netns exec ns2 swanny \
    --address 192.168.1.2 --peer-address 192.168.1.1 \
    --psk secret --tunnel-id test --mode transport \
    --grpc-listen [::1]:50052 --initiate
```

Verify with ping:

```console
$ sudo ip netns exec ns1 ping 192.168.1.2
```

### Tunnel mode (default)

Set up namespaces with XFRM interfaces for subnet-to-subnet forwarding:

```console
$ sudo tests/setup-tunnel-netns.sh ns1 ns2 <IF_ID1> <IF_ID2>
```

```
  ns1: 10.0.1.0/24 on xfrm0 ──┐
       192.168.1.1/24 on veth   ├─ veth pair (underlay)
  ns2: 10.0.2.0/24 on xfrm0 ──┘
       192.168.1.2/24 on veth
```

Start with `--local-ts` and `--remote-ts` to specify protected subnets:

```console
# ns1 (responder)
$ sudo ip netns exec ns1 swanny-dataplane &
$ RUST_LOG=info sudo -E ip netns exec ns1 swanny \
    --address 192.168.1.1 --peer-address 192.168.1.2 \
    --psk secret --tunnel-id test \
    --local-ts 10.0.1.0/24 --remote-ts 10.0.2.0/24

# ns2 (initiator)
$ sudo ip netns exec ns2 swanny-dataplane --grpc-connect [::1]:50052 &
$ RUST_LOG=info sudo -E ip netns exec ns2 swanny \
    --address 192.168.1.2 --peer-address 192.168.1.1 \
    --psk secret --tunnel-id test \
    --local-ts 10.0.2.0/24 --remote-ts 10.0.1.0/24 \
    --grpc-listen [::1]:50052 --initiate
```

### CLI options

| Flag | Description |
|---|---|
| `--address` | Local IP address (required) |
| `--peer-address` | Remote peer IP address (required) |
| `--psk` | Pre-shared key (required) |
| `--tunnel-id` | Tunnel identifier (required) |
| `--mode` | `tunnel` (default) or `transport` |
| `--local-ts` | Local traffic selector CIDR (repeatable) |
| `--remote-ts` | Remote traffic selector CIDR (repeatable) |
| `--initiate` | Auto-initiate IKE negotiation on startup |
| `--grpc-listen` | gRPC listen address (default: `[::1]:50051`) |
| `--expires` | Child SA lifetime in seconds |
| `--ike-lifetime` | IKE SA lifetime in seconds (triggers rekey) |
| `--dpd-interval` | Dead Peer Detection interval in seconds |
| `--local-identity` | Local IKE identity (e.g. `fqdn:vpn.example.com`) |
| `--remote-identity` | Expected remote peer identity for validation |
| `--strict-ts` | Require exact traffic selector match |
| `-c`, `--config` | Path to TOML configuration file |

## Testing

### Unit tests

```console
$ cargo test                           # all crates
$ cargo test -p swanny-ikev2           # ikev2 only
$ cargo test -p swanny-ikev2 test_name # single test
$ cargo clippy --all-targets           # lint
```

### E2E tests

The E2E suite boots a Fedora CoreOS VM via QEMU, deploys the binaries,
and runs test scenarios across network namespaces:

```console
$ hack/test.sh
```

Test scenarios:

- **transport** — point-to-point IPsec over a veth pair
- **tunnel** — XFRM interfaces with subnet-to-subnet forwarding
- **ike-rekey** — IKE SA rekeying
- **multi-sa** — multiple child SAs with INITIAL_CONTACT teardown
- **interop** — bidirectional interop with strongSwan (swanny as initiator and responder)

## License

- **ikev2**: LGPL-2.1-or-later
- **server**: GPL-3.0-or-later
- **dataplane-linux**: GPL-3.0-or-later
