# swanny

This is an experimental (and incomplete) implementation of IKEv2 in
Rust, developed for learning purposes.

## Building

```console
$ cargo build
```

## Testing

```console
$ sudo tests/setup-netns.sh ns1 ns2
$ sudo tests/setup-policies.sh ns1 ns2
```

On one terminal:
```console
$ RUST_LOG=debug sudo -E ip netns exec ns1 target/debug/swannyd --address 192.168.1.1 --peer-address 192.168.1.2 --psk secret
```

On another terminal:
```console
$ RUST_LOG=debug sudo -E ip netns exec ns2 target/debug/swannyd --address 192.168.1.2 --peer-address 192.168.1.1 --psk secret
```

Ping from each other:
```console
$ sudo ip netns exec ns1 ping 192.168.1.2
$ sudo ip netns exec ns2 ping 192.168.1.1
```

## License

- ikev2: LGPL-2.1-or-later
- swannyd: GPL-2.0-or-later
