# swanny

This is an experimental (and incomplete) implementation of IKEv2 in
Rust, developed for learning purposes.

## Building

```console
$ cargo build
```

## Testing

### Setting up a network with network namespaces

```console
$ sudo tests/setup-netns.sh ns1 ns2 bridge
```

This will create a network topology like:

```
                          bridge
                      192.168.1.0/24
       +------------------------------------------+
       |                                          |
      ns1                                        ns2
  192.168.1.1                                192.168.1.2
```

### Installing XFRM policies

```console
$ sudo tests/setup-policies.sh ns1 ns2
```

This will install policies to require protection of ICMP traffic
between ns1 and ns2.

### Running the IKEv2 server

On one terminal:
```console
$ RUST_LOG=debug sudo -E ip netns exec ns1 target/debug/swanny --address 192.168.1.1 --peer-address 192.168.1.2 --psk secret
```

On another terminal:
```console
$ RUST_LOG=debug sudo -E ip netns exec ns2 target/debug/swanny --address 192.168.1.2 --peer-address 192.168.1.1 --psk secret
```

Ping from each other:
```console
$ sudo ip netns exec ns1 ping 192.168.1.2
$ sudo ip netns exec ns2 ping 192.168.1.1
```

## License

- ikev2: LGPL-2.1-or-later
- server: GPL-2.0-or-later
