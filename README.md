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

### Running the server

On one terminal:
```console
$ RUST_LOG=debug sudo -E ip netns exec ns1 target/debug/swanny \
    --address 192.168.1.1 --peer-address 192.168.1.2 --psk secret
```

On another terminal:
```console
$ RUST_LOG=debug sudo -E ip netns exec ns2 target/debug/swanny \
    --address 192.168.1.2 --peer-address 192.168.1.1 --psk secret
```

Ping from each other:
```console
$ sudo ip netns exec ns1 ping 192.168.1.2
$ sudo ip netns exec ns2 ping 192.168.1.1
```

### Testing against libreswan

Follow the previous steps to set up network namespaces, but flush XFRM
policies on one of them:

```console
$ sudo tests/setup-netns.sh ns1 ns2 bridge
$ sudo tests/setup-policies.sh ns1 ns2
$ sudo ip netns exec ns2 ip x p flush
```

Create an empty configuration file and secrets:

```console
$ cat ipsec.conf
$ cat ipsec.secrets
192.168.1.1 192.168.1.2 : PSK "secret"
$ mkdir run
```

On one terminal:
```console
$ RUST_LOG=debug sudo -E ip netns exec ns1 target/debug/swanny \
    --address 192.168.1.1 --peer-address 192.168.1.2 --psk secret
```

On another terminal:
```console
$ sudo ip netns exec ns2 /usr/libexec/ipsec/pluto --config ipsec.conf \
    --secretsfile ipsec.secrets --rundir run --logfile pluto.log \
    --debug=all,crypt
$ sudo ip netns exec ns2 /usr/libexec/ipsec/whack --name mytunnel --ipv4 \
    --ikev2 --encrypt --no-esn --psk --rundir run \
    --host 192.168.1.2 --id 192.168.1.2 --authby=secret --to \
    --host 192.168.1.1 --id 192.168.1.1 --authby=secret \
    --updown up --transport
```

## License

- ikev2: LGPL-2.1-or-later
- server: GPL-2.0-or-later
