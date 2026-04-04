# Daemon Start — Unix Mode

- RNS version: 1.1.4
- Instance name: default
- Data socket: `\0rns/default` (abstract namespace)
- RPC socket: `\0rns/default/rpc` (abstract namespace)
- Data socket bound: True
- RPC socket bound: True
- Readiness: 4.00s
- Daemon alive at check: True

## Observations

Daemon binds both sockets on startup. The data socket accepts
HDLC-framed connections. The RPC socket accepts
`multiprocessing.connection` connections with HMAC auth.
