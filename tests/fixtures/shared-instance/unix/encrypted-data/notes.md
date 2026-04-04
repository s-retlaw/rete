# Encrypted Data — UNIX Mode

- RNS version: 1.1.4
- Receiver dest: `d39cf3d9dc8d57862c81e3ca6d04d3bb`
- Path found by sender: False
- Identity recalled: False
- Send success: False
- Packets received: 0

## Observations

The receiver creates a SINGLE destination (which requires encryption for
incoming data), announces it, and sets a packet callback. The sender
discovers the receiver's path and identity via the announce, then sends
an encrypted packet to it.

The daemon acts as a transparent relay — it never decrypts the packet.
It forwards the HDLC-framed RNS packet between the two locally-attached
clients. The encrypted payload is opaque to the shared instance.

This proves the data plane works for encrypted traffic through the shared
instance without any decryption or inspection by the daemon.
