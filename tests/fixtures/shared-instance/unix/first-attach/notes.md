# First Attach — UNIX Mode

- RNS version: 1.1.4
- Client attached: True
- Attach time: 0.007s
- Destination hash: `06ca5828e01e70381b4eb5ebc6f2ad60`
- Announce sent: yes

## Protocol Observations

The client connects to the shared instance data socket and immediately
begins exchanging HDLC-framed packets. There is NO handshake on the data
socket — the first bytes are HDLC frames containing RNS packets.

The client's announce is sent as an HDLC-framed RNS announce packet
through the data socket. The daemon receives it and can relay it.
