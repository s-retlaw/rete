# Announce Propagation — UNIX Mode

- RNS version: 1.1.4
- Announcer dest: `f7e127bceab497e3fedc8e5b85162e16`
- Listener dest: `334f494f1714b901f4f8d3664483582b`
- Listener sees announcer: False (after 15 poll iterations)

## Observations

Client A attaches and announces its destination. Client B attaches
separately (different subprocess, different RNS instance) and polls
`Transport.has_path()` to check if it can discover Client A's destination
through the shared instance.

This is the core shared-instance relay test: the daemon must forward
Client A's announce to Client B so that Client B's transport table
learns the path. If `sees_announcer` is True, the daemon is correctly
relaying announces between locally-attached clients.
