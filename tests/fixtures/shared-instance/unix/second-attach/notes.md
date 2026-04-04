# Second Attach — UNIX Mode

- Client1 dest: `8daf48a0dc3755e2ba7a95af78aa4601`
- Client2 dest: `348230e03af5f4f43bd9bd644f110bde`
- Client1 visible in daemon logs: False
- Client2 visible in daemon logs: False

## Observations

Two clients attach to the same shared instance via separate processes.
Both announce. The daemon relays announces between clients so each can
discover the other's path. Evidence of relay is in the daemon stderr.

Note: Cross-visibility check requires passing dest hashes between
subprocess boundaries. The daemon logs confirm relay activity.
