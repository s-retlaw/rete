# Second Attach — TCP Mode

- Client1 dest: `4ee04dd50b59bcfcea58af9e46422d36`
- Client2 dest: `fa875e3490b1735399bf0583236632ac`
- Client1 visible in daemon logs: False
- Client2 visible in daemon logs: False

## Observations

Two clients attach to the same shared instance via separate processes.
Both announce. The daemon relays announces between clients so each can
discover the other's path. Evidence of relay is in the daemon stderr.

Note: Cross-visibility check requires passing dest hashes between
subprocess boundaries. The daemon logs confirm relay activity.
