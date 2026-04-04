# Client Reconnect — UNIX Mode

- RNS version: 1.1.4
- Phase A: attached=True, dest=`c6228c7ba88fe46cf8cbf3c20c12fd51`
- Phase B: reattached=True, new_dest=`00c38eb5b2bc8208afbbf6ed62ce186d`, path_survived=False

## Observations

Phase A attaches a client, announces, then exits without calling exit_handler()
(simulating a crash). Phase B creates a new RNS instance using the same
configdir (which persists the identity to storage/). Phase B re-announces
and checks if the original destination's path is still known.

Key questions answered:
- Does the daemon allow re-registration after unclean disconnect?
- Does the daemon's path table retain the old destination path?
- What log messages does the daemon emit on disconnect + reconnect?
