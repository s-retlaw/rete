# Cutover Checklist: Python rnsd → Rust rete --shared-instance

This checklist guides operators through replacing Python `rnsd` with the Rust
`rete --shared-instance` daemon as the system shared instance.

## Pre-cutover

- [ ] Verify `rete --shared-instance` binary is built and accessible
  ```bash
  rete --help
  ```
- [ ] Note current rnsd config (instance type, ports, transport mode)
  ```bash
  cat ~/.reticulum/config
  ```
- [ ] Prepare rete --shared-instance data directory (default: `~/.rete`)
  ```bash
  mkdir -p ~/.rete
  ```
- [ ] If using TCP mode, note the data port and control port numbers
- [ ] Back up Python rnsd identity file (optional, for rollback)
  ```bash
  cp ~/.reticulum/storage/transport_identity ~/.reticulum/storage/transport_identity.bak
  ```

## Cutover Steps

1. **Stop Python rnsd**
   ```bash
   # If running as systemd service:
   sudo systemctl stop rnsd

   # If running in foreground:
   kill $(pgrep -f "rnsd")
   ```

2. **Wait for socket release** (1-2 seconds for Unix, 3-5 seconds for TCP)
   ```bash
   sleep 2
   ```

3. **Start Rust daemon**

   Unix mode (default):
   ```bash
   rete --shared-instance --transport
   ```

   TCP mode:
   ```bash
   rete --shared-instance --shared-instance-type tcp \
               --shared-instance-port 37428 \
               --instance-control-port 37429 \
               --transport
   ```

   Custom data directory:
   ```bash
   rete --shared-instance --data-dir /path/to/data --transport
   ```

4. **Verify daemon is running**
   ```bash
   # Check process
   pgrep -f "rete --shared-instance"

   # Check with rnstatus (stock Python tool)
   rnstatus
   ```

## Post-cutover Verification

- [ ] `rnstatus` shows connected interface with status=True
- [ ] Existing clients reconnect automatically (may take a few seconds)
- [ ] Announces from clients are visible via `rnstatus`
- [ ] `rnpath <destination_hash>` resolves known paths
- [ ] Monitor daemon logs for errors:
  ```bash
  # stderr contains tracing output
  journalctl -u rete -f   # if using systemd
  ```

## Known Differences

- Identity files are NOT shared between Python rnsd and Rust rete --shared-instance.
  Each daemon generates its own identity on first start.
- Snapshot/state file formats differ. Each daemon starts with a fresh
  routing table after cutover (paths will be re-learned from announces).
- The Rust daemon uses `~/.rete` by default (not `~/.reticulum`).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| "bind error" on start | Previous daemon still running or socket in TIME_WAIT | Wait longer, or check `ss -tlnp` |
| Clients don't reconnect | Wrong instance name or port | Verify config matches previous rnsd |
| `rnstatus` auth fails | Different identity = different authkey | Copy transport_identity or set `rpc_key` |
