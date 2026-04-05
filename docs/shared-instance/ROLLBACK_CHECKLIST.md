# Rollback Checklist: Rust rete-shared → Python rnsd

This checklist guides operators through reverting from the Rust `rete-shared`
daemon back to Python `rnsd`.

## Pre-rollback

- [ ] Verify Python RNS is still installed
  ```bash
  python3 -c "import RNS; print(RNS.__version__)"
  ```
- [ ] Note current rete-shared config (instance type, ports)
- [ ] Verify rnsd config still exists
  ```bash
  cat ~/.reticulum/config
  ```

## Rollback Steps

1. **Stop Rust daemon**
   ```bash
   # If running as systemd service:
   sudo systemctl stop rete-shared

   # If running in foreground:
   kill $(pgrep rete-shared)
   ```

2. **Wait for socket release** (1-2 seconds for Unix, 3-5 seconds for TCP)
   ```bash
   sleep 2
   ```

3. **Start Python rnsd**
   ```bash
   # As systemd service:
   sudo systemctl start rnsd

   # In foreground:
   rnsd
   ```

4. **Verify rnsd is running**
   ```bash
   rnstatus
   ```

## Post-rollback Verification

- [ ] `rnstatus` shows connected interface
- [ ] Clients reconnect automatically
- [ ] Announces propagate normally
- [ ] Path resolution works via `rnpath`

## Notes

- Python rnsd will generate a fresh routing table. Previously learned
  paths will be re-discovered via announces.
- If the backed-up transport_identity was restored, `rnstatus` auth
  will work with existing client configs.
- The Rust daemon's data directory (`~/.rete`) can be safely removed
  after successful rollback if no longer needed.
