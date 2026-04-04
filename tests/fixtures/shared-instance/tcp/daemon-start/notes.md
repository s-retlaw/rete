# Daemon Start — TCP Mode

- RNS version: 1.1.4
- Data port: 47428
- Control port: 47429
- Data port bound: True
- Control port bound: True
- Readiness: 4.00s

## Observations

In TCP mode, daemon binds two TCP listeners on 127.0.0.1.
Data port accepts HDLC-framed connections.
Control port accepts `multiprocessing.connection` with HMAC auth.
