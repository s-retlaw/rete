# Containerized Shared-Mode E2E Testing

## Why Containers

Each shared-mode E2E test runs inside its own Docker container. This gives
each test an isolated network namespace — ports never conflict, Unix abstract
sockets don't collide, and tests can run in parallel safely.

## Prerequisites

- Docker available in the dev environment (devcontainer has Docker-in-Docker)
- `cargo build -p rete-daemon --bin rete-shared`
- Docker image: built automatically by `container_runner.py`

## Running Tests

```bash
cd tests/interop

# Single test
uv run python shared_mode/container_runner.py unix/announce.py

# All Unix tests
uv run python shared_mode/container_runner.py --suite unix

# All TCP tests
uv run python shared_mode/container_runner.py --suite tcp

# All 20 tests
uv run python shared_mode/container_runner.py --all

# Custom binary path
uv run python shared_mode/container_runner.py --rust-binary path/to/rete-shared unix/data.py
```

## Dockerfile

`tests/docker/shared-mode-e2e.Dockerfile` — Python 3.12-slim with `rns`, `lxmf`,
and `libgcc-s1` (for the Rust binary). The `rete-shared` binary and test scripts
are bind-mounted at runtime, not baked into the image.

## Writing a New Test

1. Create `tests/interop/shared_mode/{unix,tcp}/my_test.py`
2. Import helpers from `shared_mode_helpers.py`
3. Use `SharedModeTest` for lifecycle management
4. Use `tcp_ports()` for TCP tests (returns fixed ports inside containers)
5. Use `wait_for_ready_file()` to coordinate receiver→sender startup
6. Add the test to `container_runner.py`'s test list

### Test topology

```
[Daemon (rete-shared)]
   ├── Client A (receiver/server) — subprocess
   └── Client B (sender/client)   — subprocess
```

Both clients connect to the daemon via shared instance (Unix or TCP).
The daemon relays packets between them.

### Key patterns

- **Transport mode**: All protocol tests need `transport=True` on the daemon
- **Ready file**: Receiver writes `ready.json` with `dest_hash` after announcing
- **Identity sharing**: `make_client_dir()` copies daemon's identity to
  `client/storage/transport_identity` so RPC auth matches
- **LXMF sender warmup**: LXMF sender script sleeps 5s after connecting to
  allow BackboneInterface epoll thread to initialize

## TCP Port Conventions

Inside containers, `tcp_ports()` returns fixed ports:
- Data: 37428
- Control: 37429

On the host (backward compat), PID-offset ports are used.

## Refactoring Existing Tests

When refactoring pre-container tests to use containers:
1. Replace PID-offset port logic with `tcp_ports()`
2. Wrap with `container_runner.py` invocation
3. No other changes needed — test scripts run identically inside containers
