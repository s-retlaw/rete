# Container-Per-Test E2E Testing

All E2E interop tests run inside isolated Docker containers.  Each test
gets its own container with a dedicated network namespace, so ports never
conflict — regardless of how many tests run in parallel or what else is
running on the host.

## Architecture

```
Host                                Docker Container (per test)
─────────────────────               ──────────────────────────────────
                                    ┌──────────────────────────────┐
 rete-linux (binary)  ──bind-mount──►  /opt/rete/rete-linux        │
 rete-shared (binary) ──bind-mount──►  /opt/rete/rete-shared       │
 tests/interop/       ──bind-mount──►  /opt/tests/                 │
                                    │                              │
                                    │  python3 /opt/tests/test.py  │
                                    │    ├─ rnsd  (port 4242)      │
                                    │    ├─ rete-linux (→ 4242)    │
                                    │    └─ py helpers             │
                                    │                              │
                                    │  Isolated network namespace  │
                                    │  → all ports are local       │
                                    └──────────────────────────────┘
```

- **No host port mapping** — all processes communicate within the container.
- **Fixed port** (4242) via `RETE_CONTAINERIZED=1` env var — the `InteropTest`
  harness detects this and overrides `default_port`.
- **Binaries pre-built on host**, bind-mounted read-only into the container.

## Running tests

```bash
# Build binaries first
cargo build -p rete-example-linux
cargo build -p rete-daemon --bin rete-shared

# Single test
cd tests/interop
uv run python container_runner.py live_interop.py
uv run python container_runner.py shared_mode/unix/announce.py

# Suites
uv run python container_runner.py --suite original      # all *_interop.py
uv run python container_runner.py --suite shared         # all shared-mode
uv run python container_runner.py --suite shared-unix    # shared-mode unix only
uv run python container_runner.py --suite shared-tcp     # shared-mode tcp only
uv run python container_runner.py --all                  # everything

# Parallel (4 containers at a time)
uv run python container_runner.py --all --parallel 4

# Custom timeout (default: 120s)
uv run python container_runner.py --timeout 180 --all

# justfile shortcuts
just test-e2e-containerized            # sequential
just test-e2e-containerized-parallel   # 4x parallel
```

## Writing a new test

1. Create your test file in `tests/interop/`, e.g. `my_feature_interop.py`.

2. Use `InteropTest` as usual — pick any port for `default_port` (it gets
   overridden inside containers, so the value only matters for host-mode):

   ```python
   from interop_helpers import InteropTest

   with InteropTest("my-feature", default_port=4242) as t:
       t.start_rnsd()
       rust = t.start_rust()
       # ... test logic ...
       t.check(condition, "description")
   ```

3. Add your test to the `ORIGINAL_TESTS` list in `container_runner.py`.

4. (Optional) Add a `just test-e2e-my-feature` recipe in `justfile`.

### Conventions

- **Don't rely on host filesystem** — use `t.tmpdir` for temp files.
- **Don't map container ports to host** — all communication is intra-container.
- **Multi-port tests are fine** — hardcoded ports like 4290, 4291, 4292 work
  inside the container since the network namespace is isolated.
- **Don't use `docker_*` prefix** — that's for legacy Docker Compose tests.
  New tests should use `InteropTest` and run via the unified container runner.

## How container detection works

When `RETE_CONTAINERIZED=1` is set:

- `InteropTest.__init__` overrides `default_port` to `4242` (unless `--port`
  was explicitly passed on the command line).
- `RETE_BINARY` env var overrides `--rust-binary` default.
- `SharedModeTest` (shared-mode tests) uses fixed ports `37428`/`37429`.

This means **existing tests need zero changes** to work inside containers.

## Docker image

The unified image (`tests/docker/e2e-unified.Dockerfile`) contains:
- Python 3.12 slim
- `rns` + `lxmf` Python packages
- `libgcc-s1` (for Rust binary)

Binaries and test scripts are bind-mounted at runtime, so the image rarely
needs rebuilding.

## Tests excluded from containers

| Test | Reason |
|------|--------|
| `esp32*` | Needs hardware serial port |
| `serial_interop.py` | Needs `/dev/ttyUSB0` |
| `local_ipc_interop.py` | Tests host Unix socket IPC specifically |
| `docker_*_interop.py` | Legacy Docker Compose tests (manage own containers) |
| `py_*_baseline.py` | Python-only baselines (no Rust binary needed) |

## Migration plan

**Current state:** All tests can run in containers via the unified runner.
Existing host-mode execution (`uv run python test.py`) still works unchanged.

**Future cleanup (deferred):**
- Remove `default_port` parameter from all `InteropTest` calls
- Remove `--port` CLI argument (dead code in container-only mode)
- Migrate `docker_*_interop.py` tests to use `InteropTest` (collapse multi-container
  topology into single-container)
- Consolidate `shared_mode/container_runner.py` into the unified runner
- Remove legacy Docker Compose files and `docker_helpers.py`
