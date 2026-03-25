FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libgcc-s1 \
    && rm -rf /var/lib/apt/lists/*

# Binary is bind-mounted at /opt/rete/rete-linux at runtime
ENTRYPOINT ["/opt/rete/rete-linux"]
