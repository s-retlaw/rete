FROM python:3.12-slim-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends libgcc-s1 \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir rns lxmf

# Binaries are bind-mounted at runtime:
#   /opt/rete/rete-linux    (original interop tests)
#   /opt/rete/rete-shared   (shared-mode tests)
# Test scripts are bind-mounted at /opt/tests/ at runtime.
WORKDIR /opt/tests
ENTRYPOINT ["python3"]
