FROM python:3.12-slim-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends libgcc-s1 \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir rns lxmf

# rete-shared binary is bind-mounted at /opt/rete/rete-shared at runtime.
# Test scripts are bind-mounted at /opt/tests/ at runtime.
WORKDIR /opt/tests
ENTRYPOINT ["python3"]
