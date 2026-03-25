FROM python:3.12-slim-bookworm

RUN pip install --no-cache-dir rns lxmf

# Test scripts are bind-mounted at /opt/tests/ at runtime
WORKDIR /opt/tests
ENTRYPOINT ["python3"]
