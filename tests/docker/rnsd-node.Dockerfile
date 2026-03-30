FROM python:3.12-slim-bookworm

# Ensure Python output is unbuffered so Docker captures logs immediately.
ENV PYTHONUNBUFFERED=1

RUN pip install --no-cache-dir rns

COPY rnsd-entrypoint.sh /usr/local/bin/rnsd-entrypoint.sh
RUN chmod +x /usr/local/bin/rnsd-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/rnsd-entrypoint.sh"]
