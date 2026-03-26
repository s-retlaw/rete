FROM python:3.12-slim-bookworm

RUN pip install --no-cache-dir rns

COPY rnsd-entrypoint.sh /usr/local/bin/rnsd-entrypoint.sh
RUN chmod +x /usr/local/bin/rnsd-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/rnsd-entrypoint.sh"]
