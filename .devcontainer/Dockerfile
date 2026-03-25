FROM mcr.microsoft.com/devcontainers/rust:1

# Install just (command runner)
RUN curl -sSf https://just.systems/install.sh | bash -s -- --to /usr/local/bin

# Install uv (Python package manager)
RUN curl -LsSf https://astral.sh/uv/install.sh | sh \
    && mv /root/.local/bin/uv /usr/local/bin/uv \
    && mv /root/.local/bin/uvx /usr/local/bin/uvx
