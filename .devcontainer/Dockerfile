FROM mcr.microsoft.com/devcontainers/rust:1

# Install just (command runner) — system-wide
RUN curl -sSf https://just.systems/install.sh | bash -s -- --to /usr/local/bin

# Switch to vscode user for remaining installs
USER vscode

# Install uv (Python package manager) — into ~/.local/bin
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/home/vscode/.local/bin:${PATH}"
