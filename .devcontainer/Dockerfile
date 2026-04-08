FROM mcr.microsoft.com/devcontainers/rust:1

# System packages needed for ESP development and espflash
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       pkg-config libudev-dev libssl-dev unzip \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install just (command runner) — system-wide
RUN curl -sSf https://just.systems/install.sh | bash -s -- --to /usr/local/bin

# Add vscode user to dialout group for serial port access (ESP32 flashing)
RUN usermod -aG dialout vscode

# Switch to vscode user for remaining installs
USER vscode
ENV PATH="/home/vscode/.cargo/bin:/home/vscode/.local/bin:/usr/local/share/nvm/current/bin:${PATH}"

# Install uv (Python package manager)
RUN curl -LsSf https://astral.sh/uv/install.sh | sh

# Install espup and set up ESP32 toolchains (C3, C6, S3)
# - RISC-V targets (C3, C6) use standard stable Rust
# - Xtensa target (S3) uses the Espressif Rust fork (channel "esp")
RUN mkdir -p "$HOME/.cargo/bin" \
    && curl -L "https://github.com/esp-rs/espup/releases/latest/download/espup-x86_64-unknown-linux-gnu" \
       -o "$HOME/.cargo/bin/espup" \
    && chmod +x "$HOME/.cargo/bin/espup" \
    && espup install --targets esp32c3,esp32c6,esp32s3 \
       --export-file /home/vscode/export-esp.sh

# Source ESP environment in all shells
RUN echo '. $HOME/export-esp.sh' >> ~/.bashrc

# Ensure RISC-V targets and rust-src are on stable toolchain
RUN . /home/vscode/export-esp.sh \
    && rustup target add riscv32imc-unknown-none-elf --toolchain stable \
    && rustup target add riscv32imac-unknown-none-elf --toolchain stable \
    && rustup component add rust-src --toolchain stable

# Install nightly toolchain with RISC-V targets (needed for build-std on ESP32-C3/C6)
RUN rustup toolchain install nightly \
    && rustup target add riscv32imc-unknown-none-elf --toolchain nightly \
    && rustup target add riscv32imac-unknown-none-elf --toolchain nightly \
    && rustup component add rust-src --toolchain nightly

# Install espflash (pre-compiled binary — much faster than cargo install)
RUN curl -L "https://github.com/esp-rs/espflash/releases/latest/download/espflash-x86_64-unknown-linux-gnu.zip" \
      -o /tmp/espflash.zip \
    && unzip /tmp/espflash.zip -d "$HOME/.cargo/bin/" \
    && chmod +x "$HOME/.cargo/bin/espflash" \
    && rm /tmp/espflash.zip

# Install rust-analyzer LSP server (works with any editor — nvim, VS Code, etc.)
RUN curl -L "https://github.com/rust-lang/rust-analyzer/releases/latest/download/rust-analyzer-x86_64-unknown-linux-gnu.gz" \
      | gunzip > "$HOME/.cargo/bin/rust-analyzer" \
    && chmod +x "$HOME/.cargo/bin/rust-analyzer"
