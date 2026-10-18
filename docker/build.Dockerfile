# Build environment: Rust + cross-compilation for Windows (MSVC ABI) via cargo-xwin.
FROM rust:1-bookworm
RUN apt-get update \
 && apt-get install -y --no-install-recommends clang lld llvm \
 && rm -rf /var/lib/apt/lists/*
RUN rustup target add x86_64-pc-windows-msvc \
 && cargo install --locked cargo-xwin
ENV CARGO_TARGET_DIR=/target \
    XWIN_CACHE_DIR=/xwin-cache
WORKDIR /src
