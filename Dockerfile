# Solana C Validator Dockerfile
#
# Multi-stage build for the Solana C validator
#
# Build:
#   docker build -t solana-c-validator .
#
# Run:
#   docker run -d --name validator \
#     -v ./ledger:/ledger \
#     -v ./config:/config \
#     -p 8899:8899 -p 8001:8001 -p 8003:8003 -p 8004:8004 \
#     solana-c-validator

# ==== Build Stage ====
FROM ubuntu:22.04 AS builder

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    pkg-config \
    git \
    curl \
    libsodium-dev \
    libssl-dev \
    libzstd-dev \
    liblz4-dev \
    librocksdb-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Rust for quiche build
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Build quiche from source
WORKDIR /tmp
RUN git clone --branch 0.22.0 --depth 1 https://github.com/cloudflare/quiche.git && \
    cd quiche && \
    cargo build --release --features ffi && \
    mkdir -p /usr/local/lib /usr/local/include && \
    cp target/release/libquiche.so /usr/local/lib/ 2>/dev/null || \
    cp target/release/libquiche.a /usr/local/lib/ && \
    cp quiche/include/quiche.h /usr/local/include/ && \
    ldconfig && \
    cd / && rm -rf /tmp/quiche

# Copy source code
WORKDIR /src
COPY . .

# Build validator
RUN mkdir build && cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release \
          -DCMAKE_PREFIX_PATH=/usr/local \
          .. && \
    make -j$(nproc)

# ==== Runtime Stage ====
FROM ubuntu:22.04 AS runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libsodium23 \
    libssl3 \
    libzstd1 \
    liblz4-1 \
    librocksdb7.3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy quiche library
COPY --from=builder /usr/local/lib/libquiche* /usr/local/lib/
RUN ldconfig

# Copy built binaries
COPY --from=builder /src/build/bin/solana-validator /usr/local/bin/
COPY --from=builder /src/build/bin/sol-keygen /usr/local/bin/
COPY --from=builder /src/build/bin/sol-vote /usr/local/bin/

# Create directories
RUN mkdir -p /ledger /config /data

# Create non-root user
RUN useradd -r -s /bin/false validator && \
    chown -R validator:validator /ledger /config /data

# Volume mounts
VOLUME ["/ledger", "/config", "/data"]

# Expose ports
# 8899: RPC
# 8001: Gossip
# 8003: TPU
# 8004: TVU
# 9090: Prometheus metrics
EXPOSE 8899 8001 8003 8004 9090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -sf http://localhost:8899/health || exit 1

# Run as non-root user
USER validator
WORKDIR /data

# Default command
ENTRYPOINT ["solana-validator"]
CMD ["--ledger", "/ledger", "--rpc-bind", "0.0.0.0", "--rpc-port", "8899"]
