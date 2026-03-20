# build stage
FROM --platform=$BUILDPLATFORM rust:latest AS builder

WORKDIR /usr/src/snp-guard

# Install build dependencies
RUN apt-get update && apt-get install -y \
    protobuf-compiler \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy all source files
COPY . .

# Update Cargo.lock for compatibility
RUN cargo update

# Install MUSL target for static linking
RUN rustup target add x86_64-unknown-linux-musl

# Build the server binary
RUN cargo build --release --bin snpguard-server

# Build snpguest tool (dynamic linking for now)
RUN cd snpguest && cargo build --release

# Build migration tool
RUN cargo build --release -p migration

# final stage
FROM debian:testing-slim

# Install ca-certificates for HTTPS requests and curl for health checks
RUN apt-get update && apt-get install -y ca-certificates curl && rm -rf /var/lib/apt/lists/*

# Copy server binary
COPY --from=builder /usr/src/snp-guard/target/release/snpguard-server /usr/local/bin/

# Copy snpguest binary
COPY --from=builder /usr/src/snp-guard/snpguest/target/release/snpguest /usr/local/bin/

# Copy migration binary
COPY --from=builder /usr/src/snp-guard/target/release/migration /usr/local/bin/

# Copy UI templates and static files to the working directory structure expected by the server
COPY --from=builder /usr/src/snp-guard/src/server/templates /app/templates
COPY --from=builder /usr/src/snp-guard/ui/static /app/ui/static

# Set working directory to match expected paths
WORKDIR /app

# Environment variables
ENV RUST_LOG=info
ENV DATA_DIR=/data
# Set NO_TLS=1 (default) for PaaS / containerized deployments where TLS is
# terminated by the platform (fly.io, Railway, Render, etc.).
# Override with NO_TLS= (empty) to enable self-managed TLS inside the container.
ENV NO_TLS=1

# Create data directory
RUN mkdir -p /data

# persistent volume mount point
VOLUME /data

# Run database migration on startup, then start the server
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD curl -f http://localhost:3000/ || exit 1

# Run migration first, then start the server.
# Pass --no-tls when NO_TLS is non-empty (the default for PaaS deployments).
ENTRYPOINT ["/bin/sh", "-c", "cd /app && DATA_DIR=${DATA_DIR:-/data} && mkdir -p ${DATA_DIR}/db && /usr/local/bin/migration up -u sqlite://${DATA_DIR}/db/snpguard.sqlite?mode=rwc && DATA_DIR=${DATA_DIR} /usr/local/bin/snpguard-server ${NO_TLS:+--no-tls}"]