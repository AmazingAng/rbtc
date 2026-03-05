# Stage 1: Build
FROM rust:1.83-bookworm AS builder

WORKDIR /usr/src/rbtc
COPY . .
RUN cargo build --release --bin rbtc

# Stage 2: Runtime
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/rbtc/target/release/rbtc /usr/local/bin/rbtc

EXPOSE 8333 8332

ENTRYPOINT ["rbtc"]
