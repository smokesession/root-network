# Stage 1: Build
FROM rust:1.85 as builder
WORKDIR /usr/src/root
COPY . .
RUN cargo build --release

# Stage 2: Runtime
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y libssl3 ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/src/root/target/release/root /usr/local/bin/root
ENTRYPOINT ["root"]
