# Nebula TorPortal - .root Overlay Network

A decentralized, anonymous overlay network written in Rust, featuring custom `.root` TLD resolution and onion routing.

## Overview

Nebula TorPortal is a research implementation of a Tor-like anonymity network. It uses a 3-hop onion routing model to anonymize TCP traffic. Unlike traditional DNS, it uses a decentralized directory system and cryptographic addressing for `.root` domains.

## Features

*   **Decentralized Architecture:** P2P Gossip discovery.
*   **End-to-End Encryption:** TLS 1.3 link security + X25519/AES-256-CTR onion routing.
*   **Custom TLD:** Native `.root` resolution via directory.
*   **Hidden Services:** Support for anonymous service hosting.
*   **Performance:**
    *   **Flow Control:** Tor-like SENDME window mechanism.
    *   **Rate Limiting:** Token-bucket bandwidth throttling.
    *   **Metrics:** Real-time stats interface.
*   **Containerized:** One-command deployment with Docker.

## Getting Started

### Prerequisites

*   Rust and Cargo installed.
*   Docker and Docker-Compose (optional, for testnet).

### Running with Docker (Testnet)

Spin up a local testnet with 2 relays and 1 client:

```bash
docker-compose up
```

*   **SOCKS5 Proxy:** `127.0.0.1:9050`
*   **Metrics (Relay1):** `127.0.0.1:9090` (if mapped)

### Running Locally (CLI)

**Start a Relay Node (relay-only by default, no exit traffic):**
```bash
cargo run -- node --addr 127.0.0.1:8443 --data-dir ./data
```

**Start a Relay Node that also allows exit traffic:**
```bash
cargo run -- node --addr 127.0.0.1:8443 --data-dir ./data --exit-policy exit-policy.example.conf
```

**Start a SOCKS5 Client:**
```bash
cargo run -- client --socks-addr 127.0.0.1:9050
```

**Host a Hidden Service:**
```bash
cargo run -- hs --target 127.0.0.1:80 --data-dir ./data-hs
```

Relay and hidden-service identities persist to `<data-dir>/identity.key` across restarts. Metrics are served on `--metrics-addr` (default `0.0.0.0:9090`).

## Technical Stack

*   **Language:** Rust (2024 Edition, requires rustc 1.85+)
*   **Async Runtime:** `tokio`
*   **Crypto:** `ring` (X25519), `ed25519-dalek` (Signatures), `aes`/`ctr` (Stream Ciphers), `rustls` (TLS).
*   **Serialization:** `bincode`
*   **Limiting:** `governor` (GCRA)

## Current Status

This is a working prototype, not a production-hardened anonymity network. As of this pass:

*   [x] Builds and runs cleanly (`cargo build --release`, `cargo test`)
*   [x] Gossip peer discovery actually dials and propagates directory state
*   [x] SOCKS5 proxy forwards real traffic through onion circuits (regular internet targets)
*   [x] Hidden services publish signed descriptors and accept inbound rendezvous connections
*   [x] Client-side `.root` rendezvous (browsing hidden services from the SOCKS proxy)
*   [x] Relay/HS identity keys persist to disk across restarts
*   [x] Exit-policy enforcement (relay-only by default; explicit opt-in required for exit traffic)
*   [x] TLS pinning to known relay identities once a signed descriptor has been gossiped

**Known gaps — do not treat this as safe for anonymity-sensitive use:**
*   First-contact/bootstrap TLS connections (before any relay descriptor is known) are trust-on-first-use, not pinned — a MITM on that very first connection isn't detected.
*   The hidden-service side doesn't do a `Begin`/`Connected` handshake on the rendezvous circuit; it always forwards to whatever `--target` the HS operator configured, so client-requested ports aren't honored.
*   No IPv6 support in circuit extension or exit-policy evaluation (IPv6 exit destinations are conservatively rejected).
*   No third-party security review. Treat this as a research/lab project.