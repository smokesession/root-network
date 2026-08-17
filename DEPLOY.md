# Nebula TorPortal Deployment Guide

This guide covers how to run Nebula for different use cases using Docker.

## Quick Start (Pre-built Configs)

We provide ready-to-use Docker Compose files in the `deploy/` directory.

### 1. For VPS Hosts (Running a Relay)
Help the network grow by running a relay node.

```bash
cd deploy/relay
docker-compose up -d
```
*   **Port:** 8443 (Must be open in your firewall)
*   **Env:** Edit `docker-compose.yaml` to set `HOSTNAME` or specific `BOOTSTRAP_NODES`.

### 2. For Users (Browsing the Network)
Run a local client to browse `.root` sites securely.

```bash
cd deploy/client
docker-compose up -d
```
*   **Proxy:** `127.0.0.1:9050` (SOCKS5)
*   **Browser Config:** Point Firefox/Tor Browser to this SOCKS5 proxy.

### 3. For Publishers (Hosting a Hidden Service)
Host your own website anonymously.

```bash
cd deploy/hs
docker-compose up -d
```
*   **Configuration:** The default config spins up an `nginx` server and exposes it.
*   **Your Address:** Check the logs (`docker-compose logs hs_host`) to see your generated `.root` domain (e.g., `[INFO] Hidden service identity: ...`).

---

## Technical Details

### Docker Image
The `Dockerfile` in the root directory uses a **multi-stage build**:
1.  **Builder:** Compiles the Rust code using `rust:1.81`.
2.  **Runtime:** Copies the binary to a lightweight `debian:bookworm-slim` image (~80MB).

### Bootstrapping
By default, these configs look for local nodes. For a public network, update `BOOTSTRAP_NODES` in the YAML files to point to known stable relays (Seed Nodes).