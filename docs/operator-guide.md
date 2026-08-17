# Operator guide

## Building

Requires Rust 2024 edition (rustc 1.85+).

```bash
cargo build --release
cargo test
```

`cargo test` runs 7 unit tests covering packet framing, directory add/dedup logic, exit-policy parsing/evaluation, and `.root` address resolution — see [AI_REFERENCE.md](AI_REFERENCE.md#testing) for the exact list. There is no multi-node integration test; correctness of the actual network protocol across processes is currently verified manually / by running the Docker testnet.

## The `data-dir` and identity persistence

`--data-dir` is a **global** flag (must appear before the subcommand, e.g. `root --data-dir ./data node ...`), defaulting to `./data`. All roles that need an identity (`node`, `hs`, and the output target of `vanity`) read/write `<data-dir>/identity.key` — 32 raw bytes, the Ed25519 signing key seed. `load_or_create_signing_key`:

- If the file exists and is exactly 32 bytes, loads it.
- If the file exists with any other length, hard-fails (corrupt key file) rather than silently regenerating — this is intentional, since silently regenerating would silently change your `.root` address.
- If absent, generates a new key via the OS CSPRNG and writes it.
- On Unix, best-effort `chmod 600`s the file after writing. On Windows this is a no-op (does not block startup) — there is currently no equivalent Windows ACL hardening, so protect the file yourself if that matters to you.

This means: **a relay's or hidden service's identity — and hence a hidden service's `.root` address — is stable across restarts** as long as `<data-dir>/identity.key` is preserved. Back it up if the address matters to you; losing it means generating a new (different) address.

`root client` does not use or need a persistent identity (SOCKS clients don't have a network-visible identity in this protocol).

## Running each role

### `root node` — relay

```bash
root [--data-dir ./data] node \
  --addr 0.0.0.0:8443 \
  --hostname my-relay.example \
  --metrics-addr 0.0.0.0:9090 \
  [--exit-policy exit-policy.example.conf]
```

- `--addr` (default `0.0.0.0:8443`) — the address this relay listens on for TLS connections, and (if publicly reachable) the address it advertises in its own `RelayDescriptor` so other nodes can dial it.
- `--hostname` (default `localhost`) — used only as the CN in the relay's self-signed TLS certificate; has no bearing on `.root` addressing.
- `--metrics-addr` (default `0.0.0.0:9090`) — where the plaintext HTTP metrics endpoint listens. Returns `{"bytes_received": N, "active_connections": N}`. Not authenticated — bind it to localhost or a private network if you don't want it public.
- `--exit-policy <path>` — path to an exit-policy file (see below). **If omitted, the relay is relay-only**: it forwards circuit-internal traffic between other relays but rejects every `Begin` (exit) request outright, i.e. it never originates outbound connections to arbitrary internet destinations on behalf of a circuit.

### `root client` — SOCKS5 proxy

```bash
root client --socks-addr 127.0.0.1:9050
```

Starts a SOCKS5 proxy (no auth) on `--socks-addr` (default `127.0.0.1:9050`). Point a browser or any SOCKS5-aware application at it. As documented in the Nebula manual: if using Firefox, enable "Proxy DNS when using SOCKS v5" in the manual proxy settings, or `.root` domain lookups (and regular DNS) will leak to your local resolver instead of being resolved through this proxy. This client relies on its own local gossip-built `Directory` to discover relays — see the bootstrapping section below, since a client with zero known relays cannot build any circuit.

### `root hs` — hidden service

```bash
root [--data-dir ./data-hs] hs --target 127.0.0.1:80
```

`--target` (default `127.0.0.1:80`) is the local TCP address this hidden service proxies inbound `.root` traffic to — typically a local web server. The generated `.root` address is logged at startup (`Hidden service identity: <addr>.root`) and is derived from `<data-dir>/identity.key` (persistent — see above). Use a **separate** `--data-dir` from any `node` you're also running on the same machine, since they're different identities.

Remember the asymmetry documented in [protocol.md](protocol.md#d-a-client-browses-a-root-address-full-rendezvous): whatever port a visiting client requests is irrelevant — every rendezvous connection lands on your configured `--target`, so if you want to serve multiple ports you need multiple `hs` processes (with different identities) or a reverse proxy in front of your target.

### `root vanity <prefix>` — vanity addresses

See [Vanity address tool usage](#vanity-address-tool-usage) below.

## Writing an exit-policy file

Exit policies control whether a relay will dial `Begin` (exit) requests out to the internet. **No `--exit-policy` flag at all = reject everything = relay-only node.** This is the safe default; opting into exit traffic is a deliberate choice.

Format (`ExitPolicy::parse` in `src/lib.rs`), one rule per line, `#` starts a trailing comment:

```
accept <ip-or-cidr>:<port-or-*>
reject <ip-or-cidr>:<port-or-*>
```

- Rules are evaluated top to bottom; **first match wins**.
- If nothing matches, the connection is **implicitly rejected** — you don't need (but may add, for clarity) a trailing `reject *:*`.
- IPv4 only: exact addresses or CIDR ranges (e.g. `10.0.0.0/8`). No IPv6, no hostnames, no Tor-style port lists (`*:80,443` is not supported — one port or `*` per rule).
- Non-IPv4 exit destinations (including anything that only resolves to IPv6) are **conservatively rejected** regardless of policy content, since the matcher only understands IPv4.

The shipped `exit-policy.example.conf` is a reasonable starting point: it rejects RFC1918/loopback/link-local ranges (SSRF/pivoting protection — don't let your relay be used to reach your own private network) and a set of abuse-prone ports (SMTP, SMTPS, submission, Telnet, NetBIOS/SMB, MS RPC), then accepts everything else. Copy and adjust it rather than starting from scratch; consider a stricter allowlist-only policy (comment out the trailing `accept *:*` and add narrow `accept` rules) if you want tighter control over abuse exposure.

Running as an exit relay carries real operational risk — see [security-model.md](security-model.md#exit-node-abuse--tos-considerations).

## Docker / Compose usage

Three ready-made compose files under `deploy/`, each building from the same root `Dockerfile` (multi-stage: `rust:1.81` builder → `debian:bookworm-slim` runtime, ~80MB image, tagged `nebula-net:latest`).

### `deploy/relay/docker-compose.yaml` — run a relay

```bash
cd deploy/relay
docker-compose up -d
```

- Exposes TCP 8443 (must be open in your firewall/security group for other nodes to reach you) and binds the metrics port 9090 to `127.0.0.1` only.
- `HOSTNAME` env var (default `relay`) sets the TLS cert CN.
- `BOOTSTRAP_NODES` env var — comma-separated seed peer addresses to gossip with on startup; leave empty if this is the very first node in a brand-new network (nothing to bootstrap from yet).
- Identity persists to `./data` (bind-mounted to `/data` in the container) — do not delete this directory if you want to keep the same relay identity.

### `deploy/client/docker-compose.yaml` — run a client

```bash
cd deploy/client
docker-compose up -d
```

- SOCKS5 proxy bound to `127.0.0.1:9050` only (not exposed to the network — deliberately, since this is a local trust boundary).
- `BOOTSTRAP_NODES` defaults to `127.0.0.1:8443` in this file, i.e. it assumes a locally-running relay (as in the local testnet setup); point it at real seed nodes for a real deployment.

### `deploy/hs/docker-compose.yaml` — host a hidden service

```bash
cd deploy/hs
docker-compose up -d
```

Two containers: `web` (a stock `nginx:alpine` you replace with your own content/app) and `hs_host` (runs `root hs --target web:80`, i.e. it proxies `.root` rendezvous traffic straight to the `web` container over the Docker network). Find your generated address with:

```bash
docker-compose logs hs_host | grep "identity"
```

No `--data-dir` is bind-mounted in this file by default, so on container recreation the identity (and hence the `.root` address) will regenerate — add a volume mount (mirroring the relay compose file's `./data:/data` pattern, plus a matching `--data-dir /data` on the command line) if you want a stable address across restarts.

### Local testnet

The top-level `README.md`/`docker-compose.yml` (repo root) spins up a small local testnet (2 relays + 1 client) with `docker-compose up` for quick local experimentation — useful for exercising the protocol end-to-end, but remember this is a single-operator network and therefore not an anonymity set (see [security-model.md](security-model.md)).

## Bootstrapping: new network vs. joining an existing one

`BOOTSTRAP_NODES` is read once per gossip round by `get_bootstrap_nodes()` (`src/lib.rs`) from the `BOOTSTRAP_NODES` environment variable — a comma-separated list of `host:port` addresses, resolved via `to_socket_addrs()`. If unset, it defaults to `127.0.0.1:8444,127.0.0.1:8445` (useful for local dev, meaningless in production).

- **Starting a brand-new network:** the first relay has nothing to bootstrap from — leave `BOOTSTRAP_NODES` empty (or point it at nothing reachable). It simply won't gossip with anyone until a second relay points its own `BOOTSTRAP_NODES` at the first one's address.
- **Joining an existing network:** set `BOOTSTRAP_NODES` to one or more already-running, reachable relay addresses (a "seed node" list, conceptually like Tor's fallback directories, but here just regular relays). Every gossip round (every 10 seconds), the node dials each configured bootstrap address in addition to up to 3 random peers it already knows — so even a node that has lost all its learned peers can always re-join via the bootstrap list. Bootstrap addresses are dialed with `connect_to_peer`, meaning they get the same TOFU-then-pinned treatment as any other peer.
- Every relay's own address is excluded from its own bootstrap dial list (`if addr == our_relay_descriptor.external_address { continue; }`) to avoid a relay gossiping with itself.

There's no automatic seed-node list bundled with the code — for a real public network you'd publish a small number of stable, well-known relay addresses out-of-band (documentation, a website, etc.) for new operators to configure as `BOOTSTRAP_NODES`.

## Vanity address tool usage

```bash
root [--data-dir ./my-site] vanity <prefix> [--threads N]
```

Brute-forces Ed25519 keypairs until the derived `.root` address (lowercase base32) starts with `<prefix>`, then writes the winning key to `<data-dir>/identity.key` — a drop-in identity usable directly by `node` or `hs` with the same `--data-dir`.

- `<prefix>` must use only base32 alphabet characters: `a-z`, `2-7` (case-insensitive input, normalized to lowercase). Anything else is rejected immediately with an error naming the offending character.
- `--threads N` — worker thread count; defaults to all available CPU cores (`std::thread::available_parallelism`).
- Progress is logged every 5 seconds (attempts so far, keys/sec) while searching.

**Cost scales as roughly `32^n` attempts for an `n`-character prefix** (32 possible characters per base32 symbol, uniformly distributed keyspace). Ballpark timings on a single modern multi-core machine (adjust to your own hardware — time it yourself for a real estimate):

| Prefix length | Expected attempts | Rough time |
|---|---|---|
| 4 chars | ~1M | seconds |
| 5 chars | ~33M | under a minute to a few minutes |
| 6 chars | ~1B | tens of minutes |
| 7 chars | ~34B | several hours to about a day |
| 8 chars | ~1T | days to weeks |

These are order-of-magnitude estimates, not benchmarks — the tool itself reports live keys/sec, so let it run for a few seconds and extrapolate for a number specific to your machine and thread count.
