# Architecture

## What this is, and isn't

The `.root` network is a working Rust implementation of a Tor-like onion-routing overlay network: 3-hop encrypted circuits, a decentralized gossip-based peer directory instead of Tor's directory authorities, and a custom `.root` top-level domain for hidden services whose addresses are derived directly from Ed25519 public keys.

It genuinely does the things a network like this needs to do — build multi-hop encrypted circuits, forward arbitrary TCP traffic through them, publish and resolve hidden-service descriptors, complete a full Tor-style rendezvous handshake (introduction points, rendezvous point, `Introduce1`/`Introduce2`, `Rendezvous1`/`Rendezvous2`) — and it has unit tests and Docker deployment configs to prove it.

It is **not** a security-audited, production-grade anonymity network. Be clear-eyed about the following before using it for anything where anonymity actually matters:

- **No third-party security review.** This is a solo/small-team research prototype. Treat every claim of "encrypted" or "anonymous" as "implements the mechanism," not "has been proven safe."
- **A single-operator network anonymizes nobody.** Anonymity in an onion-routing network comes from the *diversity and independence* of relay operators — if one person runs all three hops of your circuit (or even just knows which addresses belong to which operator), there's nothing to hide from them. A testnet you spin up yourself with `docker-compose up` and a handful of relays you control is a functional demo, not an anonymity set.
- **No traffic-analysis or timing-correlation defenses.** There's no padding scheme, no mixing, no defense against a global or well-positioned adversary correlating traffic timing/volume at the entry and exit.
- **Known protocol gaps** (detailed in [security-model.md](security-model.md)) including a TOFU bootstrap gap in TLS pinning and hidden services not honoring client-requested target ports.

If you want to actually understand or modify the code, treat this document (and its siblings) as an orientation aid, not a replacement for reading `src/lib.rs` and `src/main.rs` — both are compact enough to read in full.

## The three roles

The binary is `root` (built from this crate), invoked as `root <command>`. Every role shares a `--data-dir` (global flag, defaults to `./data`) used for persisting the Ed25519 identity key.

```
root node   --addr <ip:port> --hostname <name> [--metrics-addr <ip:port>] [--exit-policy <file>]
root client --socks-addr <ip:port>
root hs     --target <ip:port>
root vanity <prefix> [--threads N]
```

1. **Relay / node** (`root node`) — the workhorse. Listens for TLS connections from other relays and clients, participates in gossip (both dialing out and answering inbound gossip), forwards circuit cells (`Create`/`Created`/`Relay`/`Destroy`), and — if given `--exit-policy` — dials real internet destinations on behalf of `Begin` cells. Without `--exit-policy` it is relay-only: it forwards circuit-internal traffic between other relays but refuses to originate any outbound "exit" connection.

2. **Client (OP, "onion proxy")** (`root client`) — runs a local SOCKS5 proxy. Applications point at it (e.g. a browser's SOCKS5 setting) and it builds 3-hop circuits through relays it learns about from its own copy of the gossip directory, then tunnels the application's traffic through the circuit. It also handles `.root` name resolution and the full rendezvous handshake to reach hidden services.

3. **Hidden service** (`root hs`) — hosts a local TCP service (e.g. a web server) reachable only via the network at a `<base32-pubkey>.root` address. It picks a handful of relays as introduction points, establishes circuits to them, publishes a signed `HiddenServiceDescriptor` into the gossip directory, and waits for `Introduce2` cells that carry a rendezvous request, which it fulfills by connecting to the requested rendezvous point and bridging traffic to its local `--target`.

There is also a **vanity address generator** (`root vanity <prefix>`), a standalone CLI tool that brute-forces Ed25519 keypairs until it finds one whose derived `.root` address starts with a chosen prefix, then saves it as a drop-in identity for `node`/`hs`. See [operator-guide.md](operator-guide.md#vanity-addresses).

## The `.root` address format

A `.root` address is the lowercase RFC4648 base32 encoding (no padding) of a raw 32-byte Ed25519 public key, followed by the `.root` suffix:

```
<52 base32 chars>.root
```

- 32 bytes → 52 base32 characters (`ceil(32*8/5) = 52`).
- **No version byte, no checksum byte.** Unlike Tor's v3 `.onion` addresses (which embed a checksum and version byte precisely so a mistyped or corrupted address is detected rather than silently resolving to nothing or, worse, resolving into a keyspace collision), a `.root` address is *exactly* the encoded public key. A single flipped character produces a different, syntactically-valid-looking key rather than an error.
- Alphabet: `a-z`, `2-7` (standard base32).
- Derivation is symmetric: `root vanity`/`root hs` generate an Ed25519 `SigningKey`, derive the `VerifyingKey`, and base32-encode its 32 bytes (see `resolve_root_domain` and the address-printing code in `start_hidden_service`, both in `src/lib.rs`).

Resolution (`resolve_root_domain` in `src/lib.rs`) is purely local: strip `.root`, base32-decode, and parse the bytes as an Ed25519 `VerifyingKey`. No network round-trip is needed to turn a domain string into a key — the network round-trip only happens afterward, to find a `HiddenServiceDescriptor` signed by that key in the gossip directory.

## The gossip directory

There are no directory authorities. Every relay maintains its own `Directory` (a signed-descriptor store, see `src/lib.rs`) and a `PeerStore` (addresses it has actually gossiped with), and periodically (`start_gossip_task`, every 10 seconds):

1. Adds its own `RelayDescriptor` to its local directory.
2. Picks up to 3 random already-known peers plus all configured `BOOTSTRAP_NODES`, and dials each one, sending its entire known directory as a `Gossip(Update(...))` message.
3. The receiving side (`handle_incoming_connection`'s `Message::Gossip` branch) verifies each incoming descriptor's Ed25519 signature and only accepts it if it's either new or has a newer `last_updated` timestamp than what's already stored, then replies with its own directory view — so a single gossip exchange is bidirectional.

This is a simple flood-fill: over enough rounds, every reachable relay converges on the same view of the network. There's no explicit expiry/garbage-collection of stale relay descriptors visible in the current code, so a relay that goes offline permanently will simply linger in peers' directories (a real, if minor, known gap).

Hidden-service descriptors gossip differently: they're published directly (`Directory::publish_hidden_service`) by whichever relay a client happens to talk to for `.root` resolution, rather than flooded proactively — a client only learns of a hidden service if the specific relay/directory copy it's querying already has that HS's descriptor. In practice, a HS descriptor becomes gossiped indirectly because relay descriptors and directory contents propagate through the same gossip round; HS descriptors are stored in a separate `HashMap` (`Directory.hidden_services`) but are not itself covered by the `GossipMessage::Update` payload — **only relay descriptors are exchanged via the periodic gossip loop.** A client resolving a `.root` name looks up `Directory::get_hidden_service` on *its own local* directory instance, which is only populated if the HS itself published directly to a relay this client also connected to, or (in the shared-process case used by tests) shares the same `Directory` object. This is worth calling out because it means, in the current implementation, cross-relay propagation of hidden-service descriptors is not actually wired up over the wire — see [security-model.md](security-model.md) for the practical implication.

## Circuit building (3-hop)

A circuit is a chain of relays, each holding one AES-256-CTR keystream pair (forward/backward) derived from an independent X25519 key exchange with the client. Structure (`establish_circuit` in `src/lib.rs`):

```
Client (OP) --TLS--> Relay 1 (entry) --TLS--> Relay 2 (middle) --TLS--> Relay 3 (exit)
```

1. **Hop 1:** the client TLS-connects to the first relay and sends a `Create` cell whose payload is its ephemeral X25519 public key. The relay replies `Created` with its own ephemeral public key. Both sides derive a shared secret via X25519 ECDH, hashed through SHA-256 into a 32-byte AES-256 key; two independent `Aes256Ctr` instances (forward/backward) are keyed from it with a zero IV.
2. **Hops 2 and 3:** the client sends an `Extend` relay command (inside a `RelayCell`, itself inside an encrypted `Relay` cell on the existing circuit) containing the next hop's IPv4 address, port, and a fresh ephemeral X25519 public key. The current last-hop relay (`handle_extend`) dials the new hop itself, forwards a `Create` cell to it, and relays back an `Extended` cell carrying the new hop's response — so each relay only ever knows its immediate predecessor and successor, never the full path.
3. Layered encryption: each `RelayCell` a client sends is encrypted successively — conceptually the client "peels" or "wraps" one AES-CTR layer per hop it wants to reach, though in this implementation the per-hop `forward_cipher`/`backward_cipher` state lives on the `Circuit` at each individual relay, applied one hop at a time as data traverses the chain (see `handle_incoming_connection`'s `CellCommand::Relay` handling, which calls `cipher.apply_keystream` per hop and either interprets a cell locally when `recognized == 0` or forwards it further down the chain).

Flow control mirrors Tor's SENDME windows: `CIRCUIT_WINDOW_START`/`INCREMENT` (1000/100) and `STREAM_WINDOW_START`/`INCREMENT` (500/50) constants gate how much unacknowledged data can be in flight per circuit and per stream before a `SendMe` relay command is required to open the window back up.

## Link layer: TLS 1.3 + identity pinning

Every relay-to-relay and client-to-relay TCP connection is wrapped in TLS via `rustls`. There is no PKI/CA — every node presents a locally generated self-signed certificate (`generate_self_signed_cert`). Because there's no CA to validate against, `.root` uses an explicit pinning scheme instead (see the module docs above `AcceptAnyServerCert` in `src/lib.rs`):

- **`create_client_config()`** — an intentionally permissive "trust on first use" (TOFU) config that accepts *any* certificate the peer presents. This is meant only for genuinely first-contact dials, where no `RelayDescriptor` (and hence no known TLS cert) exists yet for the peer.
- **`create_pinned_client_config(expected_cert_der)`** — pins to one exact certificate, byte-for-byte. Used once a peer's `RelayDescriptor` is known; that descriptor's `tls_public_key` field carries the peer's certificate DER, and the whole descriptor is Ed25519-signed, so the pinned cert is cryptographically tied to a specific, previously-vouched-for relay identity.
- **`connect_to_peer(...)`** is the actual dispatcher: given a target address and (optionally) a `Directory`, it looks for a matching `RelayDescriptor`; if found, it pins; if not, it falls back to TOFU accept-any and logs a warning about the bootstrap gap.

In practice this means: the *first* connection ever made to a brand-new peer is unauthenticated at the TLS layer (a MITM on that exact connection would go undetected), but every *subsequent* connection to that same peer, once its signed descriptor has propagated via gossip, is cryptographically pinned. See [security-model.md](security-model.md) for the implications.
