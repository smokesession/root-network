# AI_REFERENCE.md — dense technical index for editing this codebase

Purpose: orient fast, not replace reading source. `src/lib.rs` is ~2070 lines, `src/main.rs` ~190. Read the actual referenced lines before editing anything they cover — line numbers below were re-verified by grepping every symbol directly (not carried over from a stale prior pass) as of the bootstrap-identity-pinning change, but will drift with future edits; re-grep if a function isn't where this doc says.

## File map

| File | Contents |
|---|---|
| `src/main.rs` (~190 lines) | CLI only. `Cli`/`Commands` clap structs, `main()` dispatches to `root::*` (lib) functions per subcommand (`node`/`client`/`hs`/`vanity`). Also installs a global `std::panic::set_hook` so panics inside `tokio::spawn`'d background tasks (gossip, sync, metrics) actually get logged instead of vanishing silently. No protocol logic lives here. |
| `src/lib.rs` (~2070 lines) | Everything else: metrics, exit policy, TLS/pinning, wire types, directory, circuits, gossip, SOCKS proxy, hidden service, vanity search, unit tests. |

### `src/lib.rs` section map

| Lines | Section |
|---|---|
| 1-56 | imports, `Metrics` struct |
| 57-75 | `start_metrics_server` |
| 76-110 | `BandwidthManager` (governor-based token bucket) |
| 111-226 | Exit policy: `PolicyAction`, `ExitRule`, `ExitPolicy` (`reject_all`, `parse`, `load_from_file`, `is_allowed`), `ipv4_in_cidr` |
| 227-308 | TLS pinning: `AcceptAnyServerCert`, `PinnedServerCert`, `resolve_root_domain` |
| 309-335 | SOCKS5 constants, `Packet` (`encapsulate`/`decapsulate`, 4-byte BE length prefix, 16MB cap) |
| 336-488 | Wire/directory types: `RelayDescriptor`, `HiddenServiceDescriptor`, `PeerInfo`, `PeerStore`, `Directory` (`add_relay` now logs `info!` on genuinely new relays, not on refreshes) |
| 489-588 | `Message`, `GossipMessage` (`Update(Vec<RelayDescriptor>, Vec<HiddenServiceDescriptor>)` — carries both, not relay-only), `CellCommand`, `Cell`, `RelayCommand`, `RelayCell`, `Stream`, `Circuit`, `CircuitManager` |
| 589-637 | `handle_extend` (circuit-hop crypto: X25519 handshake per hop) |
| 638-670 | `load_or_create_signing_key` (identity persistence) |
| 671-712 | `init_logging`, `generate_self_signed_cert`, `create_server_config`, `create_client_config`, `create_pinned_client_config` |
| 713-777 | `listen_for_connections`, `connect_to_relay`, `connect_to_peer` (10s-timeout wrapper) + `connect_to_peer_inner` (pin-or-TOFU dispatcher) |
| 778-1038 | `handle_incoming_connection` — the big dispatch loop: gossip messages + every `CellCommand`/`RelayCommand` branch (Create, Relay→{Extend, Begin, Data, SendMe, End, EstablishIntro, Introduce1, EstablishRendezvous, Rendezvous1, rendezvous-linked bridging}) |
| 1039-1069 | `send_relay_cell`, `recv_relay_cell` (client-side helpers: encrypt+send / recv+decrypt one `RelayCell`) |
| 1070-1411 | `start_socks_proxy` — SOCKS5 handshake, clearnet path, full `.root` rendezvous client path |
| 1412-1504 | `establish_circuit` (client-side multi-hop circuit builder) |
| 1505-1575 | `handle_introduce2` (HS-side: parse Introduce2, rendezvous, bridge to local target) |
| 1576-1630 | `start_hidden_service` (HS main loop; delegates intro-point selection to `establish_intro_points` and retries every 15s while it has zero, falling back to a 600s refresh cadence once it has at least one) |
| 1631-1695 | `establish_intro_points` (select relays, establish intro circuits, spawn `Introduce2` listeners — extracted so both initial setup and retry share it) |
| 1696-1705 | `BootstrapNode` struct (`addr` + optional `expected_identity: VerifyingKey`) |
| 1706-1757 | `get_bootstrap_nodes` — parses `BOOTSTRAP_NODES` as comma-separated `ip:port` or `ip:port@<52-char-base32-identity>` entries |
| 1758-1813 | `gossip_with_addr` — dials, sends, awaits reply; if the target `BootstrapNode` had a pinned identity, the entire reply is discarded unless it contains a validly-signed `RelayDescriptor` proving that exact identity at that exact address (`d.id == expected && d.external_address == addr && d.verify().is_ok()`) |
| 1814-1859 | `start_gossip_task` (relay/`Node` processes: announces `our_relay_descriptor`, gossips to known peers + bootstrap nodes every 10s) |
| 1860-1886 | `start_directory_sync_task` (non-relay `client`/`hs` processes: same pull/push loop, no self-descriptor to announce — without this, client/HS directories stayed permanently empty) |
| 1887-1893 | `BASE32_ALPHABET` const |
| 1894-1987 | `run_vanity_search` (multi-threaded brute force) |
| 1988-2074 | `#[cfg(test)] mod tests` — 7 unit tests |

### `src/main.rs` map

| Lines | Contents |
|---|---|
| 6-16 | `Cli` (clap `Parser`): global `--data-dir` |
| 18-59 | `Commands` enum: `Node{addr,hostname,metrics_addr,exit_policy}`, `Client{socks_addr}`, `Hs{target}`, `Vanity{prefix,threads}` |
| 61-136 | `main()`: per-subcommand wiring — construct `Directory`/`CircuitManager`/`PeerStore`/`Metrics`, spawn tasks, call into `root::*` |

## Core data structures

### `RelayDescriptor` (lib.rs ~336)
Fields: `id: VerifyingKey`, `external_address: SocketAddr`, `tls_public_key: Vec<u8>` (TLS cert DER, for pinning), `last_updated: u64` (unix secs), `signature: Signature`.
Invariant: **must pass `.verify()` before being accepted into `Directory`** (`Directory::add_relay` checks `descriptor.verify().is_err()` and rejects). `sign()`/`verify()` zero the signature field before serializing with `bincode` to get a stable signed payload (self-referential-signature pattern — be careful if you change `RelayDescriptor`'s field layout, since the dummy-signature substitution must stay in sync between `sign` and `verify`).
Constructed: `RelayDescriptor::new()` in `main.rs` (Node startup) and in tests.
Consumed: `Directory::add_relay`, `connect_to_peer` (pin lookup by `external_address`), gossip serialization.

### `HiddenServiceDescriptor` (lib.rs ~371)
Fields: `identity_key: VerifyingKey`, `introduction_points: Vec<SocketAddr>`, `signature: Signature`. Same sign/verify pattern as `RelayDescriptor`.
Invariant: verified before `Directory::publish_hidden_service` accepts it.
Constructed: `start_hidden_service` (initial publish + every 10-min refresh).
Consumed: `Directory::get_hidden_service`, looked up by `resolve_root_domain`'s output key in `start_socks_proxy`'s `.root` branch.
**Gap:** not carried by `GossipMessage::Update` — only `RelayDescriptor`s flood via gossip; HS descriptors live only in whichever `Directory` instance published them. See security-model.md.

### `Directory` (lib.rs ~433)
Two `RwLock<HashMap>`s: `relays: HashMap<VerifyingKey, RelayDescriptor>`, `hidden_services: HashMap<VerifyingKey, HiddenServiceDescriptor>`.
`add_relay`: rejects invalid signature; rejects if an existing entry has `last_updated >= new.last_updated` (monotonic-timestamp dedup, prevents replay of stale descriptors overwriting fresher ones).

### `PeerStore` (lib.rs ~416)
`HashMap<SocketAddr, PeerInfo>` behind `RwLock`. Tracks peers actually gossiped-with (distinct from `Directory`, which is the flooded network view). Used by `start_gossip_task` to pick "already-known peers" to gossip to each round.

### `CircuitManager` (lib.rs ~554)
- `circuits: HashMap<CircuitId, Arc<RwLock<Circuit>>>`
- `intro_points: HashMap<VerifyingKey, CircuitId>` — HS identity key → the intro-point circuit registered for it (`EstablishIntro` handler writes this; `Introduce1` handler reads it)
- `rendezvous_points: HashMap<[u8;20], CircuitId>` — cookie → RP circuit (`EstablishRendezvous` handler writes; `Rendezvous1` handler reads)

### `Circuit` (lib.rs ~539)
Per-relay-hop state: `next_hop`/`next_hop_stream` (toward exit), `prev_hop`/`prev_hop_stream` (toward client), `forward_cipher`/`backward_cipher: Option<Aes256Ctr>`, `streams: HashMap<u16, Stream>`, `package_window`/`deliver_window` (SENDME flow control, circuit-level), `linked_circuit_id: Option<CircuitId>` (set by rendezvous linking — when `Some`, this circuit acts as a transparent bridge to another circuit; see `handle_incoming_connection`'s check `if let Some(linked_id) = circuit.linked_circuit_id` before interpreting a `RelayCell` locally).

### `Cell` / `Packet` framing
- `Packet::encapsulate`: 4-byte big-endian length prefix + payload. `decapsulate`: reads length, caps at `MAX_PACKET_LEN = 16 * 1024 * 1024`, reads payload. This is the outermost wire framing for every `Message` (both `Gossip` and `TorCell`).
- `Message` enum: `Gossip(GossipMessage)` | `TorCell(Cell)`. Top-level bincode-serialized unit sent inside a `Packet`.
- `Cell { circ_id: CircuitId(u32), command: CellCommand, payload: Vec<u8> }`. `CellCommand`: `Padding=0, Create=1, Created=2, Relay=3, Destroy=4`.
- `RelayCell { stream_id: u16, recognized: u16, digest: u32, command: RelayCommand, data: Vec<u8> }` — this is what's inside a `Cell::Relay`'s `payload` once decrypted one layer. `recognized == 0` means "this hop should interpret the command" (vs. forward further down the chain) — see the `if relay_cell.recognized == 0` check in `handle_incoming_connection`. **Note:** `digest` field exists but is not populated/verified anywhere in the current code (always `0`) — there's no per-cell integrity/digest check implemented despite the field being present, matching Tor's cell format but not its integrity-checking behavior.

### `RelayCommand` variants (lib.rs ~496-520)
`Begin=1, Data=2, End=3, Connected=4, SendMe=5, Extend=6, Extended=7, Truncate=8, Truncated=9, Drop=10, Resolve=11, Resolved=12, BeginDir=13, Extend2=14, Extended2=15, EstablishIntro=32, Introduce1=33, Introduce2=34, Rendezvous1=35, Rendezvous2=36, IntroEstablished=37, EstablishRendezvous=38, RendezvousEstablished=39`.
**Only implemented (handled) in `handle_incoming_connection`:** `Extend`, `Begin`, `Data`, `SendMe`, `End`, `EstablishIntro`, `Introduce1`, `EstablishRendezvous`, `Rendezvous1`. Everything else (`Truncate`, `Truncated`, `Drop`, `Resolve`, `Resolved`, `BeginDir`, `Extend2`, `Extended2`, `Rendezvous2` as an inbound-to-relay command, `IntroEstablished`/`Connected`/`Extended`/`RendezvousEstablished` as inbound-to-relay commands) falls into the catch-all `_ => info!("Command {:?} unimplemented locally", ...)` — these are only ever sent *from* a relay to a client/HS as responses, never expected as relay-side input, except the genuinely-unimplemented `Extend2`/`Truncate`/`Drop`/`Resolve`/`BeginDir` which are declared but have no producer or consumer anywhere. Don't assume adding a new `RelayCommand` variant automatically does anything — you must add a match arm in `handle_incoming_connection`.

### `ExitPolicy` (lib.rs ~110-201)
`rules: Vec<ExitRule>`, each `{ action: Accept|Reject, net: Option<(Ipv4Addr,u8)>, port: Option<u16> }` (`None` = wildcard). `is_allowed`: first matching rule wins; **no match → `false`** (implicit final reject — this is load-bearing, don't change without updating both the doc comment and `exit-policy.example.conf`'s explanation). `reject_all()` (empty rule vec) is the compiled-in default when `--exit-policy` is not passed.

## Control-flow maps

### Relay join
```
main.rs:Commands::Node
  → root::generate_self_signed_cert
  → root::create_server_config / root::create_client_config
  → root::ExitPolicy::load_from_file | ExitPolicy::reject_all
  → root::load_or_create_signing_key(data_dir)
  → root::RelayDescriptor::new(...)
  → spawn root::start_gossip_task(descriptor, peer_store, directory, client_config)
       → loop every 10s: directory.add_relay(self) → gossip_with_addr(peer/bootstrap)
            → connect_to_peer → send Message::Gossip(Update(...)) → recv reply → directory.add_relay per descriptor
  → spawn root::start_metrics_server(metrics_addr, metrics)
  → root::listen_for_connections(addr, ...) [blocks]
       → per accepted TLS conn: spawn handle_incoming_connection
            → loop: Packet::decapsulate → bincode deserialize Message
                 → Gossip(Update) branch: directory.add_relay(each) + reply own directory
                 → TorCell(Create) branch: handle_create_cell → reply Created
                 → TorCell(Relay) branch: decrypt one layer, dispatch by RelayCommand (see below)
```

### Clearnet client browsing
```
main.rs:Commands::Client → root::start_socks_proxy(socks_addr, directory, circuit_manager, client_config)
  → per SOCKS5 CONNECT (non-.root target):
       dir.get_all_relays() [shuffled, take 3] → root::establish_circuit(circ_id, path, client_config, directory)
            → connect_to_peer(hop1) → Create/Created (X25519+SHA256→AES key)
            → per remaining hop: RelayCommand::Extend (in encrypted RelayCell) → relay's handle_extend
                 → handle_extend: connect_to_peer(next_hop) → Create/Created → returns Created payload → Extended back to client
       → send_relay_cell(RelayCommand::Begin, target) down circuit
            → exit relay: handle_incoming_connection's Begin branch → lookup_host → exit_policy.is_allowed → TcpStream::connect → Connected | End
       → recv_relay_cell expects Connected → SOCKS success reply → bidirectional pump (RelayCommand::Data both ways)
```

### Hidden-service publish
```
main.rs:Commands::Hs → root::start_hidden_service(target, directory, client_config, signing_key)
  → derive onion_addr = base32(verifying_key)
  → dir.get_all_relays() [shuffled, take 3] as intro candidates
  → per intro relay: establish_circuit(single-hop) → send_relay_cell(EstablishIntro, pubkey)
       → relay: circuit_manager.intro_points[key]=circ_id → reply IntroEstablished
       → spawn listener loop: recv_relay_cell → on Introduce2 → spawn handle_introduce2(data, target, ...)
  → HiddenServiceDescriptor::new(...) → directory.publish_hidden_service(descriptor)
  → loop forever: sleep 600s → re-sign → publish_hidden_service (refresh)
```

### HS client rendezvous
```
start_socks_proxy: target ends with ".root"
  → resolve_root_domain(domain) → VerifyingKey
  → dir.get_hidden_service(key) → HiddenServiceDescriptor (fails if absent/no intro points)
  → pick random relay as RP; establish_circuit([guard, middle, RP])
  → cookie = rand 20 bytes → send_relay_cell(EstablishRendezvous, cookie) on RP circuit
       → RP relay: circuit_manager.rendezvous_points[cookie]=circ_id → reply RendezvousEstablished
  → pick random intro point; establish_circuit(single-hop, [intro_addr])
  → send_relay_cell(Introduce1, [service_key(32)|rp_ip(4)|rp_port(2)|cookie(20)]) → drop intro circuit
       → intro relay: circuit_manager.intro_points[service_key] lookup → forward verbatim as Introduce2 to HS's intro circuit
       → HS's spawned listener → handle_introduce2(data, target_addr, client_config, directory)
            → parse data[32..36]=rp_ip, data[36..38]=rp_port, data[38..58]=cookie
            → establish_circuit(single-hop, [rp_addr])
            → send_relay_cell(Rendezvous1, cookie + 32 zero bytes) on new circuit
                 → RP relay: rendezvous_points[cookie] lookup → circuit.linked_circuit_id = client_circ (both directions)
                      → forward Rendezvous2(data[20..]) to client's original RP circuit
  → client: recv_relay_cell expects Rendezvous2 on original RP circuit → rendezvous complete
  → data relay: both sides send RelayCommand::Data; RP relay bridges via linked_circuit_id (re-encrypts one layer per hop, no local interpretation)
```

## Cryptographic primitives and call sites

| Primitive | Purpose | Where |
|---|---|---|
| Ed25519 (`ed25519_dalek`) | Relay/HS identity, descriptor signing | `RelayDescriptor::sign/verify`, `HiddenServiceDescriptor::sign/verify` (lib.rs ~350-364, ~382-396); key gen in `load_or_create_signing_key` (lib.rs 638), `run_vanity_search` (lib.rs 1894) |
| X25519 (`ring::agreement`) | Per-hop ephemeral key agreement for circuit crypto | circuit-hop crypto inside `handle_extend` (lib.rs 589-637, relay side), `establish_circuit` (lib.rs 1412-1504, client-side per-hop keygen) |
| SHA-256 (`ring::digest`) | Hashes the X25519 shared secret down to a 32-byte AES key | inline closures in both `handle_extend` and `establish_circuit`'s agreement calls |
| AES-256-CTR (`aes`/`ctr` crates, `Aes256Ctr` type alias near the top of lib.rs) | Per-hop cell encryption, forward and backward independently keyed from the same shared secret, **zero IV** (`[0u8;16]`) | keyed in `handle_extend` (relay) and `establish_circuit` (client); applied via `cipher.apply_keystream(&mut payload)` throughout `handle_incoming_connection`'s Relay branch, `send_relay_cell`, `recv_relay_cell` |
| TLS 1.3 (`rustls` via `tokio_rustls`) | Link-layer transport security, one hop at a time | `create_server_config`/`create_client_config`/`create_pinned_client_config` (lib.rs 671-712), used by `listen_for_connections`/`connect_to_relay`/`connect_to_peer` |

**Zero-IV note:** both forward and backward AES-256-CTR ciphers on a circuit hop are initialized with a constant zero IV (`&[0u8;16].into()`), relying entirely on the freshness of the per-handshake shared secret (from a fresh X25519 ephemeral keypair each time) for keystream uniqueness — not on IV variation. This is consistent (each `Circuit` gets its own fresh secret from its own handshake) but means **any code path that reuses a `Circuit`'s cipher instance across more than the intended single continuous keystream, or that resets/reconstructs a cipher with the same secret mid-circuit, would produce keystream reuse** — a real cryptographic bug class to watch for if refactoring circuit lifecycle code.

## Known invariants / gotchas a future editor must not break

- **`handle_introduce2` byte offsets** (lib.rs, function `handle_introduce2`): payload layout is `[service_key(32)][rp_ip(4)][rp_port(2)][cookie(20)]` = 58 bytes minimum. Code checks `data.len() < 58` and bails; then reads `data[32..36]` (IP), `data[36..38]` (port, `u16::from_be_bytes`), `data[38..58]` (cookie, `try_into::<[u8;20]>`). This exact layout must match what the client's `Introduce1` sends (`start_socks_proxy`, `intro1_data` construction: `key.as_bytes() + rp_ipv4.octets() + rp_addr.port().to_be_bytes() + cookie`) and what the relay's `Introduce1` handler forwards **verbatim** as `Introduce2` (no re-framing) — all three sites must stay byte-for-byte in sync. This was a real bug surface historically; if you touch any of the three sites, update all three and re-check the offsets by hand.
- **Reject-all-by-default exit policy**: `ExitPolicy::reject_all()` (empty `rules: Vec::new()`) plus `is_allowed`'s implicit-final-reject-on-no-match together mean a relay started without `--exit-policy` rejects 100% of `Begin` requests. Do not change the default without very deliberately updating `README.md`, `docs/operator-guide.md`, and `docs/security-model.md` — this default is a safety property operators are told to rely on.
- **Base32 `.root` address format has no version/checksum byte** — `resolve_root_domain` and the address-derivation code in `run_vanity_search`/`start_hidden_service` both just base32-encode/decode the raw 32-byte Ed25519 key. A corrupted or mistyped address decodes to a *different valid-looking* key rather than failing checksum validation. Do not assume typo-resistance if building UI/UX around address entry.
- **Two independent, complementary trust layers now exist — don't conflate them.** (1) **TLS-layer pin-or-TOFU**, in `connect_to_peer`/`connect_to_peer_inner` (lib.rs 756-777): looks up `directory.get_all_relays()` for a `RelayDescriptor` matching the target `SocketAddr` with a non-empty `tls_public_key`; if found, pins via `create_pinned_client_config`; otherwise falls back to `fallback_client_config` (normally accept-any) and logs a `log::warn!`. `connect_to_peer` itself just wraps `connect_to_peer_inner` in a 10s timeout — the actual pin-or-TOFU decision lives in the inner function. Every call site that dials a peer (`gossip_with_addr`, `handle_extend`, `establish_circuit`, `handle_introduce2`) should route through `connect_to_peer` (not `connect_to_relay` directly) — `connect_to_relay` has no pinning logic, just uses whatever `ClientConfig` it's handed. (2) **Bootstrap-identity pinning**, in `gossip_with_addr` (lib.rs 1758-1813): a separate, application-layer check that only applies to `BootstrapNode` entries carrying an `expected_identity`. It doesn't touch the TLS handshake at all — it validates the *content* of the gossip reply (a signed `RelayDescriptor` must match the expected identity and address) and discards the entire response if it doesn't match. This is what actually closes the first-contact trust gap for pre-arranged peers, since layer (1) has nothing to pin to on a truly first connection.
- **`RelayCell.digest` field is present but unused** — always serialized as `0`, never computed or checked. Don't assume it provides any integrity guarantee; AES-CTR alone (no MAC) means there's no cell-level authenticated encryption in the current implementation. This is a real gap, not an oversight to silently "fix" without understanding the broader implications for wire compatibility.
- **`Directory::add_relay` only logs on genuinely new relays** (lib.rs, checks `!write_guard.contains_key(&descriptor.id)` before the existing timestamp-based dedup/update logic) — a deliberate fix after a session where "nothing new in the logs" was misread as a hang when gossip was actually working fine and just silent on every success. If you touch this function, keep that log line; it's load-bearing for operator sanity, not decorative.
- **`HiddenServiceDescriptor` still has no `last_updated` field** — `Directory::publish_hidden_service` always overwrites unconditionally on signature-valid receipt (no staleness/replay protection), unlike `add_relay`'s timestamp comparison. Worth fixing if HS descriptor replay/staleness ever becomes a concrete concern.
- **Windows key-file permissions are a no-op** — `load_or_create_signing_key`'s `chmod 600` is `#[cfg(unix)]` only. No ACL hardening happens on Windows.

## Known incomplete/gap list (terse, see security-model.md for prose)

- TLS TOFU bootstrap gap on first contact — **partially closed** for pinned `BOOTSTRAP_NODES` entries (`ip:port@identity`, see `get_bootstrap_nodes`/`gossip_with_addr` above), still open for peers you have no pre-shared identity for — `connect_to_peer_inner`, lib.rs 763-777
- HS rendezvous has no per-connection Begin/Connected — target port not client-controlled — `handle_introduce2`, lib.rs 1505-1575
- No IPv6 — `establish_circuit` extend payload, `ExitPolicy::is_allowed` (IPv4-only matcher), SOCKS `.root` path `rp_ipv4` extraction
- No cell-level MAC/digest — `RelayCell.digest` unused, zero-IV AES-CTR only
- No traffic padding / timing-correlation defense anywhere in the codebase
- No third-party security review
- `Directory` has no expiry/GC for stale relay descriptors — dead relays linger indefinitely
- `HiddenServiceDescriptor` has no `last_updated`/replay protection (see invariants above)

**Fixed since the previous pass of this doc** (kept here so nobody re-discovers these from scratch): HS descriptor gossip now works across relays (`GossipMessage::Update` carries both `Vec<RelayDescriptor>` and `Vec<HiddenServiceDescriptor>`); `client`/`hs` processes now actually sync their directory via `start_directory_sync_task` (previously they ran no sync task at all); HS intro-point selection now retries every 15s instead of running once and never again; relays no longer advertise an unreachable `0.0.0.0` external address (`--external-addr` flag added); a multi-node Docker integration test now exists (`tests/integration/gossip_and_rendezvous_test.sh`, wired into CI).
- Metrics endpoint (`start_metrics_server`) is unauthenticated plaintext HTTP

## Testing

`cargo test` — 7 unit tests, all in `#[cfg(test)] mod tests` at the bottom of `src/lib.rs` (1988-2074):

1. `test_packet_framing` — `Packet::encapsulate`/`decapsulate` round-trip via an in-memory cursor.
2. `test_directory_logic` — `Directory::add_relay`: accepts new, rejects exact duplicate (same timestamp), accepts a re-signed descriptor with a newer timestamp.
3. `test_exit_policy_reject_all_default` — `ExitPolicy::reject_all()` rejects an arbitrary IP/port.
4. `test_exit_policy_parse_and_evaluate` — parses a multi-rule policy (loopback reject, port-25 reject, wildcard accept) and checks all three branches.
5. `test_exit_policy_implicit_final_reject` — a policy with only an `accept 10.0.0.0/8:*` rule correctly rejects everything outside that range.
6. `test_exit_policy_rejects_bad_syntax` — malformed action keyword, bad IP, bad port all produce `Err`.
7. `test_root_resolution` — round-trips a dummy all-zero key through address derivation and `resolve_root_domain`.

**Multi-node coverage:** `tests/integration/gossip_and_rendezvous_test.sh` — real Docker containers, not in-process mocks. Covers: a hidden service started cold (no relay reachable yet) recovering via retry once one appears; a relay learning a HS descriptor via gossip through an intermediate relay without ever contacting the HS directly; a bootstrap peer with a correctly-pinned identity being accepted; a bootstrap peer with an incorrectly-pinned identity having its entire response discarded. Wired into GitHub Actions (`.github/workflows/integration-test.yml`), runs on every push/PR. This exists specifically because every one of the bugs it checks for was first discovered by hand, the hard way, and cargo test alone would never have caught any of them — if you add a new cross-process behavior, add a scenario here rather than trusting unit tests to cover it.
