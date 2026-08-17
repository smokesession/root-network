# Protocol walkthrough

Four scenarios, step by step, with the actual function names and cell/command types from `src/lib.rs` so each step is traceable back to source.

## (a) A relay starts and joins the network

Entry point: `main.rs` → `Commands::Node { addr, hostname, metrics_addr, exit_policy }`.

1. `root::generate_self_signed_cert(&hostname)` creates a fresh self-signed TLS certificate + private key (`rcgen`), valid 1 year.
2. `root::create_server_config` / `root::create_client_config` build the rustls server/client configs. The client config is the permissive TOFU one (see [architecture.md](architecture.md#link-layer-tls-13--identity-pinning)).
3. The exit policy is loaded: `ExitPolicy::load_from_file(path)` if `--exit-policy` was given, else `ExitPolicy::reject_all()` (relay-only by default).
4. `root::load_or_create_signing_key(&data_dir)` loads or generates the relay's persistent Ed25519 identity from `<data-dir>/identity.key`.
5. A `RelayDescriptor::new(verifying_key, addr, cert_der, &signing_key)` is built and self-signed — this bundles the relay's identity key, its advertised external address, and its TLS certificate DER (for pinning) into one Ed25519-signed record.
6. Fresh `Directory`, `PeerStore`, `CircuitManager`, and `Metrics` instances are created.
7. Three tasks are spawned concurrently:
   - `root::start_gossip_task(descriptor, peer_store, directory, client_config)` — the periodic (10s) gossip loop described in [architecture.md](architecture.md#the-gossip-directory).
   - `root::start_metrics_server(&metrics_addr, metrics)` — a bare-bones HTTP endpoint serving `{"bytes_received": ..., "active_connections": ...}` as JSON.
   - (main task) `root::listen_for_connections(&addr, server_config, directory, circuit_manager, client_config, bw_manager, metrics, exit_policy)` — accepts inbound TLS connections and spawns `handle_incoming_connection` per connection.

Each gossip round: add our own descriptor to our directory, serialize the whole directory as `Message::Gossip(GossipMessage::Update(...))`, and send it to up to 3 random known peers plus every `BOOTSTRAP_NODES` address (`gossip_with_addr`, which itself routes through `connect_to_peer` — pinned if the peer is already known, TOFU otherwise). The receiving relay's `handle_incoming_connection` verifies each descriptor's signature via `RelayDescriptor::verify()`, accepts it into its `Directory` if new/newer, and gossips back — so exchanges are bidirectional and the directory floods outward.

## (b) A client browses a regular internet site through the SOCKS proxy

Entry point: `main.rs` → `Commands::Client { socks_addr }` → `root::start_socks_proxy`.

1. `start_socks_proxy` binds `socks_addr` and, for each incoming TCP connection, speaks a minimal SOCKS5 handshake: version/auth negotiation (`SOCKS5_AUTH_NONE` only), then a `CONNECT` request with either an IPv4 or domain-name target.
2. If the target does **not** end in `.root`, it's ordinary clearnet browsing:
   - Up to 3 relays are picked at random from the client's local `Directory` (`dir.get_all_relays().await`, shuffled) to form the circuit path.
   - `root::establish_circuit(circ_id, path, client_config, directory)` builds the 3-hop circuit as described in [architecture.md](architecture.md#circuit-building-3-hop): `Create`/`Created` to hop 1, then `RelayCommand::Extend`/`Extended` to hops 2 and 3.
   - A `RelayCommand::Begin` relay cell carrying the target `host:port` string is sent down the circuit to the last (exit) hop.
   - The exit relay's `handle_incoming_connection` (`RelayCommand::Begin` branch) resolves the target to an IPv4 address, checks it against its `ExitPolicy::is_allowed`, and — if allowed — dials it with a plain `TcpStream::connect` and replies `RelayCommand::Connected`; otherwise replies `RelayCommand::End` with a reason (`"exit policy rejected"` or `"connect failed"`).
   - Once `Connected` is received, the SOCKS proxy replies success to the local application and then pumps bytes bidirectionally: local bytes are wrapped as `RelayCommand::Data` cells, AES-256-CTR encrypted with the circuit's forward cipher, and sent as `CellCommand::Relay` cells; incoming `Data` cells are decrypted with the backward cipher and written back to the application socket. `RelayCommand::End` from the far side closes the stream.

## (c) Someone hosts a `.root` hidden service

Entry point: `main.rs` → `Commands::Hs { target }` → `root::start_hidden_service`.

1. Loads/generates the persistent identity key (`load_or_create_signing_key`), derives the `.root` address by base32-encoding the `VerifyingKey`'s bytes.
2. Picks up to 3 random relays from the directory as introduction points. For each:
   - Builds a single-hop circuit to it via `establish_circuit` (note: introduction-point circuits in this implementation are single-hop, not 3-hop — the HS connects directly to its own chosen intro relays).
   - Sends `RelayCommand::EstablishIntro` with the HS's raw 32-byte public key as payload. The relay (`handle_incoming_connection`, `EstablishIntro` branch) registers `circuit_manager.intro_points[key] = circ_id` and replies `RelayCommand::IntroEstablished`.
   - Spawns a background task looping on `recv_relay_cell` for that circuit, watching for `RelayCommand::Introduce2` cells and dispatching them to `handle_introduce2`.
3. Builds and signs a `HiddenServiceDescriptor::new(verifying_key, intro_addrs, &signing_key)` and publishes it via `directory.publish_hidden_service(descriptor)` — this validates the signature is present and inserts into `Directory.hidden_services`, keyed by the HS's `VerifyingKey`. **Note:** this descriptor is stored only in the local `Directory` instance the HS itself holds; it is not carried by the periodic relay-gossip payload (`GossipMessage::Update` only carries `RelayDescriptor`s) — see the caveat in [architecture.md](architecture.md#the-gossip-directory).
4. The service then loops forever, re-signing and re-publishing its descriptor every 10 minutes so it doesn't go stale.

## (d) A client browses a `.root` address (full rendezvous)

This is the SOCKS proxy's `.root` branch in `start_socks_proxy` (`src/lib.rs`), which implements the Tor-style rendezvous protocol end to end:

1. **Resolve:** `resolve_root_domain(domain)` base32-decodes the requested name into an Ed25519 `VerifyingKey` — purely local, no network round trip.
2. **Look up HS descriptor:** `dir.get_hidden_service(&key)`. If absent or has no introduction points, the SOCKS request fails (this is the practical consequence of the gossip caveat above — a client only succeeds here if its own directory somehow already has the HS's descriptor).
3. **Build a circuit to a rendezvous point (RP):** a random relay from the directory is chosen as RP; up to two more random relays are prepended as guard/middle hops, so the RP circuit is a normal-looking 3-hop circuit like any other (`establish_circuit`).
4. **Establish the rendezvous:** the client generates a random 20-byte cookie and sends `RelayCommand::EstablishRendezvous` (cookie as payload) down the RP circuit. The RP relay registers `circuit_manager.rendezvous_points[cookie] = circ_id` and replies `RelayCommand::RendezvousEstablished`.
5. **Contact an introduction point:** the client builds a *separate*, single-hop circuit directly to one of the HS's introduction points, and sends `RelayCommand::Introduce1` whose payload is `[service_key(32)][rp_ip(4)][rp_port(2)][cookie(20)]` — 58 bytes total. This intro-point circuit is then dropped; there's no ack cell defined for `Introduce1` itself.
6. **Relay-side forwarding:** the intro-point relay's `Introduce1` handler looks up the registered circuit for that `service_key` in `circuit_manager.intro_points` and forwards the cell verbatim as `RelayCommand::Introduce2` down the HS's intro circuit.
7. **HS reacts:** the HS's background listener task on that intro circuit sees `Introduce2` and calls `handle_introduce2(data, target_addr, client_config, directory)`, which:
   - Parses the same `[service_key(32)][ip(4)][port(2)][cookie(20)]` layout (bytes 32..58 = RP address + cookie — see the exact-offset note in [AI_REFERENCE.md](AI_REFERENCE.md)).
   - Builds a fresh single-hop circuit to the RP address.
   - Sends `RelayCommand::Rendezvous1` with `[cookie(20)][32 zero bytes placeholder]` as payload.
8. **RP links the two circuits:** the RP relay's `Rendezvous1` handler looks up the cookie in `circuit_manager.rendezvous_points`, finds the client's original RP circuit, and sets `linked_circuit_id` on *both* circuits (client-side ↔ HS-side) so the RP now bridges raw relay cells between them. It forwards the handshake tail as `RelayCommand::Rendezvous2` back to the client.
9. **Client sees `Rendezvous2`** on its original RP circuit and considers the rendezvous complete.
10. **Data relay:** from here, both sides just send `RelayCommand::Data` cells down their respective circuit; the RP relay (recognizing `circuit.linked_circuit_id` is set) bridges cells between the two circuits without interpreting them further, re-encrypting/decrypting one layer as it crosses.

**Important asymmetry:** the HS side does *not* implement a `Begin`/`Connected` handshake on the rendezvous circuit — `handle_introduce2` connects directly to its own configured `target_addr` and starts forwarding `Data` immediately once `Rendezvous1` is sent. This means the client's requested destination port (from the original SOCKS `CONNECT` request) is **not honored** for `.root` addresses; the client always lands on whatever `--target` the HS operator configured, regardless of what port it asked for. The SOCKS proxy code comments this explicitly right before it skips the would-be `Begin` step.
