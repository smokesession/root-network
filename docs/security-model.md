# Security model and known limitations

This document is deliberately blunt. If you're deciding whether to trust, deploy, or contribute to this project, read this before anything else.

## Headline caveat: this is a research prototype, not audited software

No third-party security review has been performed. There is no threat model document, no formal cryptographic proof of the circuit-construction handshake, and no fuzzing/red-team history behind this code. Treat every security property described below as "the mechanism exists in the code," not "this has been proven to hold under adversarial conditions."

## Single-operator networks provide no anonymity

This is the single most important thing to understand before running or recommending this project for anything sensitive: **onion routing's anonymity guarantee depends on the relays in your circuit being operated independently, by parties who don't collude and can't correlate your traffic across hops.** If you (or one operator) run all the relays in a testnet — including the common case of `docker-compose up` spinning up 2 relays and a client on one machine — there is no anonymity being provided. The traffic is encrypted hop-to-hop, and the protocol mechanics work, but the entity that can see the whole circuit trivially deanonymizes every "user." A meaningful anonymity set requires many relays under many independent operators, sustained over time, with real traffic diversity. Nothing in this codebase creates that on its own — it's a network substrate, not a community.

## TLS bootstrap gap (trust-on-first-use) — partially mitigated for pinned bootstrap peers

Described in detail in [architecture.md](architecture.md#link-layer-tls-13--identity-pinning). Practical implication: the **very first** TLS connection ever made to a given peer address — before any `RelayDescriptor` for it has propagated via gossip — is accepted with no certificate validation at all (`AcceptAnyServerCert`). A network position capable of intercepting that specific first connection (and only that one) can MITM it undetected. Every subsequent connection to that same peer, once its signed descriptor is known, is pinned and this window closes.

**As of the bootstrap-identity-pinning feature**, this gap is closed for any bootstrap peer you have an out-of-band identity for: `BOOTSTRAP_NODES` entries can be written as `ip:port@identity` (the identity is the same base32 `.root`-style string a relay logs about itself at startup). When pinned, the *response* from that bootstrap dial is only trusted if it contains a validly-signed `RelayDescriptor` proving that exact identity at that exact address — an attacker without the real operator's private key cannot forge a match, and a mismatch causes the entire response to be discarded with an `ERROR`-level log line. This is the same model Tor uses for directory authority fingerprints. See `get_bootstrap_nodes` and `gossip_with_addr` in `src/lib.rs`.

**What's still unmitigated:** peers you learn about purely through gossip (not configured as a pinned bootstrap entry) still get TOFU on first contact — there's no way to pin an identity you don't already know out-of-band. And an *unpinned* `BOOTSTRAP_NODES` entry (no `@identity` suffix) still gets plain TOFU, same as before. This feature only helps when you actually have a trustworthy identity string to pin, not by default.

## Hidden-service target port is not client-controlled

As detailed in [protocol.md](protocol.md#d-a-client-browses-a-root-address-full-rendezvous), the HS side of the rendezvous (`handle_introduce2` in `src/lib.rs`) never implements a `Begin`/`Connected` handshake — it connects to whatever `--target` the HS operator configured and starts forwarding data immediately. Any port the visiting client's SOCKS `CONNECT` request specified is silently ignored. If you're building on top of this expecting Tor-style per-port hidden service routing, it isn't there; you get exactly one fixed target per HS process.

## Hidden-service descriptor propagation — fixed, verified live

**Previously a real gap, now fixed:** the gossip payload (`GossipMessage::Update`) now carries `Vec<HiddenServiceDescriptor>` alongside `Vec<RelayDescriptor>`, and both `client` and `hs` processes run `start_directory_sync_task` (previously they ran no sync task at all and their `Directory` was permanently empty except for whatever they published locally). Verified with a real 3-container Docker test: a relay two hops away from the HS operator, never having contacted the HS directly, received and published its descriptor via gossip through an intermediate relay within ~10 seconds. See `docs/protocol.md` for the full walkthrough and `tests/integration/gossip_and_rendezvous_test.sh` for the automated regression test.

A separate, related bug was also found and fixed in the same pass: HS intro-point selection previously ran once at startup and never actually retried if the directory happened to be empty at that exact moment (despite a log message claiming it would) — a freshly-started HS could get stuck with zero intro points forever. It now retries every 15s until it succeeds.

## No traffic-analysis or timing-correlation defenses

There is no cell padding, no traffic shaping, no mixing/batching, and no defense against an adversary who can observe traffic timing and volume at both the entry and exit of a circuit (or entry and rendezvous point, for hidden services). This is a standard limitation shared with plain Tor against a global passive adversary, but is called out explicitly here because it's easy to assume a project like this has *some* mitigation when it currently has none.

## No IPv6

- Circuit extension (`establish_circuit`'s `Extend` payload construction) only encodes IPv4 addresses; attempting to extend a circuit to an IPv6 hop returns an error (`"IPv6 not supported"`).
- Exit-policy evaluation (`ExitPolicy::is_allowed`) only understands IPv4 CIDR matching; any destination that resolves only to IPv6 is conservatively rejected regardless of policy content, rather than silently allowed.
- Rendezvous-point addresses are similarly assumed IPv4 in the SOCKS client's `.root` path (`rp_ipv4` extraction explicitly errors on `IpAddr::V6`).

If your network environment is IPv6-only or IPv6-primary, this project currently won't route your traffic at all in some paths, and specifically won't let you exit to IPv6-only destinations.

## Bootstrap-node trust for `BOOTSTRAP_NODES` — pinning available, opt-in

See the "TLS bootstrap gap" section above. `BOOTSTRAP_NODES` entries can now carry a pinned identity (`ip:port@identity`) for stronger initial trust when you're distributing a seed-node list out-of-band. This is opt-in per entry — an address without `@identity` still gets plain TOFU.

## Exit-node abuse / ToS considerations for relay operators

Opting in to exit traffic (`--exit-policy <file>`) means your relay will originate real outbound TCP connections to internet destinations on behalf of strangers' circuits, and those connections will appear to come from your IP address. This carries the same practical consequences as running a Tor exit relay:

- Your IP can end up on abuse blocklists, get reported to your hosting provider, or draw law-enforcement inquiries for traffic you didn't originate and can't see the content of.
- Review your hosting provider's / VPS provider's Terms of Service before enabling exit traffic — many providers restrict or prohibit running open proxies/exit nodes.
- Use a restrictive exit policy (start from `exit-policy.example.conf`, which already blocks private/loopback ranges as SSRF protection and a set of commonly-abused ports) rather than a blanket `accept *:*`, and expect to spend ongoing effort on abuse-complaint handling if you run an exit node on a public network with real traffic.
- Relay-only (no `--exit-policy` at all) carries essentially none of this risk — you're only ever forwarding already-encrypted circuit traffic between other relays, never originating a connection to the open internet on anyone's behalf. This is the recommended default for most operators, especially first-time ones.

## Practical summary

| Concern | Status |
|---|---|
| Third-party security review | None |
| Anonymity on a single-operator/testnet deployment | None — by design of the threat model, not a bug |
| TLS bootstrap-gap MITM window | Closed for pinned `BOOTSTRAP_NODES` entries; open otherwise (opt-in, not default) |
| HS target port honored per-client | No — fixed at HS operator's `--target` |
| HS descriptor gossip across relays | Fixed — verified live across 3 nodes |
| Traffic-timing correlation defense | None |
| IPv6 | Unsupported |
| Exit-node abuse risk | Real, opt-in, mitigable with a strict policy |
