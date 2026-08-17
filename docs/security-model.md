# Security model and known limitations

This document is deliberately blunt. If you're deciding whether to trust, deploy, or contribute to this project, read this before anything else.

## Headline caveat: this is a research prototype, not audited software

No third-party security review has been performed. There is no threat model document, no formal cryptographic proof of the circuit-construction handshake, and no fuzzing/red-team history behind this code. Treat every security property described below as "the mechanism exists in the code," not "this has been proven to hold under adversarial conditions."

## Single-operator networks provide no anonymity

This is the single most important thing to understand before running or recommending this project for anything sensitive: **onion routing's anonymity guarantee depends on the relays in your circuit being operated independently, by parties who don't collude and can't correlate your traffic across hops.** If you (or one operator) run all the relays in a testnet — including the common case of `docker-compose up` spinning up 2 relays and a client on one machine — there is no anonymity being provided. The traffic is encrypted hop-to-hop, and the protocol mechanics work, but the entity that can see the whole circuit trivially deanonymizes every "user." A meaningful anonymity set requires many relays under many independent operators, sustained over time, with real traffic diversity. Nothing in this codebase creates that on its own — it's a network substrate, not a community.

## TLS bootstrap gap (trust-on-first-use)

Described in detail in [architecture.md](architecture.md#link-layer-tls-13--identity-pinning). Practical implication: the **very first** TLS connection ever made to a given peer address — before any `RelayDescriptor` for it has propagated via gossip — is accepted with no certificate validation at all (`AcceptAnyServerCert`). A network position capable of intercepting that specific first connection (and only that one) can MITM it undetected. Every subsequent connection to that same peer, once its signed descriptor is known, is pinned and this window closes. This is a real, currently-unmitigated gap; there's no out-of-band descriptor pre-seeding mechanism to close it. See `src/lib.rs` around `connect_to_peer` for the exact fallback logic and the accompanying `log::warn!` that fires every time this path is taken.

## Hidden-service target port is not client-controlled

As detailed in [protocol.md](protocol.md#d-a-client-browses-a-root-address-full-rendezvous), the HS side of the rendezvous (`handle_introduce2` in `src/lib.rs`) never implements a `Begin`/`Connected` handshake — it connects to whatever `--target` the HS operator configured and starts forwarding data immediately. Any port the visiting client's SOCKS `CONNECT` request specified is silently ignored. If you're building on top of this expecting Tor-style per-port hidden service routing, it isn't there; you get exactly one fixed target per HS process.

## Hidden-service descriptor propagation is not fully wired across the gossip network

The periodic relay gossip loop (`start_gossip_task`) only exchanges `GossipMessage::Update(Vec<RelayDescriptor>)` — relay descriptors, not hidden-service descriptors. A `HiddenServiceDescriptor` is inserted into whichever single relay's (or process's) `Directory` instance the publishing HS happens to be using; there is no code path that floods HS descriptors out to other relays' directories the way relay descriptors are flooded. In a genuinely multi-process deployment, a client's local `Directory` will generally not contain a HS's descriptor unless something else populates it. This is worth treating as a functional gap, not just a cosmetic one, if you're trying to actually reach a `.root` address hosted on a different machine than the client is bootstrapped against.

## No traffic-analysis or timing-correlation defenses

There is no cell padding, no traffic shaping, no mixing/batching, and no defense against an adversary who can observe traffic timing and volume at both the entry and exit of a circuit (or entry and rendezvous point, for hidden services). This is a standard limitation shared with plain Tor against a global passive adversary, but is called out explicitly here because it's easy to assume a project like this has *some* mitigation when it currently has none.

## No IPv6

- Circuit extension (`establish_circuit`'s `Extend` payload construction) only encodes IPv4 addresses; attempting to extend a circuit to an IPv6 hop returns an error (`"IPv6 not supported"`).
- Exit-policy evaluation (`ExitPolicy::is_allowed`) only understands IPv4 CIDR matching; any destination that resolves only to IPv6 is conservatively rejected regardless of policy content, rather than silently allowed.
- Rendezvous-point addresses are similarly assumed IPv4 in the SOCKS client's `.root` path (`rp_ipv4` extraction explicitly errors on `IpAddr::V6`).

If your network environment is IPv6-only or IPv6-primary, this project currently won't route your traffic at all in some paths, and specifically won't let you exit to IPv6-only destinations.

## Bootstrap-only trust for `BOOTSTRAP_NODES`

`BOOTSTRAP_NODES` addresses are dialed like any other peer (through `connect_to_peer`, hence subject to the same TOFU-then-pinned behavior) — there's no separate stronger verification (e.g. a pinned fingerprint list) for the seed nodes a fresh install trusts to bootstrap into the network. If you're distributing a seed-node list out-of-band, there's currently no mechanism to also distribute their expected public keys/certs for stronger initial trust.

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
| TLS bootstrap-gap MITM window | Present, unmitigated |
| HS target port honored per-client | No — fixed at HS operator's `--target` |
| HS descriptor gossip across relays | Not fully wired — relay-only gossip payload |
| Traffic-timing correlation defense | None |
| IPv6 | Unsupported |
| Exit-node abuse risk | Real, opt-in, mitigable with a strict policy |
