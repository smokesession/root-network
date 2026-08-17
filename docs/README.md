# .root network documentation

This is the documentation index for the `.root` network (internally also called "Nebula TorPortal" in some older files) — a working Rust prototype of a Tor-like onion-routing overlay network with a custom `.root` top-level domain.

Two audiences, two sets of docs:

## For humans

- **[architecture.md](architecture.md)** — what this is (and isn't), the three roles, how `.root` addresses work, circuit building, TLS pinning.
- **[protocol.md](protocol.md)** — step-by-step walkthroughs of relay join, clearnet browsing, hidden-service publishing, and hidden-service rendezvous, with the actual cell/command names from the code.
- **[operator-guide.md](operator-guide.md)** — how to run each role, CLI flags, identity persistence, exit policies, Docker/compose usage, bootstrapping a new network, the vanity address tool.
- **[security-model.md](security-model.md)** — an honest accounting of what protection this network does and doesn't provide, and its known gaps.

Start with `architecture.md` if you're evaluating the project; jump straight to `operator-guide.md` if you just want to run something.

## Testing

- `cargo test` — unit tests, single-process only (packet framing, directory logic, `.root` resolution, exit-policy parsing).
- **[tests/integration/gossip_and_rendezvous_test.sh](../tests/integration/gossip_and_rendezvous_test.sh)** — multi-node integration test using real Docker containers. Proves gossip actually propagates a hidden-service descriptor *through* an intermediate relay to a node that never contacted the HS directly, and that a hidden service started before any relay exists recovers via retry once one appears. This exact scenario caught three real bugs during development that `cargo test` never could (see the script's header comment). Runs automatically in CI (`.github/workflows/integration-test.yml`) on every push/PR; run it locally with `bash tests/integration/gossip_and_rendezvous_test.sh` (requires Docker).

## For AI coding agents

- **[AI_REFERENCE.md](AI_REFERENCE.md)** — dense, grep-friendly technical index: file map, line ranges, data structure invariants, control-flow chains, crypto call sites, known gotchas, and test coverage. Read this before editing `src/lib.rs` or `src/main.rs`.

## Source of truth

All of the above is derived from reading `src/lib.rs` (~1900 lines) and `src/main.rs` (~140 lines) directly, plus `README.md`, `PICKUP.TXT`, `DEPLOY.md`, `NEBULA_MANUAL.TXT`, `exit-policy.example.conf`, and the `deploy/*/docker-compose.yaml` files. Where those older files (particularly `NEBULA_MANUAL.TXT`, dated as an earlier "Phase 6" pass) disagree with the current code, the code wins and the discrepancy is called out explicitly — most notably: `NEBULA_MANUAL.TXT` claims relay/HS keys are ephemeral (regenerated every restart); the code (`load_or_create_signing_key` in `src/lib.rs`) actually persists them to `<data-dir>/identity.key`.
