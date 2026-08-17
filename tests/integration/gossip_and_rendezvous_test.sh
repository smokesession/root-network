#!/usr/bin/env bash
# Multi-node integration test for root-network.
#
# Unit tests (`cargo test`) only exercise single-process logic. This test
# proves the thing that actually matters for a real network: that gossip
# propagates a hidden-service descriptor *through* an intermediate relay to a
# node that never talked to the HS directly, and that a hidden service
# started cold (before any relay exists) recovers via retry once one appears.
#
# It also proves the bootstrap-identity-pinning gate: a peer that can't prove
# a pre-shared identity for a pinned bootstrap address gets its entire gossip
# response discarded, closing the trust-on-first-use gap for pre-arranged
# bootstrap peers (the same model Tor uses for directory authority
# fingerprints).
#
# This exact scenario caught real bugs during development:
#   - client/HS processes never syncing their directory with the network
#   - HS intro-point selection never actually retrying
#   - relays advertising an unreachable 0.0.0.0 external address
# None of those were caught by `cargo test`. This script exists so the next
# regression like them fails a build instead of shipping silently.
#
# Requires: Docker. Run from anywhere; paths are resolved relative to this
# script. Safe to run repeatedly - always tears down its own containers/
# network, including on failure.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
IMAGE="root-network-integration-test:latest"
NET="root-it-net-$$"
TIMEOUT_S=60

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
pass() { echo -e "${GREEN}PASS${NC}: $1"; }
fail() { echo -e "${RED}FAIL${NC}: $1"; }
step() { echo -e "${YELLOW}==>${NC} $1"; }

FAILURES=0

cleanup() {
    step "Cleaning up test containers and network..."
    docker rm -f rt-it-a rt-it-b rt-it-hs rt-it-c rt-it-e >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Polls `docker logs <container>` for a regex to appear, up to $TIMEOUT_S.
# Usage: wait_for_log <container> <regex> <description>
wait_for_log() {
    local container="$1" pattern="$2" desc="$3"
    local waited=0
    while (( waited < TIMEOUT_S )); do
        if docker logs "$container" 2>&1 | grep -qiE "$pattern"; then
            pass "$desc (after ~${waited}s)"
            return 0
        fi
        sleep 2
        waited=$(( waited + 2 ))
    done
    fail "$desc (timed out after ${TIMEOUT_S}s)"
    echo "----- $container logs -----"
    docker logs "$container" 2>&1 | tail -30
    echo "----------------------------"
    FAILURES=$(( FAILURES + 1 ))
    return 1
}

step "Building image from $PROJECT_ROOT..."
docker build -t "$IMAGE" "$PROJECT_ROOT" >/tmp/root-it-build.log 2>&1 \
    || { fail "docker build"; tail -40 /tmp/root-it-build.log; exit 1; }
pass "image built"

step "Creating isolated network $NET..."
# This host may already have other Docker networks using arbitrary subnets
# (this test doesn't own the machine), so try a few candidate ranges rather
# than assuming one is free.
NET_CREATED=0
for octet2 in 28 29 30 31 45 61 77; do
    SUBNET_PREFIX="172.${octet2}.$(( (RANDOM % 200) + 10 ))"
    if docker network create --subnet "${SUBNET_PREFIX}.0/24" "$NET" >/dev/null 2>/tmp/root-it-netcreate.log; then
        NET_CREATED=1
        break
    fi
done
if (( NET_CREATED == 0 )); then
    fail "could not find a free subnet for the test network"
    cat /tmp/root-it-netcreate.log
    exit 1
fi
IP_A="${SUBNET_PREFIX}.10"
IP_B="${SUBNET_PREFIX}.11"
IP_HS="${SUBNET_PREFIX}.12"
pass "network created ($SUBNET_PREFIX.0/24)"

# --- Scenario 1: cold-start HS recovers once a relay appears -------------
step "Starting hidden service COLD (bootstrap target doesn't exist yet)..."
docker run -d --name rt-it-hs --network "$NET" --ip "$IP_HS" \
    -e RUST_LOG=info -e "BOOTSTRAP_NODES=${IP_A}:8443" \
    "$IMAGE" --data-dir /data hs --target 127.0.0.1:9999 >/dev/null

wait_for_log rt-it-hs "no relays known" "HS logs cold-start warning" || true

step "Starting relay A (with a correct --external-addr)..."
docker run -d --name rt-it-a --network "$NET" --ip "$IP_A" \
    -e RUST_LOG=info \
    "$IMAGE" --data-dir /data node --addr 0.0.0.0:8443 --external-addr "${IP_A}:8443" >/dev/null

wait_for_log rt-it-a "Relay listening" "relay A comes up"
wait_for_log rt-it-hs "introduction point established" "HS recovers and establishes an intro point after relay A appears"

# --- Scenario 2: HS descriptor propagates through an intermediate relay --
step "Starting relay B, bootstrapped ONLY to relay A (never talks to HS directly)..."
docker run -d --name rt-it-b --network "$NET" --ip "$IP_B" \
    -e RUST_LOG=info -e "BOOTSTRAP_NODES=${IP_A}:8443" \
    "$IMAGE" --data-dir /data node --addr 0.0.0.0:8443 --external-addr "${IP_B}:8443" >/dev/null

wait_for_log rt-it-b "published hidden service descriptor" \
    "relay B learns the HS descriptor via gossip through relay A (not direct contact)"

# --- Scenario 3: bootstrap identity pinning ------------------------------
step "Extracting relay A's real identity for the pinning test..."
A_IDENTITY=$(docker logs rt-it-a 2>&1 | grep -oE '[a-z2-7]{52}\.root' | head -1 | sed 's/\.root$//')
if [[ -z "$A_IDENTITY" ]]; then
    fail "could not extract relay A's identity from its logs"
    FAILURES=$(( FAILURES + 1 ))
else
    pass "extracted relay A identity: ${A_IDENTITY:0:12}..."

    step "Starting relay C, pinned to A's CORRECT identity (should succeed)..."
    docker run -d --name rt-it-c --network "$NET" --ip "${SUBNET_PREFIX}.13" \
        -e RUST_LOG=info -e "BOOTSTRAP_NODES=${IP_A}:8443@${A_IDENTITY}" \
        "$IMAGE" --data-dir /data node --addr 0.0.0.0:8443 --external-addr "${SUBNET_PREFIX}.13:8443" >/dev/null
    wait_for_log rt-it-c "learned about a new relay at ${IP_A}" \
        "relay C accepts A's gossip when the pin matches A's real identity"
    docker rm -f rt-it-c >/dev/null 2>&1

    step "Starting relay E, pinned to a WRONG identity for A's address (should be rejected)..."
    WRONG_IDENTITY="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    docker run -d --name rt-it-e --network "$NET" --ip "${SUBNET_PREFIX}.14" \
        -e RUST_LOG=info -e "BOOTSTRAP_NODES=${IP_A}:8443@${WRONG_IDENTITY}" \
        "$IMAGE" --data-dir /data node --addr 0.0.0.0:8443 --external-addr "${SUBNET_PREFIX}.14:8443" >/dev/null
    wait_for_log rt-it-e "did NOT prove the pinned identity" \
        "relay E correctly rejects A's response when the pin doesn't match (MITM/misconfig protection)"
    docker rm -f rt-it-e >/dev/null 2>&1
fi

echo
if (( FAILURES == 0 )); then
    echo -e "${GREEN}All integration checks passed.${NC}"
    exit 0
else
    echo -e "${RED}${FAILURES} integration check(s) failed.${NC}"
    exit 1
fi
