#!/usr/bin/env bash
set -euo pipefail

# ── E2E Test ─────────────────────────────────────────────────────────────────
#
# Runs 5 processes: 1 coordinator + 3 workers + 1 client.
#
# Transport (set via TRANSPORT env var):
#   quic  — coordinator uses QUIC transport (default)
#   tls   — coordinator uses TLS-over-TCP (emulated TEE, mimics vsock+TLS)
#
# Usage:
#   TRANSPORT=quic bash examples/run_e2e.sh
#   TRANSPORT=tls  bash examples/run_e2e.sh
#
# Port isolation (for concurrent runs from different worktrees):
#   PORT_OFFSET=100 bash examples/run_e2e.sh   # shifts all ports by +100

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/common.sh"

export RUSTFLAGS="${RUSTFLAGS:--A warnings}"

TRANSPORT=${TRANSPORT:-tls}
ARTIFACT_DIR=${ARTIFACT_DIR:-"$REPO_DIR/.artifacts"}
TRACE_DIR=${TRACE_DIR:-"$REPO_DIR/.traces"}
PREPROC_DIR=${PREPROC_DIR:-"$REPO_DIR/.preprocessing"}
RAYON_THREADS=${RAYON_THREADS:-4}
MPC_QUIC_CONN_LANES=${MPC_QUIC_CONN_LANES:-$RAYON_THREADS}
NETWORK_FORKS=${NETWORK_FORKS:-$RAYON_THREADS}
NUM_ITERS=${NUM_ITERS:-10}
TRACY_ALLOC=${TRACY_ALLOC:-0}
TRACY_CAPTURE=${TRACY_CAPTURE:-0}
JEMALLOC_PRESET=${JEMALLOC_PRESET:-default}
EXTRA_FEATURES=${EXTRA_FEATURES:-}
CLIENT_EXAMPLE=${CLIENT_EXAMPLE:-sha2-chain}
DEV=${DEV:-0}

# Ports — PORT_OFFSET shifts all port families for concurrent worktree runs
PORT_OFFSET=${PORT_OFFSET:-0}
INTER_PARTY_BASE_PORT=${INTER_PARTY_BASE_PORT:-$((10000 + PORT_OFFSET))}
COORDINATOR_PORT=${COORDINATOR_PORT:-$((20000 + PORT_OFFSET))}
USER_LISTEN_BASE_PORT=${USER_LISTEN_BASE_PORT:-$((30000 + PORT_OFFSET))}
TRACY_BASE_PORT=${TRACY_BASE_PORT:-$((8086 + PORT_OFFSET))}

mkdir -p "$ARTIFACT_DIR" "$TRACE_DIR"

WORKER_FEATURES="test-utils"
if [ "$TRACY_ALLOC" = "1" ]; then
  WORKER_FEATURES="$WORKER_FEATURES,tracy-mem,jemalloc-stats"
fi
if [ -n "$EXTRA_FEATURES" ]; then
  WORKER_FEATURES="$WORKER_FEATURES,$EXTRA_FEATURES"
fi

REUSE_PREPROC=${REUSE_PREPROC:-0}
if [ "$REUSE_PREPROC" = "1" ]; then
  WORKER_FEATURES="$WORKER_FEATURES,reuse-preproc"
fi

setup_jemalloc_preset "$JEMALLOC_PRESET"

echo "=== E2E Test (transport=$TRANSPORT) ==="

case "$CLIENT_EXAMPLE" in
  sha2-chain)
    CLIENT_MANIFEST="$REPO_DIR/examples/sha2-chain/Cargo.toml"
    CLIENT_BIN="$REPO_DIR/target/release/sha2-chain"
    CLIENT_LABEL="sha2-chain"
    CLIENT_ARGS=(--config-path "$ARTIFACT_DIR/config_delegator.toml" --num-iters "$NUM_ITERS")
    ;;
  zkemail)
    CLIENT_MANIFEST="$REPO_DIR/examples/zkemail/Cargo.toml"
    CLIENT_BIN="$REPO_DIR/target/release/zkemail"
    CLIENT_LABEL="zkemail"
    CLIENT_ARGS=(
      --config-path "$ARTIFACT_DIR/config_delegator.toml"
      --email-path "$REPO_DIR/examples/zkemail/test-emails/gmail.eml"
      --from-domain gmail.com
    )
    ;;
  zkpassport)
    CLIENT_MANIFEST="$REPO_DIR/examples/zkpassport/Cargo.toml"
    CLIENT_BIN="$REPO_DIR/target/release/zkpassport"
    CLIENT_LABEL="zkpassport"
    CLIENT_ARGS=(--config-path "$ARTIFACT_DIR/config_delegator.toml" --generate)
    ;;
  *)
    echo "unsupported CLIENT_EXAMPLE=$CLIENT_EXAMPLE" >&2
    exit 1
    ;;
esac

TRACE_SUFFIX="${CLIENT_LABEL}_${NUM_ITERS}_${RAYON_THREADS}T_${MPC_QUIC_CONN_LANES}L_${NETWORK_FORKS}F"

# ── 1. Build binaries ────────────────────────────────────────────────────────

echo "Building binaries..."

cd "$REPO_DIR"

if [ "$DEV" = "1" ]; then
  BUILD_PROFILE_ARGS=(--profile build-fast)
  BUILD_BIN_DIR="$REPO_DIR/target/build-fast"
else
  BUILD_PROFILE_ARGS=(--release)
  BUILD_BIN_DIR="$REPO_DIR/target/release"
fi

cargo build "${BUILD_PROFILE_ARGS[@]}" \
  -p provia-coordinator --bin coordinator --features test-utils

cargo build "${BUILD_PROFILE_ARGS[@]}" \
  -p provia-worker --bin worker --features "$WORKER_FEATURES"

cargo build --release \
  -p mpc-net --bin gen_configs

cargo build --release \
  --manifest-path "$CLIENT_MANIFEST" \
  --target-dir "$REPO_DIR/target"

# ── 2. Generate configs ──────────────────────────────────────────────────────

# Regenerate configs every time (cheap, ensures consistency with TRANSPORT)
rm -f "$ARTIFACT_DIR"/config_*.toml "$ARTIFACT_DIR"/*.der

"$REPO_DIR/target/release/gen_configs" \
  -n 1 \
  -o "$ARTIFACT_DIR" \
  -c "$ARTIFACT_DIR" \
  -k "$ARTIFACT_DIR" \
  --inter-party-base-port "$INTER_PARTY_BASE_PORT" \
  --coordinator-port "$COORDINATOR_PORT" \
  --user-listen-base-port "$USER_LISTEN_BASE_PORT" \
  --coordinator-protocol "$TRANSPORT"

# ── 3. Launch coordinator ────────────────────────────────────────────────────

NUM_ITERS="$NUM_ITERS" MPC_QUIC_CONN_LANES="$MPC_QUIC_CONN_LANES" NETWORK_FORKS="$NETWORK_FORKS" TRACY=1 TRACY_PORT=$((TRACY_BASE_PORT - 1)) \
"$BUILD_BIN_DIR/coordinator" \
  --config-file "$ARTIFACT_DIR/config_coordinator.toml" \
  --transport "$TRANSPORT" \
  -t "$TRACE_DIR" \
  --rayon-threads "$RAYON_THREADS" &
coordinator_pid=$!

# In TLS mode, wait for the coordinator to bind before starting workers
if [ "$TRANSPORT" = "tls" ]; then
  for i in $(seq 1 20); do
    if lsof -i :${COORDINATOR_PORT} -sTCP:LISTEN >/dev/null 2>&1; then
      break
    fi
    sleep 0.5
  done
fi

# ── 4. Launch 3 workers ─────────────────────────────────────────────────────

worker_pids=()
for p in 0 1 2; do
  NUM_ITERS="$NUM_ITERS" MPC_QUIC_CONN_LANES="$MPC_QUIC_CONN_LANES" NETWORK_FORKS="$NETWORK_FORKS" TRACY=1 TRACY_PORT=$((TRACY_BASE_PORT + p)) \
  "$BUILD_BIN_DIR/worker" \
    -c "$ARTIFACT_DIR/config_worker0_${p}.toml" \
    -t "$TRACE_DIR" \
    --network-forks "$NETWORK_FORKS" \
    --rayon-threads "$RAYON_THREADS" \
    -p "$PREPROC_DIR" &
  worker_pids+=($!)
done

capture_pids=()
if [ "$TRACY_CAPTURE" = "1" ]; then
  TRACY_CAPTURE_BIN=${TRACY_CAPTURE_BIN:-$(command -v tracy-capture 2>/dev/null || echo tracy-capture)}
  for p in 0 1 2; do
    "$TRACY_CAPTURE_BIN" \
      -f \
      -o "$TRACE_DIR/worker${p}_${TRACE_SUFFIX}.tracy" \
      -a 127.0.0.1 \
      -p $((TRACY_BASE_PORT + p)) >/dev/null 2>&1 &
    capture_pids+=($!)
  done
  "$TRACY_CAPTURE_BIN" \
    -f \
    -o "$TRACE_DIR/coordinator_${TRACE_SUFFIX}.tracy" \
    -a 127.0.0.1 \
    -p $((TRACY_BASE_PORT - 1)) >/dev/null 2>&1 &
  capture_pids+=($!)
fi

# ── Cleanup trap ─────────────────────────────────────────────────────────────

cleanup() {
  # Send SIGINT to tracy-capture first (graceful flush), then kill workers
  if [ ${#capture_pids[@]} -gt 0 ]; then
    kill -INT "${capture_pids[@]}" 2>/dev/null || true
  fi
  local pids=("$coordinator_pid" "${worker_pids[@]}")
  kill "${pids[@]}" 2>/dev/null || true
  if [ ${#capture_pids[@]} -gt 0 ]; then
    wait "${capture_pids[@]}" 2>/dev/null || true
  fi
  wait "${pids[@]}" 2>/dev/null || true
}
trap cleanup EXIT

# ── 5. Wait for workers to bind, then run client ────────────────────────────

# Give workers time to bind their user-listen ports
sleep 3

WORKER_ADDRS="127.0.0.1:${USER_LISTEN_BASE_PORT}"
WORKER_ADDRS="${WORKER_ADDRS},127.0.0.1:$((USER_LISTEN_BASE_PORT + 1))"
WORKER_ADDRS="${WORKER_ADDRS},127.0.0.1:$((USER_LISTEN_BASE_PORT + 2))"

echo "Running $CLIENT_LABEL client (workers=$WORKER_ADDRS)..."

"$CLIENT_BIN" "${CLIENT_ARGS[@]}"

echo ""
echo "=== E2E Test PASSED (transport=$TRANSPORT) ==="

# Workers and coordinator are long-lived; kill them via trap
