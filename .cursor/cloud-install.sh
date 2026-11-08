#!/usr/bin/env bash
# Idempotent Cloud Agent bootstrap for kogany. Runs from the workspace root.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  build-essential \
  pkg-config \
  libssl-dev \
  cmake \
  protobuf-compiler \
  librocksdb-dev \
  ca-certificates \
  curl

# Ubuntu multiarch keeps librocksdb under the triplet directory.
ROCKSDB_DIR=""
for candidate in /usr/lib/x86_64-linux-gnu /usr/lib; do
  if compgen -G "${candidate}/librocksdb.so*" >/dev/null; then
    ROCKSDB_DIR="$candidate"
    break
  fi
done
if [[ -z "$ROCKSDB_DIR" ]]; then
  echo "librocksdb was installed but no librocksdb.so was found" >&2
  exit 1
fi

sudo tee /etc/profile.d/kogany-build.sh >/dev/null <<EOF
# System RocksDB, the library Kogany CI links instead of compiling the bundled C++.
export ROCKSDB_LIB_DIR=${ROCKSDB_DIR}
EOF
sudo chmod 644 /etc/profile.d/kogany-build.sh

CARGO_CONFIG="${CARGO_HOME:-$HOME/.cargo}/config.toml"
mkdir -p "$(dirname "$CARGO_CONFIG")"
if [[ -f "$CARGO_CONFIG" ]] && grep -q 'ROCKSDB_LIB_DIR' "$CARGO_CONFIG"; then
  :
elif [[ -f "$CARGO_CONFIG" ]]; then
  printf '\n[env]\nROCKSDB_LIB_DIR = "%s"\n' "$ROCKSDB_DIR" >> "$CARGO_CONFIG"
else
  printf '[env]\nROCKSDB_LIB_DIR = "%s"\n' "$ROCKSDB_DIR" > "$CARGO_CONFIG"
fi
export ROCKSDB_LIB_DIR="$ROCKSDB_DIR"

rustup toolchain install stable --profile minimal --component rustfmt,clippy
rustup default stable

if ! command -v cargo-nextest >/dev/null 2>&1; then
  tmp="$(mktemp -d)"
  curl -LsSf https://get.nexte.st/latest/linux | tar zxf - -C "$tmp"
  bin="$(find "$tmp" -type f -name 'cargo-nextest' -print -quit)"
  if [[ -z "$bin" ]]; then
    echo "cargo-nextest was not in the nexte.st archive" >&2
    exit 1
  fi
  sudo install -m 755 "$bin" /usr/local/bin/cargo-nextest
  rm -rf "$tmp"
fi

if [[ -f Cargo.toml ]]; then
  cargo fetch --locked
elif [[ -f repos/kogany/Cargo.toml ]]; then
  cargo fetch --locked --manifest-path repos/kogany/Cargo.toml
elif [[ -f kogany/Cargo.toml ]]; then
  cargo fetch --locked --manifest-path kogany/Cargo.toml
else
  echo "kogany Cargo.toml not found from $(pwd)" >&2
  exit 1
fi

rustc --version
cargo-nextest --version
echo "ROCKSDB_LIB_DIR=${ROCKSDB_LIB_DIR}"
