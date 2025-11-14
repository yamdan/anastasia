#!/usr/bin/env bash

# build.sh - Helper script to build Noir circuits and export artifacts.
#
# For each specified circuit directory {circuit_name} under ./ (the circuits root), perform:
#   1. nargo compile
#      (aborts script on failure)
#   2. Copy ./target/{circuit_name}.json to ../../crates/anastasia-rs/data/{circuit_name}/{version}/circuit.json
#   3. bb write_vk -b ./target/{circuit_name}.json -o ./target
#      Copy ./target/vk to ../../crates/anastasia-rs/data/{circuit_name}/{version}/vk
#   4. bb write_vk -b ./target/{circuit_name}.json -o ./target --oracle_hash=keccak
#      Copy ./target/keccak/vk to ../../crates/anastasia-rs/data/{circuit_name}/{version}/keccak.vk
#   5. bb write_solidity_verifier -k ./target/keccak/vk -o ./target/keccak/Verifier.sol
#      Copy ./target/keccak/Verifier.sol to ../../solidity_verifier/{circuit_name}/{version}/Verifier.sol
#
# Usage:
#   ./build.sh <circuit_name> [<circuit_name> ...]
#   ./build.sh all        # build all circuit directories that contain Nargo.toml (except excluded)
#
# Requirements:
#   - nargo CLI in PATH
#   - bb (barretenberg) CLI in PATH
#   - Script should be run from the circuits directory (where this script lives) or any location.
#
# Environment variables:
#   BB_CMD (default: bb)
#   NARGO_CMD (default: nargo)
#   CIRCUITS_ROOT (default: directory containing this script)
#   DATA_DIR (default: <repo_root>/crates/anastasia-rs/data)
#   SOLIDITY_OUT_ROOT (must exist or be provided; default is <repo_root>/solidity_verifier if that directory exists; otherwise script errors)
#
# Exit codes:
#   0 success
#   1 usage / argument errors
#   2 missing dependencies
#   3 build failure or missing expected artifacts

set -euo pipefail

BB_CMD=${BB_CMD:-bb}
NARGO_CMD=${NARGO_CMD:-nargo}

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
CIRCUITS_ROOT=${CIRCUITS_ROOT:-"$SCRIPT_DIR"}
REPO_ROOT=$(cd "$CIRCUITS_ROOT/.." && pwd)
DATA_DIR=${DATA_DIR:-"$REPO_ROOT/crates/anastasia-rs/data"}
if [ -z "${SOLIDITY_OUT_ROOT:-}" ]; then
  if [ -d "$REPO_ROOT/solidity_verifier" ]; then
    SOLIDITY_OUT_ROOT="$REPO_ROOT/solidity_verifier"
  else
    err "SOLIDITY_OUT_ROOT not set and '$REPO_ROOT/solidity_verifier' does not exist. Set SOLIDITY_OUT_ROOT explicitly."
    exit 1
  fi
fi

EXCLUDE_DIRS=(srs_cache)

color() { local c=$1; shift; printf "\033[%sm%s\033[0m" "$c" "$*"; }
info() { echo "$(color 34 '[INFO]') $*"; }
warn() { echo "$(color 33 '[WARN]') $*" >&2; }
err()  { echo "$(color 31 '[ERROR]') $*" >&2; }

usage() {
  cat <<EOF
Usage: $0 all | <circuit1> [<circuit2> ...]

Build Noir circuit(s) and export artifacts (JSON, VKs, Solidity verifier).

Options via env vars:
  NARGO_CMD=$NARGO_CMD
  BB_CMD=$BB_CMD
  DATA_DIR=$DATA_DIR
  SOLIDITY_OUT_ROOT=$SOLIDITY_OUT_ROOT

Examples:
  $0 es256_ca
  $0 es256_ca es256_ee
  $0 all
EOF
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    err "Required command '$1' not found in PATH"; return 1; fi
}

check_deps() {
  local missing=0
  need_cmd "$NARGO_CMD" || missing=1
  need_cmd "$BB_CMD" || missing=1
  if [ $missing -eq 1 ]; then
    err "Missing required commands. Aborting."; exit 2; fi
}

is_excluded() {
  local name=$1; for d in "${EXCLUDE_DIRS[@]}"; do [[ $d == "$name" ]] && return 0; done; return 1; }

discover_all() {
  local path d toml
  for path in "$CIRCUITS_ROOT"/*; do
    [ -d "$path" ] || continue
    d=$(basename "$path")
    if is_excluded "$d"; then
      continue; fi
    toml="$path/Nargo.toml"
    if [ ! -f "$toml" ]; then
      continue; fi
    if grep -q 'type *= *"lib"' "$toml" 2>/dev/null; then
      continue; fi
    echo "$d"
  done | sort -u
}

build_circuit() {
  local circuit=$1
  local circuit_dir="$CIRCUITS_ROOT/$circuit"
  local target_dir="$circuit_dir/target"

  if [ ! -d "$circuit_dir" ]; then
    err "Circuit directory '$circuit' not found"; return 3; fi
  if [ ! -f "$circuit_dir/Nargo.toml" ]; then
    warn "Skipping '$circuit' (no Nargo.toml)"
    return 0
  fi

  # Skip if library type (defensive; should already be filtered in discover_all)
  if grep -q 'type *= *"lib"' "$circuit_dir/Nargo.toml" 2>/dev/null; then
    warn "Skipping library circuit '$circuit' (type=lib)"
    return 0
  fi

  # Extract version from Nargo.toml
  local version=$(grep -E '^version *= *"' "$circuit_dir/Nargo.toml" | sed -E 's/^version *= *"([^"]+)".*/\1/')
  if [ -z "$version" ]; then
    warn "Could not determine version from Nargo.toml for '$circuit'"
  fi

  info "Building circuit: $circuit"
  pushd "$circuit_dir" >/dev/null

  # 1. Compile circuit (produces target/<circuit>.json)
  info "Running $NARGO_CMD compile"
  if ! "$NARGO_CMD" compile 2>&1 | sed 's/^/[nargo] /'; then
    err "nargo compile failed for $circuit"; popd >/dev/null; return 3; fi

  local json_file="$target_dir/$circuit.json"
  if [ ! -f "$json_file" ]; then
    err "Expected JSON artifact not found: $json_file"; popd >/dev/null; return 3; fi

  local circuit_out_dir="$DATA_DIR/$circuit/$version"
  mkdir -p "$circuit_out_dir"
  info "Copying $json_file -> $circuit_out_dir/circuit.json"
  cp "$json_file" "$circuit_out_dir/circuit.json"

  # 3. Write vk (Poseidon / default)
  info "Generating verifying key (poseidon)"
  "$BB_CMD" write_vk -b "$json_file" -o "$target_dir"
  local vk_file="$target_dir/vk"
  if [ ! -f "$vk_file" ]; then
    err "Poseidon vk not found: $vk_file"; popd >/dev/null; return 3; fi
  info "Copying $vk_file -> $circuit_out_dir/vk"
  cp "$vk_file" "$circuit_out_dir/vk"

  # 4. Write keccak vk
  info "Generating verifying key (keccak)"
  "$BB_CMD" write_vk -b "$json_file" -o "$target_dir/keccak" --oracle_hash=keccak
  local keccak_vk_file="$target_dir/keccak/vk"
  if [ ! -f "$keccak_vk_file" ]; then
    err "Keccak vk not found: $keccak_vk_file"; popd >/dev/null; return 3; fi
  info "Copying $keccak_vk_file -> $circuit_out_dir/keccak.vk"
  cp "$keccak_vk_file" "$circuit_out_dir/keccak.vk"

  # 5. Solidity verifier
  info "Generating Solidity verifier"
  local solidity_out_dir="$target_dir/keccak"
  mkdir -p "$solidity_out_dir"
  "$BB_CMD" write_solidity_verifier -k "$keccak_vk_file" -o "$solidity_out_dir/Verifier.sol"
  local verifier_src="$solidity_out_dir/Verifier.sol"
  if [ ! -f "$verifier_src" ]; then
    err "Verifier.sol not found after generation: $verifier_src"; popd >/dev/null; return 3; fi

  local verifier_dst_dir="$SOLIDITY_OUT_ROOT/$circuit/$version"
  mkdir -p "$verifier_dst_dir"
  info "Copying $verifier_src -> $verifier_dst_dir/Verifier.sol"
  cp "$verifier_src" "$verifier_dst_dir/Verifier.sol"

  popd >/dev/null
  info "Finished circuit: $circuit"
}

main() {
  if [ $# -lt 1 ]; then
    usage; exit 1; fi

  check_deps

  local circuits=()
  if [ "$1" = "all" ]; then
    # Portable alternative to Bash 4+ mapfile for macOS Bash 3.2
    while IFS= read -r line; do
      [ -n "$line" ] && circuits+=("$line")
    done < <(discover_all)
    if [ ${#circuits[@]} -eq 0 ]; then
      err "No circuits discovered."; exit 1; fi
  else
    circuits=("$@")
  fi

  # Debug trace removed: previously printed CIRCUITS_ROOT when TRACE=1

  info "Circuits to build: ${circuits[*]}"

  for c in "${circuits[@]}"; do
    # Defensive exclusion check
    if is_excluded "$c"; then
      warn "Skipping excluded dir '$c'"
      continue
    fi
    if ! build_circuit "$c"; then
      err "Aborting due to failure building '$c'"
      exit 3
    fi
  done

  info "All circuits processed successfully. Artifacts in: $DATA_DIR"
  if [ -d "$DATA_DIR" ]; then
    info "Artifact summary:"
    ls -1 "$DATA_DIR" | sed 's/^/  - /'
  fi
  if [ -d "$SOLIDITY_OUT_ROOT" ]; then
    info "Solidity verifiers in: $SOLIDITY_OUT_ROOT"
    find "$SOLIDITY_OUT_ROOT" -maxdepth 2 -name 'Verifier.sol' -print | sed 's/^/  - /'
  fi
}

main "$@"
