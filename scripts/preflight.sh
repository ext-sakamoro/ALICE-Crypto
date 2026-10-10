#!/usr/bin/env bash
# scripts/preflight.sh — local reproduction of the CI gates before `git push`.
# Every command is the one CI runs. A step this file does not cover is a step
# that can only fail remotely — when a workflow step is added, add it here in
# the same commit. Run `--quick` before every push.
#
# usage: scripts/preflight.sh [--quick]   (--quick skips the test / bench suites)
set -euo pipefail
cd "$(dirname "$0")/.."

quick=0
[[ "${1:-}" == "--quick" ]] && quick=1

step() { printf '\n\033[1;34m== %s\033[0m\n' "$*"; }
# `cargo clippy` reuses fresh `cargo check` artifacts and then lints nothing;
# touching the crate roots invalidates only this repo's fingerprints.
relint() { git ls-files | grep -E '(^|/)src/(lib|main)\.rs$' | xargs -r touch; }
need() { command -v "$1" >/dev/null 2>&1 || { echo "missing tool: $1 ($2)" >&2; exit 1; }; }
has_toolchain() { rustup toolchain list | grep -q "^$1"; }

# Steps CI runs that this file cannot reproduce locally (they can only fail remotely):
#   - security-audit.yml:audit:Install cargo-audit (needs network / runner-only)
#   - security-audit.yml:deny:Install cargo-deny (needs network / runner-only)
#   - security-audit.yml:coverage (job is continue-on-error: informational in CI)
#   - security-audit.yml:semver-checks (job is continue-on-error: informational in CI)
#   - fuzz.yml:fuzz:Install cargo-fuzz [target=fuzz_hash_input] (needs network / runner-only)
#   - fuzz.yml:fuzz:Set fuzz duration [target=fuzz_hash_input] (no cargo / grep)
#   - fuzz.yml:fuzz:Run fuzz target (time-boxed) [target=fuzz_hash_input] (continue-on-error)
#   - fuzz.yml:fuzz:Report crash (informational) [target=fuzz_hash_input] (no cargo / grep)
#   - fuzz.yml:fuzz:Install cargo-fuzz [target=fuzz_encrypt_decrypt_roundtrip] (needs network / runner-only)
#   - fuzz.yml:fuzz:Set fuzz duration [target=fuzz_encrypt_decrypt_roundtrip] (no cargo / grep)
#   - fuzz.yml:fuzz:Run fuzz target (time-boxed) [target=fuzz_encrypt_decrypt_roundtrip] (continue-on-error)
#   - fuzz.yml:fuzz:Report crash (informational) [target=fuzz_encrypt_decrypt_roundtrip] (no cargo / grep)
#   - fuzz.yml:fuzz:Install cargo-fuzz [target=fuzz_signature_verify] (needs network / runner-only)
#   - fuzz.yml:fuzz:Set fuzz duration [target=fuzz_signature_verify] (no cargo / grep)
#   - fuzz.yml:fuzz:Run fuzz target (time-boxed) [target=fuzz_signature_verify] (continue-on-error)
#   - fuzz.yml:fuzz:Report crash (informational) [target=fuzz_signature_verify] (no cargo / grep)

need actionlint "brew install actionlint"
need cargo-audit "cargo install cargo-audit --locked"
need cargo-deny "cargo install cargo-deny --locked"
need cargo-hack "cargo install cargo-hack --locked"
need cargo-machete "cargo install cargo-machete --locked"

step "ci.yml / clippy: Clippy (default features, all targets)"
relint
( export CARGO_TERM_COLOR="always" RUSTFLAGS="-Dwarnings" NATIVE_FEATURES="std,ffi"; cargo clippy --all-targets -- -D warnings )

step "ci.yml / clippy: Clippy (full native feature set, all targets)"
relint
( export CARGO_TERM_COLOR="always" RUSTFLAGS="-Dwarnings" NATIVE_FEATURES="std,ffi"; cargo clippy --features "$NATIVE_FEATURES" --all-targets -- -D warnings )

step "ci.yml / no_std: Build (no_std, host, no alloc)"
( export CARGO_TERM_COLOR="always" RUSTFLAGS="-Dwarnings" NATIVE_FEATURES="std,ffi"; cargo rustc --lib --no-default-features --crate-type rlib )

step "ci.yml / no_std: Build (no_std + alloc, host)"
( export CARGO_TERM_COLOR="always" RUSTFLAGS="-Dwarnings" NATIVE_FEATURES="std,ffi"; cargo rustc --lib --no-default-features --features alloc --crate-type rlib )

step "ci.yml / no_std: Build (no_std + alloc + custom-rng, bare-metal thumbv7em-none-eabihf)"
rustup target list --installed | grep -q '^thumbv7em-none-eabihf$' || rustup target add thumbv7em-none-eabihf
( export CARGO_TERM_COLOR="always" RUSTFLAGS="-Dwarnings" NATIVE_FEATURES="std,ffi"; cargo rustc --lib --no-default-features --features alloc,custom-rng --crate-type rlib --target thumbv7em-none-eabihf )

step "ci.yml / no_std: Clippy (no_std + alloc + custom-rng, bare-metal)"
relint
rustup target list --installed | grep -q '^thumbv7em-none-eabihf$' || rustup target add thumbv7em-none-eabihf
( export CARGO_TERM_COLOR="always" RUSTFLAGS="-Dwarnings" NATIVE_FEATURES="std,ffi"; RUSTC_WORKSPACE_WRAPPER="$(rustup which clippy-driver)" cargo rustc --lib --no-default-features --features alloc,custom-rng --crate-type rlib --target thumbv7em-none-eabihf -- -D warnings )

step "ci.yml / feature-powerset: Powerset (std + {alloc, ffi, custom-rng} depth 2)"
( export CARGO_TERM_COLOR="always" RUSTFLAGS="-Dwarnings" NATIVE_FEATURES="std,ffi"; cargo hack check --lib --feature-powerset --depth 2 --features std )

step "ci.yml / fmt: Check formatting"
( export CARGO_TERM_COLOR="always" RUSTFLAGS="-Dwarnings" NATIVE_FEATURES="std,ffi"; cargo fmt -- --check )
python3 scripts/dp_delta_budget.py
python3 scripts/test_tracked_generated_check.py
python3 scripts/tracked_generated_check.py
python3 scripts/dp_rr_exact.py

step "ci.yml / doc: Doc (full native feature set)"
( export CARGO_TERM_COLOR="always" RUSTFLAGS="-Dwarnings" NATIVE_FEATURES="std,ffi" RUSTDOCFLAGS="-Dwarnings"; cargo doc --no-deps --features "$NATIVE_FEATURES" )

step "ci.yml / actionlint: actionlint"
actionlint .github/workflows/*.yml

step "security-audit.yml / deny: Run cargo deny check all"
( export CARGO_TERM_COLOR="always" CARGO_NET_RETRY="5" CARGO_HTTP_MULTIPLEXING="false"; cargo deny --all-features check all )

step "security-audit.yml / unused-deps: cargo machete"
cargo machete

step "security-audit.yml / constant-time-guard: 秘密型の比較 derive と値依存の早期脱出を検出"
( export CARGO_TERM_COLOR="always" CARGO_NET_RETRY="5" CARGO_HTTP_MULTIPLEXING="false"; python3 scripts/test_constant_time_guard.py && python3 scripts/constant_time_guard.py )

step "security-audit.yml / stub-guard: Block panic!(STUB) in src/**"
(
  export CARGO_TERM_COLOR="always" CARGO_NET_RETRY="5" CARGO_HTTP_MULTIPLEXING="false"
  set -eo pipefail
  hits=$(grep -rnE 'panic!\([^)]*STUB' \
    src/ --include="*.rs" \
    --exclude-dir=bin \
    | grep -v ':[[:space:]]*//' \
    | grep -vE ':[[:space:]]*/\*' \
    || true)
  if [ -n "$hits" ]; then
    echo "❌ Explicit STUB panic detected in src/ (production path):"
    echo "$hits"
    exit 1
  fi
  echo "✓ No panic!(STUB) in src/"
)

step "security-audit.yml / stub-guard: Detect todo! / unimplemented! (informational, not blocking)"
(
  export CARGO_TERM_COLOR="always" CARGO_NET_RETRY="5" CARGO_HTTP_MULTIPLEXING="false"
  set -eo pipefail
  hits=$(grep -rnE 'todo!\(|unimplemented!\(' \
    src/ --include="*.rs" \
    --exclude-dir=bin \
    | grep -v ':[[:space:]]*//' \
    | grep -vE ':[[:space:]]*/\*' \
    || true)
  if [ -n "$hits" ]; then
    count=$(echo "$hits" | wc -l | tr -d ' ')
    echo "::warning::${count} todo!()/unimplemented!() marker(s) in src/ (informational: these are the endorsed fail-fast idiom, not stubs):"
    echo "$hits" | head -20
  else
    echo "✓ No todo!/unimplemented! markers in src/"
  fi
)

step "security-audit.yml / stub-guard: Detect dbg!() residual in src/**"
(
  export CARGO_TERM_COLOR="always" CARGO_NET_RETRY="5" CARGO_HTTP_MULTIPLEXING="false"
  set -eo pipefail
  hits=$(grep -rn 'dbg!(' src/ --include="*.rs" || true)
  if [ -n "$hits" ]; then
    echo "❌ dbg!() macro left in src/:"
    echo "$hits"
    exit 1
  fi
  echo "✓ No dbg!() in src/"
)

step "security-audit.yml / stub-guard: Detect TODO / FIXME / XXX / HACK (informational)"
(
  export CARGO_TERM_COLOR="always" CARGO_NET_RETRY="5" CARGO_HTTP_MULTIPLEXING="false"
  set -eo pipefail
  hits=$(grep -rnE 'TODO|FIXME|XXX|HACK' src/ --include="*.rs" || true)
  if [ -n "$hits" ]; then
    echo "::warning::TODO/FIXME/XXX/HACK found in src/ (informational, not blocking):"
    echo "$hits" | head -50
  else
    echo "✓ No TODO/FIXME/XXX/HACK in src/"
  fi
)

step "security-audit.yml / package-integrity: cargo package (.crate を作る)"
( export CARGO_TERM_COLOR="always" CARGO_NET_RETRY="5" CARGO_HTTP_MULTIPLEXING="false"; cargo package --no-verify --allow-dirty )

step "security-audit.yml / package-integrity: 展開して隔離 build"
(
  export CARGO_TERM_COLOR="always" CARGO_NET_RETRY="5" CARGO_HTTP_MULTIPLEXING="false"
  set -euo pipefail
  crate=$(find target/package -maxdepth 1 -name '*.crate' | head -1)
  [ -n "$crate" ] || { echo "::error::.crate が生成されていない"; exit 1; }
  echo "packaged: $(basename "$crate") ($(du -h "$crate" | cut -f1))"
  tmp=$(mktemp -d)
  tar xzf "$crate" -C "$tmp"
  cd "$tmp"/*/
  # 親 workspace を継承すると member 扱いになり、境界を越えた file が
  # 再び見えてしまう (検査の意味が消える) ので単独 package として build
  printf '\n[workspace]\n' >> Cargo.toml
  cargo check --all-features
)

step "fuzz.yml / fuzz: Build fuzz target [target=fuzz_hash_input]"
if has_toolchain nightly && cargo +nightly fuzz --version >/dev/null 2>&1; then
  (
    export CARGO_TERM_COLOR="always"
    cd fuzz
    cargo +nightly fuzz build "fuzz_hash_input"
  )
else
  echo "skip: nightly / cargo-fuzz not installed" >&2
fi

step "fuzz.yml / fuzz: Build fuzz target [target=fuzz_encrypt_decrypt_roundtrip]"
if has_toolchain nightly && cargo +nightly fuzz --version >/dev/null 2>&1; then
  (
    export CARGO_TERM_COLOR="always"
    cd fuzz
    cargo +nightly fuzz build "fuzz_encrypt_decrypt_roundtrip"
  )
else
  echo "skip: nightly / cargo-fuzz not installed" >&2
fi

step "fuzz.yml / fuzz: Build fuzz target [target=fuzz_signature_verify]"
if has_toolchain nightly && cargo +nightly fuzz --version >/dev/null 2>&1; then
  (
    export CARGO_TERM_COLOR="always"
    cd fuzz
    cargo +nightly fuzz build "fuzz_signature_verify"
  )
else
  echo "skip: nightly / cargo-fuzz not installed" >&2
fi

if [[ $quick -eq 1 ]]; then
  echo; echo "preflight --quick OK (test / bench suites skipped)"; exit 0
fi

step "ci.yml / test: Test (default)"
( export CARGO_TERM_COLOR="always" RUSTFLAGS="-Dwarnings" NATIVE_FEATURES="std,ffi"; cargo test )

step "ci.yml / test: Test (full native feature set)"
( export CARGO_TERM_COLOR="always" RUSTFLAGS="-Dwarnings" NATIVE_FEATURES="std,ffi"; cargo test --features "$NATIVE_FEATURES" )

step "security-audit.yml / audit: Run cargo audit"
(
  export CARGO_TERM_COLOR="always" CARGO_NET_RETRY="5" CARGO_HTTP_MULTIPLEXING="false"
  cargo audit \
    --deny yanked \
    --ignore RUSTSEC-2024-0436 \
    --ignore RUSTSEC-2025-0141 \
    --ignore RUSTSEC-2026-0192 \
    --ignore RUSTSEC-2026-0204 \
    --ignore RUSTSEC-2025-0020 \
    --ignore RUSTSEC-2026-0176 \
    --ignore RUSTSEC-2026-0177
)

echo; echo "preflight OK"
