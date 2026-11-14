#!/usr/bin/env python3
"""On WebAssembly with no OS (wasm32-unknown-unknown) the random source is one of two, never both:
the JavaScript host's `crypto.getRandomValues` (feature `wasm-js`, which `std-base` and so `std` and
the default build turn on) or a source the final binary registers (feature `custom-rng`, with
`default-features = false`). getrandom 0.2 takes its `js` backend over `custom` once both are on, so a
build with both would silently ignore the registered source; the crate refuses it with a
`compile_error!` instead.

Each case below is a `cargo check` of the library: the ones that must build build, with getrandom's
resolved backend features as expected (from `cargo tree`), and the ones that must not fail with the
crate's own message. Running fewer cases than listed (0 included) is a failure.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WASM = "wasm32-unknown-unknown"
# the start of the compile_error! message in src/lib.rs
MESSAGE = "alice-crypto: on wasm32-unknown-unknown the random source is either"

# (target or None for the host, cargo feature arguments, expected getrandom backend features or "error")
CASES: list[tuple[str | None, list[str], set[str] | str]] = [
    (WASM, [], {"js"}),
    (WASM, ["--no-default-features", "--features", "std-base"], {"js"}),
    (WASM, ["--no-default-features", "--features", "wasm-js"], {"js"}),
    (WASM, ["--no-default-features", "--features", "custom-rng"], {"custom"}),
    (WASM, ["--no-default-features", "--features", "alloc,custom-rng"], {"custom"}),
    (WASM, ["--features", "custom-rng"], "error"),
    (WASM, ["--features", "wasm-js,custom-rng"], "error"),
    (WASM, ["--no-default-features", "--features", "wasm-js,custom-rng"], "error"),
    # the rule is for this one target: elsewhere getrandom uses the OS for both features (neither backend
    # is selected off wasm32-unknown-unknown), so std with custom-rng builds
    (None, ["--features", "custom-rng"], {"js", "custom"}),
]
BACKENDS = {"js", "custom"}


def run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=ROOT, capture_output=True, text=True, check=False)


def backends(target: str | None, feats: list[str]) -> set[str] | None:
    """getrandom's resolved features among the backends, or None when the tree has no getrandom."""
    tgt = ["--target", target] if target else []
    out = run(["cargo", "tree", "--locked", "-e", "normal", "-i", "getrandom", "--prefix", "none",
               "--format", "{p} {f}", *tgt, *feats])
    if out.returncode != 0:
        raise RuntimeError(f"cargo tree failed: {out.stderr.strip()}")
    first = out.stdout.splitlines()[0] if out.stdout.strip() else ""
    if not first.startswith("getrandom "):
        return None
    words = first.split(" ", 2)
    feats_listed = set(words[2].split(",")) if len(words) > 2 else set()
    return feats_listed & BACKENDS


def check_case(target: str | None, feats: list[str], want: set[str] | str) -> str | None:
    tgt = ["--target", target] if target else []
    label = f"{target or 'host'} {' '.join(feats) or '[default]'}"
    out = run(["cargo", "check", "--locked", "--lib", "--message-format", "short", *tgt, *feats])
    if want == "error":
        if out.returncode == 0:
            return f"{label}: built, must fail with the random source error"
        if MESSAGE not in out.stderr:
            tail = "\n".join(out.stderr.strip().splitlines()[-5:])
            return f"{label}: failed without the random source error:\n{tail}"
        print(f"ok   {label}: refused ({MESSAGE} ...)")
        return None
    if out.returncode != 0:
        tail = "\n".join(out.stderr.strip().splitlines()[-5:])
        return f"{label}: did not build:\n{tail}"
    got = backends(target, feats)
    if got is None or got != want:
        return f"{label}: getrandom backend features {sorted(got) if got is not None else 'absent'}, want {sorted(want)}"
    print(f"ok   {label}: builds, getrandom features {sorted(got)}")
    return None


def main() -> int:
    problems = []
    ran = 0
    for target, feats, want in CASES:
        problem = check_case(target, feats, want)
        ran += 1
        if problem:
            print(f"FAIL {problem}")
            problems.append(problem)
    print(f"wasm-rng-features: {ran} cases, {len(problems)} problems")
    if ran != len(CASES) or ran == 0:
        print(f"::error::ran {ran} of {len(CASES)} cases")
        return 1
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
