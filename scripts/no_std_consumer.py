#!/usr/bin/env python3
"""Build consumers/no_std (a crate that depends on alice-crypto without std)
for each target in BUILDS and check that both crates were built as rlibs.

`cargo rustc --crate-type rlib` on alice-crypto itself overrides the crate's
declared crate-types, so it cannot see a crate-type that needs std (a cdylib
asks for an allocator and a panic handler). A downstream crate builds the
declared crate-types, so it can. thumbv7em drops a cdylib with a warning;
the host and wasm32-unknown-unknown do not, so all three are built.

Each build's artifacts are read from cargo's JSON messages; a build that
fails, or one that reports no rlib for alice-crypto or for the consumer, is a
failure, and so is running no build at all.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "consumers" / "no_std" / "Cargo.toml"
CRATES = ("alice_crypto", "alice_crypto_no_std_consumer")
# (target, features); None is the host
BUILDS: list[tuple[str | None, str]] = [
    (None, ""),
    (None, "alloc"),
    ("wasm32-unknown-unknown", "custom-rng"),
    ("thumbv7em-none-eabihf", "alloc,custom-rng"),
]


def rlibs(messages: str) -> set[str]:
    """Names of the crates for which cargo reported an rlib."""
    names = set()
    for line in messages.splitlines():
        if not line.startswith("{"):
            continue
        msg = json.loads(line)
        if msg.get("reason") != "compiler-artifact":
            continue
        if any(f.endswith(".rlib") for f in msg.get("filenames", [])):
            names.add(msg["target"]["name"].replace("-", "_"))
    return names


def errors(messages: str) -> list[str]:
    """First lines of the compiler's error diagnostics in cargo's JSON messages."""
    out = []
    for line in messages.splitlines():
        if not line.startswith("{"):
            continue
        msg = json.loads(line)
        diag = msg.get("message") if msg.get("reason") == "compiler-message" else None
        if diag and diag.get("level") == "error":
            out.append(diag.get("message", "").splitlines()[0])
    return out


def missing(built: set[str]) -> list[str]:
    return [c for c in CRATES if c not in built]


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass
    ran, problems = 0, []
    for target, features in BUILDS:
        cmd = ["cargo", "build", "--manifest-path", str(MANIFEST), "--message-format=json"]
        if target:
            cmd += ["--target", target]
        if features:
            cmd += ["--features", features]
        label = f"{target or 'host'} [{features or 'no features'}]"
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
        ran += 1
        if proc.returncode != 0:
            found = errors(proc.stdout)
            problems.append(f"{label}: build failed: {' / '.join(found[:3]) or proc.stderr[-400:]}")
            continue
        lost = missing(rlibs(proc.stdout))
        if lost:
            problems.append(f"{label}: no rlib reported for {', '.join(lost)}")
            continue
        print(f"ok   {label}: {', '.join(CRATES)} built as rlib")
    for p in problems:
        print(f"error: {p}", file=sys.stderr)
    if ran == 0:
        print("error: no build ran", file=sys.stderr)
        return 1
    print(f"no-std-consumer: {ran} builds, {len(problems)} problems")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
