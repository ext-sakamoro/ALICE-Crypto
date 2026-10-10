#!/usr/bin/env python3
"""Tests for the artifact reading in scripts/no_std_consumer.py (the builds
themselves run in CI)."""

from __future__ import annotations

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import no_std_consumer as nc  # noqa: E402


def artifact(name: str, *files: str) -> str:
    return json.dumps(
        {"reason": "compiler-artifact", "target": {"name": name}, "filenames": list(files)}
    )


BOTH = "\n".join(
    [
        artifact("alice-crypto", "/t/libalice_crypto-1.rlib", "/t/libalice_crypto-1.rmeta"),
        artifact("alice-crypto-no-std-consumer", "/t/libalice_crypto_no_std_consumer-2.rlib"),
        json.dumps({"reason": "build-finished", "success": True}),
    ]
)


class Artifacts(unittest.TestCase):
    def test_both_rlibs_are_found(self):
        self.assertEqual(nc.missing(nc.rlibs(BOTH)), [])

    def test_a_missing_consumer_is_reported(self):
        only = artifact("alice-crypto", "/t/libalice_crypto-1.rlib")
        self.assertEqual(nc.missing(nc.rlibs(only)), ["alice_crypto_no_std_consumer"])

    def test_an_rmeta_alone_is_not_an_rlib(self):
        meta = "\n".join(
            [
                artifact("alice-crypto", "/t/libalice_crypto-1.rmeta"),
                artifact("alice-crypto-no-std-consumer", "/t/libalice_crypto_no_std_consumer-2.rlib"),
            ]
        )
        self.assertEqual(nc.missing(nc.rlibs(meta)), ["alice_crypto"])

    def test_no_messages_is_everything_missing(self):
        self.assertEqual(nc.missing(nc.rlibs("")), list(nc.CRATES))

    def test_non_json_lines_are_skipped(self):
        self.assertEqual(nc.missing(nc.rlibs("warning: x\n" + BOTH)), [])

    def test_compiler_errors_are_read(self):
        diag = json.dumps(
            {
                "reason": "compiler-message",
                "message": {"level": "error", "message": "no global memory allocator found\nmore"},
            }
        )
        warn = json.dumps({"reason": "compiler-message", "message": {"level": "warning", "message": "w"}})
        self.assertEqual(nc.errors(warn + "\n" + diag), ["no global memory allocator found"])

    def test_builds_cover_host_wasm_and_bare_metal(self):
        targets = {t for t, _ in nc.BUILDS}
        self.assertEqual(targets, {None, "wasm32-unknown-unknown", "thumbv7em-none-eabihf"})


if __name__ == "__main__":
    unittest.main()
