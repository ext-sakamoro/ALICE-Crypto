#!/usr/bin/env python3
"""scripts/constant_time_guard.py の検査 D (印の付いた関数) の試験

偽の src と baseline を一時 directory に置き、違反を 1 つずつ入れて red になることを確かめる
"""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("ct_guard", HERE / "constant_time_guard.py")
guard = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(guard)

CLEAN = """\
/// draws a value
// CONSTANT-TIME: fixed work
#[inline(always)]
fn pick(a: u128, b: u128, m: u128) -> u128 {
    let mut r = 0u128;
    for _ in 0..4 {
        r = (a & m) | (b & !m); // an if in a comment is fine
    }
    r
}

fn public(n: usize) -> usize {
    if n > 3 { return 1; }
    0
}
"""


def run(src: str, baseline: str = "pick\n") -> tuple[list[str], list[str]]:
    root = Path(tempfile.mkdtemp())
    (root / "src").mkdir()
    (root / "scripts").mkdir()
    (root / "src" / "a.rs").write_text(src, encoding="utf-8")
    (root / "scripts" / "constant-time-baseline.txt").write_text(baseline, encoding="utf-8")
    guard.ROOT = root
    guard.BASELINE = root / "scripts" / "constant-time-baseline.txt"
    files = sorted((root / "src").rglob("*.rs"))
    problems, names = guard.check_marked_functions(files)
    return problems + guard.check_baseline(names), names


class MarkedFunctions(unittest.TestCase):
    def test_clean_source_passes_and_finds_the_marked_function(self):
        problems, names = run(CLEAN)
        self.assertEqual(problems, [])
        self.assertEqual(names, ["pick"])

    def test_an_if_in_a_marked_function_is_an_error(self):
        problems, _ = run(CLEAN.replace("    r\n}", "    if r == 0 { r = 1; }\n    r\n}", 1))
        self.assertTrue(any("`pick`" in p and "if r == 0" in p for p in problems), problems)

    def test_loops_and_early_exits_are_errors(self):
        for bad in ("while r < 3 { r += 1; }", "loop { break; }", "let x = f()?;", "return r;"):
            problems, _ = run(CLEAN.replace("    r\n}", f"    {bad}\n    r\n}}", 1))
            self.assertTrue(problems, f"{bad!r} was not reported")

    def test_short_circuit_and_min_max_are_errors(self):
        for bad in ("let y = a > 0 && b > 0;", "let y = a > 0 || b > 0;", "let y = a.min(b);", "let y = a.max(b);"):
            problems, _ = run(CLEAN.replace("    r\n}", f"    {bad}\n    r\n}}", 1))
            self.assertTrue(problems, f"{bad!r} was not reported")

    def test_a_for_bound_that_is_not_public_is_an_error(self):
        problems, _ = run(CLEAN.replace("for _ in 0..4 {", "for _ in 0..a {", 1))
        self.assertTrue(any("反復回数" in p and "0..a" in p for p in problems), problems)
        for ok in ("0..4", "1..=STEPS", "0..laplace_attempts(rate)", "(0..128).rev()"):
            problems, _ = run(CLEAN.replace("for _ in 0..4 {", f"for _ in {ok} {{", 1))
            self.assertEqual(problems, [], f"{ok!r} was reported")

    def test_a_removed_marker_is_an_error(self):
        problems, _ = run(CLEAN.replace("// CONSTANT-TIME: fixed work\n", ""))
        self.assertTrue(any("`pick`" in p and "印が無い" in p for p in problems), problems)

    def test_a_marked_function_missing_from_the_baseline_is_an_error(self):
        problems, _ = run(CLEAN, baseline="other\n")
        self.assertTrue(any("baseline に無い" in p for p in problems), problems)

    def test_this_repository_passes_with_marked_functions(self):
        guard.ROOT = HERE.parent
        guard.BASELINE = HERE / "constant-time-baseline.txt"
        files = sorted((HERE.parent / "src").rglob("*.rs"))
        problems, names = guard.check_marked_functions(files)
        self.assertEqual(problems + guard.check_baseline(names), [])
        self.assertGreaterEqual(len(names), 10)


if __name__ == "__main__":
    unittest.main()
