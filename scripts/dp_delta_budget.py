#!/usr/bin/env python3
"""δ の予算を厳密な有理数で計算し、src/dp.rs の定数と文書の数字を突き合わせる

`dp` の sampler は固定回数で裾を切る その切り捨てが 1 回の draw で起こる確率の和
η を、各項の**上界**を `fractions.Fraction` (と整数) で計算する 浮動小数点は使わない
e^-x は Taylor 展開の部分和で上下から挟む (交代級数なので部分和が上界 / 下界になる)

検査すること:
1. η < 2^-103 (文書が述べる値) が成り立つ
2. `BERNOULLI_STEPS` が「attempts · 1/K! ≤ 2^-110」を満たす最小の K である
   (推測でなく計算で決める、増やしすぎも減らしすぎも fail)
3. src/dp.rs の δ の表の各行の `< 2^-N` が、計算した上界の floor(−log2) と一致する
4. README / CHANGELOG / module doc の η の値 (`2^-103`) が計算と一致する
5. tests/dp_cost_model.rs の 1 attempt の語数が K から導いた値と一致する

比較 0 件 (定数や表の行が読めない) は fail
"""

from __future__ import annotations

import math
import re
import sys
from fractions import Fraction as F
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DP = ROOT / "src" / "dp.rs"
COST = ROOT / "tests" / "dp_cost_model.rs"
DOCS = [ROOT / "README.md", ROOT / "CHANGELOG.md", DP]

ETA_CLAIM_BITS = 103  # 文書が述べる η < 2^-103
BERNOULLI_TERM_BITS = 110  # Bernoulli の切り捨ての項に割り当てる予算
UNIFORM_N_BITS = 102  # uniform_below に渡る n の上界 (t · k < 2^96 · 34)


def exp_neg_upper(x: F, terms: int = 60) -> F:
    """e^-x (x ≥ 0) の上界: 交代級数の偶数項で切った部分和"""
    s, t = F(0), F(1)
    for k in range(terms):
        s += t if k % 2 == 0 else -t
        t = t * x / (k + 1)
    return s + t  # 次の (正の) 項を足して確実に上から押さえる


def exp_neg_lower(x: F, terms: int = 61) -> F:
    """e^-x (x ≥ 0) の下界: 交代級数を負の項で切った部分和"""
    s, t = F(0), F(1)
    for k in range(terms):
        s += t if k % 2 == 0 else -t
        t = t * x / (k + 1)
    return s - t


def neg_log2_floor(x: F) -> int:
    """⌊−log2 x⌋ for 0 < x < 1, exactly (integers only)"""
    n = 0
    while x * (2 ** (n + 1)) <= 1:
        n += 1
    return n


def read_const(text: str, name: str) -> int:
    m = re.search(rf"const {name}: \w+ = (\d+);", text)
    if not m:
        raise SystemExit(f"error: {name} not found in src/dp.rs (compared nothing)")
    return int(m.group(1))


def main() -> int:
    src = DP.read_text(encoding="utf-8")
    steps = read_const(src, "BERNOULLI_STEPS")
    table = re.search(r"const GEOMETRIC_TAIL: \[u128; (\d+)\]", src)
    bands = [int(x) for x in re.findall(r"^\s*(\d+)\n\s*\} else", src, re.M)] + [
        int(x) for x in re.findall(r"\} else \{\n\s*(\d+)\n\s*\}", src)
    ]
    if not table or len(bands) < 3:
        print("error: GEOMETRIC_TAIL or the attempt bands not found (compared nothing)")
        return 1
    geo = int(table.group(1))
    attempts = max(bands)
    errors: list[str] = []

    # p ≥ (1 − e^−1)(1 + e^−rate)/2, worst band: e^−rate > 0 ⇒ p ≥ (1 − e^−1)/2
    one_minus_e1 = 1 - exp_neg_upper(F(1))
    p_worst = one_minus_e1 / 2
    p_mid = one_minus_e1 * (1 + exp_neg_lower(F(1))) / 2
    p_low = one_minus_e1 * (1 + (1 - F(1, 1024))) / 2  # e^−r ≥ 1 − r
    terms = {
        "all attempts rejected": max(
            (1 - p_worst) ** 190, (1 - p_mid) ** 128, (1 - p_low) ** 74
        ),
        "bernoulli": attempts * F(1, math.factorial(steps)),
        # e^-(geo+1) = (e^-1)^(geo+1): the series itself does not converge fast enough here
        "geometric cap": attempts * exp_neg_upper(F(1)) ** (geo + 1),
        "thresholds": attempts * geo * F(1, 2**128),
        "uniform": attempts * (1 + steps) * F(2**UNIFORM_N_BITS, 2**256),
    }
    eta = sum(terms.values())

    if not eta < F(1, 2**ETA_CLAIM_BITS):
        errors.append(f"η = 2^-{neg_log2_floor(eta)} is not below 2^-{ETA_CLAIM_BITS}")

    # BERNOULLI_STEPS is the smallest K with attempts / K! ≤ 2^-110
    k = 1
    while attempts * F(1, math.factorial(k)) > F(1, 2**BERNOULLI_TERM_BITS):
        k += 1
    if steps != k:
        errors.append(f"BERNOULLI_STEPS = {steps}, the smallest K with {attempts}/K! ≤ 2^-{BERNOULLI_TERM_BITS} is {k}")

    # the doc table: one row per term, `< 2^-N` with N = ⌊−log2(bound)⌋
    rows = {
        "all attempts of CKS20 Algorithm 2 rejected": terms["all attempts rejected"],
        "a Bernoulli(": terms["bernoulli"],
        "the geometric part above": terms["geometric cap"],
        "rounded thresholds": terms["thresholds"],
        "uniform draws without rejection": terms["uniform"],
    }
    compared = 0
    for key, bound in rows.items():
        line = next((l for l in src.splitlines() if l.startswith("//! |") and key in l), None)
        if line is None:
            errors.append(f"δ table row for {key!r} not found in src/dp.rs")
            continue
        got = re.findall(r"< [^|`]*?2\^-(\d+)`", line)
        want = neg_log2_floor(bound)
        compared += 1
        if not got or int(got[-1]) != want:
            errors.append(f"δ table row {key!r} says 2^-{got[-1] if got else '?'}, computed bound is < 2^-{want}")

    for doc in DOCS:
        text = doc.read_text(encoding="utf-8")
        claims = re.findall(r"η < 2\^-(\d+)|\(1 \+ e\^ε_eff\) · 2\^-(\d+)", text)
        for c in (a or b for a, b in claims):
            compared += 1
            if int(c) != ETA_CLAIM_BITS:
                errors.append(f"{doc.relative_to(ROOT)} quotes η 2^-{c}, the computed claim is 2^-{ETA_CLAIM_BITS}")

    cost = COST.read_text(encoding="utf-8")
    want_expr = f"4 + {steps} * 4 + 2 + 1"
    compared += 1
    if want_expr not in cost:
        errors.append(f"tests/dp_cost_model.rs: words per attempt should be `{want_expr}`")

    if compared == 0:
        print("error: compared nothing")
        return 1
    for e in errors:
        print(f"error: {e}")
    print(
        f"dp δ budget: η < 2^-{neg_log2_floor(eta)} (claim 2^-{ETA_CLAIM_BITS}), BERNOULLI_STEPS {steps}, "
        f"attempts ≤ {attempts}, geometric cap {geo}; "
        + ", ".join(f"{n} < 2^-{neg_log2_floor(b)}" for n, b in terms.items())
        + f"; compared {compared}"
    )
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
