#!/usr/bin/env python3
"""randomized_response の反転確率を、sampler の整数の手順から厳密に計算する

標本抽出の試験 (tests/dp_mechanisms_oracle.rs) は頻度しか見ない ここでは
src/dp.rs の手順そのもの (固定 32 step の CKS Algorithm 1、e^-1 を ⌊ε⌋ 回と
端数を 1 回、固定 RR_ROUNDS 回の受理) が返す確率を `fractions.Fraction` で
厳密に求め、目標 1/(1 + e^ε) との差の上界を出す 浮動小数点は使わない
(ε は f64 の値を厳密な有理数にしたもの)

手順の確率:
- bernoulli_exp_neg(γ) (γ ≤ 1、K = 32 step): k 番目で初めて 0 が出る確率は
  Π_{j<k} (γ/j) · (1 − γ/k) 奇数の k の和が 1 を返す確率 (K step 内に 0 が
  出なければ 0 を返す)
- B = ∧ (e^-1 を ⌊ε⌋ 回、端数 1 回) なので P(B) = p(1)^⌊ε⌋ · p(frac)
- 1 回の round: 表 (1/2) なら「保持」で受理、裏なら B = 1 で「反転」を受理、
  他は棄却 R 回のうち最初の受理で決まり、全て棄却なら保持
  P(反転) = (P(B)/2) · (1 − ρ^R) / (1 − ρ)、ρ = (1 − P(B)) / 2

検査すること:
1. 各 ε で |P(反転) − 1/(1 + e^ε)| ≤ 2^-100 (e^-ε は Taylor の部分和で上下から挟む)
2. 一様乱数の偏り (1 draw あたり den / 2^256 以下) を draw 数倍しても 2^-100 に収まる
3. src/dp.rs の RR_ROUNDS / BERNOULLI_STEPS / RR_MAX_EPSILON_WHOLE を読んで使う
比較 0 件 (定数が読めない、ε の一覧が空) は fail
"""

from __future__ import annotations

import re
import struct
import sys
from fractions import Fraction as F
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DP = ROOT / "src" / "dp.rs"
BOUND_BITS = 100
EPSILONS = [0.5, 1.0, 2.75, 5.0, 0.1, 63.5]


def const(src: str, name: str) -> int:
    m = re.search(rf"const {name}: \w+ = (\d+);", src)
    if not m:
        raise SystemExit(f"error: {name} not found in src/dp.rs")
    return int(m.group(1))


def exact(x: float) -> F:
    """The exact rational value of a finite f64."""
    (bits,) = struct.unpack("<Q", struct.pack("<d", x))
    e = (bits >> 52) & 0x7FF
    m = bits & ((1 << 52) - 1)
    if e == 0:
        return F(m, 1 << 1074)
    m |= 1 << 52
    e -= 1075
    return F(m * (1 << e)) if e >= 0 else F(m, 1 << -e)


def p_exp_neg(gamma: F, steps: int) -> F:
    """P(1) of the K-step CKS Algorithm 1 for 0 ≤ γ ≤ 1."""
    total, prefix = F(0), F(1)  # prefix = Π_{j<k} γ/j
    for k in range(1, steps + 1):
        stop = prefix * (1 - gamma / k)
        if k % 2 == 1:
            total += stop
        prefix *= gamma / k
    return total


def exp_neg_bounds(x: F, terms: int = 400) -> tuple[F, F]:
    """Lower and upper bounds of e^-x (x ≥ 0): e^-x = (e^-(x/n))^n with x/n ≤ 1/2
    and the alternating Taylor series, whose partial sums alternate around it."""
    n = 1
    while x / n > F(1, 2):
        n *= 2
    y = x / n
    lo = hi = None
    s, t = F(0), F(1)
    for k in range(terms):
        s += t
        if k % 2 == 0:
            hi = s
        else:
            lo = s
        t = -t * y / (k + 1)
        if k > 40 and lo is not None and hi - lo < F(1, 1 << 400):
            break
    return lo**n, hi**n


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass
    src = DP.read_text(encoding="utf-8")
    rounds = const(src, "RR_ROUNDS")
    steps = const(src, "BERNOULLI_STEPS")
    max_whole = const(src, "RR_MAX_EPSILON_WHOLE")
    bound = F(1, 1 << BOUND_BITS)
    checked = 0
    problems = []
    for eps_f in EPSILONS:
        eps = exact(eps_f)
        whole = eps.numerator // eps.denominator
        if whole > max_whole:
            problems.append(f"ε = {eps_f}: ⌊ε⌋ = {whole} is over RR_MAX_EPSILON_WHOLE")
            continue
        frac = eps - whole
        pb = p_exp_neg(F(1), steps) ** whole * p_exp_neg(frac, steps)
        rho = (1 - pb) / 2
        p_flip = (pb / 2) * (1 - rho**rounds) / (1 - rho)
        e_lo, e_hi = exp_neg_bounds(eps)
        # target q = e^-ε / (1 + e^-ε) is increasing in e^-ε
        q_lo, q_hi = e_lo / (1 + e_lo), e_hi / (1 + e_hi)
        err = max(abs(p_flip - q_lo), abs(p_flip - q_hi))
        # uniform draws: den / 2^256 each; den < 2^96 · 32 for the step ratios
        draws = rounds * (whole + 1) * steps
        bias = F(draws * (1 << 101), 1 << 256)
        total = err + bias
        checked += 1
        bits = (total.denominator // max(total.numerator, 1)).bit_length() - 1
        print(f"ε = {eps_f}: |P(flip) − 1/(1+e^ε)| + uniform bias < 2^-{bits}")
        if total > bound:
            problems.append(f"ε = {eps_f}: error {float(total):.3e} exceeds 2^-{BOUND_BITS}")
    for p in problems:
        print(f"error: {p}", file=sys.stderr)
    if checked == 0:
        print("error: compared nothing", file=sys.stderr)
        return 1
    print(f"dp_rr_exact: {checked} ε values, {len(problems)} problems")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
