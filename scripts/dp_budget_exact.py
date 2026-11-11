#!/usr/bin/env python3
"""The privacy budget of src/dp/budget.rs, worked out with exact rationals

For one fixed sequence of releases (the one tests/dp_budget.rs runs) this computes, with `fractions.Fraction` and
no floating point, what each release costs and what the budget holds, from the definitions in the module doc and
not from the Rust code:

- ε of a release: `ε_eff` rounded up to a unit of 2^-64; `ε_eff = ε` for count, int and randomized response, and
  `ε · Λ · (⌊Δ/Λ⌋ + 1) / Δ` with `Λ = 2^(⌊log2 Δ⌋ − 20)` for sum
- δ of a release: `(1 + 2^k) · 2^(128 − η_bits)` units of 2^-128, `k = ⌈1.4427 · ε_units / 2^64⌉`, η_bits 103
  (discrete Laplace) or 100 (randomized response)
- the budget: ε and δ rounded down to their units
- a release is made when its ε and δ both fit what is left, refused (nothing charged) otherwise

It also checks that each δ charge bounds the module's `δ = (1 + e^ε_eff) · η` from above, with `e^x` bounded above
exactly by its Taylor sum plus a remainder bound. The numbers it prints are the ones the test pins. 0 releases
compared fails.

usage: scripts/dp_budget_exact.py
"""
from __future__ import annotations

import math
import sys
from fractions import Fraction as F

EPS_UNIT = 2**64
DELTA_UNIT = 2**128

# (kind, parameters): the sequence of tests/dp_budget.rs::the_charges_are_the_exact_closed_form
BUDGET = (1.0, 1e-9)
RELEASES = [
    ("count", {"epsilon": 0.5}),
    ("rr", {"epsilon": 0.25}),
    ("sum", {"sensitivity": 3.0, "epsilon": 0.1}),
    ("int", {"sensitivity": 2, "epsilon": 1.0 / 30.0}),
    ("count", {"epsilon": 0.2}),  # past the budget: refused
    ("count", {"epsilon": 0.1}),  # fits what is left
]
# a budget whose δ runs out while ε is still left (tests/dp_budget.rs::a_release_past_the_delta_budget_is_refused):
# δ = 15 · 2^-104 is 2.5 Laplace releases of k = 1, so the third release is refused on δ alone
DELTA_BUDGET = (10.0, 15 * 2.0**-104)
DELTA_RELEASES = [
    ("count", {"epsilon": 0.5}),
    ("count", {"epsilon": 0.5}),
    ("count", {"epsilon": 0.5}),  # ε fits, δ does not: refused
]
# single sum releases whose ε_eff · 2^64 is reached with a left shift (tests/dp_budget.rs::
# a_sum_scaled_up_is_rounded_up_exactly): each is a non-integer number of units, so rounding down would show
SINGLE_SUMS = [(0.75, 2.0), (3.0, 7.0)]


def ceil_div(a: F) -> int:
    return -((-a.numerator) // a.denominator)


def floor_log2(x: F) -> int:
    k = x.numerator.bit_length() - x.denominator.bit_length()
    while F(2) ** k > x:
        k -= 1
    while F(2) ** (k + 1) <= x:
        k += 1
    return k


def eps_eff(kind: str, p: dict) -> F:
    eps = F(p["epsilon"])
    if kind != "sum":
        return eps
    delta = F(p["sensitivity"])
    lattice = F(2) ** (floor_log2(delta) - 20)
    steps = math.floor(delta / lattice) + 1
    return eps * lattice * steps / delta


def exp_upper(x: F, terms: int = 60) -> F:
    """e^x <= Σ_{n<N} x^n/n! + x^N/N! · 2 for 0 <= x <= N/2 (the tail is at most twice its first term)"""
    assert 0 <= x <= F(terms, 2)
    s, t = F(0), F(1)
    for n in range(terms):
        s += t
        t = t * x / (n + 1)
    return s + 2 * t


def simulate(label: str, budget: tuple[float, float], releases: list) -> int | None:
    """the releases against the budget; the number compared, None on a failed bound"""
    eps_limit = math.floor(F(budget[0]) * EPS_UNIT)
    delta_limit = math.floor(F(budget[1]) * DELTA_UNIT)
    eps_spent = delta_spent = 0
    made = 0
    compared = 0
    print(f"{label} budget eps_units={eps_limit} delta_units={delta_limit}")
    for kind, p in releases:
        e_eff = eps_eff(kind, p)
        e_units = ceil_div(e_eff * EPS_UNIT)
        k = ceil_div(F(e_units * 14427, 10000 * EPS_UNIT))
        eta_bits = 100 if kind == "rr" else 103
        d_units = (1 + 2**k) * 2 ** (128 - eta_bits)
        # the charge bounds the module's δ from above: (1 + e^ε_eff) · 2^-η_bits <= d_units / 2^128
        true_delta = (1 + exp_upper(e_eff)) * F(1, 2**eta_bits)
        if not true_delta <= F(d_units, DELTA_UNIT):
            print(f"FAIL {kind} {p}: the δ charge does not bound (1 + e^ε) η", file=sys.stderr)
            return None
        if not F(e_units, EPS_UNIT) >= e_eff:
            print(f"FAIL {kind} {p}: the ε charge is below ε_eff", file=sys.stderr)
            return None
        eps_fits = e_units <= eps_limit - eps_spent
        delta_fits = d_units <= delta_limit - delta_spent
        fits = eps_fits and delta_fits
        if fits:
            eps_spent += e_units
            delta_spent += d_units
            made += 1
        compared += 1
        why = "made" if fits else ("refused on delta only" if eps_fits else "refused")
        print(f"{label} {kind} {p} eps_units={e_units} delta_units={d_units} {why}")
    print(f"{label} spent eps_units={eps_spent} delta_units={delta_spent} releases={made}")
    print(f"{label} left eps_units={eps_limit - eps_spent} delta_units={delta_limit - delta_spent}")
    return compared


def main() -> int:
    compared = 0
    for label, budget, releases in (("seq", BUDGET, RELEASES), ("delta", DELTA_BUDGET, DELTA_RELEASES)):
        n = simulate(label, budget, releases)
        if n is None:
            return 1
        compared += n
    for sensitivity, epsilon in SINGLE_SUMS:
        e_eff = eps_eff("sum", {"sensitivity": sensitivity, "epsilon": epsilon})
        scaled = e_eff * EPS_UNIT
        if scaled.denominator == 1:
            print(f"FAIL sum {sensitivity} {epsilon}: a whole number of units does not test the rounding", file=sys.stderr)
            return 1
        e_units = ceil_div(scaled)
        k = ceil_div(F(e_units * 14427, 10000 * EPS_UNIT))
        d_units = (1 + 2**k) * 2 ** (128 - 103)
        compared += 1
        print(f"single sum sensitivity={sensitivity} epsilon={epsilon} eps_units={e_units} delta_units={d_units}")
    if compared == 0:
        print("FAIL: 0 releases compared", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
