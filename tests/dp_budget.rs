//! A privacy budget across releases (`dp::budget`): sequential composition of `(ε, δ)`
//!
//! oracle: the charges and the budget are the closed form of basic composition, `(Σ ε_eff, Σ δ)`, worked out with
//! exact rationals by `scripts/dp_budget_exact.py` from the definitions in the module doc (not from this crate) and
//! pinned here; a refused release changes neither the budget nor the random source (compared with a twin source
//! that only made the releases that were allowed); the budget draws nothing of its own, so its outputs are the bare
//! mechanisms' outputs under the same key.

#![allow(clippy::float_cmp, clippy::unreadable_literal)]

use alice_crypto::dp::budget::{BudgetError, PrivacyBudget, BUDGET_MAX_EPSILON};
use alice_crypto::dp::{
    dp_count, dp_int, dp_sum, randomized_response, DpError, DpNoise, SecureRng,
};

const KEY: [u8; 32] = [42u8; 32];

/// The units of each release of the sequence, from `scripts/dp_budget_exact.py`
const EPS: [u128; 6] = [
    9223372036854775808,
    4611686018427387904,
    1844675580183358226,
    614891469123651712,
    3689348814741910528,
    1844674407370955264,
];
const DELTA: [u128; 6] = [
    100663296, 805306368, 100663296, 100663296, 100663296, 100663296,
];
const EPS_LIMIT: u128 = 18446744073709551616;
const DELTA_LIMIT: u128 = 340282366920938484656701964288;

#[test]
fn the_charges_are_the_exact_closed_form() {
    let mut b = PrivacyBudget::new(1.0, 1e-9).unwrap();
    assert_eq!(b.epsilon_limit_units(), EPS_LIMIT);
    assert_eq!(b.delta_limit_units(), DELTA_LIMIT);
    let mut rng = SecureRng::from_key(KEY);
    let (mut eps, mut delta) = (0u128, 0u128);
    let mut step = |b: &PrivacyBudget, i: usize, made: bool| {
        if made {
            eps += EPS[i];
            delta += DELTA[i];
        }
        assert_eq!(b.epsilon_spent_units(), eps, "release {i}: ε");
        assert_eq!(b.delta_spent_units(), delta, "release {i}: δ");
    };
    b.count(100, 0.5, &mut rng).unwrap();
    step(&b, 0, true);
    b.randomized_response(true, 0.25, &mut rng).unwrap();
    step(&b, 1, true);
    b.sum(12.5, 3.0, 0.1, &mut rng).unwrap();
    step(&b, 2, true);
    b.int(-7, 2, 1.0 / 30.0, &mut rng).unwrap();
    step(&b, 3, true);
    let refused = b.count(5, 0.2, &mut rng);
    assert_eq!(
        refused,
        Err(BudgetError::Exceeded {
            epsilon_cost: EPS[4],
            epsilon_left: EPS_LIMIT - EPS[..4].iter().sum::<u128>(),
            delta_cost: DELTA[4],
            delta_left: DELTA_LIMIT - DELTA[..4].iter().sum::<u128>(),
        })
    );
    step(&b, 4, false);
    b.count(5, 0.1, &mut rng).unwrap();
    step(&b, 5, true);
    assert_eq!(b.releases(), 5);
    assert_eq!(b.epsilon_left_units(), 307444561749422702);
    assert_eq!(b.delta_left_units(), 340282366920938484655494004736);
}

#[test]
fn a_refused_release_changes_nothing() {
    // the budget is spent down to 0.25 of ε, then a release of 0.5 is refused: the budget and the random source are
    // as a twin's that made only the allowed releases
    let mut b = PrivacyBudget::new(1.0, 1e-9).unwrap();
    let mut rng = SecureRng::from_key(KEY);
    let mut twin = SecureRng::from_key(KEY);
    b.count(10, 0.5, &mut rng).unwrap();
    dp_count(10, 0.5, &mut twin).unwrap();
    b.randomized_response(false, 0.25, &mut rng).unwrap();
    randomized_response(false, 0.25, &mut twin).unwrap();
    let before = b.clone();
    for refused in [
        b.count(3, 0.5, &mut rng).map(|_| ()),
        b.randomized_response(true, 0.5, &mut rng).map(|_| ()),
        b.int(3, 1, 0.5, &mut rng).map(|_| ()),
        b.sum(1.0, 1.0, 0.5, &mut rng).map(|_| ()),
    ] {
        assert!(
            matches!(refused, Err(BudgetError::Exceeded { .. })),
            "{refused:?}"
        );
    }
    // parameters the mechanisms refuse: nothing charged, nothing drawn
    for bad in [
        b.count(3, f64::NAN, &mut rng).map(|_| ()),
        b.count(u64::MAX, 0.1, &mut rng).map(|_| ()),
        b.randomized_response(true, 100.0, &mut rng).map(|_| ()),
        b.int(3, 0, 0.1, &mut rng).map(|_| ()),
        b.sum(1e300, 1.0, 0.1, &mut rng).map(|_| ()),
        b.sum(1.0, -1.0, 0.1, &mut rng).map(|_| ()),
    ] {
        assert!(matches!(bad, Err(BudgetError::Dp(_))), "{bad:?}");
    }
    assert_eq!(b, before, "the budget is unchanged");
    assert_eq!(
        rng.next_u64(),
        twin.next_u64(),
        "the random source is unchanged"
    );
}

#[test]
fn the_budget_draws_nothing_of_its_own_and_repeats_under_the_same_key() {
    let run = || {
        let mut b = PrivacyBudget::new(4.0, 1e-6).unwrap();
        let mut rng = SecureRng::from_key(KEY);
        let out = (
            b.count(1_000, 0.5, &mut rng).unwrap(),
            b.randomized_response(true, 1.0, &mut rng).unwrap(),
            b.sum(123.25, 10.0, 0.5, &mut rng).unwrap().to_bits(),
            b.int(-40, 3, 0.75, &mut rng).unwrap(),
        );
        (out, b, rng.next_u64())
    };
    let (a, ba, na) = run();
    let (c, bc, nc) = run();
    assert_eq!(a, c);
    assert_eq!(ba, bc);
    assert_eq!(na, nc);
    // the bare mechanisms under the same key, in the same order
    let mut rng = SecureRng::from_key(KEY);
    let bare = (
        dp_count(1_000, 0.5, &mut rng).unwrap(),
        randomized_response(true, 1.0, &mut rng).unwrap(),
        dp_sum(123.25, 10.0, 0.5, &mut rng).unwrap().to_bits(),
        dp_int(-40, 3, 0.75, &mut rng).unwrap(),
    );
    assert_eq!(a, bare);
    assert_eq!(na, rng.next_u64());
}

#[test]
fn a_release_that_fits_exactly_is_made_and_the_next_is_not() {
    let mut b = PrivacyBudget::new(1.0, 1e-9).unwrap();
    let mut rng = SecureRng::from_key(KEY);
    b.count(1, 0.5, &mut rng).unwrap();
    b.count(1, 0.5, &mut rng).unwrap();
    assert_eq!(b.epsilon_left_units(), 0);
    assert_eq!(b.epsilon_left(), 0.0);
    // the smallest ε a release can cost is one unit
    assert!(matches!(
        b.count(1, 1e-12, &mut rng),
        Err(BudgetError::Exceeded {
            epsilon_cost: 18446745,
            ..
        })
    ));
}

#[test]
fn a_release_that_fails_after_its_draw_stays_charged() {
    // a count at the top of i64: whether count + noise overflows depends on the noise, so the failure tells
    // something and is charged
    let mut found = false;
    for k in 0u8..64 {
        let mut b = PrivacyBudget::new(8.0, 1e-6).unwrap();
        let mut rng = SecureRng::from_key([k; 32]);
        match b.count(i64::MAX as u64, 0.5, &mut rng) {
            Err(BudgetError::Dp(DpError::CountOutOfRange)) => {
                assert_eq!(b.epsilon_spent_units(), 1u128 << 63);
                assert_eq!(b.releases(), 1);
                found = true;
                break;
            }
            Ok(_) => assert_eq!(b.releases(), 1),
            Err(e) => panic!("{e:?}"),
        }
    }
    assert!(found, "no key gave noise above 0 in 64 tries");
}

#[test]
fn a_sum_is_charged_its_effective_epsilon() {
    // ε_eff of the lattice: what DpNoise reports, rounded up to the unit and no further
    for (sensitivity, epsilon) in [(3.0, 0.1), (10.0, 0.5), (0.75, 2.0), (1.0, 0.125)] {
        let mut b = PrivacyBudget::new(8.0, 1e-6).unwrap();
        let mut rng = SecureRng::from_key(KEY);
        b.sum(1.0, sensitivity, epsilon, &mut rng).unwrap();
        let eff = DpNoise::with_key(sensitivity, epsilon, KEY).effective_epsilon();
        let units = b.epsilon_spent_units() as f64 / 18_446_744_073_709_551_616.0;
        assert!(
            units >= eff * (1.0 - 1e-15),
            "{sensitivity} {epsilon}: {units} < {eff}"
        );
        assert!(
            units <= eff * (1.0 + 1e-15) + 1e-19,
            "{sensitivity} {epsilon}: {units} > {eff}"
        );
        assert!(eff >= epsilon, "the lattice never lowers ε");
    }
}

#[test]
fn a_sum_scaled_up_is_rounded_up_exactly() {
    // ε_eff · 2^64 is reached with a left shift here and is not a whole number of units: the charge is the
    // ceiling, from `scripts/dp_budget_exact.py` (single sum lines)
    for (sensitivity, epsilon, eps_units, delta_units) in [
        (0.75, 2.0, 36893511603667162454u128, 301989888u128),
        (3.0, 7.0, 129127290612835068587, 68753031168),
    ] {
        let mut b = PrivacyBudget::new(BUDGET_MAX_EPSILON, 1e-6).unwrap();
        let mut rng = SecureRng::from_key(KEY);
        b.sum(1.0, sensitivity, epsilon, &mut rng).unwrap();
        assert_eq!(
            b.epsilon_spent_units(),
            eps_units,
            "{sensitivity} {epsilon}: ε"
        );
        assert_eq!(
            b.delta_spent_units(),
            delta_units,
            "{sensitivity} {epsilon}: δ"
        );
    }
}

#[test]
fn a_budget_outside_its_range_is_refused() {
    for (e, d) in [
        (0.0, 1e-9),
        (-1.0, 1e-9),
        (f64::NAN, 1e-9),
        (f64::INFINITY, 1e-9),
        (BUDGET_MAX_EPSILON * (1.0 + f64::EPSILON), 1e-9),
        (1.0, 0.0),
        (1.0, 1.0),
        (1.0, f64::NAN),
        // 2^-129 and 2^-65 (biased exponents 894 and 958): each rounds to 0 units
        (1.0, f64::from_bits(894 << 52)),
        (f64::from_bits(958 << 52), 1e-9),
    ] {
        assert_eq!(
            PrivacyBudget::new(e, d),
            Err(BudgetError::InvalidBudget),
            "{e} {d}"
        );
    }
    assert!(PrivacyBudget::new(BUDGET_MAX_EPSILON, 0.5).is_ok());
}
