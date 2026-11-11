//! A privacy budget across releases: sequential composition of `(ε, δ)`
//!
//! Every release of a mechanism in [`crate::dp`] is `(ε_eff, δ)`-differentially private on its own (the module doc
//! of [`crate::dp`]). Releasing several about the same people adds up: by basic sequential composition the
//! releases together are `(Σ ε_eff, Σ δ)`-differentially private. [`PrivacyBudget`] keeps that sum. Each release
//! goes through it: the release's cost is worked out from its parameters, checked against what is left, charged,
//! and only then is the noise drawn. A release that would go past the budget is refused before anything is drawn,
//! so a refused release changes nothing, neither the budget nor the random source.
//!
//! # The accounting is exact and errs on the safe side
//!
//! ε is kept in integer units of `2^-64` and δ in units of `2^-128` (`u128`), so sums are exact and do not depend on
//! the order of the releases. A release is charged at least its true cost and a budget is set at most to what was
//! asked:
//!
//! - ε: the release's `ε_eff` as an exact rational (the `f64` ε is a dyadic rational; for the lattice mechanisms
//!   `ε_eff = ε · Λ · (⌊Δ/Λ⌋ + 1) / Δ`, [`crate::dp::DpNoise::effective_epsilon`]), rounded **up** to a unit
//! - δ: the module's `δ = (1 + e^ε_eff) · η` with `η < 2^-103` for the discrete Laplace mechanisms ([`count`],
//!   [`int`], [`sum`]) and `η ≤ 2^-100` for [`randomized_response`] (`scripts/dp_rr_exact.py`), with `e^ε_eff`
//!   bounded above by `2^k`, `k = ⌈1.4427 · ε_eff⌉` (`log2 e = 1.44269… < 1.4427`): charged
//!   `(1 + 2^k) · 2^(128 − 103)` or `(1 + 2^k) · 2^(128 − 100)` units, an integer upper bound
//! - the budget: ε and δ rounded **down** to a unit
//!
//! ⚠️ Basic composition is the plain sum. Tighter bounds exist for many releases (advanced composition, Rényi or
//! zero-concentrated accounting); they are not used, so the sum here never claims more privacy than holds.
//!
//! # What is charged when a release fails
//!
//! Parameters that a mechanism would refuse (ε not finite and positive, out of the sampler's range, a value too
//! large for its lattice, a count that does not fit an `i64`) are checked before the charge, with the mechanism's
//! own checks: such a call changes nothing. A release that fails after its noise is drawn (the noisy count or sum
//! overflows) stays charged: whether it failed depends on the noise, so the failure itself tells something.
//!
//! [`count`]: PrivacyBudget::count
//! [`int`]: PrivacyBudget::int
//! [`sum`]: PrivacyBudget::sum
//! [`randomized_response`]: PrivacyBudget::randomized_response

use super::{
    dp_count, dp_int, dp_sum, dyadic, exp_neg_whole_steps, int_rate, lattice_and_rate,
    randomized_response, ratio_from_parts, round_to_lattice, DpError, SecureRng,
    RR_MAX_EPSILON_WHOLE,
};

/// ε is kept in units of `2^-EPSILON_UNIT_BITS`
pub const EPSILON_UNIT_BITS: u32 = 64;
/// δ is kept in units of `2^-DELTA_UNIT_BITS`
pub const DELTA_UNIT_BITS: u32 = 128;
/// The largest ε a budget may be set to: `e^ε` stays within the δ units (`2^⌈1.4427 · 64⌉ · 2^28 < 2^128`) and a
/// budget past it protects nothing anyway
pub const BUDGET_MAX_EPSILON: f64 = 64.0;
/// `η < 2^-ETA_LAPLACE_BITS` per release of the discrete Laplace mechanisms (the module doc of [`crate::dp`])
const ETA_LAPLACE_BITS: u32 = 103;
/// `η ≤ 2^-ETA_RR_BITS` per release of randomized response (`scripts/dp_rr_exact.py`)
const ETA_RR_BITS: u32 = 100;

/// Why a budget could not be set, or a release was not made
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BudgetError {
    /// The budget's ε is not in `(0, BUDGET_MAX_EPSILON]` or its δ not in `(0, 1)`, or either rounds to 0 units
    InvalidBudget,
    /// The release would take ε or δ past the budget: refused, nothing was charged or drawn
    Exceeded {
        /// The release's ε, in units of `2^-64`
        epsilon_cost: u128,
        /// The ε left, in units of `2^-64`
        epsilon_left: u128,
        /// The release's δ, in units of `2^-128`
        delta_cost: u128,
        /// The δ left, in units of `2^-128`
        delta_left: u128,
    },
    /// The mechanism refused its parameters (nothing charged or drawn) or failed after drawing (charged)
    Dp(DpError),
}

impl core::fmt::Display for BudgetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidBudget => {
                f.write_str("a budget needs 0 < epsilon <= 64 and 0 < delta < 1")
            }
            Self::Exceeded { .. } => f.write_str("the release would go past the privacy budget"),
            Self::Dp(e) => write!(f, "{e}"),
        }
    }
}

#[cfg(feature = "std-base")]
impl std::error::Error for BudgetError {}

impl From<DpError> for BudgetError {
    fn from(e: DpError) -> Self {
        Self::Dp(e)
    }
}

/// What one release costs, in units
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Cost {
    epsilon: u128,
    delta: u128,
}

/// `⌈a · 2^shift / b⌉` for `a, b > 0`, `None` when the result does not fit a `u128`; a quotient below one unit is one
fn ceil_scaled(a: u128, b: u128, shift: i64) -> Option<u128> {
    if shift >= 0 {
        let s = u32::try_from(shift).ok()?;
        let num = a.checked_shl(s).filter(|n| n >> s == a)?;
        Some(num.div_ceil(b))
    } else {
        // a / (b · 2^-shift): when the divisor does not fit, the quotient is below one and rounds up to 1
        let s = u32::try_from(-shift).ok()?;
        match b.checked_shl(s).filter(|d| d >> s == b) {
            Some(d) => Some(a.div_ceil(d)),
            None => Some(1),
        }
    }
}

/// `⌊m · 2^(e + bits)⌋` for an `f64` written `m · 2^e`, `None` when it does not fit
fn floor_units(m: u64, e: i32, bits: u32) -> Option<u128> {
    let shift = i64::from(e) + i64::from(bits);
    let m = u128::from(m);
    if shift >= 0 {
        let s = u32::try_from(shift).ok()?;
        m.checked_shl(s).filter(|v| v >> s == m)
    } else {
        let s = u32::try_from(-shift).ok()?;
        Some(if s >= 128 { 0 } else { m >> s })
    }
}

/// The δ units of a release with `epsilon` units of ε and `η ≤ 2^-eta_bits`: `(1 + 2^k) · 2^(128 − eta_bits)`,
/// `k = ⌈1.4427 · ε⌉`
fn delta_cost(epsilon: u128, eta_bits: u32) -> Option<u128> {
    // k = ⌈ε_units · 14427 / (10000 · 2^64)⌉
    let k = (epsilon.checked_mul(14_427)?).div_ceil(10_000u128 << EPSILON_UNIT_BITS);
    let k = u32::try_from(k).ok()?;
    let e_bound = 1u128.checked_shl(k).filter(|v| v.trailing_zeros() == k)?;
    (1 + e_bound).checked_mul(1u128.checked_shl(DELTA_UNIT_BITS - eta_bits)?)
}

/// The cost of a release with ε exactly `epsilon` (the integer-lattice mechanisms)
fn plain_cost(epsilon: f64, eta_bits: u32) -> Result<Cost, DpError> {
    let (m, e) = dyadic(epsilon).ok_or(DpError::InvalidScale)?;
    let eps = ceil_scaled(
        u128::from(m),
        1,
        i64::from(e) + i64::from(EPSILON_UNIT_BITS),
    )
    .ok_or(DpError::EpsilonOutOfRange)?;
    let delta = delta_cost(eps, eta_bits).ok_or(DpError::EpsilonOutOfRange)?;
    Ok(Cost {
        epsilon: eps,
        delta,
    })
}

/// The cost of a lattice release (sensitivity Δ, ε): `ε_eff = ε · Λ · (⌊Δ/Λ⌋ + 1) / Δ` rounded up, exactly
fn lattice_cost(sensitivity: f64, epsilon: f64, lattice: f64) -> Result<Cost, DpError> {
    let (me, ee) = dyadic(epsilon).ok_or(DpError::InvalidScale)?;
    let (md, ed) = dyadic(sensitivity).ok_or(DpError::InvalidScale)?;
    let (ml, el) = dyadic(lattice).ok_or(DpError::ValueOutOfRange)?;
    debug_assert_eq!(ml, 1, "the lattice is a power of two");
    // ⌊Δ/Λ⌋ is exact: Λ is a power of two
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let steps = (sensitivity / lattice) as u64 + 1;
    let num = u128::from(me)
        .checked_mul(u128::from(steps))
        .ok_or(DpError::EpsilonOutOfRange)?;
    let shift = i64::from(ee) + i64::from(el) - i64::from(ed) + i64::from(EPSILON_UNIT_BITS);
    let eps = ceil_scaled(num, u128::from(md), shift).ok_or(DpError::EpsilonOutOfRange)?;
    let delta = delta_cost(eps, ETA_LAPLACE_BITS).ok_or(DpError::EpsilonOutOfRange)?;
    Ok(Cost {
        epsilon: eps,
        delta,
    })
}

/// A privacy budget `(ε, δ)` that every release is charged against (sequential composition)
///
/// ```
/// use alice_crypto::dp::budget::{BudgetError, PrivacyBudget};
/// use alice_crypto::dp::SecureRng;
///
/// let mut rng = SecureRng::from_key([7u8; 32]);
/// let mut budget = PrivacyBudget::new(1.0, 1e-9).unwrap();
/// budget.count(120, 0.5, &mut rng).unwrap();
/// budget.randomized_response(true, 0.5, &mut rng).unwrap();
/// // 0.5 + 0.5 is the whole ε: the next release is refused and nothing is drawn
/// assert!(matches!(budget.count(3, 0.25, &mut rng), Err(BudgetError::Exceeded { .. })));
/// assert_eq!(budget.epsilon_left_units(), 0);
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivacyBudget {
    epsilon_limit: u128,
    epsilon_spent: u128,
    delta_limit: u128,
    delta_spent: u128,
    releases: u64,
}

impl PrivacyBudget {
    /// A budget of `(epsilon, delta)`, each rounded down to a unit
    ///
    /// # Errors
    ///
    /// [`BudgetError::InvalidBudget`] unless `0 < epsilon <= BUDGET_MAX_EPSILON` and `0 < delta < 1` and neither
    /// rounds to 0 units.
    pub fn new(epsilon: f64, delta: f64) -> Result<Self, BudgetError> {
        if !(epsilon > 0.0 && epsilon <= BUDGET_MAX_EPSILON && delta > 0.0 && delta < 1.0) {
            return Err(BudgetError::InvalidBudget);
        }
        let (me, ee) = dyadic(epsilon).ok_or(BudgetError::InvalidBudget)?;
        let (md, ed) = dyadic(delta).ok_or(BudgetError::InvalidBudget)?;
        let epsilon_limit =
            floor_units(me, ee, EPSILON_UNIT_BITS).ok_or(BudgetError::InvalidBudget)?;
        let delta_limit = floor_units(md, ed, DELTA_UNIT_BITS).ok_or(BudgetError::InvalidBudget)?;
        if epsilon_limit == 0 || delta_limit == 0 {
            return Err(BudgetError::InvalidBudget);
        }
        Ok(Self {
            epsilon_limit,
            epsilon_spent: 0,
            delta_limit,
            delta_spent: 0,
            releases: 0,
        })
    }

    /// Check a release's cost against what is left and charge it, or refuse and change nothing
    fn charge(&mut self, cost: Cost) -> Result<(), BudgetError> {
        let epsilon_left = self.epsilon_left_units();
        let delta_left = self.delta_left_units();
        if cost.epsilon > epsilon_left || cost.delta > delta_left {
            return Err(BudgetError::Exceeded {
                epsilon_cost: cost.epsilon,
                epsilon_left,
                delta_cost: cost.delta,
                delta_left,
            });
        }
        self.epsilon_spent += cost.epsilon;
        self.delta_spent += cost.delta;
        self.releases += 1;
        Ok(())
    }

    /// [`dp_count`] charged against the budget: `ε` exactly, the discrete Laplace δ
    ///
    /// # Errors
    ///
    /// [`BudgetError::Exceeded`] or the parameter errors of [`dp_count`] (nothing charged or drawn);
    /// [`DpError::CountOutOfRange`] for a noisy count that overflows (charged).
    pub fn count(
        &mut self,
        true_count: u64,
        epsilon: f64,
        rng: &mut SecureRng,
    ) -> Result<i64, BudgetError> {
        let (m, e) = dyadic(epsilon).ok_or(DpError::InvalidScale)?;
        ratio_from_parts(m, 1, e).ok_or(DpError::EpsilonOutOfRange)?;
        i64::try_from(true_count).map_err(|_| DpError::CountOutOfRange)?;
        self.charge(plain_cost(epsilon, ETA_LAPLACE_BITS)?)?;
        Ok(dp_count(true_count, epsilon, rng)?)
    }

    /// [`dp_int`] charged against the budget: `ε` exactly (sensitivity Δ is in the mechanism's decay), the
    /// discrete Laplace δ
    ///
    /// # Errors
    ///
    /// As [`Self::count`], with the parameter errors of [`dp_int`].
    pub fn int(
        &mut self,
        value: i64,
        sensitivity: u64,
        epsilon: f64,
        rng: &mut SecureRng,
    ) -> Result<i64, BudgetError> {
        int_rate(sensitivity, epsilon)?;
        self.charge(plain_cost(epsilon, ETA_LAPLACE_BITS)?)?;
        Ok(dp_int(value, sensitivity, epsilon, rng)?)
    }

    /// [`randomized_response`] charged against the budget: `ε` exactly, the randomized-response δ
    ///
    /// # Errors
    ///
    /// [`BudgetError::Exceeded`] or the parameter errors of [`randomized_response`] (nothing charged or drawn).
    pub fn randomized_response(
        &mut self,
        bit: bool,
        epsilon: f64,
        rng: &mut SecureRng,
    ) -> Result<bool, BudgetError> {
        let (m, e) = dyadic(epsilon).ok_or(DpError::InvalidScale)?;
        let rate = ratio_from_parts(m, 1, e).ok_or(DpError::EpsilonOutOfRange)?;
        if exp_neg_whole_steps(rate) > u128::from(RR_MAX_EPSILON_WHOLE) {
            return Err(DpError::EpsilonOutOfRange.into());
        }
        self.charge(plain_cost(epsilon, ETA_RR_BITS)?)?;
        Ok(randomized_response(bit, epsilon, rng)?)
    }

    /// [`dp_sum`] charged against the budget: its `ε_eff` (the lattice's rounding included), the discrete Laplace δ
    ///
    /// # Errors
    ///
    /// [`BudgetError::Exceeded`] or the parameter errors of [`dp_sum`] (nothing charged or drawn);
    /// [`DpError::ValueOutOfRange`] for a noisy sum past its lattice (charged).
    pub fn sum(
        &mut self,
        true_sum: f64,
        sensitivity: f64,
        epsilon: f64,
        rng: &mut SecureRng,
    ) -> Result<f64, BudgetError> {
        let (lattice, _) = lattice_and_rate(sensitivity, epsilon)?;
        round_to_lattice(true_sum, lattice)?;
        self.charge(lattice_cost(sensitivity, epsilon, lattice)?)?;
        Ok(dp_sum(true_sum, sensitivity, epsilon, rng)?)
    }

    /// ε spent so far, in units of `2^-64`
    #[must_use]
    pub const fn epsilon_spent_units(&self) -> u128 {
        self.epsilon_spent
    }

    /// ε left, in units of `2^-64`
    #[must_use]
    pub const fn epsilon_left_units(&self) -> u128 {
        self.epsilon_limit - self.epsilon_spent
    }

    /// δ spent so far, in units of `2^-128`
    #[must_use]
    pub const fn delta_spent_units(&self) -> u128 {
        self.delta_spent
    }

    /// δ left, in units of `2^-128`
    #[must_use]
    pub const fn delta_left_units(&self) -> u128 {
        self.delta_limit - self.delta_spent
    }

    /// The budget's ε, in units of `2^-64` (what was asked, rounded down)
    #[must_use]
    pub const fn epsilon_limit_units(&self) -> u128 {
        self.epsilon_limit
    }

    /// The budget's δ, in units of `2^-128` (what was asked, rounded down)
    #[must_use]
    pub const fn delta_limit_units(&self) -> u128 {
        self.delta_limit
    }

    /// ε left as an `f64` (the unit count over `2^64`, rounded to the nearest `f64`: for display, not for
    /// deciding; decide with [`Self::epsilon_left_units`])
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn epsilon_left(&self) -> f64 {
        self.epsilon_left_units() as f64 / 18_446_744_073_709_551_616.0
    }

    /// Releases charged so far (refused ones are not counted)
    #[must_use]
    pub const fn releases(&self) -> u64 {
        self.releases
    }
}
