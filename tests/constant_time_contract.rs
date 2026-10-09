//! The contract behind `src/lib.rs` § Timing behaviour, as executable checks.
//!
//! Two kinds of property live here:
//!
//! 1. **Value correctness of the branch-free variants.** Making `inv` / `div` /
//!    `batch_inv` stop branching on their input only counts if the values they
//!    produce are still the mathematically right ones. The expected values come
//!    from the *definition* of a multiplicative inverse in GF(2^8)
//!    (`a * a^-1 = 1`), checked exhaustively over all 256 elements — not from
//!    the implementation's own output.
//! 2. **Behaviour that must not depend on where a secret value sits.**
//!    `batch_inv` has to report "some input was zero" identically no matter
//!    which position the zero is in, and the MAC-tag comparison has to reject a
//!    tag that differs in its last byte exactly as it rejects one that differs
//!    in its first.
//!
//! The timing property itself (same amount of work regardless of the values) is
//! not measured here — wall-clock measurement in CI is too noisy to be a gate.
//! It is enforced statically by `scripts/constant_time_guard.py`, which runs in
//! `preflight.sh` and in CI.

use alice_crypto::gf256::{batch_inv, batch_inv_stack, GF};
use alice_crypto::signature::{sign, verify, Signature, SigningKey};

// ---------------------------------------------------------------------------
// GF(2^8) inverse: branch-free variant vs the definition
// ---------------------------------------------------------------------------

#[test]
fn inv_or_zero_matches_the_definition_of_an_inverse_on_all_256_elements() {
    // Oracle: `a * a^-1 = 1` for every non-zero a, and 0 has no inverse so the
    // branch-free variant is specified to return 0.
    assert_eq!(GF::ZERO.inv_or_zero(), GF::ZERO, "0 の逆元は 0 と規定");

    let mut checked = 0u32;
    for v in 1u16..=255 {
        let a = GF(v as u8);
        let r = a.inv_or_zero();
        assert_ne!(
            r,
            GF::ZERO,
            "a = {v}: 非零の逆元が 0 になった (`inv` の零判定が壊れる)"
        );
        assert_eq!(a.mul(r), GF::ONE, "a = {v}: a * inv(a) が 1 でない");
        checked += 1;
    }
    assert_eq!(checked, 255, "比較件数が 255 でない (走査が成立していない)");
}

#[test]
fn inv_returns_none_exactly_for_zero_and_otherwise_agrees_with_inv_or_zero() {
    // `inv` は早期 return を捨てた代わりに、最後に `inv_or_zero` の結果の
    // 零判定で `None` を作る この 2 つが同値であることが置き換えの前提
    assert!(GF::ZERO.inv().is_none());
    let mut checked = 0u32;
    for v in 1u16..=255 {
        let a = GF(v as u8);
        assert_eq!(a.inv(), Some(a.inv_or_zero()), "a = {v}");
        checked += 1;
    }
    assert_eq!(checked, 255);
}

#[test]
fn div_and_div_or_zero_agree_with_multiplication_by_the_inverse() {
    let mut checked = 0u32;
    for av in 0u16..=255 {
        let a = GF(av as u8);
        assert_eq!(a.div(GF::ZERO), None, "a = {av}: 0 除算が None でない");
        assert_eq!(
            a.div_or_zero(GF::ZERO),
            GF::ZERO,
            "a = {av}: 0 除算の分岐なし版が 0 でない"
        );
        for bv in 1u16..=255 {
            let b = GF(bv as u8);
            let want = a.mul(b.inv_or_zero());
            assert_eq!(a.div(b), Some(want), "{av} / {bv}");
            assert_eq!(a.div_or_zero(b), want, "{av} / {bv} (分岐なし版)");
            checked += 1;
        }
    }
    assert_eq!(checked, 256 * 255, "比較件数が合わない");
}

// ---------------------------------------------------------------------------
// batch_inv: the answer must not depend on *where* the zero is
// ---------------------------------------------------------------------------

#[test]
fn batch_inv_reports_a_zero_input_from_every_position_alike() {
    // 旧実装は最初の 0 を見つけた位置で loop を抜けていたので、0 の位置が
    // 反復回数に出ていた 置き換え後も「どの位置の 0 でも None」が要る
    for n in 1usize..=16 {
        for zero_at in 0..n {
            let mut inputs: Vec<GF> = (0..n).map(|i| GF(u8::try_from(i + 1).unwrap())).collect();
            inputs[zero_at] = GF::ZERO;
            let mut outputs = vec![GF::ZERO; n];
            assert_eq!(
                batch_inv(&inputs, &mut outputs),
                None,
                "n = {n}, 0 の位置 = {zero_at}: None でない"
            );
        }
    }
}

#[test]
fn batch_inv_inverts_every_element_when_none_is_zero() {
    // Oracle: 各要素について a * out = 1 (batch 版を単発 inv と比べない)
    for n in 1usize..=32 {
        let inputs: Vec<GF> = (0..n)
            .map(|i| GF(u8::try_from((i * 7) % 255 + 1).unwrap()))
            .collect();
        let mut outputs = vec![GF::ZERO; n];
        assert_eq!(batch_inv(&inputs, &mut outputs), Some(()), "n = {n}");
        for (i, (&a, &r)) in inputs.iter().zip(outputs.iter()).enumerate() {
            assert_eq!(a.mul(r), GF::ONE, "n = {n}, i = {i}: a * out != 1");
        }
    }
}

#[test]
fn batch_inv_length_checks_are_on_lengths_only() {
    // 長さは公開値なので分岐してよい 空入力は成功、出力が短いのは拒否
    let mut outputs = [GF::ZERO; 4];
    assert_eq!(batch_inv(&[], &mut outputs), Some(()), "空入力は成功");
    let inputs = [GF(1), GF(2), GF(3), GF(4)];
    let mut too_small = [GF::ZERO; 3];
    assert_eq!(
        batch_inv(&inputs, &mut too_small),
        None,
        "出力が短いのは拒否"
    );

    // 固定長版も同じ契約
    let mut buf = [GF::ZERO; 4];
    assert_eq!(batch_inv_stack(&[], &mut buf), Some(0));
    assert_eq!(batch_inv_stack(&inputs, &mut buf), Some(4));
    for (&a, &r) in inputs.iter().zip(buf.iter()) {
        assert_eq!(a.mul(r), GF::ONE);
    }
    let mut small: [GF; 2] = [GF::ZERO; 2];
    assert_eq!(
        batch_inv_stack(&inputs, &mut small),
        None,
        "N を超える長さは拒否"
    );
}

// ---------------------------------------------------------------------------
// Signature: the comparison must not short-circuit
// ---------------------------------------------------------------------------

#[test]
fn signature_equality_rejects_a_difference_in_any_single_byte() {
    // derive した `==` は不一致の位置で打ち切るので、先頭が違う tag と末尾だけ
    // 違う tag を同じ扱いにできなかった 手書きの定数時間比較は両方 false
    let base = [0x5au8; 32];
    let a = Signature::from_bytes(base);
    assert_eq!(a, Signature::from_bytes(base), "同一 tag が等しくない");

    let mut checked = 0u32;
    for i in 0..32 {
        let mut other = base;
        other[i] ^= 0x01;
        assert_ne!(
            a,
            Signature::from_bytes(other),
            "byte {i} だけ違う tag を等しいと判定した"
        );
        checked += 1;
    }
    assert_eq!(checked, 32, "32 byte 全部を比較していない");
}

#[test]
fn verify_accepts_the_real_signature_and_rejects_single_byte_forgeries() {
    let key = SigningKey::from_bytes([7u8; 32]);
    let vk = key.verifying_key();
    let msg = b"timing contract";
    let sig = sign(&key, msg);
    assert!(verify(&vk, msg, &sig), "正しい署名が通らない");

    let real = *sig.as_bytes();
    for i in [0usize, 1, 15, 30, 31] {
        let mut forged = real;
        forged[i] ^= 0x80;
        assert!(
            !verify(&vk, msg, &Signature::from_bytes(forged)),
            "byte {i} を変えた偽造が通った"
        );
    }
}
