# Changelog

All notable changes to ALICE-Crypto are documented here.

## [Unreleased]

### Added
- **`dp` module — 差分プライバシーの Laplace noise を鍵基準の CSPRNG で生成する** 再現性と秘匿は「決定論の基準を何に置くか」で両立する: 公開値 (時刻 / 連番) を基準にすると攻撃者も同じ値を推測して noise を引き去れるが、**秘密の鍵**を基準にすれば同じ鍵で同じ列が出て (replay / 監査 / 試験)、鍵を知らない側からは予測も再現もできない ⚠️ **本 module は同日に ALICE-* 2 crate で見つかった同型の欠陥のために作った**: `xorshift64` を時刻 seed で回し状態を呼び出し側に返す形で、(a) 時刻は推測できるので鍵が総当たりできる (b) **xorshift は F2 線形なので出力 64 bit から状態が線形代数で解け、総当たりすら不要** 入れたもの: `SecureRng` (RFC 8439 ChaCha20 の keystream、鍵と buffer は drop 時に `zeroize`) / `DpNoise` (Laplace、逆関数法、符号は別の keystream bit から取る — `u` を流用すると符号と大きさが相関して片側の裾が薄くなる) / `dp_count` / `dp_sum` (**乱数源だけを受け取り scale を ε から導く** ⚠️ scale を引数にすると、呼び出し側の ε と実際の noise が食い違っても誰も気付かない = 配線の変異が恒等になる) / 不正な scale・ε・sensitivity は `Err`
- 依存 2 本: `chacha20` (`chacha20poly1305` が既に引いているので依存木は増えない ⚠️ **手書きの block 関数を持つと同じ法則の写しが 2 つになる**ので実装は 1 つに寄せた) と `alice-det-math` (`ln64` は bit 一致・1 ulp 保証、platform libm では同じ鍵でも機械ごとに noise が変わり replay が成立しない)
- `tests/dp_noise_oracle.rs` (10 test) + `src/dp.rs` の inline test 2 本 — 固定するのは 3 性質 (予測不能性 / 再現性 / 分布) 期待値の出所は **Laplace の定義** (平均 0、分散 2b²) と **RFC 8439 § 2.3.2 の keystream** (RFC 本文からの転記、実装の出力は 1 つも使っていない) 変異 **8/8 red** ⚠️ **うち 1 件は最初 生存した** — 一様値の 0 ガードは `bits == 0` が 2⁻⁵³ の事象なので 20 万回の抽出では 1 度も通らず、標本抽出の試験では歯が無かった ⇒ 変換を純関数 `open01_from_bits` に切り出して `0` を直接渡す inline test を置いた
- README に `Differential privacy (dp)` 節、`src/lib.rs` の timing 表に `dp` の行

### Fixed
- 一様値の doc が `(0, 1]` と書いていたが **1.0 は返らない** (53 bit は `0 … 2^53-1` なので上端は `1 - 2^-53`) 実際の範囲 `[2^-53, 1 - 2^-53]` に訂正し、上端を assert する test を置いた (移送元の doc も同じ誤りを持っていた)

### Security
- **`Signature` の `==` が定数時間になった (breaking: `PartialEq` / `Eq` の derive を手書き impl に置換)** 導出された `==` は 32 byte の tag を先頭から比べて不一致の位置で打ち切るので、**一致した先頭 byte 数が実行時間に出ていた** (MAC tag を 1 byte ずつ合わせ込む偽造の足場) crate 自身の `verify` は定数時間比較を使っていたので、**危なかったのは「便利に見える方」**だけ 手書きの `impl PartialEq` が同じ比較関数を通る 値の意味は不変 (同じ bytes が等しい)
- **GF(2^8) の逆元・除算・batch 逆元から値依存の早期脱出を除去** `inv` は `if self.0 == 0 { return None }`、`batch_inv` は loop の中で要素ごとに零判定して `return None` していたため、**反復回数が「最初の 0 の位置」に依存**していた `batch_inv` は走る積が 0 かどうかで「どれかが 0」を判定する (GF(2^8) は体で零因子を持たないので同値、追加の計算は 0) 乗算回数は `inputs.len()` のみに依存する
- **秘密を落とす時の 0 埋めを `zeroize` に寄せた** 従来の `self.0.iter_mut().for_each(|b| *b = 0)` は「以降読まれない書き込み」として最適化で消えうる 対象: `SigningKey` / `VerifyingKey` / `kdf::Prk` / `keystore::KeyEntry`、**新たに** `stream::Key` と `sss::Shard.y` (どちらも 0 埋めが無かった)、および `sss::split` が持っていた stack buffer (秘密 byte と乱数係数)
- **誤った主張 2 件を訂正** `src/lib.rs` の「All operations are constant-time」を**操作ごとの表**に置換 (実行時間が何に依存してよいかを 1 行ずつ、`blake3` / `chacha20poly1305` に委譲している範囲も明記)、`stream` の「nonce-misuse resistant」を削除 — XChaCha20-Poly1305 に misuse 耐性は無く、拡張 nonce が与えるのは「乱数 nonce を調整なしで安全に使える」ことだけ `Nonce` に再利用時の帰結を明記した

### Added
- `scripts/constant_time_guard.py` — 上の表を機械で守る静的検査 (A: 秘密型が比較の `derive` を持たない / B: 定数時間を名乗る関数に値依存の早期脱出が無い / C: **検査対象 0 件で fail**) `security-audit.yml` の新 job と `scripts/preflight.sh` の両方で実行 変異 4 件 (derive 復活 / `inv` の早期 return / `batch_inv` の要素ごと零判定 / 検査対象を空にする) で全て red を確認
- `tests/constant_time_contract.rs` (8 test) — 分岐を外した実装が**値として正しい**ことを逆元の定義 (`a * a^-1 = 1`) から全 256 元で突合、`batch_inv` が 0 の位置に関わらず同じ判定を返すこと、tag の比較が 32 byte のどの 1 byte の違いでも拒否することを固定
- `GF::inv_or_zero` / `GF::div_or_zero` — 分岐の無い形 (`0` を `0` に写す) 既存の `inv` / `div` はこれを呼ぶ
- README に **Timing behaviour** と **Key material handling** の節

### Changed
- **License: `AGPL-3.0-or-later` → `AGPL-3.0-or-later OR LicenseRef-Commercial` (dual-licensed、2026-09-27)** AGPL 側の条件は変更なし (既存 AGPL 利用者への影響ゼロ)、商用という選択肢が追加されただけ SPDX が AGPL 単独だと cargo-deny / FOSSA / SBOM に「商用オプションなし」と見えるため宣言を dual に 変更点: SPDX / `LICENSE` → `LICENSE-AGPL` rename / `LICENSE-COMMERCIAL.md` (商用トリガー 6 条件 = クローズド製品・商用 SaaS・エッジ・ファームウェア配布・plugin 再配布・プラットフォーム NDA・保証、社内利用は AGPL 側で無償と明記) / README の選択肢表 商用窓口は法人 `contact@extoria.co.jp`

### Added
- `custom-rng` feature (`getrandom/custom`) — `getrandom` が非対応の bare-metal target (`thumbv7em-none-eabihf` 等) 向け、最終 binary で `register_custom_getrandom!` を登録する (README no_std 節) それまで crates.io `no-std` category を掲げつつ bare-metal では `getrandom` の「target is not supported」で build 不能だった
- `ci.yml` (それまで fuzz / security-audit のみ): test (default + `std,ffi`) / clippy `--all-targets -D warnings` 2 variant / `no_std` job (host rlib `alloc` + bare-metal thumbv7em `alloc,custom-rng` + clippy-driver wrapper、`crate-type` に cdylib を含むため `cargo rustc --crate-type rlib`) / `feature-powerset` (std 固定 depth 2) / fmt / doc `-D warnings` / actionlint、rust-cache
- `rust-toolchain.toml` (1.98.1 pin + thumbv7em target)

### Fixed
- `keystore.rs` の no_std build で unused import (`String`)

## [0.1.0] — 2026-02-23

### Added
- **GF(2^8) arithmetic** (`gf256`) — branchless constant-time multiplication (Russian Peasant, 8-stage unrolled), Fermat inverse (11-step addition chain), Montgomery batch inversion (1 inv + 3K mul for K elements), stack-allocated batch variant
- **Shamir's Secret Sharing** (`sss`) — K-of-N threshold splitting, buffered RNG (1 KB, 256x fewer syscalls), Horner polynomial evaluation, 4-way ILP unrolled Lagrange reconstruction
- **BLAKE3 hashing** (`hash`) — `hash()`, `keyed_hash()`, `derive_key()`, incremental `Hasher`, `Hash` display (hex)
- **XChaCha20-Poly1305** (`stream`) — zero-allocation `encrypt_in_place` / `decrypt_in_place`, AEAD variants with associated data, convenience `seal` / `open` wrappers, `Key::generate()` / `Nonce::generate()`
- **`no_std` support** — `#![no_std]` with `alloc` feature for embedded / WASM targets
- **FFI** — `ffi` feature for C-compatible cdylib exports
- **104 unit tests + 1 doc-test** covering GF arithmetic, SSS round-trip, encryption round-trip, edge cases, error handling
- Release profile: `opt-level=3`, `lto=fat`, `codegen-units=1`, `strip=true`, `panic=abort`
