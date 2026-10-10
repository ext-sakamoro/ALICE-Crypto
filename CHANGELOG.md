# Changelog

All notable changes to ALICE-Crypto are documented here.

## [Unreleased]

## [0.4.1] — 2026-10-11

### Changed
- **破壊的変更 (build 出力):** `[lib] crate-type` から `cdylib` を外した (`lib` だけになる) std なし (`default-features = false`) で依存する crate の build が、host と `wasm32-unknown-unknown` で「no global memory allocator found」「`#[panic_handler]` function required」で失敗していた (cdylib は最終成果物として allocator と panic handler を要求する Cargo は crate-type を feature で切り替えられない) `thumbv7em-none-eabihf` は cdylib を警告つきで落とすので、これまでの no_std の CI では見えなかった Rust の API は変わらない (`cargo semver-checks` は crate-type を API として扱わない) cdylib の出力を使っていた利用者は無いことを確かめた: `src/` には履歴の全体でも公開済の 0.3.0 / 0.4.0 でも `extern "C"` / `#[no_mangle]` が無く、cdylib は C の記号を 1 つも出していなかった 依存している 15 repo はすべて Rust の依存として使っており、`ffi` を有効にしているものも、`libalice_crypto` / C header / `DllImport` を参照するものも無い

### Deprecated
- `ffi` feature: 何も切り替えない (`ffi = ["std"]` だけで、`feature = "ffi"` で gate された code は無い) `features = ["ffi"]` が compile し続けるように残し、0.5.0 で削除する Cargo は feature の非推奨を表す手段を持たないので、使っても compiler の警告は出ない (非推奨は `Cargo.toml` の comment、README、crate の doc、この CHANGELOG にだけ書いてある) README と crate の doc の「C-compatible cdylib exports」は誤りだったので直した

### Added
- CI (no_std job): `consumers/no_std` (std なしで alice-crypto に依存する下流 crate) を host / `wasm32-unknown-unknown` / `thumbv7em-none-eabihf` で build し、cargo の JSON の出力から両方の crate の rlib が報告されたことを確かめる (`scripts/no_std_consumer.py`、build の失敗と build 0 件は失敗) cdylib を戻すと host と wasm32 の 3 件が red になる alice-crypto 自身の no_std の build は `cargo rustc --crate-type rlib` の回避をやめて `cargo build` / `cargo clippy` にした

## [0.4.0] — 2026-10-10

### Added
- `dp::dp_int(value, sensitivity, ε, rng)`: 整数の値に、感度 `Δ` (整数) の離散 Laplace noise (減衰 `ε/Δ`、格子 `Λ = 1` なので丸め無し) を足す `dp_count` は `Δ = 1` の非負の場合 `value + Z` が `i64` を溢れる時は `CountOutOfRange` で拒否し、飽和はしない (飽和した出力は noise が上限を越えたことを漏らす) `Δ = 0` は `InvalidScale`
- `dp::randomized_response(bit, ε, rng)`: 確率 `e^ε / (1 + e^ε)` で元の bit、他は反転 (1 bit の ε-差分プライバシー) 反転は整数の Bernoulli の手順 (CKS20 Algorithm 1 の `e^-1` を `⌊ε⌋` 回と端数を 1 回) で決め、浮動小数点の `exp` を使わない 固定 105 round の受理で、1 回の呼び出しが使う keystream の語数は ε だけで決まる (`105 · (1 + (⌊ε⌋ + 1) · 128)`) `⌊ε⌋ ≤ RR_MAX_EPSILON_WHOLE` (63)
- `dp::bernoulli_ratio(num, den, rng)`: 確率がちょうど `num / den` (分数で受け、丸めた入口は無い) の Bernoulli、1 回 4 語 `den = 0` / `num > den` は新しい `DpError::InvalidProbability`
- `scripts/dp_rr_exact.py` (ci.yml と preflight): `randomized_response` の手順 (固定 step と round の打ち切りを含む) が返す反転確率を `fractions.Fraction` で厳密に求め、`1/(1 + e^ε)` との差 (一様乱数の偏りを含む) が 6 つの ε で `2^-100` 以下であることを確かめる (`RR_ROUNDS` を 40、`BERNOULLI_STEPS` を 12 にすると失敗)
- 試験 `tests/dp_mechanisms_oracle.rs`: `dp_int` の確率質量関数 (4 組の Δ, ε) と対称性、`i64::MIN` / `MAX` での拒否、Δ = 0 と不正な ε / 反転の頻度 (ε = 0.5 / 1 で 2·10^5 回、2.75 / 5 で 4·10^4 回) と χ² / `bernoulli_ratio` の境界 (`u64::MAX`) と頻度 / 3 つとも語数が値に依らないこと / 固定鍵での出力の pin
- 用途: ALICE-Physics の privacy (RandomizedResponse / Rappor / 整数の Laplace) をこの module に寄せるため 同じ理由で ALICE-Analytics の DP 機能の削除 (既定の方針) でも参照先にできる

### Changed
- 定数時間の検査 (検査 D) の `for` の上限に、公開の rate から決まる `exp_neg_whole_steps` を許す (`laplace_attempts` と同じ扱い) 印の付いた関数は 14 本

### Fixed
- **`SecureRng` が keystream の 2^32 − 1 block 目 (約 256 GiB、`dp_int` を ε = 0.5 で数百万回) で panic していた (0.3.0 から)** 32 bit の block counter が最後の値に達すると `chacha20` crate が `StreamCipherError` を返し、`apply_keystream` が panic した 1 つの nonce の stream では counter `0 ..= 2^32 − 2` だけを使い、その次は nonce の stream 番号を 1 進めて counter 0 から続ける (counter `2^32 − 1` は使わない) 境界より前の出力は変わらないので、同じ鍵の再現と既存の固定値はそのまま 試験は境界の 2 block 前から読んで次の stream に入ること、buffer の 70 通りの位置から同じように越えること、crate がその block を拒むこと、境界直後の 2 語の固定値 (独立に書いた Python の RFC 8439 実装でも同じ値)
- Fuzz の workflow が crash を見つけても成功していた (run の step が `continue-on-error`) crash で job を失敗させ、各 target が 1 件以上の入力を実行したことを確かめ (0 件は失敗)、target ごとの実行数と coverage を job summary に出す `fuzz/regressions/<target>` の入力を毎回 corpus として再生する 手元で 3 target を各 90 秒 (計 3260 万件) 走らせて crash は無かった
- CI: 生成物 (`__pycache__` / `*.pyc` / `target/` / fuzz の artifacts と corpus / `.DS_Store` / `*.profraw`) が tracked でないことを確かめる (`scripts/tracked_generated_check.py`、ci.yml と preflight、`git ls-files` が 0 件なら失敗) `.gitignore` に `__pycache__/` と `*.pyc` を足した

## [0.3.0] — 2026-10-09

### Security
- **`dp` の noise から浮動小数点の逆関数法を除いた (Mironov 2012)** 0.2.0 の `-b·ln(u)` は CSPRNG を使っても結果の下位 bit が一様値 `u` を漏らし、`f64` では計算上の ε が成り立たなかった (module doc に「未対応」と書いていた点) 浮動小数点の `ln` / `exp` は一切使わない形に作り直した: count は離散 Laplace `P(Z = z) = (1 − e^−ε) / (1 + e^−ε) · e^(−ε·|z|)`、実数は格子 `Λ = 2^(⌊log2 Δ⌋ − 20)` に最近接で丸めて `Λ ·` 離散 Laplace を足す 標本化は Canonne, Kamath, Steinke (NeurIPS 2020) の Algorithm 1 / 2 を整数演算だけで行い、ε (と Δ) は `f64` の値から厳密に有理数へ変換する 丸めによる劣化は `ε_eff = ε · Λ · (⌊Δ/Λ⌋ + 1) / Δ ≤ ε · (1 + 2^-20)` Mironov 自身の snapping は採らなかった (その ε の上限は正しく丸められた `ln` を仮定するが、`alice-det-math` の `ln64` は 1 ulp 未満の誤差で正しく丸められてはいない)
- **`dp` の標本化を定数時間にした** 停止するまで回す rejection や幾何分布の loop は noise が大きいほど長くかかり、出力 (真の値 + noise) は公開されるので、時間を測れる側は noise の大きさ、ひいては真の値の位置を絞れた (旧実装で |noise| ≥ 6 の呼び出しは 0 の時の 3.45 倍かかった、`tests/dp_timing.rs`) loop は固定回数、選択は mask、一様値は 256 × 128 bit の乗算 (秘密を割らない)、`⌊X/s⌋` は公開の逆数との乗算と mask の補正 2 回で、1 回の draw が使う keystream の語数は ε と Δ だけで決まる (`tests/dp_cost_model.rs`) 固定回数で裾を切るので、出力は厳密な離散 Laplace から統計距離 `η < 2^-103` だけずれ (各項の上界は `scripts/dp_delta_budget.py` が有理数で厳密に計算し、Bernoulli の段数 32 はその予算 `190/K! ≤ 2^-110` を満たす最小の K として決め、module doc の表と README・CHANGELOG の数字と cost model の語数を CI で突き合わせる)、機構は `(ε_eff, δ)`-差分プライバシー (`δ = (1 + e^ε_eff) · η`) で純粋な ε-差分プライバシーではない 各項は module doc の表 機械語の段で値依存の分岐が無いことは検証していない (source での検査のみ)

### Changed
- **破壊的変更 (0.x の minor)** 移行手順:
  - `dp_count(count, ε, rng)` の戻り値は `Result<f64, _>` から `Result<i64, _>` に (整数の noise) `true_count` が `i64` に収まらない時と noise を足して溢れる時は `DpError::CountOutOfRange`
  - `DpNoise::with_key(scale, key)` / `try_with_key(scale, key)` / `try_from_entropy(scale)` は `(sensitivity, epsilon, key)` / `(sensitivity, epsilon)` に 旧 `scale` は `sensitivity / epsilon` だったので、`with_key(b, key)` は `with_key(b, 1.0, key)` で同じ尺度になる
  - `DpNoise::laplace()` (noise だけを返す) は削除し、値を受けて格子に丸めてから noise を足す `DpNoise::privatize(x)` に置き換えた ⚠️ 丸めずに `x + Λ·Z` を出すと、Δ 以内の 2 値の出力の台が重ならず差分プライバシーが成り立たないため、丸めを経ない入口は残さない
  - `dp_sum(sum, sensitivity, ε, rng)` は引数は同じで、出力が格子 Λ の倍数になった
  - `DpError` に `EpsilonOutOfRange` (ε の厳密な有理数が sampler の 96 bit に収まらない、目安 ε が `[2^-43, 2^43]` の外) / `CountOutOfRange` / `ValueOutOfRange` (`|x| / Λ ≥ 2^52`) を追加、`DpNoise::scale()` は `sensitivity()` / `epsilon()` / `lattice()` / `effective_epsilon()` に置き換えた
  - `SecureRng` は keystream を 64 block ずつまとめて作る (出力は同じ、RFC 8439 の試験で確認)
- 依存 `alice-det-math` を外した (`ln64` を使わなくなったため)
- CI: `ci.yml` と `security-audit.yml` が `ci/**` branch の push でも走る (main に fast-forward する前に同じ検査を branch で回すため)

### Added
- `scripts/dp_delta_budget.py` (ci.yml と preflight): δ の各項の厳密な上界、`BERNOULLI_STEPS` の最小性、文書の数字の一致
- `SecureRng::words_drawn()`: 渡した 64 bit 語の数 (noise 関数が値に依らず同じ語数を使うことを呼び出し側と試験が確かめるため)
- 試験: `tests/dp_discrete_laplace_oracle.rs` (離散 Laplace の確率質量関数・対称性・隣の比 e^−ε・非二進の ε = 0.1 の分散・退化入力) / `tests/dp_lattice_oracle.rs` (格子の倍数・最近接の丸め・`ε_eff` を Python `fractions` で独立に計算した値との一致・`dp_sum` と `DpNoise` が同じ機構) / `tests/dp_cost_model.rs` (語数が固定、旧実装では red) / `tests/dp_timing.rs` (noise の大きさで時間の中央値が変わらない、旧実装では 3.45 倍で red)
- `scripts/constant_time_guard.py` の検査 D: `// CONSTANT-TIME:` の印が付いた関数 (dp の sampler 12 本、`scripts/constant-time-baseline.txt`) に `if` / `while` / `loop` / `match` / `?` / `return` / `break` / `continue` / `&&` / `||` / `.min(` / `.max(` が無いこと、`for` の反復回数が literal・大文字の定数・公開の引数だけで決まる関数に限られること、印と baseline の一致、0 件で fail 試験は `scripts/test_constant_time_guard.py`
- test の build は `opt-level = 3` (定数時間の sampler は 1 draw の仕事が大きく、分布の試験は数万回引く)


## [0.2.0] — 2026-10-09

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
