#!/usr/bin/env python3
"""crate が名乗る「定数時間」を機械で検査する。

## なぜ要るのか

`src/lib.rs` は "All operations are constant-time" と宣言しているが、2026-10-09 の
実測では 3 つの例外があった:

1. `Signature` が `derive(PartialEq, Eq)` を持ち、`==` が **short-circuit する byte 比較**
   になっていた (MAC tag の byte 単位 timing oracle = 偽造の足場)
   ⚠️ crate 自身の `verify` は `constant_time_eq` を使うので、**危ないのは「便利に見える方」**
2. `gf256::inv` が `if self.0 == 0 { return None; }` で値依存の早期 return
3. `gf256::batch_inv` が loop 内で `if inputs[i].0 == 0 { return None; }` ⇒ **反復回数が
   入力値に依存** (最初の 0 の位置が時間に出る)

⚠️⚠️ **doc の主張に検査が無いと、実装が主張から離れても誰も気付かない**
(同日 ALICE-Analytics で「ChaCha20-based」と書いて実装が xorshift64 だった事例と同型)

## 何を検査するか

- **検査 A**: 秘密を運ぶ型に `derive(PartialEq / Eq / Ord / PartialOrd)` が無いこと
  (byte 比較が short-circuit する ⇒ 定数時間でない)
- **検査 B**: 定数時間を名乗る関数の中に、**値に依存する早期 return / `continue` /
  `break`** が無いこと (長さ・容量の検査は公開値なので許す)
- **検査 C**: 比較対象が 0 件なら fail (空振りを成功と読ませない)

⚠️ これは**静的な近似**であって、定数時間性の証明ではない (命令列や cache の挙動は
測っていない) 統計的な時間測定 (dudect 方式) は CI のノイズが大きいので、ここでは
「明らかに定数時間でない書き方」を止めることに絞る。

## 使い方

    python3 scripts/constant_time_guard.py          # 違反を列挙、あれば exit 1
    python3 scripts/constant_time_guard.py --list    # 検査対象を表示 (件数の確認)
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# 秘密 (鍵・tag・share・係数) を運ぶ型
# ⚠️ 名前で拾うので、秘密を持つ型を足した時はここにも足す
SECRET_TYPES = [
    "SigningKey",
    "VerifyingKey",
    "Signature",
    "Key",
    "KeyEntry",
    "Shard",
]
# 定数時間を名乗る関数 (`src/lib.rs` § Timing behaviour の表と対応させる)
# ⚠️ 実在しない名前を並べても検査は増えない (黙って 0 件になる) ので、
#    足す時は `--list` の件数が増えることを確かめる
CONSTANT_TIME_FNS = [
    "constant_time_eq",
    "mul",
    "inv",
    "inv_or_zero",
    "div",
    "div_or_zero",
    "batch_inv",
    "batch_inv_stack",
]

DERIVE_RE = re.compile(r"#\[derive\(([^)]*)\)\]\s*(?:#\[[^\]]*\]\s*)*pub struct\s+([A-Za-z_][A-Za-z0-9_]*)")
FORBIDDEN_DERIVES = ("PartialEq", "Eq", "Ord", "PartialOrd")


def src_files() -> list[Path]:
    return sorted(p for p in (ROOT / "src").rglob("*.rs"))


def check_secret_derives(files: list[Path]) -> tuple[list[str], int]:
    """検査 A: 秘密型に比較の derive が無いか"""
    problems: list[str] = []
    checked = 0
    for f in files:
        text = f.read_text(encoding="utf-8", errors="replace")
        for m in DERIVE_RE.finditer(text):
            derives, name = m.group(1), m.group(2)
            if name not in SECRET_TYPES:
                continue
            checked += 1
            bad = [d for d in FORBIDDEN_DERIVES if re.search(rf"\b{d}\b", derives)]
            if bad:
                line = text[: m.start()].count("\n") + 1
                problems.append(
                    f"{f.relative_to(ROOT)}:{line}: 秘密型 `{name}` が derive({', '.join(bad)}) "
                    f"を持つ ⇒ `==` が short-circuit する byte 比較になり定数時間でない "
                    f"(手書きの `impl PartialEq` で `constant_time_eq` を使う)"
                )
    return problems, checked


def check_early_returns(files: list[Path]) -> tuple[list[str], int]:
    """検査 B: 定数時間を名乗る関数に値依存の早期脱出が無いか

    長さ / 容量の検査 (`len()` / `is_empty()` を条件に含むもの) は公開値なので許す
    """
    problems: list[str] = []
    checked = 0
    fn_head = re.compile(
        r"^\s*(?:pub\s+)?(?:const\s+)?fn\s+(" + "|".join(CONSTANT_TIME_FNS) + r")\s*[(<]",
        re.M,
    )
    for f in files:
        text = f.read_text(encoding="utf-8", errors="replace")
        lines = text.split("\n")
        for m in fn_head.finditer(text):
            name = m.group(1)
            start = text[: m.start()].count("\n")
            # brace 対応で関数の終わりを求める
            depth = 0
            started = False
            end = start
            for i in range(start, len(lines)):
                depth += lines[i].count("{") - lines[i].count("}")
                if "{" in lines[i]:
                    started = True
                if started and depth == 0:
                    end = i
                    break
            checked += 1
            for i in range(start, end + 1):
                line = lines[i]
                if "if " not in line:
                    continue
                # 公開値 (長さ / 容量) の検査は許す
                if any(tok in line for tok in ("len()", "is_empty()", "capacity()")):
                    continue
                # 次の数行に早期脱出があるか
                window = "\n".join(lines[i : min(i + 3, end + 1)])
                if re.search(r"\breturn\b|\bcontinue\b|\bbreak\b", window):
                    problems.append(
                        f"{f.relative_to(ROOT)}:{i + 1}: `{name}` の中に値依存の早期脱出がある "
                        f"⇒ 反復回数 / 実行時間が入力値に依存する "
                        f"(mask で合成して常に全要素を走査する): {line.strip()}"
                    )
    return problems, checked


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()

    files = src_files()
    a_problems, a_checked = check_secret_derives(files)
    b_problems, b_checked = check_early_returns(files)

    if args.list:
        print(f"src {len(files)} file / 秘密型の derive {a_checked} 件 / 定数時間 fn {b_checked} 件")
        return 0

    # 検査 C: 空振りを成功と読ませない
    if a_checked == 0 or b_checked == 0:
        print(
            f"constant-time guard: 比較件数 0 (秘密型 {a_checked} / fn {b_checked}) "
            f"— 検査が成立していない (SECRET_TYPES / CONSTANT_TIME_FNS と実装の名前を突き合わせる)",
            file=sys.stderr,
        )
        return 2

    problems = a_problems + b_problems
    if problems:
        print(f"constant-time guard: {len(problems)} 件", file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        return 1
    print(
        f"constant-time guard: OK (秘密型 {a_checked} 件 / 定数時間 fn {b_checked} 件を検査)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
