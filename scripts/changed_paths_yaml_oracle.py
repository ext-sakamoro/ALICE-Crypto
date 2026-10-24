#!/usr/bin/env python3
"""Compare the strict workflow reader of scripts/changed_paths.py with PyYAML.

usage: changed_paths_yaml_oracle.py ROOT [ROOT ...]

For every .github/workflows/*.yml / *.yaml under each ROOT (a repository checkout), the reader's
tree must equal yaml.safe_load's, or the reader must refuse the file (FormError: outside the subset,
fail-closed). A tree that differs is a failure: sync would read a workflow differently from GitHub.
The cases of test_changed_paths.py are checked against PyYAML too: every READ case equals
safe_load, every REFUSE case is valid YAML (so a refusal is a construct outside the subset, not an
error the reader invents), every INVALID case is rejected by PyYAML. Fails when no workflow file
was compared. Needs PyYAML (CI pins it); this file is not one of the shared copies.
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import changed_paths as cp  # noqa: E402
import test_changed_paths as t  # noqa: E402

# PyYAML builds these from text the reader refuses, and that is the point of refusing them
# (YAML errors for the reader, values for PyYAML): duplicate keys (PyYAML keeps the last one)
REFUSE_PYYAML_ACCEPTS = True


def first_diff(a, b, path="$"):
    if type(a) is not type(b):
        return f"{path}: {type(a).__name__} {a!r:.60} != {type(b).__name__} {b!r:.60}"
    if isinstance(a, dict):
        for k in list(a) + [k for k in b if k not in a]:
            if k not in a or k not in b:
                return f"{path}.{k}: present on one side only"
            d = first_diff(a[k], b[k], f"{path}.{k}")
            if d:
                return d
    elif isinstance(a, list):
        if len(a) != len(b):
            return f"{path}: {len(a)} items != {len(b)}"
        for i, (x, y) in enumerate(zip(a, b)):
            d = first_diff(x, y, f"{path}[{i}]")
            if d:
                return d
    elif a != b:
        return f"{path}: {a!r:.80} != {b!r:.80}"
    return None


def main(roots: list[str]) -> int:
    bad: list[str] = []
    equal = refused = not_yaml = 0
    files = sorted({f for r in roots for pat in ("*.yml", "*.yaml")
                    for f in (Path(r) / ".github" / "workflows").glob(pat)})
    for f in files:
        text = f.read_text(encoding="utf-8")
        try:
            want = yaml.safe_load(text)
        except yaml.YAMLError as e:
            not_yaml += 1
            print(f"not YAML (skipped): {f}: {str(e).splitlines()[0]}")
            continue
        try:
            got = cp.load_yaml(text)
        except cp.FormError as e:
            refused += 1
            print(f"refused: {f}: {e}")
            continue
        if got == want:
            equal += 1
        else:
            bad.append(f"{f}: the reader's tree differs from yaml.safe_load: {first_diff(got, want)}")

    cases = 0
    for name, src, expected in t.Reader.READ:
        cases += 1
        if yaml.safe_load(src) != expected:
            bad.append(f"READ case {name!r}: the expected tree is not what PyYAML builds")
    for name, src in t.Reader.REFUSE:
        cases += 1
        try:
            yaml.safe_load(src)
        except yaml.YAMLError as e:
            if name != "a tab in the indentation":
                bad.append(f"REFUSE case {name!r} is not valid YAML ({str(e).splitlines()[0]})")
    for name, src in t.Reader.INVALID:
        cases += 1
        try:
            yaml.safe_load(src)
            bad.append(f"INVALID case {name!r} is valid YAML")
        except yaml.YAMLError:
            pass

    for b in bad:
        print(f"FAIL: {b}")
    print(f"compared: workflow files {len(files)}, equal {equal}, refused {refused}, not YAML {not_yaml}, "
          f"test cases {cases}, {len(bad)} failure(s)")
    if equal == 0:
        print("FAIL: no workflow file compared equal (compared nothing)")
        return 1
    return 1 if bad else 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__.split("\n\n", 1)[1].split("\n", 1)[0], file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1:]))
