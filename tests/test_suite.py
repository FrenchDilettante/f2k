"""The on-target QEMU suite: one test per case in scripts/qemu-tests.yaml.

Each case builds the kernel and disk with its cargo features (once per feature set per test run),
boots the kernel ELF through QEMU's Multiboot loader with the disk attached (`image: kernel`) or the
disk itself through Limine (`image: disk`), and passes once its expected strings have appeared on
COM1 by its rules (see `f2kboot.Expectation`). "KERNEL PANIC" fails every case.

    uv run pytest tests/test_suite.py                 # every case
    uv run pytest tests/test_suite.py -m kernel       # kernel-path cases (make test)
    uv run pytest tests/test_suite.py -k fault-ud     # one case
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

import f2kboot

SUITE = f2kboot.REPO_ROOT / "scripts" / "qemu-tests.yaml"
# Output no case may produce: a kernel panic is never an expected outcome.
DEFAULT_FORBIDS = ["KERNEL PANIC"]
DEFAULT_TIMEOUT = 10.0


def load_cases(path: Path) -> list[dict]:
    """The suite's cases, validated: a malformed description fails collection, not a boot."""
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict) or not isinstance(doc.get("cases"), list) or not doc["cases"]:
        raise ValueError(f"{path}: expected a non-empty top-level 'cases' list")
    seen = set()
    for case in doc["cases"]:
        name = case.get("name") if isinstance(case, dict) else None
        if not name:
            raise ValueError(f"{path}: every case must be a mapping with a 'name'")
        if name in seen:
            raise ValueError(f"{path}: duplicate case name {name!r}")
        seen.add(name)
        if case.get("image") not in ("kernel", "disk"):
            raise ValueError(f"{path}: case {name!r}: 'image' must be 'kernel' or 'disk'")
        expects = case.get("expects")
        if not isinstance(expects, list) or not expects or not all(isinstance(e, str) and e for e in expects):
            raise ValueError(f"{path}: case {name!r}: 'expects' must be a non-empty list of strings")
        for key in ("features", "forbids", "contiguous"):
            value = case.get(key, [])
            if not isinstance(value, list) or not all(isinstance(x, str) and x for x in value):
                raise ValueError(f"{path}: case {name!r}: '{key}' must be a list of strings")
        if not isinstance(case.get("ordered", False), bool):
            raise ValueError(f"{path}: case {name!r}: 'ordered' must be true or false")
        cmdline = case.get("cmdline")
        if cmdline is not None:
            if not isinstance(cmdline, str) or not cmdline.strip():
                raise ValueError(f"{path}: case {name!r}: 'cmdline' must be a non-empty string")
            if case["image"] != "kernel":
                raise ValueError(f"{path}: case {name!r}: 'cmdline' needs image: kernel")
    return doc["cases"]


CASES = load_cases(SUITE)


@pytest.mark.parametrize(
    "case",
    [pytest.param(case, id=case["name"], marks=getattr(pytest.mark, case["image"])) for case in CASES],
)
def test_suite(case, builder, log_path, boot_timeout):
    """The case's description, as the suite states it."""
    build = builder(case.get("features", []))
    expectation = f2kboot.Expectation(
        expects=case["expects"],
        ordered=case.get("ordered", False),
        contiguous=case.get("contiguous", []),
        forbids=DEFAULT_FORBIDS + case.get("forbids", []),
    )
    log, stopped = f2kboot.boot(
        build,
        image=case["image"],
        cmdline=case.get("cmdline"),
        log_path=log_path,
        timeout=boot_timeout(DEFAULT_TIMEOUT),
        done=lambda log: expectation.check(log)[0] != "pending",
    )
    status, detail = expectation.check(log)
    if status == "pass":
        return
    if status == "forbidden":
        why = f"forbidden output appeared on COM1: {detail!r}"
    elif stopped == "exited":
        why = f"QEMU exited before the expected output appeared ({detail})"
    else:
        why = f"expected output not found within the timeout ({detail})"
    pytest.fail(f"{case.get('description', case['name'])}\n{why}\nlog: {log_path}\n--- COM1 (tail) ---\n"
                f"{f2kboot.tail(log)}", pytrace=False)
