#!/usr/bin/env python3
"""
Run the QEMU on-target test suite described by a YAML file.

Each case in the YAML names the image to boot (kernel ELF or disk
image), optional cargo features to build the kernel with, and the COM1
strings that must appear for the case to pass. Optional keys tighten
the match: `ordered: true` (the expects must appear in order, each on a
later line), `contiguous` (strings that must appear on consecutive
lines: an uninterrupted block), and `forbids` (strings that fail the
case on sight, added to the suite default, "KERNEL PANIC"). The
per-case engine — build, boot, assert — is scripts/test-boot.sh; this
script adds the suite level: case selection, per-case builds, and a
summary.

Usage:
  run-qemu-tests.py <config.yaml> [--image kernel|disk|all]
                    [--only NAME ...] [--list]
                    [--kernel PATH] [--disk PATH]
                    [--timeout SECONDS]
"""
import argparse
import os
import subprocess
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required: run through `make test` (which uses the repository's .venv"
             " when present), or install it: pip3 install --user --break-system-packages pyyaml"
             " (or apt install python3-yaml)")

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = Path(__file__).resolve().parent

# Output no case may produce: a kernel panic is never an expected outcome.
DEFAULT_FORBIDS = ["KERNEL PANIC"]

PASS = f"[\033[92mPASS\033[0m]"
FAIL = f"[\033[91mFAIL\033[0m]"

def fail(context, message):
    sys.exit(f"{context}: {message}")


def load_cases(config_path):
    """Read and validate the case list; fail fast on bad structure."""
    with open(config_path, encoding="utf-8") as f:
        try:
            doc = yaml.safe_load(f)
        except yaml.YAMLError as e:
            fail(config_path, f"invalid YAML: {e}")
    if not isinstance(doc, dict) or not isinstance(doc.get("cases"), list):
        fail(config_path, "expected a top-level 'cases' list")
    cases = doc["cases"]
    if not cases:
        fail(config_path, "no cases defined")

    seen = set()
    for case in cases:
        if not isinstance(case, dict):
            fail(config_path, "every case must be a mapping")
        name = case.get("name")
        if not name:
            fail(config_path, "a case has no 'name'")
        if name in seen:
            fail(config_path, f"duplicate case name: {name!r}")
        seen.add(name)
        if case.get("image") not in ("kernel", "disk"):
            fail(config_path, f"case {name!r}: 'image' must be 'kernel' or 'disk'")
        expects = case.get("expects")
        if not isinstance(expects, list) or not expects or not all(
            isinstance(e, str) and e for e in expects
        ):
            fail(config_path, f"case {name!r}: 'expects' must be a non-empty list of strings")
        for key in ("features", "forbids", "contiguous"):
            value = case.get(key, [])
            if not isinstance(value, list) or not all(isinstance(x, str) and x for x in value):
                fail(config_path, f"case {name!r}: '{key}' must be a list of strings")
        if not isinstance(case.get("ordered", False), bool):
            fail(config_path, f"case {name!r}: 'ordered' must be true or false")
    return cases


def select_cases(cases, image, only):
    picked = [c for c in cases if image in ("all", c["image"])]
    if only:
        known = {c["name"] for c in picked}
        unknown = [n for n in only if n not in known]
        if unknown:
            fail("selection", f"unknown case(s) {unknown}; available: {sorted(known)}")
        picked = [c for c in picked if c["name"] in only]
    return picked


def run_case(case, kernel_elf, disk_img, timeout):
    """Build the case's kernel and disk and boot them; return True on pass.

    Every case rebuilds the disk image, with the case's features (or
    none): the volume carries the programs the kernel loads, so every
    boot has it attached. The disk build also builds the kernel ELF
    with those features. Disk cases boot the image through Limine (the
    disk embeds one kernel, and the image on disk is whatever the
    previous build left, so booting it unrebuilt could test another
    case's kernel); kernel cases boot the ELF through QEMU's Multiboot
    loader with the same disk as the IDE primary master.
    """
    features = case.get("features", [])
    build = ["make", "disk", f"CARGO_FEATURES={','.join(features)}"]
    build_what = "disk build"
    built = subprocess.run(
        build,
        cwd=REPO_ROOT,
        stderr=subprocess.STDOUT,
        stdout=subprocess.PIPE,
        text=True,
    )
    if built.returncode != 0:
        print(f"{FAIL}: {case['name']} ({build_what} failed: {' '.join(build)})", flush=True)
        print("\n".join(built.stdout.splitlines()[-40:]), flush=True)
        return False

    image = kernel_elf if case["image"] == "kernel" else disk_img
    env = dict(os.environ)
    if case["image"] == "kernel":
        env["BOOT_DISK"] = str(disk_img)
    if timeout is not None:
        env["BOOT_TIMEOUT"] = str(timeout)
    env["BOOT_ORDERED"] = "1" if case.get("ordered", False) else "0"
    env["BOOT_FORBID"] = "\n".join(DEFAULT_FORBIDS + case.get("forbids", []))
    env["BOOT_CONTIGUOUS"] = "\n".join(case.get("contiguous", []))
    cmd = [str(SCRIPTS / "test-boot.sh"), str(image), *case["expects"]]
    passed = subprocess.run(cmd, env=env).returncode == 0
    print(f"{PASS if passed else FAIL}: {case['name']}", flush=True)
    return passed


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("config", help="YAML file describing the test cases")
    ap.add_argument(
        "--image",
        choices=["kernel", "disk", "all"],
        default="all",
        help="run only cases for this boot path (default: all)",
    )
    ap.add_argument("--only", nargs="+", metavar="CASE", help="run only these case names")
    ap.add_argument("--list", action="store_true", help="list case names and exit")
    ap.add_argument("--kernel", default=str(REPO_ROOT / "target/x86-f2k/debug/f2k-kernel"))
    ap.add_argument("--disk", default=str(REPO_ROOT / "target/x86-f2k/debug/f2k-disk.img"))
    ap.add_argument("--timeout", type=int, help="per-case boot timeout in seconds")
    args = ap.parse_args()

    cases = load_cases(args.config)
    if args.list:
        for case in cases:
            print(f"{case['name']:16s} {case['image']:6s} {case.get('description', '')}")
        return 0

    selected = select_cases(cases, args.image, args.only)
    if not selected:
        fail("selection", "no cases match the given filters")

    results = []
    for case in selected:
        print(f"=== {case['name']}: {case.get('description', '')}", flush=True)
        results.append(run_case(case, args.kernel, args.disk, args.timeout))

    failed = len(results) - sum(results)
    print(f"\n{len(results) - failed} passed, {failed} failed", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
