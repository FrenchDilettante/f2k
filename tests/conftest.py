"""Shared fixtures for the on-target QEMU tests: the kernel's own boots (tests/kernel/test_kernel.py)
and the sectioned corpus (tests/<name>/test_<name>.py)."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Callable

import pytest

import f2kboot

# The profile converter (scripts/perf_profile.py) is a repository script the suite shares.
sys.path.insert(0, str(f2kboot.REPO_ROOT / "scripts"))
import perf_profile  # noqa: E402

# The cargo feature that arms the kernel's tick sampler (kernel/src/perf.rs).
PERF_TRACE = "perf-trace"


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("f2k", "F2K QEMU tests")
    group.addoption(
        "--no-build",
        action="store_true",
        help="boot the kernel and disk the last `make disk` left; a test needing other features is"
        " skipped (the build stamps say which)",
    )
    group.addoption(
        "--boot-timeout",
        type=float,
        default=None,
        help="seconds per boot, overriding the cases' own (kernel cases default 10, corpus default 20)",
    )
    group.addoption(
        "--update-screens",
        action="store_true",
        help="record the screen smokes' reference images (tests/screens/) from this run's screens"
        " instead of comparing against them",
    )
    group.addoption(
        "--perf-trace",
        action="store_true",
        help="build with the kernel's perf-trace feature and write each boot's profile to"
        " target/qemu/profiles/, loadable at profiler.firefox.com (scripts/perf_profile.py)",
    )


def pytest_sessionstart(session: pytest.Session) -> None:
    """Before anything builds: clear the earlier runs' leftovers (stale builds, logs, disk
    variants). Once per run, on the controller (xdist workers carry `workerinput`)."""
    if not hasattr(session.config, "workerinput"):
        f2kboot.prune()


@pytest.fixture(scope="session")
def builder(request: pytest.FixtureRequest, testrun_uid: str) -> Callable[[list[str]], f2kboot.Build]:
    """Build (once per test run) the kernel and disk for a set of cargo features."""
    # The performance trace builds with every feature set: the sampler rides every boot.
    if request.config.getoption("--perf-trace"):
        features = lambda wanted: [*wanted, PERF_TRACE]  # noqa: E731
    else:
        features = lambda wanted: wanted  # noqa: E731
    if request.config.getoption("--no-build"):

        def reuse(wanted: list[str]) -> f2kboot.Build:
            build = f2kboot.last_build()
            unstamped = f2kboot.unstamped(build)
            if unstamped is not None:
                pytest.fail(f"--no-build: {unstamped}", pytrace=False)
            mismatch = f2kboot.build_mismatch(build, features(wanted))
            if mismatch is not None:
                pytest.skip(f"--no-build: {mismatch}")
            return build

        return reuse

    def build(wanted: list[str]) -> f2kboot.Build:
        try:
            return f2kboot.build(features(wanted), testrun_uid)
        except f2kboot.BuildError as error:
            pytest.fail(str(error), pytrace=False)

    return build


@pytest.fixture
def log_path(request: pytest.FixtureRequest) -> Path:
    """This test's COM1 log (kept after the run, for inspection)."""
    return f2kboot.log_path_for(request.node.nodeid)


@pytest.fixture
def profile_path(request: pytest.FixtureRequest) -> Path:
    """This test's performance profile (the suite's `--perf-trace`)."""
    return f2kboot.profile_path_for(request.node.nodeid)


@pytest.fixture
def write_profile(request: pytest.FixtureRequest, profile_path: Path) -> Callable[[str, f2kboot.Build], None]:
    """Write a boot's profile from its log, when the run asked for `--perf-trace`; a log without a
    trace writes nothing."""
    if not request.config.getoption("--perf-trace"):
        return lambda log, build: None

    def write(log: str, build: f2kboot.Build) -> None:
        trace = perf_profile.parse_trace(log)
        if trace is None or not trace[1]:
            return
        name_of = perf_profile.symbolizer(perf_profile.elf32_symbols(build.kernel))
        profile_path.parent.mkdir(parents=True, exist_ok=True)
        profile_path.write_text(
            json.dumps(perf_profile.build_profile(trace[1], trace[0], name_of), indent=1)
        )

    return write


@pytest.fixture
def boot_timeout(request: pytest.FixtureRequest) -> Callable[[float], float]:
    """The boot timeout: the command line's --boot-timeout, else the case's own."""
    override = request.config.getoption("--boot-timeout")
    return lambda own: override if override is not None else own


@pytest.fixture
def run_block(builder, log_path, boot_timeout, write_profile) -> Callable[[f2kboot.Captured], None]:
    """Run one captured block on F2K: the plain kernel booted with the block's command line (by
    QEMU's Multiboot loader, or with `image="disk"` through Limine), the program run from the
    corpus's directory; fails unless the program's output equals the block line
    for line (masks applied), the process ends with the block's exit code, and its teardown audits
    clean."""

    def run(captured: f2kboot.Captured, image: str = "kernel") -> None:
        block = captured.block
        build = builder([])
        log, stopped = f2kboot.boot(
            build,
            image=image,
            cmdline=f"{f2kboot.CORPUS_DIRECTORY}\\{block.command}",
            memory="256M",
            log_path=log_path,
            timeout=boot_timeout(captured.timeout),
            done=f2kboot.teardown_audited,
        )
        write_profile(log, build)
        mismatch = f2kboot.compare_block(block, log, list(captured.masks))
        if mismatch is not None:
            # Why the boot stopped ("done", "exited", "timeout") and anything QEMU itself said.
            context = f"boot stopped: {stopped}"
            complaint = f2kboot.qemu_complaint(log)
            if complaint is not None:
                context += f"; QEMU: {complaint}"
            pytest.fail(f"{block.command}: {mismatch}\n{context}\nlog: {log_path}", pytrace=False)

    return run
