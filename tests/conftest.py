"""Shared fixtures for the on-target QEMU tests: the suite (tests/test_suite.py) and the sectioned
corpus (tests/<name>/test_<name>.py)."""
from __future__ import annotations

from pathlib import Path
from typing import Callable

import pytest

import f2kboot


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("f2k", "F2K QEMU tests")
    group.addoption(
        "--no-build",
        action="store_true",
        help="boot the kernel and disk the last `make disk` left, whatever its features",
    )
    group.addoption(
        "--boot-timeout",
        type=float,
        default=None,
        help="seconds per boot, overriding the cases' own (suite default 10, corpus default 20)",
    )


@pytest.fixture(scope="session")
def builder(request: pytest.FixtureRequest, testrun_uid: str) -> Callable[[list[str]], f2kboot.Build]:
    """Build (once per test run) the kernel and disk for a set of cargo features."""
    if request.config.getoption("--no-build"):
        return lambda features: f2kboot.last_build()

    def build(features: list[str]) -> f2kboot.Build:
        try:
            return f2kboot.build(features, testrun_uid)
        except f2kboot.BuildError as error:
            pytest.fail(str(error), pytrace=False)

    return build


@pytest.fixture
def log_path(request: pytest.FixtureRequest) -> Path:
    """This test's COM1 log (kept after the run, for inspection)."""
    return f2kboot.log_path_for(request.node.nodeid)


@pytest.fixture
def boot_timeout(request: pytest.FixtureRequest) -> Callable[[float], float]:
    """The boot timeout: the command line's --boot-timeout, else the case's own."""
    override = request.config.getoption("--boot-timeout")
    return lambda own: override if override is not None else own


@pytest.fixture
def run_block(builder, log_path, boot_timeout) -> Callable[[f2kboot.Captured], None]:
    """Run one captured block on F2K: the plain kernel booted with the block's command line, the
    program run from the corpus's directory; fails unless the program's output equals the block line
    for line (masks applied) and the process ends with the block's exit code."""

    def run(captured: f2kboot.Captured) -> None:
        block = captured.block
        log, _ = f2kboot.boot(
            builder([]),
            image="kernel",
            cmdline=f"{f2kboot.CORPUS_DIRECTORY}\\{block.command}",
            memory="256M",
            log_path=log_path,
            timeout=boot_timeout(captured.timeout),
            done=f2kboot.process_ended,
        )
        mismatch = f2kboot.compare_block(block, log, list(captured.masks))
        if mismatch is not None:
            pytest.fail(f"{block.command}: {mismatch}\nlog: {log_path}", pytrace=False)

    return run
