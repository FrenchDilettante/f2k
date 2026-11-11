"""ehprolog - msvcrt's _EH_prolog, the C++ exception frame a function Visual C++ compiles with /O1
or /Os sets up by calling it: ehprolog.exe (userland/ehprolog) on a copy of the disk with it in
\\WINNT\\system32.

No fixture of the corpus calls _EH_prolog (the corpus is built without /O1), so ehprolog plays the
compiled function: its probe calls _EH_prolog with a handler in EAX, records the frame it returns
with, unlinks the registration and returns through the saved EBP, and ehprolog prints one line for
each check of the record (the frame's four dwords, EBP, ESP, fs:[0], ECX and EDX kept, the first
argument at [ebp+8], fs:[0] restored by the epilogue). The kernel option `redirected` puts its
lines on COM1, which are compared line for line.

    uv run pytest tests/core/test_ehprolog.py
"""
from __future__ import annotations

import pytest

import f2kboot

EHPROLOG = f2kboot.BUILT_PROGRAMS / "ehprolog.exe"
CMDLINE = "WINNT\\system32\\ehprolog.exe"
EXPECTED = [
    "ebp: the slot of the function's return address, less 4: ok",
    "[ebp]: the caller's ebp: ok",
    "[ebp-4]: -1: ok",
    "[ebp-8]: the handler from eax: ok",
    "[ebp-12]: the previous fs:[0]: ok",
    "fs:[0]: ebp-12: ok",
    "esp: ebp-12: ok",
    "ecx: unchanged: ok",
    "edx: unchanged: ok",
    "[ebp+8]: the first argument: ok",
    "fs:[0] after the epilogue: the previous fs:[0]: ok",
]
TIMEOUT = 30.0


@pytest.mark.kernel
def test_the_frame_eh_prolog_builds(builder, log_path, boot_timeout):
    """_EH_prolog leaves the frame the compiled function's code and epilogue expect, and the
    epilogue returns through it with fs:[0] as it was; ehprolog ends with 0."""
    build = builder([])
    assert EHPROLOG.exists(), f"{EHPROLOG} is missing: `make userland` builds and copies it"
    variant = f2kboot.disk_with_programs(build, [EHPROLOG],
                                         f2kboot.WORK / "variants" / f"{log_path.stem}.img")
    try:
        log, stopped = f2kboot.boot(
            f2kboot.Build(build.kernel, variant),
            image="kernel",
            cmdline=CMDLINE,
            kernel_options=f2kboot.REDIRECTED_OPTION,
            log_path=log_path,
            timeout=boot_timeout(TIMEOUT),
            done=f2kboot.process_ended,
        )
    finally:
        variant.unlink(missing_ok=True)
    context = f"(stopped: {stopped})\nlog: {log_path}\n--- COM1 (tail) ---\n{f2kboot.tail(log)}"
    lines, code = f2kboot.program_output(log)
    assert lines == EXPECTED, f"ehprolog's lines differ {context}"
    assert code == 0, f"ehprolog's exit code {code} {context}"
