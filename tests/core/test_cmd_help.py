"""cmd - `/?`: cmd.exe's own help, and a built-in command's, booted.

Each boot runs cmd.exe from a copy of the test disk with it added (as tests/core/test_cmd.py's
`/c` boots do), with the kernel option `redirected`, so that its output reaches COM1:

- `cmd.exe /?` prints the shell's help, its syntax first among its lines, and ends with 1, running
  nothing else: no banner, no prompt;
- `cmd.exe /c cd /?` prints cd's help in place of changing the directory, and ends with 1, the
  return code of a help printed (tests/cmd/bathelp's capture shows both 1s).

The texts themselves are userland/cmd/src/help.rs's, checked on the host (`make run-tests`).

    uv run pytest tests/core/test_cmd_help.py
"""
from __future__ import annotations

import pytest

import f2kboot
from test_cmd import BANNER, COMMAND_LINE, TIMEOUT, disk_with_cmd, run_with_c

# The first syntax lines of cmd's and cd's helps.
CMD_SYNTAX = "CMD [/Q] [/S] [/A | /U] [/D] [/E:ON | /E:OFF] [/F:ON | /F:OFF] [/V:ON | /V:OFF]"
CD_SYNTAX = ["CHDIR [/D] [drive:][path]", "CHDIR ..", "CD [/D] [drive:][path]", "CD .."]


def run_cmd(builder, log_path, boot_timeout, arguments: str) -> tuple[list[str], int | None]:
    """Boot `cmd.exe <arguments>` with the kernel option `redirected`: its output lines and exit
    code."""
    build, variant = disk_with_cmd(builder, log_path, [])
    try:
        log, stopped = f2kboot.boot(
            f2kboot.Build(build.kernel, variant),
            image="kernel",
            cmdline=f"{COMMAND_LINE} {arguments}",
            kernel_options=f2kboot.REDIRECTED_OPTION,
            memory="256M",
            log_path=log_path,
            timeout=boot_timeout(TIMEOUT),
            done=f2kboot.process_ended,
        )
    finally:
        variant.unlink(missing_ok=True)
    if not f2kboot.process_ended(log):
        pytest.fail(f"cmd.exe never ended (stopped: {stopped})\nlog: {log_path}\n"
                    f"--- COM1 (tail) ---\n{f2kboot.tail(log)}", pytrace=False)
    return f2kboot.program_output(log)


@pytest.mark.kernel
def test_cmd_s_own_help(builder, log_path, boot_timeout):
    """`cmd /?`: the shell's help, from its summary to its syntax, no banner, and the exit code 1."""
    output, code = run_cmd(builder, log_path, boot_timeout, "/?")
    assert code == 1, "\n".join(output)
    assert output[0].startswith("Starts F2K's command interpreter"), "\n".join(output)
    assert CMD_SYNTAX in output, "\n".join(output)
    assert BANNER not in output, "\n".join(output)


@pytest.mark.kernel
def test_a_built_in_s_help(builder, log_path, boot_timeout):
    """`cmd /c cd /?`: cd's help, its syntax lines after its summary and an empty line, and the
    exit code 1, a help's return code."""
    output, code = run_with_c(builder, log_path, boot_timeout, "cd /?", [])
    assert code == 1, "\n".join(output)
    assert output[:6] == ["Shows the current directory, or changes it.", "", *CD_SYNTAX], \
        "\n".join(output)
