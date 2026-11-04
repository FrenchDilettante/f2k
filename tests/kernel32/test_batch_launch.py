"""batch launch - CreateProcess hands a batch file to the command processor: a `.bat` file run as a
program becomes `cmd /c` and its command line, run by the cmd.exe the search finds.

The boot is the kernel through QEMU's Multiboot loader, with the `redirected` kernel option, its
command line running `CORPUS\\pipekid.exe /c job.bat`. The disk the tests boot has no cmd.exe, so
this boot attaches a copy of it (removed after the boot) with three files added:

- \\WINNT\\system32\\cmd.exe: the pipe fixture's companion, pipekid.exe, whose `/c` mode stands in
  for the command processor (tests/kernel32/pipe/pipekid.c): it prints its own command line, then
  runs the rest of it after the switch with CreateProcessA;
- \\CORPUS\\job.bat: a batch file, text with no MZ signature;
- \\WINNT\\system32\\job.bat: the spawn fixture's companion, spawnkid.exe, under the batch file's
  name. A file is a batch file only when no image section can be made of it, so this one runs as
  the program it is, printing its command line.

pipekid, run from \\CORPUS (which is also its current directory), prints its command line and runs
`job.bat`. The search finds \\CORPUS\\job.bat first (the program's directory), which is no image:
kernel32 runs `cmd /c job.bat` instead, cmd found in the system directory. The stand-in there prints
that command line and runs `job.bat` in turn; its search looks in its own directory first, finds
the image named job.bat, and spawnkid prints the command line it was given. Without that image the
stand-in's `job.bat` would be the batch file again, each command processor starting another. The
exit code is spawnkid's, 0, passed back up through both pipekids. The program's output must read:

    pipekid: /c: command line [CORPUS\\pipekid.exe /c job.bat]
    pipekid: /c: command line [cmd /c job.bat]
    kid: command line [job.bat]
    kid: argc 1
    kid: argv[0] [job.bat]

    uv run pytest tests/kernel32/test_batch_launch.py
"""
from __future__ import annotations

import shutil
import subprocess

import pytest

import f2kboot

COMMAND_LINE = r"CORPUS\pipekid.exe /c job.bat"
PIPEKID = f2kboot.TESTS / "kernel32" / "pipe" / "pipekid.exe"
SPAWNKID = f2kboot.TESTS / "kernel32" / "spawn" / "spawnkid.exe"
BATCH = b"@echo off\r\necho the command processor ran job.bat\r\n"
OUTPUT = [
    r"pipekid: /c: command line [CORPUS\pipekid.exe /c job.bat]",
    "pipekid: /c: command line [cmd /c job.bat]",
    "kid: command line [job.bat]",
    "kid: argc 1",
    "kid: argv[0] [job.bat]",
]
# How long the boot may take to run the three processes.
TIMEOUT = 30.0


@pytest.mark.kernel
def test_a_batch_file_runs_under_cmd(builder, log_path, boot_timeout, tmp_path):
    """`job.bat` run by CreateProcess: the command processor's command line is `cmd /c job.bat`."""
    build = builder([])
    system = tmp_path / "system32"
    corpus = tmp_path / "corpus"
    system.mkdir()
    corpus.mkdir()
    shutil.copyfile(PIPEKID, system / "cmd.exe")
    shutil.copyfile(SPAWNKID, system / "job.bat")
    (corpus / "job.bat").write_bytes(BATCH)
    variant = f2kboot.disk_with_programs(build, [system / "cmd.exe", system / "job.bat"],
                                         f2kboot.WORK / "variants" / f"{log_path.stem}.img")
    try:
        subprocess.run(
            ["mcopy", "-i", f"{variant}{f2kboot.PARTITION}", str(corpus / "job.bat"),
             f"::/{f2kboot.CORPUS_DIRECTORY}/"],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        log, stopped = f2kboot.boot(
            f2kboot.Build(build.kernel, variant),
            image="kernel",
            cmdline=COMMAND_LINE,
            memory="256M",
            log_path=log_path,
            timeout=boot_timeout(TIMEOUT),
            done=f2kboot.teardown_audited,
            kernel_options=f2kboot.REDIRECTED_OPTION,
        )
    finally:
        variant.unlink(missing_ok=True)
    context = f"\nlog: {log_path}\n--- COM1 (tail) ---\n{f2kboot.tail(log)}"
    assert "KERNEL PANIC" not in log, f"the kernel panicked{context}"
    output, exit_code = f2kboot.program_output(log)
    assert exit_code is not None, f"the program never ended (stopped: {stopped}){context}"
    assert output == OUTPUT, f"the output differs{context}"
    assert exit_code == 0, f"exit code {exit_code}{context}"
    problem = f2kboot.teardown_problem(f2kboot.lines_of(log))
    assert problem is None, f"{problem}{context}"
