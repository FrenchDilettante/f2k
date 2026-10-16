"""Checks on the repository's own files (no QEMU)."""
from pathlib import Path

import pytest

import f2kboot

BATCH_FILES = sorted((f2kboot.REPO_ROOT / "tests").rglob("*.bat"))


@pytest.mark.parametrize("path", BATCH_FILES, ids=lambda p: str(p.relative_to(f2kboot.REPO_ROOT)))
def test_batch_files_keep_crlf_line_endings(path: Path):
    """cmd.exe misreads LF-only batch files (it can resume mid-line between its reads), which mangles
    commands: the Windows 2000 scripts must keep CRLF on every line."""
    data = path.read_bytes()
    bare_lf = data.count(b"\n") - data.count(b"\r\n")
    assert bare_lf == 0, f"{bare_lf} line(s) end in a bare LF"
