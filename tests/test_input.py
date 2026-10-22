"""input - the PS/2 keyboard's path into the console's input buffer, driven through QEMU's monitor:
the bytes the i8042 driver reads, and the key event records the console's producer appends.

The boot is hello's program smoke (as tests/test_screen.py's: the kernel through QEMU's Multiboot
loader, `hello.exe` from the volume's root, a QMP socket beside it), built with the `kbd-smoke`
feature: the keyboard driver's DPC reports on COM1 each byte it takes from the controller

    F2K: kbd: byte 0x1e                      (a reply to the driver's own command: "(reply)")

and each record the producer appends, as the input buffer then holds it

    F2K: kbd: record down vk=0x41 scan=0x1e char=0x0061 state=0x0000 repeat=1

(" (coalesced)" when it raised the last record's repeat count instead of taking a slot). The kernel's
lines are not program output, so hello's block still matches its fixture. Once the program has
ended and been torn down, keys are sent with the monitor's `sendkey` (a press and, its hold time
later, the release) while the idle thread keeps serving interrupts; each step waits, bounded, for
its keys' records before the next.

What the emulator was found to do, and the cases pin: the controller translates (bring-up reports
"translation on"); `sendkey pause` sends Pause's make and break back to back (E1 1D 45 E1 9D C5);
`sendkey` never repeats a held key (no typematic repeat, however long the hold), so two sendkeys
of one key are two presses; each lights exchange comes back as two 0xFA replies (the command's and
its argument's), which never reach the producer. The repeat count is built by the input buffer: two
keydowns with no keyup between (QMP's input-send-event) fold into one record counted 2.

    uv run pytest tests/test_input.py
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass
from pathlib import Path

import pytest

import f2kboot

HELLO = f2kboot.Block("hello.exe", ["Hello, world!"], exit_code=0)
FEATURES = ["kbd-smoke"]
# How long one step's records may take to arrive.
STEP_TIMEOUT = 5.0

READY = "F2K: kbd: keyboard ready on IRQ 1 (translation on)"
BYTE = re.compile(r"^F2K: kbd: byte 0x([0-9a-f]{2})( \(reply\))?$")
RECORD = re.compile(
    r"^F2K: kbd: record (down|up) vk=0x([0-9a-f]+) scan=0x([0-9a-f]+) char=0x([0-9a-f]+)"
    r" state=0x([0-9a-f]+) repeat=(\d+)( \((\w+)\))?$")

# The control-key state bits (dwControlKeyState).
LEFT_CTRL_PRESSED = 0x8
SHIFT_PRESSED = 0x10
NUMLOCK_ON = 0x20
CAPSLOCK_ON = 0x80
ENHANCED_KEY = 0x100
# The virtual keys the cases name.
VK_A = 0x41
VK_C = 0x43
VK_D = 0x44
VK_CLEAR = 0x0C
VK_RIGHT = 0x27
VK_NUMPAD5 = 0x65
VK_CAPITAL = 0x14


@dataclass(frozen=True)
class Record:
    down: bool
    vk: int
    scan: int
    char: int
    state: int
    repeat: int
    outcome: str  # "stored", or the line's mark ("coalesced", ...)


@dataclass
class Step:
    """Monitor commands sent together, and how many keyup records they end with."""

    commands: list[str]
    ups: int
    lines: list[str] | None = None

    @property
    def records(self) -> list[Record]:
        found = []
        for line in self.lines or []:
            match = RECORD.match(line)
            if match:
                down, vk, scan, char, state, repeat, _, outcome = match.groups()
                found.append(Record(down == "down", int(vk, 16), int(scan, 16), int(char, 16),
                                    int(state, 16), int(repeat), outcome or "stored"))
        return found

    @property
    def bytes(self) -> list[tuple[int, bool]]:
        """Each byte the driver read: its value, and whether it was a reply to the driver."""
        return [(int(match.group(1), 16), match.group(2) is not None)
                for match in map(BYTE.match, self.lines or []) if match]

    def key_bytes(self) -> list[int]:
        return [value for value, reply in self.bytes if not reply]

    def of(self, vk: int) -> list[Record]:
        return [record for record in self.records if record.vk == vk]


def sendkey(key: str) -> dict:
    return {"execute": "human-monitor-command", "arguments": {"command-line": f"sendkey {key}"}}


def key_event(qcode: str, down: bool) -> dict:
    return {"execute": "input-send-event",
            "arguments": {"events": [{"type": "key", "data": {"down": down, "key": {"type": "qcode", "data": qcode}}}]}}


def kbd_lines(log_path: Path) -> list[str]:
    return [line.strip() for line in f2kboot.lines_of(f2kboot.read_log(log_path))
            if line.startswith("F2K: kbd: ")]


def run(builder, log_path: Path, boot_timeout, steps: list[Step]) -> list[str]:
    """Boot hello with the diagnostic, then run each step once the program has ended: its commands
    in one QMP session, then a bounded wait for its keyup records. Each step keeps the diagnostic's
    lines it produced; the boot's own kbd lines are returned."""
    ran: list[bool] = []

    def observe(socket: Path) -> None:
        for step in steps:
            before = len(kbd_lines(log_path))
            commands = [sendkey(command) if isinstance(command, str) else command for command in step.commands]
            f2kboot.qmp_command(socket, commands)
            deadline = time.monotonic() + STEP_TIMEOUT
            while True:
                lines = kbd_lines(log_path)[before:]
                if sum(1 for line in lines if line.startswith("F2K: kbd: record up ")) >= step.ups:
                    break
                if time.monotonic() > deadline:
                    break
                time.sleep(0.05)
            # The keys' releases are in; anything still in flight (a lights reply) lands now.
            time.sleep(0.2)
            step.lines = kbd_lines(log_path)[before:]
        ran.append(True)

    log, stopped = f2kboot.boot(
        builder(FEATURES),
        image="kernel",
        cmdline=HELLO.command,
        memory="256M",
        log_path=log_path,
        timeout=boot_timeout(f2kboot.CORPUS_TIMEOUT) + STEP_TIMEOUT * len(steps),
        done=f2kboot.teardown_audited,
        observe=observe,
    )
    if not ran:
        pytest.fail(f"the boot never reached its teardown (stopped: {stopped})\nlog: {log_path}\n"
                    f"--- COM1 (tail) ---\n{f2kboot.tail(log)}", pytrace=False)
    mismatch = f2kboot.compare_block(HELLO, log, [])
    assert mismatch is None, f"the serial log does not carry hello's block: {mismatch}\nlog: {log_path}"
    boot_lines = [line for line in kbd_lines(log_path) if not BYTE.match(line) and not RECORD.match(line)]
    assert READY in boot_lines, f"bring-up: {boot_lines}\nlog: {log_path}"
    for step in steps:
        assert step.lines is not None and len(step.records) >= 2 * step.ups, (
            f"{step.commands}: records missing: {step.lines}\nlog: {log_path}")
    return boot_lines


@pytest.mark.kernel
def test_the_driver_reads_set_one_bytes(builder, log_path, boot_timeout):
    """The bytes as the controller translates them: a's make and break, the E0-prefixed left arrow,
    and Pause's E1 sequence, which the emulator sends make and break together."""
    a, left, pause = Step(["a"], 1), Step(["left"], 1), Step(["pause"], 1)
    run(builder, log_path, boot_timeout, [a, left, pause])
    assert a.key_bytes() == [0x1E, 0x9E], a.lines
    assert left.key_bytes() == [0xE0, 0x4B, 0xE0, 0xCB], left.lines
    assert pause.key_bytes() == [0xE1, 0x1D, 0x45, 0xE1, 0x9D, 0xC5], pause.lines
    assert [(r.down, r.vk, r.scan) for r in pause.records] == [(True, 0x13, 0x45), (False, 0x13, 0x45)]


@pytest.mark.kernel
def test_the_producer_appends_key_event_records(builder, log_path, boot_timeout):
    """The records: one keydown and one keyup per press, the character on the keydown only, the
    live control-key state, the toggles (their lights exchanged without a record), the keypad's Num
    Lock resolution, Ctrl+C kept by the default filter, the enhanced bit, and the repeat count."""
    a = Step(["a"], 1)
    shift_a = Step(["shift-a"], 2)
    caps_on, caps_a, caps_off, plain_a = Step(["caps_lock"], 1), Step(["a"], 1), Step(["caps_lock"], 1), Step(["a"], 1)
    num_on, pad_digit = Step(["num_lock"], 1), Step(["kp_5"], 1)
    # Two more presses leave Num Lock on; a third turns it off.
    num_off_again, num_on_again, pad_still = Step(["num_lock"], 1), Step(["num_lock"], 1), Step(["kp_5"], 1)
    num_off, pad_clear = Step(["num_lock"], 1), Step(["kp_5"], 1)
    ctrl_c = Step(["ctrl-c"], 2)
    right = Step(["right"], 1)
    twice = Step(["a", "a"], 2)
    held = Step(["a 1000"], 1)
    repeated = Step([key_event("d", True), key_event("d", True), key_event("d", False)], 1)
    steps = [a, shift_a, caps_on, caps_a, caps_off, plain_a, num_on, pad_digit,
             num_off_again, num_on_again, pad_still, num_off, pad_clear,
             ctrl_c, right, twice, held, repeated]
    run(builder, log_path, boot_timeout, steps)

    assert a.records == [Record(True, VK_A, 0x1E, ord("a"), 0, 1, "stored"),
                         Record(False, VK_A, 0x1E, 0, 0, 1, "stored")], a.lines

    down, up = shift_a.of(VK_A)
    assert (down.char, down.state & SHIFT_PRESSED, up.char, up.state & SHIFT_PRESSED) == (
        ord("A"), SHIFT_PRESSED, 0, SHIFT_PRESSED), shift_a.lines
    assert shift_a.records[-1].state & SHIFT_PRESSED == 0, "the shift's keyup: released"

    # Each toggle's make exchanges the lights: two replies, no record of their own.
    for step in (caps_on, caps_off, num_on, num_off):
        assert [value for value, reply in step.bytes if reply] == [0xFA, 0xFA], step.lines
        assert len(step.records) == 2, step.lines
    assert caps_on.records[0].vk == VK_CAPITAL and caps_on.records[0].state & CAPSLOCK_ON
    assert [(r.char, r.state) for r in caps_a.records] == [(ord("A"), CAPSLOCK_ON), (0, CAPSLOCK_ON)], caps_a.lines
    assert [(r.char, r.state) for r in plain_a.records] == [(ord("a"), 0), (0, 0)], plain_a.lines

    for step in (pad_digit, pad_still):
        keydown = step.records[0]
        assert (keydown.vk, keydown.scan, keydown.char, keydown.state) == (
            VK_NUMPAD5, 0x4C, ord("5"), NUMLOCK_ON), step.lines
    keydown = pad_clear.records[0]
    assert (keydown.vk, keydown.char, keydown.state & NUMLOCK_ON) == (VK_CLEAR, 0, 0), pad_clear.lines

    down, up = ctrl_c.of(VK_C)
    assert (down.char, down.state, down.outcome) == (0x03, LEFT_CTRL_PRESSED, "stored"), ctrl_c.lines
    assert up.char == 0

    assert [(r.down, r.vk, r.scan, r.state) for r in right.records] == [
        (True, VK_RIGHT, 0x4D, ENHANCED_KEY), (False, VK_RIGHT, 0x4D, ENHANCED_KEY)], right.lines

    # The emulator does not repeat: two sendkeys are two presses, a long hold one keydown.
    assert [(r.down, r.repeat, r.outcome) for r in twice.records] == [
        (True, 1, "stored"), (False, 1, "stored")] * 2, twice.lines
    assert [(r.down, r.repeat) for r in held.records] == [(True, 1), (False, 1)], held.lines
    # Two keydowns with no keyup between: the buffer counts the second on the first.
    assert [(r.down, r.vk, r.repeat, r.outcome) for r in repeated.records] == [
        (True, VK_D, 1, "stored"), (True, VK_D, 2, "coalesced"), (False, VK_D, 1, "stored")], repeated.lines
