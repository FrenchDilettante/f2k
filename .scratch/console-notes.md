# Console backend: VGA display, PS/2 keyboard — notes

Branch `feat/console` (off master 743d4a7), uncommitted. Written 2026-10-15.
Decisions taken with you: the screen is the console and every console byte is mirrored to COM1
(the suite keeps reading COM1); VGA text mode 80x25; PS/2 keyboard for input.

## What was done

Output:
- `console/screen.rs`: the screen buffer, a grid of cells (UTF-16 character and attribute word,
  the shape of `CHAR_INFO`) of 80x300, with a cursor and an 80x25 window that follows the cursor.
  Bytes written follow the default output mode (processed output, wrap at end of line); details
  and assumptions below.
- `console/cp437.rs`: codepage 437, used both for bytes written to the console (output codepage)
  and to turn cells back into VGA font glyphs. Unmapped characters show as `?`.
- `hw/vga.rs`: the 80x25 text grid at physical 0xB8000 (through the kernel window) and the CRT
  controller's cursor (location registers, disable bit; the shape is left as the firmware set it).
- `console/mod.rs`: the single console. `write` updates the buffer, mirrors the bytes unchanged
  to COM1, redraws the window if it changed, and places the cursor. `init` (right after the boot
  banner) draws a blank window. All console state is touched with interrupts masked
  (`pushfd`/`cli`/`popfd`): that is the lock on one CPU.
- `compat/kernel32.rs` WriteFile: console handles now go to `console::write`, in chunks of 256
  bytes (one redraw per chunk). The byte-by-byte copy from user memory is kept, so a bad buffer
  behaves as before (the bytes before the bad one are still written).

Input:
- `hw/ps2.rs`: the 8042. Bring-up drains pending bytes and rewrites the configuration byte with
  the keyboard interrupt, keyboard clock and set-1 translation on (other bits kept). IRQ 1 at the
  new `irql::KEYBOARD` level (26, by the 27-minus-IRQ rule the IDE level 13 also follows). The
  service routine reads the byte into a 32-byte ring and queues a DPC; the DPC feeds the console.
  Mouse bytes are read and dropped.
- `console/keyboard.rs`: scancode set 1 decoder to key events with the fields of a console input
  record (down/up, virtual key, scan code, character, control-key state), US layout.
- `console/input.rs`: a bounded ring (drops and counts when full); the console's key-event queue
  holds 64. Nothing reads it yet except the diagnostic: no console read service exists.
- The decoder starts from the BIOS data area's lock flags (physical 0x417).

Diagnostics and harness:
- Feature `console-smoke`: writes 30 lines and a tab through the console, reads the VGA grid and
  the CRTC cursor back, reports on COM1. Cases `console-smoke` and `console-smoke-disk`.
- Feature `keyboard-smoke`: waits (10 s max) for 10 key events, reports each, echoes the typed
  characters through the console and reads the row back. Cases `keyboard-smoke` and
  `keyboard-smoke-disk`.
- Suite key injection: a case can have `keys: {after: "<COM1 string>", send: [h, i, shift-a,
  ret]}`. `run-qemu-tests.py` passes them to `test-boot.sh` (`BOOT_KEYS`, `BOOT_KEYS_AFTER`), which
  gives that case a QEMU monitor socket (others keep `-monitor none`) and sends one `sendkey` per
  key, 200 ms apart, once the string appears.
- `make qemu` / `make run` now open the display window; COM1 and the QEMU monitor share the
  terminal (`-serial mon:stdio`: Ctrl-A C switches, Ctrl-A X quits). Headless override in README.

Verification: host tests 674 passed (620 + 54 new); `make fmt-check` clean; `make check` at the
master warning count (145); on-target cases console-smoke, keyboard-smoke and hello-smoke pass on
both boot paths. Screendumps of hello on both boot paths are 720x400 (VGA text mode with the 9x16
font) and show "Hello, world!" with the cursor on the next line: `console-hello.png` (Limine
path). Full-suite results: see the end of this file.

## Assumptions to validate

### Windows behaviour (needs console fixtures from the real machine)

1. **Default buffer 80x300, window 80x25, attribute 0x07.** Believed to be Windows 2000's
   defaults for a new console; not captured. A fixture calling GetConsoleScreenBufferInfo pins all
   three (and the initial cursor).
2. **Line feed starts a new line** (column 0 of the next row), not just a row down. This is the
   classic console's processed-output behaviour as I understand it; hello writes CR LF, so it
   doesn't tell.
3. **Backspace** moves one column left and never erases; at column 0 it does not move (and does
   not go back to the previous row).
4. **Tab** writes blanks (overwriting) up to the next multiple-of-8 column, wrapping like ordinary
   characters at the end of a row.
5. **BEL** does nothing (no speaker); on Windows it beeps. Other control codes (0x01, ESC...) are
   stored as characters and show as their VGA glyphs.
6. **Wrap at end of line**: the cursor moves to the next row as soon as the last column is
   written, so CR LF after a full row leaves an empty row.
7. **Scrolling**: the window follows the cursor down the 300 rows; at the last row the whole
   buffer scrolls and the new row is blank in the current attributes.
8. **Output codepage 437** for bytes written with WriteFile, with the standard published mapping
   (not a real-machine capture, unlike the 1252 tables). Unmapped characters display as `?`.
9. **Key events**: Shift/Ctrl/Alt report the generic VK_SHIFT/VK_CONTROL/VK_MENU; the control-key
   state is the state after the key; the up event carries the same character as the down event;
   Ctrl+letter gives the control code, Ctrl with [ \ ] gives 0x1B-0x1D, Ctrl+Enter gives LF,
   Ctrl+Backspace gives 0x7F, Ctrl+anything else and Ctrl+Alt give no character, Alt alone keeps
   the character; the keypad prints under Num Lock XOR Shift; Pause is one down event with scan
   code 0x45. All from my reading of the US layout; a fixture printing ReadConsoleInput records
   for a scripted typing session pins them.

### Hardware and firmware (verified on QEMU only)

10. **The firmware leaves VGA text mode 80x25** with the colour CRTC at 0x3D4. Verified by
    screendump on QEMU for both boot paths (SeaBIOS, and Limine's Multiboot 1 path). Not tried on
    VirtualBox or real hardware; a UEFI boot would have no text mode at all.
11. **The 8042 needs no reset**: the driver trusts the firmware's controller state and only fixes
    the configuration byte. QEMU's controller came up as 0x61 after configuration. A keystroke
    arriving during bring-up could be misread as the configuration byte (narrow window at boot).
12. **The BIOS data area holds the lock state** at 0x417. QEMU/SeaBIOS starts with all locks off.
    The keyboard LEDs are never updated by F2K, so they can disagree with the decoder's state.
13. **QEMU `sendkey` releases in reverse order** (shift-a gives Shift down, A down, A up, Shift
    up); the keyboard-smoke expectations rely on it.

### Design choices you may want to revisit

14. **The kernel log stays COM1-only**: only console output (program writes, diagnostics that go
    through the console) appears on the screen. Boot messages are not shown on the display.
15. **One console, one input queue**, both global; per-process consoles, AllocConsole/FreeConsole
    and handle-based console objects are later work.
16. **Input is dropped when nobody reads it** (64 events, 32 raw bytes). Typing at the QEMU window
    today fills the queue and then drops.
17. **WriteFile redraws the whole window once per 256-byte chunk** (2000 cell writes). Fine for
    now; dirty-row tracking can come when scrolling output gets heavy.

## Not done (needs fixtures, or later steps)

- Win32 console services: WriteConsoleW, ReadConsoleW / ReadFile on stdin (cooked mode with echo
  and line editing), ReadConsoleInput, Get/SetConsoleMode, GetConsoleScreenBufferInfo,
  SetConsoleTextAttribute, SetConsoleCursorPosition, FillConsoleOutputCharacterW/Attribute,
  ScrollConsoleScreenBufferW, Get/SetConsoleTitleW, FlushConsoleInputBuffer, GetConsoleOutputCP.
- Ctrl-C / Ctrl-Break delivery (SetConsoleCtrlHandler) — needs a thread injected into the process.
- Keyboard LEDs, Beep, the mouse, other layouts.

## Suggested fixtures

- `conwrite`: writes a fixed byte sequence (tab, backspace at column 0, a full 80-column row then
  CR LF, a bare LF, BEL, a control code, a 437 high byte) with WriteFile, then dumps the cursor
  and the first rows of the buffer (GetConsoleScreenBufferInfo, ReadConsoleOutputCharacterA,
  ReadConsoleOutputAttribute) to a file. Pins assumptions 1-8.
- `coninput`: ReadConsoleInput in a loop, printing each KEY_EVENT_RECORD, while a scripted key
  sequence is typed (letters, Shift, Caps Lock, Ctrl+C with processed input off, keypad with and
  without Num Lock, arrows, Pause). Pins assumption 9.
- `conread`: ReadConsoleA / ReadFile on stdin in the default cooked mode, typing a line with a
  backspace in it. Pins echo and line-editing behaviour for the read service.

## Full-suite results

`make test`: 20 passed, 0 failed (the 18 existing kernel-path cases plus console-smoke and
keyboard-smoke). `make test-disk`: 14 passed, 0 failed (the 12 existing disk-path cases plus
console-smoke-disk and keyboard-smoke-disk). Every existing case passed unchanged: the COM1 mirror keeps the program output
they expect.
