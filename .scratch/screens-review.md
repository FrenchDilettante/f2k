# Review of a896114 (VBE framebuffer and FiSH), 2026-11-04

Findings of a review of `a896114`, and what the wip commit holding this file changes.
That commit's diff was prototyped and stressed during the review; nothing was re-run after committing it.

## Fixed in this commit

### 1. The real-mode window kills every hardware interrupt (the flaky `test_framebuffer`)

- **Cause:** the blob's real-mode leg runs `sti` with the BIOS's IVT.
  The kernel remaps IRQ 0-15 to vectors 0x30-0x3F, and SeaBIOS points those at a bare `iret`, which sends no EOI.
  A tick arriving during the window, or already pending from the masked part of the service, leaves IRQ 0 in service forever.
  That blocks every line, so the clock stops and fish waits forever on the disk interrupt for `exit0.exe`.
- **Evidence:**
  - Stalled machines over QMP: master PIC `irr=05 imr=f8 isr=01`, slave `irr=40` (IRQ 14 blocked behind IRQ 0), CPU halted in `pcr::halt_enabled`.
  - A PIC readout around `vbe_enter`: ISR went from 0x00 to 0x01 across the first trampoline run in every failing boot, and stayed 0x00 in every passing one.
  - Each run takes about 1.3-1.5 M TSC counts.
- **Symptom:** the test fails at "exited normally (exit code=0)" after its timeout.
  COM1 ends at `F2K: vbe: 640x480x32, LFB at 0xfd000000, mapped at 0xc0800000`.
- **Fix:**
  - `interrupt::with_lines_masked(f)` (over `Pic::line_masks` and a new `Pic::set_line_masks`) masks every line around `vbe_enter` and restores the masks after, so a tick raised in the window stays pending and arrives afterwards.
  - `vbe_enter` saves the caller's EFLAGS (`pushfd` before `cli`), and `pm_virtual` ends `popad; popfd; ret` instead of `sti; popad; ret`.
- **Stress (`test_framebuffer`):**

  | Build | Before | After |
  |---|---|---|
  | dev | 121/334 (36%) | 0/440 |
  | dev-opt | 70/200 (35%) | 0/200 |

  These counts were taken while another agent was stress-testing QEMU on the same machine.

### 2. The trampoline overwrites live kernel page tables

- **Cause:** `bootmem.rs` reserved only frame 0x90.
  The blob also writes frame 7 (its stack below 0x7C00), frame 8 (the bounce blocks at 0x8000-0x84FF) and frames 0x10-0x17 (the mode-info buffer at 0x10000-0x17FFF).
  The frame database hands those out first.
- **Seen:** a page-content comparison around each run showed overwritten page tables:
  - frame 0x8: the page table for PDE 657, kernel stacks at 0xA4400000;
  - frame 0x10: the page table for PDE 659, kernel stacks;
  - frame 0x14: the page table for PDE 1019, the nonpaged pool's first table.

  The mode list itself often sits in the reply block at 0x8000, so the kernel read mode numbers out of a live page table.
- **Failure:** with only fix 1, `fish.exe \CORPUS\pipe.exe create` panics with `kernel page already mapped` (`mem/paging.rs:870`) at CreatePipe's first pool allocation.
- **Fix:** frames 7, 8, 0x10-0x17 and 0x90 are taken out of the free lists at boot, all or none.
  With it, the pipe run is clean ("frame database ok").
- **Tidier later:** the stack, bounce blocks and buffer next to 0x90 in one reserved run. Done: see "Resolved after the review", item 1.
- **Still wrong:** the SAFETY comments in `TrampolineBios::run` and `mode_info` ("the trampoline's own memory"), and `test_repository.py`'s exemption text ("never a program's"), are not updated by this commit. Resolved: item 1 below.

### 3. The protected-mode `sti` broke the masked-service rule

- `trampoline.rs`'s `pm_virtual` re-enabled interrupts inside a service, which runs masked until its first wait.
- **Risk:** between the `sti` and `activate_address_space(caller_dir)`, a tick could switch processes.
  The cleanup would then run on the wrong directory: `remove_low_identity` would wipe the user directory's entries 0-3 (the image at 0x400000, the stack at 0x130000), or the switch's debug assert would panic.
- Found by reading the code, not seen in a run.
- Fixed by the `popfd` above.
  The SAFETY comment "Interrupts are as `vbe_enter` saved them" now holds.

## Open at the review (each resolved below)

1. **`enter_graphics_mode` can spin forever** (`trampoline.rs`, about line 570).
   The second caller spins on `DONE` with interrupts masked, and a failed first set never sets `DONE`.
   Suggestion: wait while `SETTING`, then check `DONE` again and return the failure.
2. **The real-mode switch skips Intel's procedure.**
   It never loads the 16-bit data descriptors (0x10, 0x18) before clearing PE, so real mode inherits flat limits and SS with B=1.
   This works today because ESP's upper half is 0; a BIOS relying on SP wrap-around could break.
   An NMI between the paging-off legs and the IDT reload would triple-fault.
3. **fish's child command line may lack its NUL** (`userland/fish/src/main.rs`, about line 27).
   `line.get_mut(..child.len())` accepts exactly MAX_PATH bytes.
   `exe::create_child(&mut [u8])` is safe but its callee reads to NUL: unsound for a slice without one.
4. **`exe::gate`'s SAFETY claim:** the kernel copies the service's declared argument size (20 bytes), not `args.len() * 4`.
   Also, fish calls `int 2Eh` itself rather than going through user32's ChangeDisplaySettingsA, which isn't Windows 2000's layering.
5. **Minor:**
   - `Child::wait_exit_code` leaks both handles on its error paths.
   - fish returns NO_GRAPHICS (1) when the child can't start.
   - NtUserChangeDisplaySettings returns an NTSTATUS where Windows 2000's returns a DISP_CHANGE.
   - `TrampolineBios` (about 780 bytes) is returned by value, and `vbe_present` has a 512-byte array.
   - The console keeps writing to 0xB8000 after the mode set.
6. **The test proves too little.** A child that creates a pipe and sleeps (`\CORPUS\pipe.exe create`) would catch findings 1 and 2 directly.

## Checked and fine

- **The GDT round trip:** `PCR` is a static in the kernel image, so subtracting KERNEL_BASE gives its physical address.
- **The scan's bounds:** it stops at 128 modes, so DI ≤ 0x7F00 and the buffer ends at 0x17FFF.
- **By reading only:** CR0 toggles only PE and PG; A20 via port 0x92; the framebuffer region's shared tables, uncached mapping and TLB flushes; `display.rs` reads no user memory.

## Checks on a896114 as it stood

- run-tests: 1632 passed.
- `compat.py --check`: ok.
- check-all: 1 failed (`test_framebuffer`, the hang), 489 passed, 42 xfailed.

## Resolved after the review

The open items and the stale text, as the commits after `a13a5a6` resolve them.

1. **The stale text, and the tidier layout** (`fix:` commit on the trampoline).
   - The trampoline now owns one run of conventional memory, 0x90000-0x9AFFF (11 frames), taken out of the free lists at boot, all or none (`bootmem::TRAMPOLINE_FIRST_FRAME`, `TRAMPOLINE_FRAMES`, `TRAMPOLINE_RESERVED`).
     It holds the blob's code (0x0000), the VBE information block (0x1000), the save area (0x1200), the real-mode stack (0x2000-0x2FFF) and the mode-info buffer (0x3000-0xAFFF, 128 blocks).
   - Why it simplifies: every segment register is 0x9000 in real mode, so the blob's real-mode addresses are offsets in one segment; the five scattered frames, the separate 0x1000 buffer segment and the `LOW_PAGE` reload go.
     The save area is a `repr(C)` structure the assembly reaches through `offset_of!`, and the transition GDT is built in Rust (a const-checked `descriptor`), so the blob no longer writes descriptor bytes.
   - The lone `AX=4F01h` probe of mode 0x112 and its 256-byte block were dropped: nothing read them.
   - The SAFETY comments in `TrampolineBios::run`, `vbe_info`, `mode` and `mode_info` say the run is the trampoline's alone; `test_repository.py`'s exemption names the reserved run, the BIOS's mode list and the framebuffer.
   - EBDA: on QEMU the map's usable low memory ends at 0x9FC00; a firmware reservation inside the run leaves the mode set unservable (`ModeError::Unsupported`), as before.
2. **`enter_graphics_mode` can spin forever.**
   Restructured so nobody waits: `hw::vbe::ModeSet` (host-tested, `the_mode_set_never_waits`) answers a caller arriving during a set `Busy` at once (DISP_CHANGE_FAILED), and a failed set returns the state to unset, so the next call tries again.
   The geometry lives in an `InitOnce`, set before the state says set.
3. **Intel's procedure.**
   - The blob is entered at its physical address with paging still on (the identity window), loads the transition GDT, and in its 16-bit code segment loads the 16-bit data descriptor (base 0x90000, limit 0xFFFF, B=0) into SS, DS, ES, FS and GS and sets ESP (upper half 0); then paging off, LIDT of the BIOS's vector table, PE off, a far jump reloading CS.
     The change of CR0.PG flushes the TLB, so CR3 is not zeroed.
   - The way back: PE on, a far jump into the 32-bit segment, the kernel's GDT (its linear base: it is loaded before paging goes on and read only after), paging on, the kernel's data segments and saved stack, a far return into the kernel image, the kernel's IDT. FS and GS are saved and restored (the real-mode leg zeroed them before).
     The kernel GDTR's physical-base round trip is gone.
   - NMI: no IDT is usable from the transition GDT's load to real mode, and from PE's return to the kernel's LIDT: about a dozen instructions each, with no memory traffic but the save area's.
     F2K arms no NMI source; only a hardware error (parity, a channel check) raises one, which is fatal anyway.
     Masking NMI through the CMOS index port (0x70 bit 7) would close the windows, but the RTC driver owns that port; left as a note in the trampoline's module docs.
4. **fish's command line terminator** (`fix:` commit on fish and exe).
   `exe::create_child` takes an `exe::CommandLine`, made only by `CommandLine::new`, which copies the text and its NUL into the caller's buffer and refuses text that does not fit with it, or holds a NUL (host-tested).
   fish's line of exactly MAX_PATH bytes is now refused as too long (USAGE).
5. **`exe::gate`, and the layering** (`feat:` commit).
   - user32 exports ChangeDisplaySettingsA, ChangeDisplaySettingsW, ChangeDisplaySettingsExA and ChangeDisplaySettingsExW (ordinals 28-31) over its own NtUserChangeDisplaySettings stub; the narrow forms convert the name (RtlMultiByteToUnicodeN, in the real user32's imports) and the DEVMODEA (read as far as its dmSize goes) to the wide forms.
     `rtl::display` holds DEVMODEA/DEVMODEW (Windows 2000's 156 and 220 bytes, offsets asserted), the DM_, CDS_ and DISP_CHANGE values and the conversion.
   - fish calls ChangeDisplaySettingsA with a DEVMODEA asking 640x480x32 (`exe::change_display_mode`); `exe::gate`, its `int 2Eh` stub and the service numbers are removed: nothing else used them.
     fish.exe now imports user32; pwd.exe still imports kernel32 alone.
   - NtUserChangeDisplaySettings answers DISP_CHANGE codes in EAX: SUCCESSFUL; BADMODE for an unlisted mode, a DEVMODE shorter than the display fields, a refresh rate other than 0/1 or display flags; FAILED for a refusing BIOS or a set in progress; BADFLAGS for flags other than 0, CDS_FULLSCREEN and CDS_TEST; BADPARAM for a window, a parameter, an unreadable argument or a name other than `\\.\DISPLAY1`.
     CDS_TEST runs the information pass and answers without setting. The DEVMODE's width, height and depth become a `ModeRequest`; 640x480 stays the preference when it leaves them open; once set, only requests that mode answers succeed.
   - `uv run scripts/compat.py --check`: ok (user32's imports stay within the real one's).
6. **Minor.**
   - `Child` closes its handles in `Drop`, so every path of `wait_exit_code` closes them.
   - fish's own exit codes are documented in its library: NO_GRAPHICS 1, USAGE 2, NO_CHILD 4 (a child that cannot be started, waited for or read; 3 is the runtime's panic code).
   - `TrampolineBios` holds one `bool` (the blocks are read in place from the run); the BIOS seam reads an 18-byte header (`VBE_HEADER_BYTES`) and the mode list one entry at a time, so `vbe_present`'s 512-byte array and `set_graphics_mode`'s 256-byte mode array are gone; the largest remaining frame array is one 256-byte mode-info block.
   - The console server stops presenting to the VGA text page once `hw::vbe::graphics_mode_set()`: the damage is taken and dropped; the serial mirror is untouched.
7. **The test** (`test:` commit).
   `test_framebuffer` runs `fish.exe \CORPUS\pipe.exe create` (`\CORPUS` is on every disk the Makefile builds; the create section makes pipes, i.e. nonpaged-pool allocations, and its threads wait on 100 ms timeouts, so the clock must run).
   It asserts pipe's normal exit, FiSH's, the clean teardown and the solid-desktop screen (pipe's console output must not reach it).
   Checked against a build that left the run in the free lists: the boot stalls after the mode line and the test fails.

## Checks after the fixes

- `test_framebuffer` stress on the dev build, `fish.exe \CORPUS\pipe.exe create`, 4 boots at a time while other agents ran QEMU: 0 failures in 200 boots (`target/screens/fbstress.py`, the review's driver with the new command line and pipe's exit line added to its verdict).
- run-tests: 1644 passed.
- `compat.py --check`: ok.
- check-all (`-n 2`): 490 passed, 42 xfailed, none failed.

## Still open

- Real hardware (unchanged): BIOSes that need interrupts during int 10h (the lines stay masked), and where Limine puts the Multiboot structures relative to 0x90000-0x9AFFF (a reservation there only disables the mode set).
- The NMI windows above.
- The mode is set once: a request for another mode after it answers DISP_CHANGE_BADMODE rather than switching.
