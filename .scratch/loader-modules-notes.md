# Loader: preferred bases, DLLs, modules, exports — notes

Branch `feat/loader-modules` (off master 743d4a7), uncommitted. Written 2026-10-15.

## What was done

Steps 1–5 of the loader plan, i.e. everything that does not need a DLL fixture.

1. **Preferred base.** `Image::parse` no longer pins 0x0040_0000. A base must be a nonzero
   64 KiB multiple (`Reject::ImageBaseUnaligned`) and the image must end at or below
   `KERNEL_BASE` (`Reject::ImageOutsideUserSpace`). The loader maps at `image.image_base`.
   Before mapping it checks the image against `SYSTEM_REGIONS` in `loader.rs` (main stack, main
   TEB, process parameters, child TEBs, child stacks, kernel32 thunk page, heap region, CRT
   region floor); an overlap is reported on COM1 and halts. `THUNK_PAGE` keeps its value
   (0x0140_0000) but is now a fixed layout constant instead of `IMAGE_BASE + MAX_IMAGE_SIZE`.
2. **DLL recognition.** The file header's characteristics are parsed; `Image::is_dll()` tests
   IMAGE_FILE_DLL (0x2000). DLLs skip the console-subsystem rule and may have entry point 0 (an
   entry point, when present, must still be in an executable section). `Image::parse_program`
   refuses a DLL (`Reject::NotAProgram`); `load_image` uses it. The "at least one live import"
   contract applies only to programs.
3. **Per-module import resolution.** `snap_imports` takes `resolve(module, name) ->
   Result<u32, Unresolved>`; `Unresolved::{NoModule, NoEntry}` panic as "import module 'X' is not
   loaded" / "entry point 'Y' not found in X". The module table is `loader::resolve_import`: today
   only the synthesized kernel32. Helper `pe::same_module` (case-insensitive, missing extension
   means ".dll").
4. **Export directory.** `Image::exports(mapped)` gives `Exports` with `by_name` (exact, linear
   over the whole name table) and `by_ordinal` (biased by the ordinal base); an unused slot (RVA 0)
   is no export; an RVA inside the directory's own range is `Export::Forwarder`.
   `pe::split_forwarder` splits "MODULE.Name" / "MODULE.#n". Marked `allow(dead_code)` on target:
   nothing calls it until DLL loading lands.
5. **Staging.** File and image staging grew from 0x8000 to 0x8_0000 (512 KiB) each. An image that
   does not fit the image staging is now a COM1 refusal instead of a kernel panic.

Smaller changes:
- Import module names are read from the file bytes (they used to be read from the mapped image;
  the borrow now has to outlive the IAT write). Out-of-image / non-file-backed names panic with
  "import module name RVA ... is outside the image" / "... is not backed by file data".
- `THREAD_STACK_PAGES` moved from `process/threads.rs` to `user/mod.rs` (the layout table needs it
  on host builds). `HEAP_REGION_BASE`, `HEAP_REGION_MAX` and `CRT_REGION_BASE` are no longer
  x86-gated, so their placement test now runs on the host.
- The "image loaded" COM1 line now prints the base too (the suite matches only its prefix).

Test changes to existing tests (deliberate):
- `foreign_image_base_rejects` → replaced by `the_preferred_base_is_the_mapping_base`,
  `unaligned_image_base_rejects`, `image_past_user_space_rejects`.
- `foreign_module_panics`: new message; its patch now writes the NUL (it used to leave
  "USER32.dllll", which the old message hid).
- `module_name_outside_image_panics`: new message (file-backed read).
- `refusals_report_their_status`: staging size in the message.
- `thunk_page_layout_is_consistent` / `params_layout` (user/mod.rs): the IMAGE_BASE comparisons
  went with the constant; the loader's placement tests cover what they guarded.

Verification: host tests 646 passed (620 baseline + 26 new); on-target `make test` 18/18,
`make test-disk` 12/12; `make fmt-check` clean; `make check` at the master warning count (145).

## Assumptions to validate

Ordered by how likely they are to bite when cmd.exe / msvcrt.dll are first loaded.

### Need data from the Windows 2000 machine (dumpbin /headers, /imports, /exports)

1. **512 KiB staging is enough.** I assumed cmd.exe and msvcrt.dll are "a few hundred KiB" both as
   files and as SizeOfImage. Not measured. Check the file sizes and SizeOfImage. (Kernel room is
   not the limit: the debug kernel now ends at 0x8055F000 in an 8 MiB window ending at
   0x80800000, about 2.6 MiB of headroom.)
2. **The system images place cleanly.** `system_binary_bases_place_cleanly` uses the bases from
   closure.txt with an assumed size of 1 MiB each. Confirm SizeOfImage stays below that, or at
   least clear of the next system region. Nothing low in user space is at risk: every system base
   sits far above the fixed regions (highest region ends at 0x0211_0000).
3. **No ordinal imports.** Ordinal imports still panic ("ordinal import ..."). closure.txt listed
   every import by name, but dumpbin prints ordinal-only imports as "Ordinal N", and I did not see
   the raw dump. Check that `dumpbin /imports` shows no "Ordinal" lines for cmd.exe and
   msvcrt.dll.
4. **Bound imports carry an original thunk array.** I assumed Win2000 system binaries are bound
   (IAT pre-filled with addresses inside the real DLLs). The snap ignores IAT contents and reads
   names from OriginalFirstThunk, so binding is harmless as long as OriginalFirstThunk is present
   and valid. If it is missing or out of range, the walk falls back to the IAT, which on a bound
   image holds addresses, not name RVAs, and the snap would panic. Check `dumpbin /headers`
   (Bound Import Directory) and that each import descriptor has a nonzero OriginalFirstThunk.
5. **msvcrt.dll exports no forwarders, or only to modules we will have.** Forwarders are parsed but
   not resolved across modules yet. Check `dumpbin /exports msvcrt.dll` for "forwarded to" lines.
6. **Preferred bases are 64 KiB multiples.** The format requires it and the closure's bases comply;
   if a real image didn't, it would now be refused rather than mapped. Low risk.

### Assumptions about loader semantics (from the PE/COFF spec, not observed)

7. **Forwarder split on the last dot.** `split_forwarder("A.B.C")` gives module "A.B", entry "C".
   I have not confirmed whether the NT loader splits on the first or the last dot. It does not
   matter for Win2000-era module names (no dots), but should be pinned by observation if a dotted
   name ever appears.
8. **Module-name matching.** A name with no dot means "<name>.dll"; a name with a dot compares
   whole and case-insensitively. Not handled: a trailing dot meaning "no extension", and path
   components in a module name. Neither appears in the closure.
9. **Export names compare exactly and the name table is walked in full.** Windows binary-searches
   the (sorted) name table after trying the hint. The results differ only for an unsorted table,
   where we find a name Windows would not. Hints are still ignored.
10. **Name-ordinal entries are unbiased address-table indexes.** Per the spec; tested only against
    the synthetic table.
11. **A DLL's subsystem is irrelevant and its entry point may be 0.** Per the spec and the closure's
    note that DLL subsystems vary (msvcrt.dll is GUI). Programs are still CUI-only.

### Things the synthetic tests cannot prove (need the DLL fixture)

12. **The export reader on a real linker's output.** All export tests run against a hand-written
    export directory patched into exit0's .rdata padding. The first real DLL fixture should get
    a test that resolves every export by name and ordinal against its `dumpbin /exports`.
13. **The placement check against a real DLL plus program pair.** Only single-program placement is
    exercised on target. Two modules at distinct bases have not been mapped in one address space
    yet.

### Known gap (not an assumption, a hazard)

14. **CRT region vs images.** VirtualAlloc's NULL reservation starts at `CRT_REGION_BASE`
    (0x0210_0000) and may extend up to `KERNEL_BASE`. `SYSTEM_REGIONS` reserves only its 64 KiB
    minimum, because reserving the whole range would refuse cmd.exe (0x4AD0_0000). A reservation
    large enough to reach a mapped image would panic on commit ("user page already mapped").
    Today's CRT reserves far less (believed about 1 MiB, not measured). The fix is address-space
    bookkeeping (a VAD-like range list) that both the loader and VirtualAlloc consult.

## Not done (waits for the DLL fixture or later steps)

- Loading DLL files: dependency walk, mapping several images per process, a per-process module
  list for `resolve_import`.
- The DllMain sequence (process/thread attach and detach, `lpReserved` non-NULL for static
  loads, FALSE fails the load) and where it runs (kernel-provided stub page vs a user-mode
  ntdll-like layer). This is the one real design decision left.
- Forwarder resolution across loaded modules (needs the module list; depth-limit it).
- Ordinal imports (`by_ordinal` exists; the import walk still refuses them).
- Base relocations (`DIR_BASERELOC` still unused): only needed when two images want the same
  range.
- TLS directory, load-config directory: unknown whether cmd.exe or msvcrt.dll have them (see
  `dumpbin /headers`, item 1).

## Suggested DLL fixture (for whoever writes it)

`tests/dllload/`: `dllload.dll` with a DllMain that prints each reason it is called with (and
whether `lpReserved` is NULL), plus one exported function, by name; `dllload.exe` importing it by
name, calling the export, creating and joining one thread, then exiting. Capture `output.txt` on
the real machine. Optional second DLL with the same preferred base as the first, to force a
relocation later.
