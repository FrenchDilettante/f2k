# F2K Test Corpus

C programs compiled on a real Windows 2000 machine with the era's
toolchain. They are the compatibility baseline: every test is a real
PE32 executable whose imports and behavior are dictated by that
environment, not by what F2K happens to implement.

## Layout

One directory per test, named after the test:

```
tests/<name>/
├── <name>.c    # the source, built on the real Windows 2000 machine
├── <name>.exe  # the compiled fixture (committed; it is the point)
└── <name>.rs   # planned: the same test for F2K's own Rust toolchain
```

The Rust counterpart exists so the same test can be built and run by
our own toolchain as well as the reference one; it lands when the
toolchain can build it. Build intermediates (`.obj` etc.) are ignored,
not committed.

## Conventions

- Exit code 0 means pass. A test that wants to distinguish failures
  returns distinct nonzero codes and documents them in its header.
- Tests are ordered by what they exercise: each test should add a
  bounded, known amount of API surface to the previous one.
- The inventory below records each fixture's actual import surface
  (from the PE import table), not an assumption.

## Building

On a real Windows 2000 machine (MSVC 6):

```
cl /nologo exit0.c /link /NODEFAULTLIB /ENTRY:ExitMain /SUBSYSTEM:CONSOLE kernel32.lib
cl /nologo ret0.c
```

## Inventory

| Test    | Entry                  | Expected exit | Imports                                                                                                                             |
|---------|------------------------|---------------|-------------------------------------------------------------------------------------------------------------------------------------|
| `exit0` | `ExitMain` (no CRT)    | 0             | `ExitProcess` only (not yet built)                                                                                                  |
| `ret0`  | `mainCRTStartup` (CRT) | 0             | 35 KERNEL32.dll imports (verified, see below); no `msvcrt.dll`: static /ML CRT                                                        |

### ret0.exe fixture facts (verified from the binary)

PE32, subsystem CUI (console), ImageBase 0x400000, SectionAlignment
0x1000, AddressOfEntryPoint RVA 0x1007, SizeOfImage 0x6000, sections
.text/.rdata/.data. Imports, all from KERNEL32.dll:

```
ExitProcess  TerminateProcess  GetCurrentProcess  UnhandledExceptionFilter
GetModuleFileNameA  GetVersion  GetCommandLineA  GetStartupInfoA
GetStdHandle  GetFileType  SetHandleCount  WriteFile
GetEnvironmentStrings  GetEnvironmentStringsW
FreeEnvironmentStringsA  FreeEnvironmentStringsW
HeapCreate  HeapDestroy  HeapAlloc  HeapReAlloc  HeapFree
VirtualAlloc  VirtualFree  RtlUnwind  GetProcAddress  LoadLibraryA
GetACP  GetOEMCP  GetCPInfo  WideCharToMultiByte  MultiByteToWideChar
LCMapStringA  LCMapStringW  GetStringTypeA  GetStringTypeW
```

Notable reads of the surface: the CRT builds its own heap
(HeapCreate/Alloc/ReAlloc/Free plus VirtualAlloc for large blocks);
the locale/codepage group (GetACP/GetOEMCP/GetCPInfo, the
*ToMultiByte family, LCMapString, GetStringType) runs during CRT
locale init even for a plain `return 0`; GetProcAddress +
LoadLibraryA probe for platform flavors; RtlUnwind and
UnhandledExceptionFilter cover the CRT's exception teardown.

## How F2K consumes these

Until F2K can read from its FAT32 disk partition, the QEMU boot smoke
test embeds a fixture directly in the kernel image (`include_bytes!`)
and prints the observed process exit code on COM1. The pass criterion
is the expected exit code from the inventory above. Once disk I/O
exists, fixtures load from the disk image instead and the embedding
goes away.
