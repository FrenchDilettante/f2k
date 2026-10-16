//! The export surface under test, and the existing implementation path behind it.
//!
//! Scenarios call exports the way the binaries do: by name, with dword arguments, reading the EAX
//! result ([`Surface`]). [`Fixture`] pairs a [`FakeKernel`] with the surface of record and checks
//! every call's argument count against the export's public prototype ([`SIGNATURES`]) — the
//! stdcall discipline the callers' pushes assume.
//!
//! [`ExistingPath`] is today's surface of record, routing each export to the existing
//! implementation:
//!
//! - **Registry**: the service handler from `kernel32::SERVICES`, through a trap frame. The
//!   handlers address caller memory as raw 32-bit pointers, which a 64-bit host cannot map, so
//!   every nonzero pointer argument is fenced into the kernel half first: a handler that reaches
//!   caller memory fails its probe and takes its own failure return. Argument validation, return
//!   values, and size queries run for real; a scenario that needs bytes moved does not pass on this
//!   route.
//! - **Heap**: the user heap's allocator core (`userheap::alloc_block` / `free_block` /
//!   `realloc_block`) over the heap region, committed through the boundary. The per-call
//!   composition around the core (the handle check, commit-and-retry, the in-place flag, the reset)
//!   is target-only in the kernel and restated here from `userheap`.
//! - **Target-only**: handlers whose host build is a stub (the scheduler and handle-table
//!   services, the process exit, the address-space mapping). Calling one panics with the reason.
//!
//! A future implementation of the exports implements [`Surface`] over a [`KernelBoundary`]; the
//! fixture's surface of record then routes the migrated exports to it.

use super::boundary::{AddressSpace, KernelBoundary};
use super::fake::{FakeKernel, HEAP_REGION_BASE, HEAP_REGION_MAX, MEM_COMMIT, PAGE_SIZE};
use crate::compat::kernel32::{NATIVES, SERVICES};
use crate::user::userheap::{alloc_block, free_block, realloc_block, HEADER_SIZE};
use crate::user::TrapFrame;

/// One argument of a prototype.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Arg {
    /// A value: a handle, a count, flags, a code address.
    Value(&'static str),
    /// A pointer into caller memory.
    Pointer(&'static str),
}

/// An export's public prototype: its arguments, in push order reversed (the first is at the
/// lowest address).
pub struct Signature {
    pub export: &'static str,
    pub args: &'static [Arg],
}

use Arg::{Pointer as P, Value as V};

/// The public prototypes of the 62 exports.
pub const SIGNATURES: [Signature; 62] = [
    sig("ExitProcess", &[V("uExitCode")]),
    sig("CloseHandle", &[V("hObject")]),
    sig(
        "CreateEventA",
        &[
            P("lpEventAttributes"),
            V("bManualReset"),
            V("bInitialState"),
            P("lpName"),
        ],
    ),
    sig(
        "CreateFileA",
        &[
            P("lpFileName"),
            V("dwDesiredAccess"),
            V("dwShareMode"),
            P("lpSecurityAttributes"),
            V("dwCreationDisposition"),
            V("dwFlagsAndAttributes"),
            V("hTemplateFile"),
        ],
    ),
    sig(
        "CreateThread",
        &[
            P("lpThreadAttributes"),
            V("dwStackSize"),
            V("lpStartAddress"),
            V("lpParameter"),
            V("dwCreationFlags"),
            P("lpThreadId"),
        ],
    ),
    sig("FlushFileBuffers", &[V("hFile")]),
    sig("FreeEnvironmentStringsA", &[P("lpszEnvironmentBlock")]),
    sig("FreeEnvironmentStringsW", &[P("lpszEnvironmentBlock")]),
    sig("GetACP", &[]),
    sig("GetCommandLineA", &[]),
    sig("GetCPInfo", &[V("CodePage"), P("lpCPInfo")]),
    sig("GetCurrentProcess", &[]),
    sig("GetEnvironmentStrings", &[]),
    sig("GetEnvironmentStringsW", &[]),
    sig("GetFileType", &[V("hFile")]),
    sig("GetLastError", &[]),
    sig(
        "GetModuleFileNameA",
        &[V("hModule"), P("lpFilename"), V("nSize")],
    ),
    sig("GetOEMCP", &[]),
    sig("GetProcAddress", &[V("hModule"), P("lpProcName")]),
    sig("GetStartupInfoA", &[P("lpStartupInfo")]),
    sig("GetStdHandle", &[V("nStdHandle")]),
    sig(
        "GetStringTypeA",
        &[
            V("Locale"),
            V("dwInfoType"),
            P("lpSrcStr"),
            V("cchSrc"),
            P("lpCharType"),
        ],
    ),
    sig(
        "GetStringTypeW",
        &[V("dwInfoType"), P("lpSrcStr"), V("cchSrc"), P("lpCharType")],
    ),
    sig("GetTickCount", &[]),
    sig("GetVersion", &[]),
    sig("HeapAlloc", &[V("hHeap"), V("dwFlags"), V("dwBytes")]),
    sig(
        "HeapCreate",
        &[V("flOptions"), V("dwInitialSize"), V("dwMaximumSize")],
    ),
    sig("HeapDestroy", &[V("hHeap")]),
    sig("HeapFree", &[V("hHeap"), V("dwFlags"), P("lpMem")]),
    sig(
        "HeapReAlloc",
        &[V("hHeap"), V("dwFlags"), P("lpMem"), V("dwBytes")],
    ),
    sig(
        "LCMapStringA",
        &[
            V("Locale"),
            V("dwMapFlags"),
            P("lpSrcStr"),
            V("cchSrc"),
            P("lpDestStr"),
            V("cchDest"),
        ],
    ),
    sig(
        "LCMapStringW",
        &[
            V("Locale"),
            V("dwMapFlags"),
            P("lpSrcStr"),
            V("cchSrc"),
            P("lpDestStr"),
            V("cchDest"),
        ],
    ),
    sig("LoadLibraryA", &[P("lpFileName")]),
    sig(
        "MultiByteToWideChar",
        &[
            V("CodePage"),
            V("dwFlags"),
            P("lpMultiByteStr"),
            V("cbMultiByte"),
            P("lpWideCharStr"),
            V("cchWideChar"),
        ],
    ),
    sig(
        "ReadFile",
        &[
            V("hFile"),
            P("lpBuffer"),
            V("nNumberOfBytesToRead"),
            P("lpNumberOfBytesRead"),
            P("lpOverlapped"),
        ],
    ),
    sig("ResumeThread", &[V("hThread")]),
    sig(
        "RtlUnwind",
        &[
            P("TargetFrame"),
            V("TargetIp"),
            P("ExceptionRecord"),
            V("ReturnValue"),
        ],
    ),
    sig("SetEvent", &[V("hEvent")]),
    sig(
        "SetFilePointer",
        &[
            V("hFile"),
            V("lDistanceToMove"),
            P("lpDistanceToMoveHigh"),
            V("dwMoveMethod"),
        ],
    ),
    sig("SetHandleCount", &[V("uNumber")]),
    sig("SetStdHandle", &[V("nStdHandle"), V("hHandle")]),
    sig("SetThreadPriority", &[V("hThread"), V("nPriority")]),
    sig("Sleep", &[V("dwMilliseconds")]),
    sig("SuspendThread", &[V("hThread")]),
    sig("TerminateProcess", &[V("hProcess"), V("uExitCode")]),
    sig("UnhandledExceptionFilter", &[P("ExceptionInfo")]),
    sig(
        "VirtualAlloc",
        &[
            V("lpAddress"),
            V("dwSize"),
            V("flAllocationType"),
            V("flProtect"),
        ],
    ),
    sig(
        "VirtualFree",
        &[V("lpAddress"), V("dwSize"), V("dwFreeType")],
    ),
    sig("WaitForSingleObject", &[V("hHandle"), V("dwMilliseconds")]),
    sig(
        "WideCharToMultiByte",
        &[
            V("CodePage"),
            V("dwFlags"),
            P("lpWideCharStr"),
            V("cchWideChar"),
            P("lpMultiByteStr"),
            V("cbMultiByte"),
            P("lpDefaultChar"),
            P("lpUsedDefaultChar"),
        ],
    ),
    sig(
        "WriteFile",
        &[
            V("hFile"),
            P("lpBuffer"),
            V("nNumberOfBytesToWrite"),
            P("lpNumberOfBytesWritten"),
            P("lpOverlapped"),
        ],
    ),
    sig("SetLastError", &[V("dwErrCode")]),
    sig("SetErrorMode", &[V("uMode")]),
    sig("GetCurrentThreadId", &[]),
    sig("GetCurrentProcessId", &[]),
    sig("GetCurrentThread", &[]),
    sig("GetProcessHeap", &[]),
    sig("InterlockedIncrement", &[P("lpAddend")]),
    sig("InterlockedDecrement", &[P("lpAddend")]),
    sig("InterlockedExchange", &[P("Target"), V("Value")]),
    sig("InterlockedExchangeAdd", &[P("Addend"), V("Value")]),
    sig(
        "InterlockedCompareExchange",
        &[P("Destination"), V("Exchange"), V("Comperand")],
    ),
];

const fn sig(export: &'static str, args: &'static [Arg]) -> Signature {
    Signature { export, args }
}

/// The public prototype of `export`.
pub fn signature(export: &str) -> &'static Signature {
    SIGNATURES
        .iter()
        .find(|signature| signature.export == export)
        .unwrap_or_else(|| panic!("no prototype for {export}"))
}

/// The argument block a stdcall caller pushes for `export` (and the callee must pop).
pub fn prototype_arg_bytes(export: &str) -> u32 {
    4 * signature(export).args.len() as u32
}

/// The argument block the surface's code pops for `export` (a service's stub or a native body).
pub fn registry_arg_bytes(export: &str) -> u32 {
    crate::compat::kernel32::exports()
        .find(|&(name, _)| name == export)
        .unwrap_or_else(|| panic!("{export} is not on the surface"))
        .1
}

fn registry_entry(export: &str) -> (&'static str, u32, crate::user::syscall::ServiceFn) {
    *SERVICES
        .iter()
        .find(|(name, ..)| *name == export)
        .unwrap_or_else(|| panic!("{export} is not on the surface"))
}

/// An implementation of the exports.
pub trait Surface {
    /// Call `export` with its arguments (exactly its prototype's count), on the process `kernel`
    /// stands for; the EAX result.
    fn call(&mut self, kernel: &mut dyn KernelBoundary, export: &str, args: &[u32]) -> u32;
}

/// Where the existing path serves an export from.
enum Route {
    /// The registry's handler, every pointer argument fenced.
    Registry,
    /// The registry's handler for argument shapes `reachable` accepts; target-only otherwise.
    Guarded(fn(&[u32]) -> bool, &'static str),
    /// The heap adapter.
    Heap,
    /// Not on the host.
    TargetOnly(&'static str),
}

fn route(export: &str) -> Route {
    if NATIVES.iter().any(|&(name, ..)| name == export) {
        return Route::TargetOnly("a native export runs in user mode, on the calling thread's TEB");
    }
    match export {
        "HeapAlloc" | "HeapCreate" | "HeapDestroy" | "HeapFree" | "HeapReAlloc" => Route::Heap,
        // The copy reads the parameters page through a raw kernel-side read; only the refusals
        // before it are reachable.
        "GetModuleFileNameA" => Route::Guarded(
            |args| args[0] != 0 || args[2] == 0,
            "the staged-name copy reads the parameters page directly",
        ),
        "ExitProcess" => Route::TargetOnly("the process exit runs through the scheduler"),
        "SetErrorMode" => Route::TargetOnly("the error mode lives in the live process record"),
        "VirtualAlloc" => {
            Route::TargetOnly("the CRT region maps pages into the live address space")
        }
        "CloseHandle"
        | "CreateEventA"
        | "SetEvent"
        | "WaitForSingleObject"
        | "Sleep"
        | "GetTickCount"
        | "CreateThread"
        | "SetThreadPriority"
        | "SuspendThread"
        | "ResumeThread" => {
            Route::TargetOnly("the handler runs against the live handle table, scheduler, or clock")
        }
        _ => Route::Registry,
    }
}

/// Where fenced pointer arguments point: the kernel half, which every user-memory access probe
/// refuses. Each argument position gets its own fence page so the handlers' pointer arithmetic
/// cannot carry one into another.
const FENCE: u32 = 0xC000_0000;
const FENCE_STRIDE: u32 = 0x0100_0000;

/// The existing implementation path (see the module docs).
#[derive(Default)]
pub struct ExistingPath {
    heap: HeapAdapter,
}

impl ExistingPath {
    pub fn new() -> ExistingPath {
        ExistingPath::default()
    }

    /// Run the registry's handler for `export` with fenced pointers.
    fn registry(export: &str, args: &[u32]) -> u32 {
        let (_, arg_bytes, service) = registry_entry(export);
        let dwords = arg_bytes as usize / 4;
        assert!(
            args.len() <= dwords,
            "{export}: {} arguments, the registry's block holds {dwords}",
            args.len()
        );
        let mut block = [0u32; crate::user::syscall::MAX_ARG_BYTES / 4];
        for (index, (&value, arg)) in args.iter().zip(signature(export).args).enumerate() {
            block[index] = match arg {
                Arg::Pointer(_) if value != 0 => FENCE + index as u32 * FENCE_STRIDE,
                _ => value,
            };
        }
        let mut frame = TrapFrame {
            edi: 0,
            esi: 0,
            ebp: 0,
            esp: 0,
            ebx: 0,
            edx: 0,
            ecx: 0,
            eax: 0xDEAD_BEEF,
            vector: 0,
            error_code: 0,
            eip: 0,
            cs: 0,
            eflags: 0,
            user_esp: 0,
            user_ss: 0,
        };
        service(&mut frame, &block[..dwords]);
        frame.eax
    }
}

impl Surface for ExistingPath {
    fn call(&mut self, kernel: &mut dyn KernelBoundary, export: &str, args: &[u32]) -> u32 {
        match route(export) {
            Route::Registry => ExistingPath::registry(export, args),
            Route::Guarded(reachable, _) if reachable(args) => ExistingPath::registry(export, args),
            Route::Guarded(_, reason) | Route::TargetOnly(reason) => {
                panic!("{export} is target-only on the existing path: {reason}")
            }
            Route::Heap => self.heap.call(kernel, export, args),
        }
    }
}

/// The handle HeapCreate reports: the heap region's base (the user heap module's target constant).
pub const HEAP_HANDLE: u32 = HEAP_REGION_BASE;

/// HeapAlloc / HeapReAlloc flags (public constants).
pub const HEAP_ZERO_MEMORY: u32 = 0x0000_0008;
pub const HEAP_REALLOC_IN_PLACE_ONLY: u32 = 0x0000_0010;

/// The heap services over the allocator core: the heap region's committed prefix and bump edge.
#[derive(Default)]
struct HeapAdapter {
    committed: usize,
    top: usize,
}

impl HeapAdapter {
    fn call(&mut self, kernel: &mut dyn KernelBoundary, export: &str, args: &[u32]) -> u32 {
        match export {
            "HeapCreate" => self.create(),
            "HeapDestroy" => self.destroy(args[0]),
            _ if args[0] != HEAP_HANDLE => 0,
            "HeapAlloc" => self.alloc(kernel, args[1], args[2] as usize),
            "HeapFree" => self.free(kernel, args[2]),
            "HeapReAlloc" => self.realloc(kernel, args[2], args[1], args[3] as usize),
            _ => unreachable!("{export} is not a heap service"),
        }
    }

    /// Reset the bump edge; the handle is a constant.
    fn create(&mut self) -> u32 {
        self.top = 0;
        HEAP_HANDLE
    }

    fn destroy(&mut self, handle: u32) -> u32 {
        if handle == HEAP_HANDLE {
            self.create();
            1
        } else {
            0
        }
    }

    /// The region image: its committed prefix.
    fn region<'a>(&self, kernel: &'a mut dyn KernelBoundary) -> &'a mut [u8] {
        if self.committed == 0 {
            return &mut [];
        }
        kernel
            .memory()
            .slice_mut(HEAP_REGION_BASE, self.committed as u32)
            .expect("the committed prefix is mapped")
    }

    /// Commit the region so its image covers `bytes`, in whole pages; refused past the cap.
    fn commit(&mut self, kernel: &mut dyn KernelBoundary, bytes: usize) -> bool {
        if bytes <= self.committed {
            return true;
        }
        if bytes > HEAP_REGION_MAX {
            return false;
        }
        let end = bytes.next_multiple_of(PAGE_SIZE as usize);
        let base = HEAP_REGION_BASE + self.committed as u32;
        let size = (end - self.committed) as u32;
        if kernel
            .nt_allocate_virtual_memory(base, size, MEM_COMMIT)
            .is_err()
        {
            return false;
        }
        self.committed = end;
        true
    }

    /// First fit; when the bump path runs out of committed region, commit one page beyond the need
    /// and retry; past the cap the request fails.
    fn alloc(&mut self, kernel: &mut dyn KernelBoundary, flags: u32, request: usize) -> u32 {
        let zero = flags & HEAP_ZERO_MEMORY != 0;
        loop {
            let mut top = self.top;
            if let Some(user) = alloc_block(self.region(kernel), &mut top, request, zero) {
                self.top = top;
                return HEAP_REGION_BASE + user as u32;
            }
            let Some(need) = request
                .max(1)
                .checked_next_multiple_of(8)
                .and_then(|rounded| top.checked_add(HEADER_SIZE + rounded))
            else {
                return 0;
            };
            if need > HEAP_REGION_MAX || !self.commit(kernel, need + PAGE_SIZE as usize) {
                return 0;
            }
        }
    }

    fn free(&mut self, kernel: &mut dyn KernelBoundary, ptr: u32) -> u32 {
        if ptr < HEAP_REGION_BASE {
            return 0;
        }
        let user = (ptr - HEAP_REGION_BASE) as usize;
        free_block(self.region(kernel), self.top, user) as u32
    }

    /// Resize within the committed region (a growth that needs more of it fails). The in-place
    /// flag serves exactly the resizes that keep the block — decided on a scratch copy, so a
    /// refused move leaves the region as it was.
    fn realloc(
        &mut self,
        kernel: &mut dyn KernelBoundary,
        ptr: u32,
        flags: u32,
        request: usize,
    ) -> u32 {
        let zero = flags & HEAP_ZERO_MEMORY != 0;
        if ptr < HEAP_REGION_BASE {
            return 0;
        }
        let user = (ptr - HEAP_REGION_BASE) as usize;
        let region = self.region(kernel);
        let mut top = self.top;
        if flags & HEAP_REALLOC_IN_PLACE_ONLY != 0 {
            let mut scratch = region.to_vec();
            return match realloc_block(&mut scratch, &mut top, user, request, false) {
                Some(kept) if kept == user => ptr,
                _ => 0,
            };
        }
        match realloc_block(region, &mut top, user, request, zero) {
            Some(new) => {
                self.top = top;
                HEAP_REGION_BASE + new as u32
            }
            None => 0,
        }
    }
}

/// Scenario memory: where fixtures stage buffers and strings, clear of every region the kernel
/// stages or serves.
pub const SCRATCH_BASE: u32 = 0x0400_0000;
const SCRATCH_SIZE: u32 = 0x0004_0000;

/// An address nothing is ever mapped at.
pub const UNMAPPED: u32 = 0x0600_0000;

/// A scenario's world: the fake kernel and the surface of record.
pub struct Fixture {
    pub kernel: FakeKernel,
    surface: Box<dyn Surface>,
    scratch_next: u32,
}

impl Default for Fixture {
    fn default() -> Fixture {
        Fixture::new()
    }
}

impl Fixture {
    /// A fresh process on the surface of record.
    pub fn new() -> Fixture {
        Fixture::with_surface(Box::new(ExistingPath::new()))
    }

    /// A fresh process on `surface`.
    pub fn with_surface(surface: Box<dyn Surface>) -> Fixture {
        let mut kernel = FakeKernel::new();
        kernel.memory().map(SCRATCH_BASE, SCRATCH_SIZE);
        Fixture {
            kernel,
            surface,
            scratch_next: SCRATCH_BASE,
        }
    }

    /// Call `export`; the argument count must be its prototype's.
    pub fn call(&mut self, export: &str, args: &[u32]) -> u32 {
        let expected = signature(export).args.len();
        assert_eq!(args.len(), expected, "{export} takes {expected} arguments");
        self.surface.call(&mut self.kernel, export, args)
    }

    /// The process's address space.
    pub fn memory(&mut self) -> &mut AddressSpace {
        self.kernel.memory()
    }

    /// `length` zeroed scratch bytes, 16-byte aligned; their address.
    pub fn buffer(&mut self, length: u32) -> u32 {
        let address = self.scratch_next;
        self.scratch_next = (address + length.max(1)).next_multiple_of(16);
        assert!(
            self.scratch_next <= SCRATCH_BASE + SCRATCH_SIZE,
            "scratch exhausted"
        );
        address
    }

    /// `bytes` staged in scratch memory; their address.
    pub fn stage(&mut self, bytes: &[u8]) -> u32 {
        let address = self.buffer(bytes.len() as u32);
        self.memory().write(address, bytes).unwrap();
        address
    }

    /// `text` staged NUL-terminated; its address.
    pub fn c_string(&mut self, text: &[u8]) -> u32 {
        let mut bytes = text.to_vec();
        bytes.push(0);
        self.stage(&bytes)
    }

    /// `units` staged as UTF-16LE (no terminator added); their address.
    pub fn wide(&mut self, units: &[u16]) -> u32 {
        let bytes: Vec<u8> = units.iter().flat_map(|unit| unit.to_le_bytes()).collect();
        self.stage(&bytes)
    }

    /// The `count` UTF-16 units at `address`.
    pub fn wide_at(&mut self, address: u32, count: u32) -> Vec<u16> {
        self.memory()
            .bytes(address, 2 * count)
            .chunks(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect()
    }
}

/// Assert that every export in `members` pops exactly the block its prototype's callers push.
pub fn assert_argument_blocks(members: &[&str]) {
    for &export in members {
        assert_eq!(
            registry_arg_bytes(export),
            prototype_arg_bytes(export),
            "{export}: the stub's ret imm16 against the prototype's pushes"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The prototypes cover the surface exactly, once each.
    #[test]
    fn prototypes_cover_the_registry() {
        for (name, _) in crate::compat::kernel32::exports() {
            assert_eq!(
                SIGNATURES.iter().filter(|s| s.export == name).count(),
                1,
                "{name}"
            );
        }
        assert_eq!(SIGNATURES.len(), crate::compat::kernel32::exports().count());
    }

    /// The fence: every fenced pointer, and anything a handler adds to it, fails the user probe.
    #[test]
    fn fenced_pointers_fail_the_user_probe() {
        let last = FENCE + 7 * FENCE_STRIDE;
        for pointer in [FENCE, last, last + 0x2_0000] {
            assert!(crate::user::syscall::probe_user_range(pointer, 1).is_err());
        }
        assert!((last as u64 + 0x2_0000) < 1 << 32);
    }

    /// A target-only export refuses loudly on the existing path.
    #[test]
    #[should_panic(expected = "target-only on the existing path")]
    fn target_only_exports_refuse_loudly() {
        Fixture::new().call("GetTickCount", &[]);
    }

    /// The fixture checks the argument count against the prototype.
    #[test]
    #[should_panic(expected = "takes 1 arguments")]
    fn the_fixture_checks_argument_counts() {
        Fixture::new().call("GetStdHandle", &[]);
    }
}
