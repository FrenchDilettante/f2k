//! Ring 3: the user layout, the boot's choice of what runs, and the end of the user process.
//!
//! The kernel maps the image, stack, TEB and parameters pages — each inside a region of the
//! process's address space (`mem::vm`), the one writer of its page-table entries — and enters the
//! process as its main thread: the scheduler's first switch into the thread leaves its startup ladder for ring 3,
//! at kernel32's BaseProcessStartThunk ([`main_thread_start`]), whose frame calls the image's entry
//! point under kernel32's exception registration and hands its return value to ExitThread.
//! The fault-test features substitute a hand-assembled stub ([`RING3_STUB`]) so the kernel's own
//! paths can be verified without a PE fixture.
//!
//! Every user context is a thread: a thread's return ends the thread (the last thread's end is the
//! process's), NtTerminateProcess ends the process and all its threads, and faults raised by user
//! code go to the thread's own exception handlers ([`seh`]); one nobody takes ends the process, not
//! the kernel.

pub mod apc;
pub mod args;
pub mod ldr;
pub mod params;
pub mod seh;
pub mod shared;
pub mod stack;
pub mod syscall;
pub mod teb;
pub mod tls;

/// The fault-test stub's code page (the corpus programs' preferred base, which the fault-test builds
/// never map).
#[cfg(any(
    feature = "fault-test-badargs",
    feature = "fault-test-segments",
    feature = "fault-test-threadexit",
    feature = "fault-test-exitio",
    feature = "fault-test-ntclose",
    test
))]
pub const USER_CODE_PAGE: u32 = 0x0040_0000;
/// The user stack's top page, in its own 4 MiB window (window 0, whose boot identity mapping was
/// removed). The stack spans two pages growing down — the CRT's startup passes need the room.
pub const USER_STACK_PAGE: u32 = 0x0030_0000;
/// The stack's second page, one below the top.
pub const USER_STACK_LOW_PAGE: u32 = USER_STACK_PAGE - 4096;
/// One past the stack's top page: the stack's base (the TEB's StackBase).
pub const USER_STACK_TOP: u32 = USER_STACK_PAGE + 4096;
/// The main thread's stack reservation: 1 MiB, the MSVC linker's default, of which the two pages
/// above are committed at start and the rest on demand (see [`stack`]).
pub const USER_STACK_RESERVE: u32 = 0x10_0000;
/// The reservation's lowest address.
pub const USER_STACK_BASE: u32 = USER_STACK_TOP - USER_STACK_RESERVE;
/// The main thread's initial ESP: one dword below the stack's base, as Windows 2000's
/// BaseInitializeContext leaves it (its `Esp -= sizeof(Parameter)`); BaseProcessStartThunk pushes
/// its frame from there.
pub const USER_INITIAL_ESP: u32 = USER_STACK_TOP - 4;
/// The main thread's TEB page, reached through the FS-based TEB segment (the CRT installs its
/// exception frames at fs:[0] first thing); the loader maps it with the fresh TEB's words
/// ([`teb`]).
pub const TEB_PAGE: u32 = 0x0031_0000;
/// The EFLAGS every planted user context carries: bit 1 (architecturally one) plus the interrupt
/// flag — user code runs enabled, IOPL 0 (port I/O stays privileged).
pub const USER_EFLAGS: u32 = 0x0000_0202;

/// The process parameters pages: RTL_USER_PROCESS_PARAMETERS and its strings ([`params`], two
/// pages from here).
pub const PARAMS_PAGE: u32 = 0x0032_0000;

/// The PEB page: the process environment block ([`teb`]), and past the PEB proper the system DLLs'
/// own per-process slots.
pub const PEB_PAGE: u32 = 0x0033_0000;

/// The region per-thread TEB pages allocate from (user window 2, mapped by no run path today). A
/// process's first thread keeps the fixed TEB page below; later threads take one page from here.
pub const THREAD_TEB_REGION: u32 = 0x0080_0000;

/// The main thread's initial context for an image whose entry point is `entry`, as Windows 2000's
/// CreateProcess builds it (BaseInitializeContext): EIP kernel32's BaseProcessStartThunk, EAX the
/// entry point, ESP [`USER_INITIAL_ESP`]. The thunk calls the entry point under kernel32's
/// exception frame (UnhandledExceptionFilter's verdict, then ExitProcess with the code) and hands
/// its return value to ExitThread.
pub fn main_thread_start(entry: u32) -> crate::sched::startup::UserStart {
    crate::sched::startup::UserStart {
        eip: crate::exec::modules::process_start_thunk(),
        esp: USER_INITIAL_ESP,
        eax: entry,
        ..Default::default()
    }
}

/// Thread `index`'s TEB page.
pub const fn thread_teb_va(index: u32) -> u32 {
    if index == 0 {
        TEB_PAGE
    } else {
        THREAD_TEB_REGION + (index - 1) * 4096
    }
}

/// An unmapped user address the bad-args stub passes as the syscall argument pointer: below the
/// user probe limit (the range probe passes) but backed by no page, so the kernel's argument copy
/// faults on the user process's behalf.
#[cfg(any(feature = "fault-test-badargs", test))]
pub const BAD_ARGS_PTR: u32 = 0x0050_0000;

/// The ring-3 fault-test stub, in bytes: a faulting body plus a spin as the safety net.
/// Hand-assembled so it can be copied into the user page (kernel code is unreachable from ring 3).
/// Never combine the features: `fault-test-badargs` passes an unmapped user address as the syscall
/// argument pointer.
#[cfg(feature = "fault-test-badargs")]
pub const RING3_STUB: [u8; 14] = [
    0xB8, 0xE0, 0x00, 0x00, 0x00, // mov eax, NtTerminateProcess (0xE0)
    0xBA, 0x00, 0x00, 0x50, 0x00, // mov edx, BAD_ARGS_PTR
    0xCD, 0x2E, // int 0x2E (syscall gate)
    0xEB, 0xFE, // jmp $
];

/// DS/ES loaded with the TEB selector (base TEB_PAGE, limit 0xFFF: legal at CPL 3), then a spin
/// long enough that the clock preempts it many times over, then NtTerminateProcess(NtCurrentProcess,
/// 7) (the argument block sits on the stack, which SS still reaches). The TEB segment rather than a null
/// selector: real hardware faults on both once the kernel runs on them, but QEMU's TCG skips the
/// null-selector check on flat data accesses, so only the based selector exposes the bug under
/// emulation.
#[cfg(all(
    feature = "fault-test-segments",
    not(feature = "fault-test-badargs")
))]
#[rustfmt::skip]
pub const RING3_STUB: [u8; 31] = [
    0x66, 0xB8, 0x33, 0x00, // mov ax, TEB_SELECTOR | 3
    0x8E, 0xD8, // mov ds, ax
    0x8E, 0xC0, // mov es, ax
    0xB9, 0x00, 0x00, 0x00, 0x08, // mov ecx, 0x08000000
    0x49, // dec ecx
    0x75, 0xFD, // jnz (back to dec ecx)
    0x6A, 0x07, // push 7 (ExitStatus)
    0x6A, 0xFF, // push NtCurrentProcess
    0x89, 0xE2, // mov edx, esp
    0xB8, 0xE0, 0x00, 0x00, 0x00, // mov eax, NtTerminateProcess (0xE0)
    0xCD, 0x2E, // int 0x2E
    0xEB, 0xFE, // jmp $
];

/// NtTerminateThread(NtCurrentThread, 0) on the main thread: the main thread ends, and with it the
/// process (exit code 0), its last thread. Were the service refused, NtTerminateProcess below would
/// report the status the gate returned in EAX instead.
#[cfg(all(
    feature = "fault-test-threadexit",
    not(feature = "fault-test-badargs"),
    not(feature = "fault-test-segments")
))]
#[rustfmt::skip]
pub const RING3_STUB: [u8; 28] = [
    0x6A, 0x00, // push 0 (ExitStatus)
    0x6A, 0xFE, // push NtCurrentThread
    0x89, 0xE2, // mov edx, esp
    0xB8, 0xE1, 0x00, 0x00, 0x00, // mov eax, NtTerminateThread (0xE1)
    0xCD, 0x2E, // int 0x2E
    0x50, // push eax (ExitStatus: the refusal)
    0x6A, 0xFF, // push NtCurrentProcess
    0x89, 0xE2, // mov edx, esp
    0xB8, 0xE0, 0x00, 0x00, 0x00, // mov eax, NtTerminateProcess (0xE0)
    0xCD, 0x2E, // int 0x2E
    0xEB, 0xFE, // jmp $
    0x90, // pad
];

/// The exit-during-read stub: the main thread opens HELLO.EXE (NtOpenFile), allocates a stack for a
/// child at [`CHILD_STACK`] (NtAllocateVirtualMemory: a page for its CONTEXT, then two stack pages)
/// and creates the child there (NtCreateThread, EIP its loop, EBX the file handle), raises it
/// time-critical (NtSetInformationThread's ThreadBasePriority, as kernel32's SetThreadPriority asks
/// it) to read the file's first sector forever (NtReadFile at offset zero); main runs again only
/// while the child waits on the disk, and ends the process there (NtTerminateProcess). Every number
/// is Windows 2000's; the INITIAL_TEB, the name's OBJECT_ATTRIBUTES, UNICODE_STRING and units follow
/// the code.
#[cfg(any(feature = "fault-test-exitio", test))]
#[rustfmt::skip]
pub const EXIT_DURING_READ_STUB: [u8; 344] = [
    0x83, 0xEC, 0x0C, // 0x00: sub esp, 12 (the handle's slot, then the I/O status block)
    0x89, 0xE0, // 0x03: mov eax, esp (&handle)
    0x8D, 0x4C, 0x24, 0x04, // 0x05: lea ecx, [esp+4] (&io_status)
    0x6A, 0x60, // 0x09: push FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE
    0x6A, 0x01, // 0x0B: push FILE_SHARE_READ
    0x51, // 0x0D: push ecx (IoStatusBlock)
    0x68, 0x18, 0x01, 0x40, 0x00, // 0x0E: push attributes
    0x68, 0x00, 0x00, 0x10, 0x80, // 0x13: push GENERIC_READ | SYNCHRONIZE
    0x50, // 0x18: push eax (FileHandle)
    0x89, 0xE2, // 0x19: mov edx, esp
    0xB8, 0x64, 0x00, 0x00, 0x00, // 0x1B: mov eax, NtOpenFile (0x64)
    0xCD, 0x2E, // 0x20: int 0x2E
    0x83, 0xC4, 0x18, // 0x22: add esp, 24
    0x8B, 0x1C, 0x24, // 0x25: mov ebx, [esp] (the file handle)
    0x83, 0xC4, 0x0C, // 0x28: add esp, 12
    0x68, 0x00, 0x30, 0x00, 0x00, // 0x2B: push 0x3000 (RegionSize: the context page and two stack pages)
    0x68, 0x00, 0x00, 0x60, 0x00, // 0x30: push CHILD_STACK (BaseAddress)
    0x89, 0xE0, // 0x35: mov eax, esp (&base)
    0x8D, 0x4C, 0x24, 0x04, // 0x37: lea ecx, [esp+4] (&size)
    0x6A, 0x04, // 0x3B: push PAGE_READWRITE
    0x68, 0x00, 0x30, 0x00, 0x00, // 0x3D: push MEM_COMMIT | MEM_RESERVE
    0x51, // 0x42: push ecx (RegionSize)
    0x6A, 0x00, // 0x43: push 0 (ZeroBits)
    0x50, // 0x45: push eax (BaseAddress)
    0x6A, 0xFF, // 0x46: push NtCurrentProcess
    0x89, 0xE2, // 0x48: mov edx, esp
    0xB8, 0x10, 0x00, 0x00, 0x00, // 0x4A: mov eax, NtAllocateVirtualMemory (0x10)
    0xCD, 0x2E, // 0x4F: int 0x2E
    0x83, 0xC4, 0x20, // 0x51: add esp, 32 (the arguments and both slots)
    0xC7, 0x05, 0x00, 0x00, 0x60, 0x00, 0x03, 0x00, 0x01, 0x00, // 0x54: mov dword [CHILD_STACK], CONTEXT_CONTROL | CONTEXT_INTEGER
    0x89, 0x1D, 0xA4, 0x00, 0x60, 0x00, // 0x5E: mov [CHILD_STACK+0xA4], ebx (the context's EBX: the file handle)
    0xC7, 0x05, 0xB8, 0x00, 0x60, 0x00, 0xC6, 0x00, 0x40, 0x00, // 0x64: mov dword [CHILD_STACK+0xB8], child (EIP)
    0xC7, 0x05, 0xC4, 0x00, 0x60, 0x00, 0x00, 0x30, 0x60, 0x00, // 0x6E: mov dword [CHILD_STACK+0xC4], CHILD_STACK + 0x3000 (ESP)
    0x6A, 0x00, // 0x78: push 0 (the child's handle slot)
    0x89, 0xE0, // 0x7A: mov eax, esp
    0x6A, 0x00, // 0x7C: push 0 (CreateSuspended)
    0x68, 0x04, 0x01, 0x40, 0x00, // 0x7E: push initial_teb
    0x68, 0x00, 0x00, 0x60, 0x00, // 0x83: push CHILD_STACK (ThreadContext)
    0x6A, 0x00, // 0x88: push 0 (ClientId)
    0x6A, 0xFF, // 0x8A: push NtCurrentProcess
    0x6A, 0x00, // 0x8C: push 0 (ObjectAttributes)
    0x68, 0xFF, 0x03, 0x1F, 0x00, // 0x8E: push THREAD_ALL_ACCESS
    0x50, // 0x93: push eax (ThreadHandle)
    0x89, 0xE2, // 0x94: mov edx, esp
    0xB8, 0x2E, 0x00, 0x00, 0x00, // 0x96: mov eax, NtCreateThread (0x2E)
    0xCD, 0x2E, // 0x9B: int 0x2E
    0x83, 0xC4, 0x20, // 0x9D: add esp, 32
    0x58, // 0xA0: pop eax (the child's handle)
    0x6A, 0x10, // 0xA1: push 16 (the saturation THREAD_PRIORITY_TIME_CRITICAL converts to)
    0x89, 0xE1, // 0xA3: mov ecx, esp (&priority)
    0x6A, 0x04, // 0xA5: push 4 (ThreadInformationLength)
    0x51, // 0xA7: push ecx (ThreadInformation)
    0x6A, 0x03, // 0xA8: push ThreadBasePriority
    0x50, // 0xAA: push eax (the child's handle)
    0x89, 0xE2, // 0xAB: mov edx, esp
    0xB8, 0xC7, 0x00, 0x00, 0x00, // 0xAD: mov eax, NtSetInformationThread (0xC7: the child preempts here)
    0xCD, 0x2E, // 0xB2: int 0x2E
    0x83, 0xC4, 0x14, // 0xB4: add esp, 20 (the arguments and the priority)
    0x6A, 0x00, // 0xB7: push 0 (ExitStatus)
    0x6A, 0xFF, // 0xB9: push NtCurrentProcess
    0x89, 0xE2, // 0xBB: mov edx, esp
    0xB8, 0xE0, 0x00, 0x00, 0x00, // 0xBD: mov eax, NtTerminateProcess (0xE0: the child is inside a read)
    0xCD, 0x2E, // 0xC2: int 0x2E
    0xEB, 0xFE, // 0xC4: jmp $
    0x81, 0xEC, 0x00, 0x02, 0x00, 0x00, // 0xC6: child (EBX the file handle): sub esp, 0x200
    0x89, 0xE7, // 0xCC: mov edi, esp (the buffer)
    0x83, 0xEC, 0x10, // 0xCE: sub esp, 16 (the offset, zero, then the I/O status block)
    0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00, // 0xD1: mov dword [esp], 0
    0xC7, 0x44, 0x24, 0x04, 0x00, 0x00, 0x00, 0x00, // 0xD8: mov dword [esp+4], 0
    0x89, 0xE6, // 0xE0: mov esi, esp (&offset)
    0x6A, 0x00, // 0xE2: child_loop: push 0 (Key)
    0x56, // 0xE4: push esi (ByteOffset: the start)
    0x68, 0x00, 0x02, 0x00, 0x00, // 0xE5: push 512 (Length)
    0x57, // 0xEA: push edi (Buffer)
    0x8D, 0x46, 0x08, // 0xEB: lea eax, [esi+8]
    0x50, // 0xEE: push eax (IoStatusBlock)
    0x6A, 0x00, // 0xEF: push 0 (ApcContext)
    0x6A, 0x00, // 0xF1: push 0 (ApcRoutine)
    0x6A, 0x00, // 0xF3: push 0 (Event)
    0x53, // 0xF5: push ebx (FileHandle)
    0x89, 0xE2, // 0xF6: mov edx, esp
    0xB8, 0xA1, 0x00, 0x00, 0x00, // 0xF8: mov eax, NtReadFile (0xA1)
    0xCD, 0x2E, // 0xFD: int 0x2E
    0x83, 0xC4, 0x24, // 0xFF: add esp, 36
    0xEB, 0xDE, // 0x102: jmp child_loop
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x60, 0x00, 0x00, 0x10, 0x60, 0x00, 0x00, 0x00, 0x60, 0x00, // 0x104: INITIAL_TEB (no old stack; base, limit, allocation base)
    0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x01, 0x40, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x118: OBJECT_ATTRIBUTES (24, no root, the name, OBJ_CASE_INSENSITIVE)
    0x20, 0x00, 0x20, 0x00, 0x38, 0x01, 0x40, 0x00, // 0x130: UNICODE_STRING
    0x5C, 0x00, 0x3F, 0x00, 0x3F, 0x00, 0x5C, 0x00, 0x43, 0x00, 0x3A, 0x00, 0x5C, 0x00, 0x48, 0x00, 0x45, 0x00, 0x4C, 0x00, 0x4C, 0x00, 0x4F, 0x00, 0x2E, 0x00, 0x45, 0x00, 0x58, 0x00, 0x45, 0x00, // 0x138: the name
];

/// Where the exit-during-read stub's child stack (its CONTEXT's page, then two stack pages) is
/// allocated: free in the stub's process, which maps only its code page there.
#[cfg(any(feature = "fault-test-exitio", test))]
pub const CHILD_STACK: u32 = 0x0060_0000;

#[cfg(all(
    feature = "fault-test-exitio",
    not(feature = "fault-test-badargs"),
    not(feature = "fault-test-segments"),
    not(feature = "fault-test-threadexit")
))]
pub const RING3_STUB: [u8; 344] = EXIT_DURING_READ_STUB;

/// NtClose through ntdll's gate number (Windows 2000's 0x18) on a handle naming nothing, then
/// NtTerminateProcess with the status the gate returned in EAX (STATUS_INVALID_HANDLE): the NT
/// service table answers by Windows 2000's numbers.
#[cfg(all(
    feature = "fault-test-ntclose",
    not(feature = "fault-test-badargs"),
    not(feature = "fault-test-segments"),
    not(feature = "fault-test-threadexit"),
    not(feature = "fault-test-exitio")
))]
#[rustfmt::skip]
pub const RING3_STUB: [u8; 25] = [
    0x6A, 0x44, // push 0x44 (a handle naming nothing)
    0x89, 0xE2, // mov edx, esp
    0xB8, 0x18, 0x00, 0x00, 0x00, // mov eax, NtClose (0x18)
    0xCD, 0x2E, // int 0x2E
    0x50, // push eax (ExitStatus)
    0x6A, 0xFF, // push NtCurrentProcess
    0x89, 0xE2, // mov edx, esp
    0xB8, 0xE0, 0x00, 0x00, 0x00, // mov eax, NtTerminateProcess (0xE0)
    0xCD, 0x2E, // int 0x2E
    0xEB, 0xFE, // jmp $
];

/// Trap frame the gate stubs build on the ring-0 stack, in the shape shared with the exception
/// stubs (the CPU pushes the ring-3 tail; the stub pushes the rest in the same order).
#[allow(dead_code)]
#[repr(C)]
pub struct TrapFrame {
    pub edi: u32,
    pub esi: u32,
    pub ebp: u32,
    pub esp: u32,
    pub ebx: u32,
    pub edx: u32,
    pub ecx: u32,
    pub eax: u32,
    pub vector: u32,
    pub error_code: u32,
    pub eip: u32,
    pub cs: u32,
    pub eflags: u32,
    /// Present only because the gate was raised from ring 3.
    pub user_esp: u32,
    pub user_ss: u32,
}

/// NtTerminateProcess's landing point: the process ends with `code` — its other threads are
/// terminated, then the calling thread — and the exit code is reported (the line every boot's
/// check reads). Never returns.
pub fn process_exited(code: u32) -> ! {
    #[cfg(target_arch = "x86")]
    {
        crate::process::threads::exit_process(code)
    }
    #[cfg(not(target_arch = "x86"))]
    {
        // Host builds compile the dispatch tables but never run them: there is no serial port and
        // no process to end.
        let _ = code;
        unimplemented!("process exit is a kernel-runtime operation")
    }
}

/// Launch the boot's user code: the multi-process suite with `run-process-suite`, a fault-test
/// stub with a `fault-test-*` feature, or one image from the boot volume through the PE loader: the
/// program the kernel command line names (see [`command_line_image`]), else exit0.
/// Every path enters its process as a main thread through the idle loop. Never returns.
#[cfg(target_arch = "x86")]
pub fn run_user_process() -> ! {
    // The system DLLs' pages: the kernel's for the boot's life, every process one more holder of
    // them — made before the teardown audit's baseline, as the boot's other permanent pages are.
    crate::exec::loader::prepare_system_dlls();
    #[cfg(feature = "run-process-suite")]
    {
        crate::process::runner::run_suite()
    }
    #[cfg(all(
        not(feature = "run-process-suite"),
        any(
            feature = "fault-test-badargs",
            feature = "fault-test-segments",
            feature = "fault-test-threadexit",
            feature = "fault-test-exitio",
            feature = "fault-test-ntclose"
        )
    ))]
    {
        // The teardown audit's baseline: the boot's permanent allocations are done, the process
        // has taken nothing yet.
        crate::process::record_allocator_baseline();
        run_fault_stub()
    }
    #[cfg(all(
        not(feature = "run-process-suite"),
        not(any(
            feature = "fault-test-badargs",
            feature = "fault-test-segments",
            feature = "fault-test-threadexit",
            feature = "fault-test-exitio",
            feature = "fault-test-ntclose"
        ))
    ))]
    {
        let (path, name, command_line): (&'static [u8], &'static str, &'static [u8]) =
            command_line_image().unwrap_or((b"exit0.exe", "exit0", b"exit0"));
        // The teardown audit's baseline: the boot's permanent allocations are done, the process
        // has taken nothing yet.
        crate::process::record_allocator_baseline();
        let entry = crate::exec::loader::load_path(path, name, command_line);
        crate::process::threads::enter_as_main_thread(main_thread_start(entry))
    }
}

/// The longest program path the command line may name (Win32's MAX_PATH).
#[cfg(target_arch = "x86")]
const MAX_PATH: usize = 260;

/// The program the boot's user command line names (see [`crate::boot::cmdline`]), as its volume
/// path, its process name (the file name's stem) and the command line itself; none without a user
/// command line (the boot then runs exit0). The program token is a root-relative path on the boot
/// volume (`CORPUS\sync.exe`; a leading `C:` or backslash is dropped); one without an extension
/// gets `.exe`, as CreateProcess gives it, and one that is not a well-formed volume path is
/// reported and halts, like an image that does not load.
#[cfg(target_arch = "x86")]
fn command_line_image() -> Option<(&'static [u8], &'static str, &'static [u8])> {
    use crate::boot::cmdline::{kernel_command_line, program_token, user_command_line};

    /// The program's volume path: built once, here, at boot.
    static mut PROGRAM: ([u8; MAX_PATH], usize) = ([0; MAX_PATH], 0);

    let line = user_command_line(kernel_command_line())?;
    let token = program_token(line);
    let path = volume_path(token);
    // SAFETY: single-threaded boot; the buffer is written once, here, and only read afterwards.
    let (buffer, length) = unsafe { &mut *core::ptr::addr_of_mut!(PROGRAM) };
    let file_name_start = path
        .iter()
        .rposition(|&byte| byte == b'\\')
        .map_or(0, |i| i + 1);
    let needs_extension = !path[file_name_start..].contains(&b'.');
    let total = path.len() + if needs_extension { 4 } else { 0 };
    if !crate::fs::fat32::path::is_valid(path) || total >= MAX_PATH {
        crate::serial_println!(
            "F2K: command line program {} names no file",
            core::str::from_utf8(token).unwrap_or("(not ASCII)")
        );
        crate::halt()
    }
    buffer[..path.len()].copy_from_slice(path);
    if needs_extension {
        buffer[path.len()..total].copy_from_slice(b".exe");
    }
    *length = total;
    let path: &'static [u8] = &buffer[..*length];
    let file_name = &path[file_name_start..];
    let stem = &file_name[..file_name
        .iter()
        .position(|&byte| byte == b'.')
        .unwrap_or(file_name.len())];
    Some((path, core::str::from_utf8(stem).unwrap_or("program"), line))
}

/// A program token as a root-relative volume path: a drive prefix (`C:`) and leading backslashes
/// dropped (the boot volume is the only volume).
pub fn volume_path(token: &[u8]) -> &[u8] {
    let mut path = token;
    if path.len() >= 2 && path[1] == b':' && path[0].is_ascii_alphabetic() {
        path = &path[2..];
    }
    while let Some(rest) = path.strip_prefix(b"\\") {
        path = rest;
    }
    path
}

/// Create the fault-test stub's process — its code and stack pages mapped in the process's own
/// address space — and enter it as its main thread. Never returns.
#[cfg(target_arch = "x86")]
#[cfg(any(
    feature = "fault-test-badargs",
    feature = "fault-test-segments",
    feature = "fault-test-threadexit",
    feature = "fault-test-exitio",
    feature = "fault-test-ntclose"
))]
pub fn run_fault_stub() -> ! {
    use crate::mem::{paging, vm};

    // The stub's one code page stands where an image would, with the system areas around it.
    let space = crate::process::Process::start("stub").vm();
    crate::exec::loader::seed_regions(space, USER_CODE_PAGE, paging::PAGE_SIZE);

    let code_frame = paging::allocate_frame_phys();
    paging::init_frame(code_frame, 0, &RING3_STUB);
    vm::map_prepared(space, USER_CODE_PAGE, code_frame, vm::PAGE_EXECUTE_READ);
    vm::map_zeroed(space, USER_STACK_PAGE, vm::PAGE_READWRITE);
    vm::map_zeroed(space, USER_STACK_LOW_PAGE, vm::PAGE_READWRITE);

    crate::serial_println!(
        "F2K: entering ring 3 (code {:#010x}, stack {:#010x})",
        USER_CODE_PAGE,
        USER_STACK_TOP
    );
    crate::process::threads::enter_as_main_thread(crate::sched::startup::UserStart {
        eip: USER_CODE_PAGE,
        esp: USER_STACK_TOP,
        ..Default::default()
    })
}

/// The exit-during-read boot's check, on the idle thread after the process's teardown: the volume
/// must be usable again — its lock free, the drive between commands — so a lookup succeeds.
#[cfg(all(target_arch = "x86", feature = "fault-test-exitio"))]
pub fn check_volume_after_teardown() {
    let found = crate::fs::fat32::volume::with_boot_volume(|volume| {
        crate::fs::fat32::lookup::lookup(volume, b"hello.exe")
    });
    match found {
        Some(Ok(file)) => {
            crate::serial_println!(
                "F2K: exit-during-read: volume usable after teardown (HELLO.EXE, {} bytes)",
                file.size
            );
        }
        other => {
            crate::serial_println!(
                "F2K: exit-during-read: volume unusable after teardown ({:?})",
                other
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    /// A command line's program token names a root-relative path on the boot volume: a drive
    /// prefix and leading backslashes go, the rest is the path as given.
    #[test]
    fn the_program_token_is_a_root_relative_volume_path() {
        assert_eq!(super::volume_path(b"CORPUS\\sync.exe"), b"CORPUS\\sync.exe");
        assert_eq!(
            super::volume_path(b"C:\\CORPUS\\sync.exe"),
            b"CORPUS\\sync.exe"
        );
        assert_eq!(super::volume_path(b"\\ret0.exe"), b"ret0.exe");
        assert_eq!(super::volume_path(b"ret0"), b"ret0");
    }
    use core::ptr::addr_of;

    use super::*;
    use crate::mem::paging::KERNEL_BASE;
    use crate::user::syscall::SYSCALL_VECTOR;

    /// The bad-args stub requests NtTerminateProcess with an unmapped argument pointer: BA+imm32
    /// (mov edx, imm32), int, jmp $.
    #[cfg(feature = "fault-test-badargs")]
    #[test]
    fn badargs_stub_bytes_match_their_encoding() {
        let mut expected = [0u8; 14];
        expected[0] = 0xB8;
        expected[1..5].copy_from_slice(&0xE0u32.to_le_bytes());
        expected[5] = 0xBA;
        expected[6..10].copy_from_slice(&BAD_ARGS_PTR.to_le_bytes());
        expected[10] = 0xCD;
        expected[11] = SYSCALL_VECTOR as u8;
        expected[12] = 0xEB;
        expected[13] = 0xFE;
        assert_eq!(RING3_STUB, expected);
    }

    /// The exit-during-read stub: every `mov eax, imm32` raising the gate right after carries
    /// Windows 2000's number for its service, in the stub's order; the absolute addresses name the
    /// child's entry, its INITIAL_TEB (the stack it is created on) and the name's structures inside
    /// the code page, and its CONTEXT the child's loop, stack top and file handle.
    #[test]
    fn exit_during_read_stub_raises_windows_2000_services() {
        let stub = &EXIT_DURING_READ_STUB;
        let gates: Vec<u32> = (1..stub.len() - 6)
            .filter(|&at| stub[at - 1] == 0xB8 && stub[at + 4..at + 6] == [0xCD, SYSCALL_VECTOR as u8])
            .map(|at| u32::from_le_bytes(stub[at..at + 4].try_into().unwrap()))
            .collect();
        let nt = |name: &str| crate::nt::NT_SERVICES.iter().find(|entry| entry.1 == name).unwrap().0;
        let expected: Vec<u32> = [
            "NtOpenFile",
            "NtAllocateVirtualMemory",
            "NtCreateThread",
            "NtSetInformationThread",
            "NtTerminateProcess",
            "NtReadFile",
        ]
        .iter()
        .map(|name| nt(name))
        .collect();
        assert_eq!(gates, expected);
        // The priority is ThreadBasePriority's saturation value, pushed before the arguments.
        assert_eq!(&stub[0xA1..0xAA], &[0x6A, 0x10, 0x89, 0xE1, 0x6A, 0x04, 0x51, 0x6A, 0x03]);
        let word = |at: usize| u32::from_le_bytes(stub[at..at + 4].try_into().unwrap());
        // The child's CONTEXT: control and integer registers, EBX the file handle, EIP the child,
        // ESP the top of the two stack pages above the context's page.
        assert_eq!((word(0x56), word(0x5A)), (CHILD_STACK, 0x0001_0003));
        assert_eq!(&stub[0x5E..0x60], &[0x89, 0x1D], "mov [CONTEXT.Ebx], ebx");
        assert_eq!(word(0x60), CHILD_STACK + 0xA4);
        assert_eq!((word(0x66), word(0x6A)), (CHILD_STACK + 0xB8, USER_CODE_PAGE + 0xC6), "the child");
        assert_eq!((word(0x70), word(0x74)), (CHILD_STACK + 0xC4, CHILD_STACK + 0x3000));
        assert_eq!(&stub[0xC6..0xCC], &[0x81, 0xEC, 0x00, 0x02, 0x00, 0x00], "the child's first instruction");
        // The INITIAL_TEB: no old stack; the two stack pages, the reservation from the context's.
        assert_eq!(word(0x7F), USER_CODE_PAGE + 0x104, "the initial TEB");
        let teb: Vec<u32> = (0..5).map(|i| word(0x104 + 4 * i)).collect();
        assert_eq!(teb, [0, 0, CHILD_STACK + 0x3000, CHILD_STACK + 0x1000, CHILD_STACK]);
        assert_eq!(word(0x0F), USER_CODE_PAGE + 0x118, "the attributes");
        assert_eq!(word(0x118 + 8), USER_CODE_PAGE + 0x130, "the attributes name the string");
        assert_eq!(word(0x130 + 4), USER_CODE_PAGE + 0x138, "the string names its units");
        let name: Vec<u16> = stub[0x138..].chunks(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
        assert_eq!(String::from_utf16(&name).unwrap(), "\\??\\C:\\HELLO.EXE");
        // The loop's back jump lands on its first instruction.
        assert_eq!(0x104 + (stub[0x103] as i8 as i32), 0xE2);
    }

    /// The fault-test addresses: the bad-args pointer below the probe limit but on no mapped page.
    #[test]
    fn fault_probe_layout_is_consistent() {
        assert!(BAD_ARGS_PTR < KERNEL_BASE);
        assert_ne!(BAD_ARGS_PTR & !0xFFF, USER_CODE_PAGE);
        assert_ne!(BAD_ARGS_PTR & !0xFFF, USER_STACK_PAGE);
    }

    /// 15 u32s; the CPU-pushed tail keeps the iret order after the exception-stub prefix.
    #[test]
    fn trap_frame_layout() {
        assert_eq!(size_of::<TrapFrame>(), 15 * 4);
        let frame = TrapFrame {
            edi: 0,
            esi: 0,
            ebp: 0,
            esp: 0,
            ebx: 0,
            edx: 0,
            ecx: 0,
            eax: 0,
            vector: 0,
            error_code: 0,
            eip: 0,
            cs: 0,
            eflags: 0,
            user_esp: 0,
            user_ss: 0,
        };
        let base = addr_of!(frame) as usize;
        assert_eq!(addr_of!(frame.eax) as usize - base, 7 * 4);
        assert_eq!(addr_of!(frame.vector) as usize - base, 8 * 4);
        assert_eq!(addr_of!(frame.error_code) as usize - base, 9 * 4);
        assert_eq!(addr_of!(frame.eip) as usize - base, 10 * 4);
        assert_eq!(addr_of!(frame.cs) as usize - base, 11 * 4);
        assert_eq!(addr_of!(frame.eflags) as usize - base, 12 * 4);
        assert_eq!(addr_of!(frame.user_esp) as usize - base, 13 * 4);
        assert_eq!(addr_of!(frame.user_ss) as usize - base, 14 * 4);
    }

    /// Per-thread TEB pages: the first thread keeps the loader's fixed page; later threads take
    /// their own page from the region, so threads of one process never share a TEB.
    #[test]
    fn per_thread_teb_pages_are_distinct() {
        assert_eq!(thread_teb_va(0), TEB_PAGE);
        let pages = [thread_teb_va(0), thread_teb_va(1), thread_teb_va(2)];
        assert_eq!(pages[1], THREAD_TEB_REGION);
        assert_eq!(pages[2], THREAD_TEB_REGION + 4096);
        for index in 1..pages.len() {
            for other in 0..index {
                assert_ne!(pages[index], pages[other]);
            }
            assert!(pages[index] > PARAMS_PAGE);
            // The region stays below the space the program's own reservations (its heaps
            // included) start in.
            assert!(pages[index] < 0x0200_0000);
        }
        for &page in &pages {
            assert_eq!(page % 4096, 0);
            assert!(page < KERNEL_BASE);
        }
    }

    /// The user pages: below the kernel window, page-aligned, the stack top one past its top page,
    /// the image window clear of window 0.
    #[test]
    fn user_layout_is_consistent() {
        for page in [
            USER_CODE_PAGE,
            USER_STACK_PAGE,
            USER_STACK_LOW_PAGE,
            TEB_PAGE,
            PARAMS_PAGE,
            PEB_PAGE,
        ] {
            assert_eq!(page % 4096, 0);
            assert!(page < KERNEL_BASE);
        }
        assert_ne!(USER_CODE_PAGE >> 22, USER_STACK_PAGE >> 22);
        assert_eq!(USER_STACK_LOW_PAGE, USER_STACK_PAGE - 4096);
        assert_eq!(USER_STACK_TOP, USER_STACK_PAGE + 4096);
        assert!(TEB_PAGE > USER_STACK_TOP);
        assert!(PARAMS_PAGE > TEB_PAGE);
        assert!(PARAMS_PAGE + params::PAGES * 4096 <= PEB_PAGE);
        assert!(PEB_PAGE + 4096 <= USER_CODE_PAGE);
    }
}
