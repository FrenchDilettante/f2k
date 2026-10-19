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

/// The exit-during-read stub, before its service numbers are patched in: the main thread opens
/// HELLO.EXE (CreateFileA, still kernel-served), allocates a stack for a child at [`CHILD_STACK`]
/// (NtAllocateVirtualMemory: a page for its CONTEXT, then two stack pages) and creates the child
/// there (NtCreateThread, EIP its loop, EBX the file handle), raises it time-critical
/// (NtSetInformationThread's ThreadBasePriority, as kernel32's SetThreadPriority asks it) to seek to
/// the start and read a sector forever (SetFilePointer and ReadFile, still kernel-served); main
/// runs again only while the child waits on the disk, and ends the process there
/// (NtTerminateProcess). The thread and process calls are Windows 2000's services by their own
/// numbers; the zeroed immediates are the served file calls' ([`EXIT_DURING_READ_SERVICES`]). The
/// INITIAL_TEB follows the code and the path.
#[cfg(any(feature = "fault-test-exitio", test))]
#[rustfmt::skip]
const EXIT_DURING_READ_TEMPLATE: [u8; 272] = [
    0x6A, 0x00, // 0x00: push 0 (hTemplateFile)
    0x6A, 0x00, // 0x02: push 0 (dwFlagsAndAttributes)
    0x6A, 0x03, // 0x04: push OPEN_EXISTING
    0x6A, 0x00, // 0x06: push 0 (lpSecurityAttributes)
    0x6A, 0x01, // 0x08: push FILE_SHARE_READ
    0x68, 0x00, 0x00, 0x00, 0x80, // 0x0a: push GENERIC_READ
    0xB8, 0xF2, 0x00, 0x40, 0x00, // 0x0f: mov eax, path
    0x50, // 0x14: push eax (lpFileName)
    0x89, 0xE2, // 0x15: mov edx, esp
    0xB8, 0x00, 0x00, 0x00, 0x00, // 0x17: mov eax, CreateFileA (patched)
    0xCD, 0x2E, // 0x1c: int 0x2E
    0x83, 0xC4, 0x1C, // 0x1e: add esp, 28
    0x89, 0xC3, // 0x21: mov ebx, eax (the file handle)
    0x68, 0x00, 0x30, 0x00, 0x00, // 0x23: push 0x3000 (RegionSize: the context page and two stack pages)
    0x68, 0x00, 0x00, 0x60, 0x00, // 0x28: push CHILD_STACK (BaseAddress)
    0x89, 0xE0, // 0x2d: mov eax, esp (&base)
    0x8D, 0x4C, 0x24, 0x04, // 0x2f: lea ecx, [esp+4] (&size)
    0x6A, 0x04, // 0x33: push PAGE_READWRITE
    0x68, 0x00, 0x30, 0x00, 0x00, // 0x35: push MEM_COMMIT | MEM_RESERVE
    0x51, // 0x3a: push ecx (RegionSize)
    0x6A, 0x00, // 0x3b: push 0 (ZeroBits)
    0x50, // 0x3d: push eax (BaseAddress)
    0x6A, 0xFF, // 0x3e: push NtCurrentProcess
    0x89, 0xE2, // 0x40: mov edx, esp
    0xB8, 0x10, 0x00, 0x00, 0x00, // 0x42: mov eax, NtAllocateVirtualMemory (0x10)
    0xCD, 0x2E, // 0x47: int 0x2E
    0x83, 0xC4, 0x20, // 0x49: add esp, 32 (the arguments and both slots)
    0xC7, 0x05, 0x00, 0x00, 0x60, 0x00, 0x03, 0x00, 0x01, 0x00, // 0x4c: mov dword [CHILD_STACK], CONTEXT_CONTROL | CONTEXT_INTEGER
    0x89, 0x1D, 0xA4, 0x00, 0x60, 0x00, // 0x56: mov [CHILD_STACK+0xA4], ebx (the context's EBX: the file handle)
    0xC7, 0x05, 0xB8, 0x00, 0x60, 0x00, 0xBE, 0x00, 0x40, 0x00, // 0x5c: mov dword [CHILD_STACK+0xB8], child (EIP)
    0xC7, 0x05, 0xC4, 0x00, 0x60, 0x00, 0x00, 0x30, 0x60, 0x00, // 0x66: mov dword [CHILD_STACK+0xC4], CHILD_STACK + 0x3000 (ESP)
    0x6A, 0x00, // 0x70: push 0 (the child's handle slot)
    0x89, 0xE0, // 0x72: mov eax, esp
    0x6A, 0x00, // 0x74: push 0 (CreateSuspended)
    0x68, 0xFC, 0x00, 0x40, 0x00, // 0x76: push initial_teb
    0x68, 0x00, 0x00, 0x60, 0x00, // 0x7b: push CHILD_STACK (ThreadContext)
    0x6A, 0x00, // 0x80: push 0 (ClientId)
    0x6A, 0xFF, // 0x82: push NtCurrentProcess
    0x6A, 0x00, // 0x84: push 0 (ObjectAttributes)
    0x68, 0xFF, 0x03, 0x1F, 0x00, // 0x86: push THREAD_ALL_ACCESS
    0x50, // 0x8b: push eax (ThreadHandle)
    0x89, 0xE2, // 0x8c: mov edx, esp
    0xB8, 0x2E, 0x00, 0x00, 0x00, // 0x8e: mov eax, NtCreateThread (0x2E)
    0xCD, 0x2E, // 0x93: int 0x2E
    0x83, 0xC4, 0x20, // 0x95: add esp, 32
    0x58, // 0x98: pop eax (the child's handle)
    0x6A, 0x10, // 0x99: push 16 (the saturation THREAD_PRIORITY_TIME_CRITICAL converts to)
    0x89, 0xE1, // 0x9b: mov ecx, esp (&priority)
    0x6A, 0x04, // 0x9d: push 4 (ThreadInformationLength)
    0x51, // 0x9f: push ecx (ThreadInformation)
    0x6A, 0x03, // 0xa0: push ThreadBasePriority
    0x50, // 0xa2: push eax (the child's handle)
    0x89, 0xE2, // 0xa3: mov edx, esp
    0xB8, 0xC7, 0x00, 0x00, 0x00, // 0xa5: mov eax, NtSetInformationThread (0xC7: the child preempts here)
    0xCD, 0x2E, // 0xaa: int 0x2E
    0x83, 0xC4, 0x14, // 0xac: add esp, 20 (the arguments and the priority)
    0x6A, 0x00, // 0xaf: push 0 (ExitStatus)
    0x6A, 0xFF, // 0xb1: push NtCurrentProcess
    0x89, 0xE2, // 0xb3: mov edx, esp
    0xB8, 0xE0, 0x00, 0x00, 0x00, // 0xb5: mov eax, NtTerminateProcess (0xE0: the child is inside a read)
    0xCD, 0x2E, // 0xba: int 0x2E
    0xEB, 0xFE, // 0xbc: jmp $
    0x81, 0xEC, 0x00, 0x02, 0x00, 0x00, // 0xbe: child (EBX the file handle): sub esp, 0x200
    0x89, 0xE7, // 0xc4: mov edi, esp (the buffer)
    0x6A, 0x00, // 0xc6: child_loop: push FILE_BEGIN
    0x6A, 0x00, // 0xc8: push 0 (lpDistanceToMoveHigh)
    0x6A, 0x00, // 0xca: push 0 (lDistanceToMove)
    0x53, // 0xcc: push ebx
    0x89, 0xE2, // 0xcd: mov edx, esp
    0xB8, 0x00, 0x00, 0x00, 0x00, // 0xcf: mov eax, SetFilePointer (patched)
    0xCD, 0x2E, // 0xd4: int 0x2E
    0x83, 0xC4, 0x10, // 0xd6: add esp, 16
    0x6A, 0x00, // 0xd9: push 0 (lpOverlapped)
    0x6A, 0x00, // 0xdb: push 0 (lpNumberOfBytesRead)
    0x68, 0x00, 0x02, 0x00, 0x00, // 0xdd: push 512
    0x57, // 0xe2: push edi
    0x53, // 0xe3: push ebx
    0x89, 0xE2, // 0xe4: mov edx, esp
    0xB8, 0x00, 0x00, 0x00, 0x00, // 0xe6: mov eax, ReadFile (patched)
    0xCD, 0x2E, // 0xeb: int 0x2E
    0x83, 0xC4, 0x14, // 0xed: add esp, 20
    0xEB, 0xD4, // 0xf0: jmp child_loop
    b'h', b'e', b'l', b'l', b'o', b'.', b'e', b'x', b'e', 0, // 0xf2: path
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x60, 0x00, 0x00, 0x10, 0x60, 0x00, 0x00, 0x00, 0x60, 0x00, // 0xfc: INITIAL_TEB (no old stack; base, limit, allocation base)
];

/// Where the exit-during-read stub's child stack (its CONTEXT's page, then two stack pages) is
/// allocated: free in the stub's process, which maps only its code page there.
#[cfg(any(feature = "fault-test-exitio", test))]
pub const CHILD_STACK: u32 = 0x0060_0000;

/// Where the template's served service-number immediates sit (each one byte past its `mov eax`
/// opcode), and the export each names.
#[cfg(any(feature = "fault-test-exitio", test))]
const EXIT_DURING_READ_SERVICES: [(usize, &str); 3] = [
    (0x18, "CreateFileA"),
    (0xD0, "SetFilePointer"),
    (0xE7, "ReadFile"),
];

/// The exit-during-read stub: the template with the registry's service numbers patched in at build
/// time, so a registry change cannot leave it calling the wrong services.
#[cfg(any(feature = "fault-test-exitio", test))]
pub const EXIT_DURING_READ_STUB: [u8; 272] = {
    let mut stub = EXIT_DURING_READ_TEMPLATE;
    let mut index = 0;
    while index < EXIT_DURING_READ_SERVICES.len() {
        let (offset, name) = EXIT_DURING_READ_SERVICES[index];
        let number = crate::compat::kernel32::service_number(name).to_le_bytes();
        stub[offset] = number[0];
        stub[offset + 1] = number[1];
        stub[offset + 2] = number[2];
        stub[offset + 3] = number[3];
        index += 1;
    }
    stub
};

#[cfg(all(
    feature = "fault-test-exitio",
    not(feature = "fault-test-badargs"),
    not(feature = "fault-test-segments"),
    not(feature = "fault-test-threadexit")
))]
pub const RING3_STUB: [u8; 272] = EXIT_DURING_READ_STUB;

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

    /// The exit-during-read stub: each patch site is a `mov eax, imm32` raising the gate right
    /// after, carrying its served export's service number; the NT calls carry Windows 2000's own
    /// numbers; the absolute addresses name the child entry, the path string and the INITIAL_TEB
    /// inside the code page, and the INITIAL_TEB the child's stack above its CONTEXT's page.
    #[test]
    fn exit_during_read_stub_patches_its_service_numbers() {
        let word =
            |at: usize| u32::from_le_bytes(EXIT_DURING_READ_STUB[at..at + 4].try_into().unwrap());
        let gate = |at: usize| {
            assert_eq!(EXIT_DURING_READ_STUB[at - 1], 0xB8, "{at:#x}: mov eax");
            assert_eq!(
                &EXIT_DURING_READ_STUB[at + 4..at + 6],
                &[0xCD, SYSCALL_VECTOR as u8],
                "{at:#x}: int"
            );
            word(at)
        };
        for (offset, name) in EXIT_DURING_READ_SERVICES {
            let number = gate(offset);
            assert_eq!(
                number,
                crate::compat::kernel32::service_number(name),
                "{name}"
            );
            assert!(
                crate::compat::kernel32::lookup_service(number).is_some(),
                "{name}"
            );
        }
        // NtAllocateVirtualMemory, NtCreateThread, NtSetInformationThread, NtTerminateProcess.
        for (offset, number) in [(0x43, 0x10), (0x8F, 0x2E), (0xA6, 0xC7), (0xB6, 0xE0)] {
            assert_eq!(gate(offset), number, "{offset:#x}");
            assert!(crate::nt::lookup(number).is_some(), "{number:#x}");
        }
        let (child, path, initial_teb): (usize, usize, usize) = (0xBE, 0xF2, 0xFC);
        assert_eq!(
            word(0x62),
            USER_CODE_PAGE + child as u32,
            "the context's EIP"
        );
        assert_eq!(word(0x10), USER_CODE_PAGE + path as u32);
        assert_eq!(word(0x77), USER_CODE_PAGE + initial_teb as u32);
        assert_eq!(&EXIT_DURING_READ_STUB[child..child + 2], &[0x81, 0xEC]);
        assert_eq!(&EXIT_DURING_READ_STUB[path..initial_teb], b"hello.exe\0");
        assert_eq!(
            [
                word(initial_teb + 8),
                word(initial_teb + 12),
                word(initial_teb + 16)
            ],
            [CHILD_STACK + 0x3000, CHILD_STACK + 0x1000, CHILD_STACK]
        );
        assert_eq!(initial_teb + 20, EXIT_DURING_READ_STUB.len());
        // The loop's back jump lands on its first instruction.
        assert_eq!(0xF2 + (EXIT_DURING_READ_STUB[0xF1] as i8 as i32), 0xC6);
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
