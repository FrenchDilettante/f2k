//! Interrupt Descriptor Table and CPU exception handling.
//!
//! Every CPU exception lands in one of 32 generated stubs, which save the register state and hand
//! it to a Rust handler. A fault in the kernel's fault-tolerant user copy resumes at the copy's
//! fixup, the copy failing; a fault raised by user code goes to the thread's own exception handlers
//! (`user::seh`); anything else gets a diagnostic dump on COM1 (silent triple-fault resets become
//! actionable output) and ends the user process, or halts the kernel. Exceptions fire regardless of
//! IF, so nothing here needs the PIC or `sti`; hardware IRQs come later.

use crate::cpu::gdt::KERNEL_CODE_SELECTOR;

/// Number of CPU exception vectors (0-31).
const EXCEPTION_VECTORS: usize = 32;

/// IDT size: the 32 exception vectors plus the syscall gate at vector 0x2E (see `syscall.rs`),
/// registered at DPL 3. A vector left absent is a not-present gate: raising it faults with the
/// vector-derived error code — #NP from ring 0, and #GP from ring 3 (the zeroed descriptor's DPL 0
/// fails the privilege check first).
pub const IDT_VECTORS: usize = 256;

/// Registers saved by the common exception stub, in stack order. Constructed by assembly, never by
/// Rust code. The segment registers are not part of the frame: the stubs save them just below it
/// ([`SavedSegments`]), moved through EAX as full words (LLVM assembles `push <segreg>` as a 16-bit
/// push), so the frame shape every stub and the thread-startup ladder share stays unchanged.
#[allow(dead_code)]
#[repr(C)]
pub(crate) struct ExceptionFrame {
    edi: u32,
    esi: u32,
    ebp: u32,
    esp: u32,
    ebx: u32,
    edx: u32,
    ecx: u32,
    eax: u32,
    pub(crate) vector: u32,
    error_code: u32,
    eip: u32,
    cs: u32,
    eflags: u32,
}

/// The interrupted context's data segments, as the entry stubs (exception, hardware-interrupt,
/// syscall) save them: four words directly below the register frame, GS lowest. The stubs then
/// load the kernel's data selector into DS/ES, so a ring-3 context that loaded a null or based
/// selector cannot steer the kernel's data accesses; the returning stubs restore them before
/// `popad`.
#[allow(dead_code)]
#[repr(C)]
pub(crate) struct SavedSegments {
    pub(crate) gs: u32,
    pub(crate) fs: u32,
    pub(crate) es: u32,
    pub(crate) ds: u32,
}

impl SavedSegments {
    /// The segments saved below `frame` (the stubs' layout), for as long as the frame is borrowed.
    ///
    /// # Safety
    ///
    /// `frame` must be the frame an entry stub passed, so the four words below it are the saved
    /// segments.
    pub(crate) unsafe fn below<T>(frame: &T) -> &SavedSegments {
        // SAFETY: per the contract, the stub stored the four words directly below the frame, on
        // the same stack, which outlives the frame's borrow.
        unsafe { &*core::ptr::from_ref(frame).cast::<SavedSegments>().sub(1) }
    }
}

/// The ring-3 tail the CPU pushes on the TSS stack when the exception was raised in ring 3: the
/// interrupted ESP/SS pair, above the common frame. Only valid when the interrupted CS carries RPL
/// 3; a ring-0 exception pushes nothing there.
#[allow(dead_code)]
#[repr(C)]
struct Ring3ExceptionFrame {
    frame: ExceptionFrame,
    user_esp: u32,
    user_ss: u32,
}

impl ExceptionFrame {
    /// The interrupted instruction pointer and code segment (the perf trace's sample; the
    /// segment's RPL says which ring was running).
    pub(crate) fn interrupted_pc(&self) -> (u32, u32) {
        (self.eip, self.cs)
    }

    /// The interrupted frame pointer (where the perf trace's stack walk starts).
    pub(crate) fn interrupted_ebp(&self) -> u32 {
        self.ebp
    }
}

/// One 32-bit IDT gate descriptor: interrupt gate, present, ring 0.
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct Gate {
    offset_low: u16,
    selector: u16,
    reserved: u8,
    type_attr: u8,
    offset_high: u16,
}

impl Gate {
    /// A not-present gate: every vector the IDT does not register.
    pub const ABSENT: Gate = Gate {
        offset_low: 0,
        selector: 0,
        reserved: 0,
        type_attr: 0,
        offset_high: 0,
    };
    /// 0x8E = present, ring 0, 32-bit interrupt gate (clears IF on entry).
    ///
    /// Gates that user code must be able to raise use DPL 3 instead ([`Gate::new_user`]): the
    /// syscall gate and the software exceptions (int3, into).
    const INTERRUPT_ATTR: u8 = 0x8E;
    /// 0xEE = present, ring 3, 32-bit interrupt gate: ring-3 code may raise the vector with `int`;
    /// entry clears IF as usual.
    const USER_INTERRUPT_ATTR: u8 = 0xEE;

    fn new(handler: usize) -> Self {
        Self {
            offset_low: handler as u16,
            selector: KERNEL_CODE_SELECTOR,
            reserved: 0,
            type_attr: Self::INTERRUPT_ATTR,
            offset_high: (handler >> 16) as u16,
        }
    }

    /// A ring-3-raisable interrupt gate.
    fn new_user(handler: usize) -> Self {
        Self {
            offset_low: handler as u16,
            selector: KERNEL_CODE_SELECTOR,
            reserved: 0,
            type_attr: Self::USER_INTERRUPT_ATTR,
            offset_high: (handler >> 16) as u16,
        }
    }
}

// Pin the attribute bytes at the definition: present, 32-bit interrupt gates (clears IF on entry),
// ring 0 or ring 3.
const _: () = assert!(Gate::INTERRUPT_ATTR == 0x8E && Gate::USER_INTERRUPT_ATTR == 0xEE);

/// The Interrupt Descriptor Table, every vector's gate.
pub type Idt = [Gate; IDT_VECTORS];

/// Address of a generated stub. Casts through a pointer: clippy flags a direct
/// function-item-to-integer cast as provenance-lossy.
#[cfg(target_arch = "x86")]
fn stub_addr(stub: unsafe extern "C" fn()) -> usize {
    stub as *const () as usize
}

/// Build the IDT in the processor's table and load it. The stub addresses are link-time constants,
/// but their casts are not const-evaluable, so the gates are written here rather than in the
/// table's initial value.
///
/// # Safety
///
/// Must run on the boot CPU in ring 0 with interrupts disabled, before any code that might raise a
/// CPU exception; `idt` is the processor control region's table, which stays in place for the
/// kernel's life.
#[cfg(target_arch = "x86")]
pub unsafe fn init(idt: &mut Idt) {
    for (gate, stub) in idt.iter_mut().zip(EXCEPTION_STUBS) {
        *gate = Gate::new(stub_addr(stub));
    }

    // The software exceptions user code raises itself, as on Windows: int3 (the breakpoint) and
    // into (the overflow check) are ring-3 gates, so they raise their own exceptions rather than a
    // general protection fault.
    for vector in [3, 4] {
        idt[vector] = Gate::new_user(stub_addr(EXCEPTION_STUBS[vector]));
    }

    // The syscall gate (see `syscall.rs`): ring-3 reachable, entered on the TSS ring-0 stack, the
    // return path for user code.
    idt[crate::user::syscall::SYSCALL_VECTOR] =
        Gate::new_user(stub_addr(crate::user::syscall::syscall_gate_stub));

    // The hardware vectors (see `interrupt/`): one interrupt-gate stub per vector in the remapped
    // band. Nothing can raise them until the interrupt subsystem enables the lines.
    let band = &mut idt[crate::interrupt::FIRST_VECTOR as usize..];
    for (gate, stub) in band.iter_mut().zip(IRQ_STUBS) {
        *gate = Gate::new(stub_addr(stub));
    }

    let idtr = super::DescriptorTablePointer::of(&*idt);
    // SAFETY: the caller's contract: ring 0, interrupts disabled, and the table stays where the
    // pointer names it, each vector it registers a stub of this file's or the syscall gate.
    unsafe {
        core::arch::asm!("lidt [{}]", in(reg) &idtr, options(readonly, nostack, preserves_flags));
    }
}

/// Mnemonics for the 32 CPU exception vectors, for the diagnostic dump.
#[allow(dead_code)] // referenced only by the assembly-called handler
const NAMES: [&str; EXCEPTION_VECTORS] = [
    "Divide Error (#DE)",
    "Debug (#DB)",
    "NMI",
    "Breakpoint (#BP)",
    "Overflow (#OF)",
    "Bound Range (#BR)",
    "Invalid Opcode (#UD)",
    "Device Not Available (#NM)",
    "Double Fault (#DF)",
    "Coprocessor Segment Overrun",
    "Invalid TSS (#TS)",
    "Segment Not Present (#NP)",
    "Stack-Segment Fault (#SS)",
    "General Protection Fault (#GP)",
    "Page Fault (#PF)",
    "Reserved (15)",
    "x87 FPU Error (#MF)",
    "Alignment Check (#AC)",
    "Machine Check (#MC)",
    "SIMD FP Exception (#XM)",
    "Virtualization Exception (#VE)",
    "Control Protection (#CP)",
    "Reserved (22)",
    "Reserved (23)",
    "Reserved (24)",
    "Reserved (25)",
    "Reserved (26)",
    "Reserved (27)",
    "Reserved (28)",
    "VMM Communication (#VC)",
    "Security Exception (#SE)",
    "Reserved (31)",
];

/// Resolve the exception when it can be resolved and return, the stub resuming the interrupted
/// context: a write to a copy-on-write page makes the page the process's own, and a guard page
/// firing in the running thread's stack grows the stack (from user code, or from the kernel's
/// fault-tolerant user copy); any other fault in that copy resumes at its fixup, the copy failing
/// (`user::syscall::copy_fixup`), and a fault raised by user code returns into the thread's
/// user-mode exception dispatcher (`user::seh::dispatch_fault`). Everything else prints a
/// diagnostic dump on COM1 and the origin decides: user-raised faults (including bad user pointers
/// in syscall argument copies) end the user process with the exception code they raise; the rest
/// are kernel faults, which halt.
///
/// The gates are interrupt gates: the entry cleared the interrupt flag, and the level ledger is
/// told so first (as the system-service gate does), so a wait or a raise/lower pair inside the
/// resolution — a copy-on-write's frame, a stack's growth, the exception's dispatch — cannot turn
/// interrupts back on halfway through it. A resolved exception's return gives the ledger the
/// interrupted context's flag, which the stub's `iretd` puts back in the hardware.
#[allow(dead_code)] // referenced only from the generated stubs (sym operand)
#[cfg(target_arch = "x86")]
extern "C" fn exception_handler(frame: &mut ExceptionFrame) {
    crate::pcr::pcr().enter_gate();
    resolve_or_end(frame);
    crate::pcr::pcr().leave_gate(frame.eflags & EFLAGS_IF != 0);
}

/// The interrupt flag's bit in EFLAGS.
#[cfg(target_arch = "x86")]
const EFLAGS_IF: u32 = 1 << 9;

/// The exception handler's body (see [`exception_handler`]): returns only when the exception is
/// resolved and the interrupted context resumes; otherwise it ends the process or halts.
#[cfg(target_arch = "x86")]
fn resolve_or_end(frame: &mut ExceptionFrame) {
    let from_user = frame.cs & 3 != 0;
    let in_copy = !from_user && crate::user::syscall::copy_fixup(frame.eip).is_some();
    let cr2: u32 = if frame.vector == 14 {
        let cr2: u32;
        // SAFETY: reading CR2 has no side effect.
        unsafe {
            core::arch::asm!("mov {}, cr2", out(reg) cr2, options(nomem, nostack));
        }
        cr2
    } else {
        0
    };
    // The exception code a user fault raises, when the page-fault resolution below decides it.
    let mut raised = None;
    if frame.vector == 14 && (from_user || in_copy) {
        // A write to a present copy-on-write page (error code: present, write) makes the page its
        // own and the write resumes — the program's, or the kernel's copy on its behalf.
        if frame.error_code & 0b11 == 0b11
            && crate::mem::vm::copy_on_write(&mut crate::mem::vm::CurrentPages, cr2)
        {
            return;
        }
        // A guard page fires, once. Inside the running thread's stack it grows the stack and the
        // access resumes; any other guard's access raises the guard violation — the program's, or,
        // for the kernel's copy, a failed copy (as the platform's probe of one fails), the guard
        // spent. A thread attached to another process's address space (the kernel's copy into
        // that process's memory) has no stack there: its guard is any other.
        if crate::mem::vm::fire_guard(&mut crate::mem::vm::CurrentPages, cr2) {
            use crate::process::exit::status;
            use crate::user::stack::{grow_on_guard, Growth};
            let growth = if crate::sched::attach::running_attached() {
                Growth::NotStack
            } else {
                grow_on_guard(cr2)
            };
            match growth {
                Growth::Grown => return,
                Growth::Overflow => raised = Some(status::STACK_OVERFLOW),
                Growth::NotStack => raised = Some(status::GUARD_PAGE_VIOLATION),
            }
        }
    }
    // Whatever the stack's growth did not resolve fails the kernel's copy at its fixup: a spent
    // guard, the stack's overflow (the call fails, as a probe of the last page does on the
    // platform, rather than the process ending inside the service), a page it may not touch
    // (unmapped, protected, the kernel's).
    if in_copy {
        frame.eip = crate::user::syscall::copy_fixup(frame.eip).expect("a copy fault has a fixup");
        return;
    }

    // A fault raised by user code goes to the thread's own exception handlers first; the frame then
    // returns into ntdll's dispatcher with the exception's records. Only a fault nobody can take
    // (no handler chain, no room for the records) ends the process here.
    if from_user {
        let status = user_fault_status(frame, raised);
        let vector = frame.vector;
        // SAFETY: a ring-3 exception frame carries the ring-3 tail: it has the syscall frame's
        // shape, word for word.
        let trap = unsafe { &mut *(frame as *mut ExceptionFrame as *mut crate::user::TrapFrame) };
        if crate::user::seh::dispatch_fault(trap, vector, status, cr2) {
            return;
        }
    }

    let name = NAMES
        .get(frame.vector as usize)
        .copied()
        .unwrap_or("Unknown");

    // The ring-3 tail exists only for ring-3 exceptions; read it once, through the extended
    // frame. Ring-0 frames report zeroes.
    let (user_esp, user_ss) = ring3_tail(frame).unwrap_or((0, 0));

    crate::serial_println!("CPU EXCEPTION: vector {} ({})", frame.vector, name);
    crate::serial_println!(
        "  error code {:#010x}  EIP {:#010x}  CS {:#04x}  EFLAGS {:#010x}",
        frame.error_code,
        frame.eip,
        frame.cs,
        frame.eflags,
    );
    crate::serial_println!(
        "  EAX {:#010x}  EBX {:#010x}  ECX {:#010x}  EDX {:#010x}",
        frame.eax,
        frame.ebx,
        frame.ecx,
        frame.edx
    );
    crate::serial_println!(
        "  ESI {:#010x}  EDI {:#010x}  EBP {:#010x}  ESP {:#010x}",
        frame.esi,
        frame.edi,
        frame.ebp,
        interrupted_esp(frame, user_esp)
    );
    // The faulting context's segments, as the stub saved them (the handler itself runs on the
    // kernel's DS/ES).
    // SAFETY: `frame` is the pointer the common stub passed, above its saved segments.
    let segments = unsafe { SavedSegments::below(&*frame) };
    crate::serial_println!(
        "  DS {:#04x}  ES {:#04x}  FS {:#04x}  GS {:#04x}",
        segments.ds & 0xFFFF,
        segments.es & 0xFFFF,
        segments.fs & 0xFFFF,
        segments.gs & 0xFFFF
    );
    if from_user {
        crate::serial_println!(
            "  raised from ring 3: user ESP {:#010x}  user SS {:#04x}",
            user_esp,
            user_ss
        );
    }
    if frame.vector == 14 {
        crate::serial_println!("  CR2 (faulting address) {:#010x}", cr2);
    }
    // Classify the fault by origin. A fault raised by user code (or, while the kernel copies
    // syscall arguments, by a bad user pointer on the kernel's behalf) ends the user process, not
    // the kernel: the faulting thread's exit terminates every other thread of the process, reports
    // the end, and the idle thread tears the process down (a suite boot then runs its next
    // process; a one-process boot rests). A kernel fault from any other origin stays the raw
    // diagnostic halt.
    if from_user {
        crate::process::threads::fault_exit(crate::process::exit::Fault {
            vector: frame.vector,
            status: user_fault_status(frame, raised),
            in_user_copy: false,
        });
    } else if crate::user::syscall::copying_user_args() {
        // The copy that set the thread's flag never resumes: clear it here, or the thread's exit
        // path would run attributed to the copy.
        crate::user::syscall::end_user_attribution();
        // The fault was raised on the process's behalf inside a user-memory copy: same
        // containment, its own report.
        crate::process::threads::fault_exit(crate::process::exit::Fault {
            vector: frame.vector,
            status: crate::process::exit::status::ACCESS_VIOLATION,
            in_user_copy: true,
        });
    }
    crate::halt();
}

/// The exception code a ring-3 fault raises: the one the page-fault resolution `raised` (the
/// stack's overflow, a guard violation), else the trap's own code, a protection fault telling a
/// privileged instruction apart by the faulting instruction's bytes.
#[cfg(target_arch = "x86")]
fn user_fault_status(frame: &ExceptionFrame, raised: Option<u32>) -> u32 {
    if let Some(status) = raised {
        return status;
    }
    let mut code = [0u8; 15];
    let privileged = frame.vector == 13
        && frame.cs & 3 != 0
        && read_code(frame.eip, &mut code)
        && crate::process::exit::is_privileged_instruction(&code);
    crate::process::exit::fault_status(frame.vector, privileged)
}

/// Read the faulting instruction's bytes at user address `eip`, as far as they are readable (the
/// copy is fault-tolerant: an instruction ending a page reads short, its tail zeroed).
#[cfg(target_arch = "x86")]
fn read_code(eip: u32, out: &mut [u8]) -> bool {
    let mut read = 0;
    while read < out.len() {
        // An EIP near the top of the address space (a jump into the kernel's window) must not
        // overflow: the read past it stops there.
        let Some(at) = eip.checked_add(read as u32) else {
            break;
        };
        let page_left = (0x1000 - (at as usize & 0xFFF)).min(out.len() - read);
        if crate::user::syscall::read_user(at, &mut out[read..read + page_left]).is_err() {
            break;
        }
        read += page_left;
    }
    read > 0
}

/// The interrupted user ESP and SS of a ring-3 exception, which the CPU pushed as the ring-3
/// tail above the common frame. `None` for a frame without RPL 3: ring-0 exceptions have no tail.
fn ring3_tail(frame: &ExceptionFrame) -> Option<(u32, u32)> {
    if frame.cs & 3 != 3 {
        return None;
    }
    // SAFETY: the frame's CS carries RPL 3, so the CPU changed privilege on entry and pushed the
    // user ESP and SS above the common frame on the TSS stack: the words `Ring3ExceptionFrame`
    // reads past `ExceptionFrame` are part of this exception's frame.
    let ring3 = unsafe { &*(core::ptr::addr_of!(*frame) as *const Ring3ExceptionFrame) };
    Some((ring3.user_esp, ring3.user_ss))
}

/// ESP of the interrupted context. Ring 0: five frame words (vector, error code, EIP, CS, EFLAGS)
/// sit between the stub-saved ESP and the interrupted stack. Ring 3: the interrupted stack is the
/// user stack — report the ESP the CPU pushed in the ring-3 tail, not arithmetic on the TSS stack.
fn interrupted_esp(frame: &ExceptionFrame, user_esp: u32) -> u32 {
    if frame.cs & 3 != 0 {
        user_esp
    } else {
        frame.esp + 5 * 4
    }
}

// --- Exception stubs ------------------------------------------------------
//
// Single source of truth: the vector table below drives both the generated assembly and the
// Rust-side ERROR_CODE_VECTORS, so the two cannot drift apart. `true` = the CPU pushes an error
// code for this vector (the stub must not add one); `false` = the stub pushes a zero placeholder so
// every frame shares one layout.
//
// The `true` set is exactly the exceptions the x86 architecture enters with an error code on the
// stack: 8, 10-14 and 17, plus 21 (#CP), 29 (#VC) and 30 (#SX), which need CET / SEV-ES / SVM and
// cannot fire in this kernel today. The CPU leaves the upper 16 bits of the pushed value undefined;
// we store the raw push.

/// Expands to the list of vectors tagged `true` in a `define_exception_stubs!` table.
macro_rules! error_code_vectors {
    (@acc [$($acc:tt)*]) => { [$($acc)*] };
    (@acc [$($acc:tt)*] $vector:literal => true , $($rest:tt)*) => {
        error_code_vectors!(@acc [$($acc)* $vector,] $($rest)*)
    };
    (@acc [$($acc:tt)*] $vector:literal => false , $($rest:tt)*) => {
        error_code_vectors!(@acc [$($acc)*] $($rest)*)
    };
    ($($entries:tt)*) => { error_code_vectors!(@acc [] $($entries)*) };
}

/// One stub invocation line per vector: EXC_STUB_ERR when the CPU pushes the error code,
/// EXC_STUB_NOERR otherwise, labelled with the stub's Rust name. Only invoked from inside the
/// x86-only `global_asm!` expansion, hence the allow.
#[allow(unused_macros)]
macro_rules! stub_line {
    (true, $stub:ident, $vector:literal) => {
        concat!(
            "EXC_STUB_ERR ",
            stringify!($stub),
            ", ",
            stringify!($vector)
        )
    };
    (false, $stub:ident, $vector:literal) => {
        concat!(
            "EXC_STUB_NOERR ",
            stringify!($stub),
            ", ",
            stringify!($vector)
        )
    };
}

/// Emits the 32 exception stubs in assembly (with the common tail), their declarations and the
/// table of them by vector (`EXCEPTION_STUBS`, which the IDT's build reads), and the matching
/// ERROR_CODE_VECTORS list, all from one vector table. Each stub's label is its Rust name.
macro_rules! define_exception_stubs {
    ($($stub:ident = $vector:literal => $err:tt),* $(,)?) => {
        #[cfg(target_arch = "x86")]
        core::arch::global_asm!(
            ".section .text.exception_stubs, \"ax\"",
            // Stubs for exceptions the CPU does NOT hand an error code: push a zero placeholder
            // first so every frame has the same layout.
            ".macro EXC_STUB_NOERR name, n",
            ".globl \\name",
            "\\name:",
            "    push 0",
            "    push \\n",
            "    jmp exception_common",
            ".endm",
            // Stubs for exceptions the CPU hands an error code.
            ".macro EXC_STUB_ERR name, n",
            ".globl \\name",
            "\\name:",
            "    push \\n",
            "    jmp exception_common",
            ".endm",
            "",
            $(stub_line!($err, $stub, $vector),)*
            "",
            // Common tail: save registers, clear DF (interrupt gates do not, and Rust code requires
            // it), call the handler; when it returns, restore and resume.
            "exception_common:",
            "    pushad",
            "    cld",
            // The faulting context's data segments, below the frame (`SavedSegments`, read back
            // by the dump); the handler runs on the kernel's.
            "    mov eax, ds",
            "    push eax",
            "    mov eax, es",
            "    push eax",
            "    mov eax, fs",
            "    push eax",
            "    mov eax, gs",
            "    push eax",
            "    mov ax, {kernel_data}",
            "    mov ds, ax",
            "    mov es, ax",
            "    lea eax, [esp + 16]", // frame pointer: exception_handler(frame)
            "    push eax",
            "    call {handler}",
            // The handler returns only when it resolved the exception (a copy redirected to its
            // fixup): resume the interrupted context, as the hardware tail does.
            "    add esp, 4", // drop the frame pointer
            "    pop eax",
            "    mov gs, ax",
            "    pop eax",
            "    mov fs, ax",
            "    pop eax",
            "    mov es, ax",
            "    pop eax",
            "    mov ds, ax",
            "    popad",
            "    add esp, 8", // drop vector + error code
            "    iretd",
            kernel_data = const crate::cpu::gdt::KERNEL_DATA_SELECTOR,
            handler = sym exception_handler,
        );

        #[cfg(target_arch = "x86")]
        unsafe extern "C" {
            $(fn $stub();)*
        }

        /// The exception stubs, by vector: the IDT's first 32 gates.
        #[cfg(target_arch = "x86")]
        const EXCEPTION_STUBS: [unsafe extern "C" fn(); EXCEPTION_VECTORS] = [$($stub),*];

        // The table lists the vectors in order, so a stub's place in it is its vector.
        const _: () = {
            let vectors = [$($vector),*];
            assert!(vectors.len() == EXCEPTION_VECTORS);
            let mut index = 0;
            while index < vectors.len() {
                assert!(vectors[index] == index);
                index += 1;
            }
        };

        /// Vectors whose stubs rely on the CPU-pushed error code; every other stub pushes a zero
        /// placeholder so all frames share one layout. Generated from the same table as the stubs.
        #[allow(dead_code)]
        const ERROR_CODE_VECTORS: &[u8] = &error_code_vectors!($($vector => $err,)*);
    }
}

define_exception_stubs!(
    exception_stub_0 = 0 => false,
    exception_stub_1 = 1 => false,
    exception_stub_2 = 2 => false,
    exception_stub_3 = 3 => false,
    exception_stub_4 = 4 => false,
    exception_stub_5 = 5 => false,
    exception_stub_6 = 6 => false,
    exception_stub_7 = 7 => false,
    exception_stub_8 = 8 => true,
    exception_stub_9 = 9 => false,
    exception_stub_10 = 10 => true,
    exception_stub_11 = 11 => true,
    exception_stub_12 = 12 => true,
    exception_stub_13 = 13 => true,
    exception_stub_14 = 14 => true,
    exception_stub_15 = 15 => false,
    exception_stub_16 = 16 => false,
    exception_stub_17 = 17 => true,
    exception_stub_18 = 18 => false,
    exception_stub_19 = 19 => false,
    exception_stub_20 = 20 => false,
    exception_stub_21 = 21 => true,
    exception_stub_22 = 22 => false,
    exception_stub_23 = 23 => false,
    exception_stub_24 = 24 => false,
    exception_stub_25 = 25 => false,
    exception_stub_26 = 26 => false,
    exception_stub_27 = 27 => false,
    exception_stub_28 = 28 => false,
    exception_stub_29 = 29 => true,
    exception_stub_30 = 30 => true,
    exception_stub_31 = 31 => false,
);

// --- Hardware interrupt stubs ---------------------------------------------
//
// One stub per vector in the remapped band (0x30-0x3F): complete the frame in the shape shared with
// the exception stubs (error pad plus vector around `pushad`), then the common tail calls the
// interrupt core's dispatch with the frame and `iretd`s back to whoever was interrupted — ring 0 or
// ring 3, the tail is the same.
/// Emits the band's stubs in assembly (with the common tail), their declarations and the table of
/// them by vector (`IRQ_STUBS`, which the IDT's build reads), all from one vector table. Each
/// stub's label is its Rust name.
macro_rules! define_irq_stubs {
    ($($stub:ident = $vector:literal),* $(,)?) => {
        #[cfg(target_arch = "x86")]
        core::arch::global_asm!(
            ".section .text.irq_stubs, \"ax\"",
            ".macro IRQ_STUB name, n",
            ".globl \\name",
            "\\name:",
            "    push 0",
            "    push \\n",
            "    jmp irq_common",
            ".endm",
            $(concat!("IRQ_STUB ", stringify!($stub), ", ", stringify!($vector)),)*
            "irq_common:",
            "    pushad",
            "    cld", // Rust code requires a forward direction flag
            // The interrupted data segments, below the frame (see `SavedSegments`); the handler
            // runs on the kernel's.
            "    mov eax, ds",
            "    push eax",
            "    mov eax, es",
            "    push eax",
            "    mov eax, fs",
            "    push eax",
            "    mov eax, gs",
            "    push eax",
            "    mov ax, {kernel_data}",
            "    mov ds, ax",
            "    mov es, ax",
            "    lea eax, [esp + 16]", // frame pointer (interrupt/mod.rs dispatch): the pushad block
            "    push eax",
            "    call {dispatch}",
            "    add esp, 4", // drop the frame pointer
            // Restoring FS reloads the TEB descriptor's base: a thread resumed here by a switch
            // inside the dispatch sees its own TEB.
            "    pop eax",
            "    mov gs, ax",
            "    pop eax",
            "    mov fs, ax",
            "    pop eax",
            "    mov es, ax",
            "    pop eax",
            "    mov ds, ax",
            "    popad",
            "    add esp, 8", // drop vector + error pad
            "    iretd", // pops EIP, CS, EFLAGS (plus user ESP/SS from ring 3)
            kernel_data = const crate::cpu::gdt::KERNEL_DATA_SELECTOR,
            dispatch = sym crate::interrupt::dispatch,
        );

        #[cfg(target_arch = "x86")]
        unsafe extern "C" {
            $(fn $stub();)*
        }

        /// The hardware-vector stubs, by vector from the band's first.
        #[cfg(target_arch = "x86")]
        const IRQ_STUBS: [unsafe extern "C" fn(); crate::interrupt::VECTOR_COUNT] = [$($stub),*];

        // The table lists the band's vectors in order, so a stub's place in it is its vector's
        // offset from the band's first.
        const _: () = {
            let vectors: [u8; crate::interrupt::VECTOR_COUNT] = [$($vector),*];
            let mut index = 0;
            while index < vectors.len() {
                assert!(vectors[index] as usize == crate::interrupt::FIRST_VECTOR as usize + index);
                index += 1;
            }
        };
    }
}

define_irq_stubs!(
    irq_stub_0x30 = 0x30,
    irq_stub_0x31 = 0x31,
    irq_stub_0x32 = 0x32,
    irq_stub_0x33 = 0x33,
    irq_stub_0x34 = 0x34,
    irq_stub_0x35 = 0x35,
    irq_stub_0x36 = 0x36,
    irq_stub_0x37 = 0x37,
    irq_stub_0x38 = 0x38,
    irq_stub_0x39 = 0x39,
    irq_stub_0x3A = 0x3A,
    irq_stub_0x3B = 0x3B,
    irq_stub_0x3C = 0x3C,
    irq_stub_0x3D = 0x3D,
    irq_stub_0x3E = 0x3E,
    irq_stub_0x3F = 0x3F,
);

#[cfg(test)]
mod tests {
    use core::mem::size_of;
    use core::ptr::addr_of;

    use super::*;

    fn zero_frame() -> ExceptionFrame {
        ExceptionFrame {
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
        }
    }

    /// Every name is non-empty and distinct, and the vectors x86 leaves architecturally reserved
    /// are visibly labeled. We use SDM mnemonics for the exceptions modern hardware defines (18-21,
    /// 29, 30).
    #[test]
    fn reserved_vectors_are_labeled_reserved() {
        for (i, name) in NAMES.iter().enumerate() {
            assert!(!name.is_empty(), "vector {i} has no name");
        }
        for i in 0..NAMES.len() {
            for j in i + 1..NAMES.len() {
                assert_ne!(NAMES[i], NAMES[j], "vectors {i} and {j} share a name");
            }
        }
        for v in [15usize, 22, 23, 24, 25, 26, 27, 28, 31] {
            assert!(NAMES[v].contains("Reserved"), "vector {v}");
        }
    }

    /// The 8-byte x86 gate descriptor as `lidt` consumes it: offset low@0, selector@2, reserved@4,
    /// type/attr@5, offset high@6.
    #[test]
    fn gate_layout_matches_x86_gate_descriptor() {
        assert_eq!(size_of::<Gate>(), 8);
        assert_eq!(size_of::<[Gate; IDT_VECTORS]>(), 0x800);

        let gate = Gate::new(0x001E_BEEF);
        // Gate is packed: copy fields to locals instead of taking references.
        let offset_low = gate.offset_low;
        let selector = gate.selector;
        let reserved = gate.reserved;
        let type_attr = gate.type_attr;
        let offset_high = gate.offset_high;
        assert_eq!(offset_low, 0xBEEF);
        assert_eq!(offset_high, 0x001E);
        assert_eq!(reserved, 0);
        assert_eq!(selector, KERNEL_CODE_SELECTOR);
        assert_eq!(type_attr, Gate::INTERRUPT_ATTR);

        let base = addr_of!(gate) as usize;
        assert_eq!(addr_of!(gate.offset_low) as usize - base, 0);
        assert_eq!(addr_of!(gate.selector) as usize - base, 2);
        assert_eq!(addr_of!(gate.reserved) as usize - base, 4);
        assert_eq!(addr_of!(gate.type_attr) as usize - base, 5);
        assert_eq!(addr_of!(gate.offset_high) as usize - base, 6);
    }

    /// A user gate differs from a kernel gate in exactly the DPL bits of the type/attr byte (0x8E
    /// -> 0xEE).
    #[test]
    fn user_gate_differs_only_in_dpl() {
        let kernel_gate = Gate::new(0x0010_0000);
        let user_gate = Gate::new_user(0x0010_0000);
        // Gates are packed: copy fields to locals instead of taking references.
        let (k_low, k_high, k_sel, k_res) = (
            kernel_gate.offset_low,
            kernel_gate.offset_high,
            kernel_gate.selector,
            kernel_gate.reserved,
        );
        let (u_low, u_high, u_sel, u_res) = (
            user_gate.offset_low,
            user_gate.offset_high,
            user_gate.selector,
            user_gate.reserved,
        );
        assert_eq!(user_gate.type_attr, 0xEE);
        assert_eq!(user_gate.type_attr ^ kernel_gate.type_attr, 0x60);
        // Everything else (offsets, selector, reserved) is identical.
        assert_eq!(u_low, k_low);
        assert_eq!(u_high, k_high);
        assert_eq!(u_sel, k_sel);
        assert_eq!(u_res, k_res);
    }

    /// Gate::new splits the handler address into the two halves the descriptor stores: low word at
    /// byte 0, high word at byte 6.
    #[test]
    fn gate_offset_round_trips() {
        for handler in [0usize, 1, 0xFFFF, 0x1_0000, 0x0010_0000, 0xDEAD_BEEF] {
            let gate = Gate::new(handler);
            let low = gate.offset_low;
            let high = gate.offset_high;
            assert_eq!((high as usize) << 16 | low as usize, handler);
        }
    }

    /// Exactly the CPU exception vectors that push an error code; every other stub must push the
    /// zero placeholder instead. The constant is generated from the same table as the stubs, so
    /// this pins that table against the x86 error-code set.
    #[test]
    fn error_code_vectors_match_cpu_pushed_set() {
        assert_eq!(
            ERROR_CODE_VECTORS,
            &[8u8, 10, 11, 12, 13, 14, 17, 21, 29, 30][..]
        );
    }

    /// The exception frame is 13 u32s; the ring-3 tail adds the interrupted ESP/SS pair the CPU
    /// pushes, following the same order the iret frame uses.
    #[test]
    fn frame_layout_size_and_tail_offsets() {
        assert_eq!(size_of::<ExceptionFrame>(), 13 * 4);
        assert_eq!(size_of::<Ring3ExceptionFrame>(), 15 * 4);
        let frame = zero_frame();
        let base = addr_of!(frame) as usize;
        assert_eq!(addr_of!(frame.error_code) as usize - base, 9 * 4);
        assert_eq!(addr_of!(frame.eip) as usize - base, 10 * 4);
        assert_eq!(addr_of!(frame.cs) as usize - base, 11 * 4);
        assert_eq!(addr_of!(frame.eflags) as usize - base, 12 * 4);
        let ring3 = Ring3ExceptionFrame {
            frame,
            user_esp: 0,
            user_ss: 0,
        };
        let rbase = addr_of!(ring3) as usize;
        assert_eq!(addr_of!(ring3.frame) as usize - rbase, 0);
        assert_eq!(addr_of!(ring3.user_esp) as usize - rbase, 13 * 4);
        assert_eq!(addr_of!(ring3.user_ss) as usize - rbase, 14 * 4);
    }

    /// The interrupted-ESP reconstruction: ring 0 counts five frame words; ring 3 must report the
    /// user ESP from the tail, not the TSS stack.
    #[test]
    fn interrupted_esp_is_user_esp_for_ring3() {
        let mut frame = zero_frame();
        frame.esp = 0x8013_A000; // the TSS esp0, where the stub runs
        frame.cs = 0x08; // ring 0: reconstructed from the stub's stack
        assert_eq!(interrupted_esp(&frame, 0), 0x8013_A000 + 5 * 4);
        frame.cs = 0x1B; // ring 3: the pushed user ESP wins
        assert_eq!(interrupted_esp(&frame, 0x0013_0000), 0x0013_0000);
        assert_ne!(interrupted_esp(&frame, 0x0013_0000), 0x8013_A000 + 5 * 4);
        frame.cs = 0x07; // only the low two bits decide
        assert_eq!(interrupted_esp(&frame, 0x0013_0000), 0x0013_0000);
    }

    /// The IDTR limit is the offset of the last valid byte: table size minus one. This checks the
    /// pointer `init` feeds to `lidt`.
    #[test]
    fn idt_limit_is_last_valid_byte_offset() {
        let idt = [Gate::ABSENT; IDT_VECTORS];
        let limit = crate::cpu::DescriptorTablePointer::of(&idt).limit();
        assert_eq!(limit, 0x7FF);
    }
}
