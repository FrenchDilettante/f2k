//! Interrupt Descriptor Table and CPU exception handling.
//!
//! Every CPU exception lands in one of 32 generated stubs, which save
//! the register state and hand it to a Rust handler that prints a
//! diagnostic dump to COM1 before halting (silent triple-fault resets
//! become actionable output). Exceptions fire regardless of IF, so
//! nothing here needs the PIC or `sti`; hardware IRQs come later.

use crate::gdt::KERNEL_CODE_SELECTOR;

/// Number of CPU exception vectors (0-31).
const EXCEPTION_VECTORS: usize = 32;

/// IDT size: the 32 exception vectors plus the syscall gate at vector
/// 0x2E (see `syscall.rs`), registered at DPL 3. A vector left absent
/// is a not-present gate: raising it faults with the vector-derived
/// error code — #NP from ring 0, and #GP from ring 3 (the zeroed
/// descriptor's DPL 0 fails the privilege check first).
const IDT_VECTORS: usize = 256;

/// Registers saved by the common exception stub, in stack order.
/// Constructed by assembly, never by Rust code. The segment registers are
/// not part of the frame: LLVM assembles `push <segreg>` as a 16-bit push,
/// so the handler reads them with `mov` instead.
#[allow(dead_code)]
#[repr(C)]
struct ExceptionFrame {
    edi: u32,
    esi: u32,
    ebp: u32,
    esp: u32,
    ebx: u32,
    edx: u32,
    ecx: u32,
    eax: u32,
    vector: u32,
    error_code: u32,
    eip: u32,
    cs: u32,
    eflags: u32,
}

/// The ring-3 tail the CPU pushes on the TSS stack when the exception
/// was raised in ring 3: the interrupted ESP/SS pair, above the
/// common frame. Only valid when the interrupted CS carries RPL 3;
/// a ring-0 exception pushes nothing there.
#[allow(dead_code)]
#[repr(C)]
struct Ring3ExceptionFrame {
    frame: ExceptionFrame,
    user_esp: u32,
    user_ss: u32,
}

/// One 32-bit IDT gate descriptor: interrupt gate, present, ring 0.
#[derive(Clone, Copy)]
#[repr(C, packed)]
struct Gate {
    offset_low: u16,
    selector: u16,
    reserved: u8,
    type_attr: u8,
    offset_high: u16,
}

impl Gate {
    /// 0x8E = present, ring 0, 32-bit interrupt gate (clears IF on entry).
    ///
    /// Gates that user code must be able to raise use DPL 3 instead
    /// ([`Gate::new_user`]); software exceptions (int3/into) will be
    /// DPL-3 gates in their own vectors later.
    const INTERRUPT_ATTR: u8 = 0x8E;

    /// 0xEE = present, ring 3, 32-bit interrupt gate: ring-3 code may
    /// raise the vector with `int`; entry clears IF as usual.
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

// Pin the attribute bytes at the definition: present, 32-bit interrupt
// gates (clears IF on entry), ring 0 or ring 3.
const _: () = assert!(Gate::INTERRUPT_ATTR == 0x8E && Gate::USER_INTERRUPT_ATTR == 0xEE);

/// The IDT is built at runtime (stub addresses are link-time constants but
/// their casts are not const-evaluable), then loaded with `lidt`.
///
/// Writes go through raw pointers: taking `&static mut` references is UB
/// territory, and this runs once on the boot CPU before `sti`.
static mut IDT: [Gate; IDT_VECTORS] = [Gate {
    offset_low: 0,
    selector: 0,
    reserved: 0,
    type_attr: 0,
    offset_high: 0,
}; IDT_VECTORS];

/// Address of a generated stub. Casts through a pointer: clippy flags a
/// direct function-item-to-integer cast as provenance-lossy.
fn stub_addr(stub: unsafe extern "C" fn()) -> usize {
    stub as *const () as usize
}

/// IDTR limit for the exception table: the offset of the last valid byte
/// (table size minus one), which is what `lidt` expects.
const fn idt_limit() -> u16 {
    (core::mem::size_of::<[Gate; IDT_VECTORS]>() - 1) as u16
}

/// Build the IDT and load it.
///
/// # Safety
///
/// Must run on the boot CPU in ring 0 with interrupts disabled, before any
/// code that might raise a CPU exception.
#[cfg(target_arch = "x86")]
pub unsafe fn init() {
    let stubs: [usize; EXCEPTION_VECTORS] = [
        stub_addr(exception_stub_0),
        stub_addr(exception_stub_1),
        stub_addr(exception_stub_2),
        stub_addr(exception_stub_3),
        stub_addr(exception_stub_4),
        stub_addr(exception_stub_5),
        stub_addr(exception_stub_6),
        stub_addr(exception_stub_7),
        stub_addr(exception_stub_8),
        stub_addr(exception_stub_9),
        stub_addr(exception_stub_10),
        stub_addr(exception_stub_11),
        stub_addr(exception_stub_12),
        stub_addr(exception_stub_13),
        stub_addr(exception_stub_14),
        stub_addr(exception_stub_15),
        stub_addr(exception_stub_16),
        stub_addr(exception_stub_17),
        stub_addr(exception_stub_18),
        stub_addr(exception_stub_19),
        stub_addr(exception_stub_20),
        stub_addr(exception_stub_21),
        stub_addr(exception_stub_22),
        stub_addr(exception_stub_23),
        stub_addr(exception_stub_24),
        stub_addr(exception_stub_25),
        stub_addr(exception_stub_26),
        stub_addr(exception_stub_27),
        stub_addr(exception_stub_28),
        stub_addr(exception_stub_29),
        stub_addr(exception_stub_30),
        stub_addr(exception_stub_31),
    ];

    // SAFETY: single boot CPU, interrupts disabled; the only access to IDT.
    unsafe {
        let base = core::ptr::addr_of_mut!(IDT) as *mut Gate;
        for (i, stub) in stubs.iter().enumerate() {
            core::ptr::write_volatile(base.add(i), Gate::new(*stub));
        }

        // The syscall gate (see `syscall.rs`): ring-3 reachable, entered
        // on the TSS ring-0 stack, the return path for user code.
        core::ptr::write_volatile(
            base.add(crate::syscall::SYSCALL_VECTOR),
            Gate::new_user(stub_addr(crate::syscall::syscall_gate_stub)),
        );

        // Build the IDTR on the stack: 6 bytes of limit + base, then lidt.
        let mut idtr = [0u8; 6];
        idtr[0..2].copy_from_slice(&idt_limit().to_le_bytes());
        idtr[2..6].copy_from_slice(&(base as u32).to_le_bytes());
        global_asm_lidt(&idtr as *const u8);
    }
}

/// Wrapper so the inline `lidt` keeps its side effects and memory operand
/// from being optimized away.
#[cfg(target_arch = "x86")]
#[inline(never)]
unsafe fn global_asm_lidt(idtr: *const u8) {
    core::arch::asm!("lidt [eax]", in("eax") idtr, options(nostack));
}

#[cfg(target_arch = "x86")]
unsafe extern "C" {
    /// Exception stubs generated from the vector table at the bottom of
    /// this file: vectors tagged `true` there receive a CPU-pushed error
    /// code, the rest push a zero placeholder.
    fn exception_stub_0();
    fn exception_stub_1();
    fn exception_stub_2();
    fn exception_stub_3();
    fn exception_stub_4();
    fn exception_stub_5();
    fn exception_stub_6();
    fn exception_stub_7();
    fn exception_stub_8();
    fn exception_stub_9();
    fn exception_stub_10();
    fn exception_stub_11();
    fn exception_stub_12();
    fn exception_stub_13();
    fn exception_stub_14();
    fn exception_stub_15();
    fn exception_stub_16();
    fn exception_stub_17();
    fn exception_stub_18();
    fn exception_stub_19();
    fn exception_stub_20();
    fn exception_stub_21();
    fn exception_stub_22();
    fn exception_stub_23();
    fn exception_stub_24();
    fn exception_stub_25();
    fn exception_stub_26();
    fn exception_stub_27();
    fn exception_stub_28();
    fn exception_stub_29();
    fn exception_stub_30();
    fn exception_stub_31();
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

/// Prints a diagnostic dump on COM1 and halts. Origin decides the
/// final line: user-raised faults (including bad user pointers in
/// syscall copies) end the user process; the rest are kernel faults.
#[allow(dead_code)] // referenced only from the generated stubs (sym operand)
#[cfg(target_arch = "x86")]
extern "C" fn exception_handler(frame: &ExceptionFrame) -> ! {
    let name = NAMES
        .get(frame.vector as usize)
        .copied()
        .unwrap_or("Unknown");

    // The ring-3 tail exists only for ring-3 exceptions; read it once,
    // guarded, through the extended frame.
    let from_user = frame.cs & 3 != 0;
    let (user_esp, user_ss) = if from_user {
        (ring3_tail(frame), ring3_user_ss(frame))
    } else {
        (0, 0)
    };

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
    // Segment registers are read at dump time: pushing them in the stub
    // would only store 16 bits per register (see comment on ExceptionFrame).
    let (ds, es, fs, gs): (u32, u32, u32, u32);
    unsafe {
        core::arch::asm!(
            "mov {}, ds",
            "mov {}, es",
            "mov {}, fs",
            "mov {}, gs",
            lateout(reg) ds,
            lateout(reg) es,
            lateout(reg) fs,
            lateout(reg) gs,
            options(nostack)
        );
    }
    crate::serial_println!(
        "  DS {:#04x}  ES {:#04x}  FS {:#04x}  GS {:#04x}",
        ds,
        es,
        fs,
        gs
    );
    if from_user {
        crate::serial_println!(
            "  raised from ring 3: user ESP {:#010x}  user SS {:#04x}",
            user_esp,
            user_ss
        );
    }
    if frame.vector == 14 {
        let cr2: u32;
        unsafe {
            core::arch::asm!("mov {}, cr2", out(reg) cr2, options(nomem, nostack));
        }
        crate::serial_println!("  CR2 (faulting address) {:#010x}", cr2);
    }
    // Classify the fault by origin. A fault raised by user code (or,
    // while the kernel copies syscall arguments, by a bad user
    // pointer on the kernel's behalf) ends the user process: single
    // tasking means the kernel then has nothing left to run, so it
    // halts — but as the intended end of the process, reported as
    // such, not as a kernel panic. A kernel fault from any other
    // origin stays the raw diagnostic halt.
    if from_user {
        crate::serial_println!(
            "F2K: user process ended by fault (vector {}); halting",
            frame.vector
        );
    } else if crate::syscall::copying_user_args() {
        crate::serial_println!(
            "F2K: user process ended by fault (bad user argument pointer); halting"
        );
    }
    crate::halt();
}

/// The interrupted user ESP of a ring-3 exception: the CPU pushed it
/// as part of the ring-3 tail. Zero for ring-0 frames (no tail).
///
/// # Safety contract
///
/// Call only when `frame.cs` carries RPL 3; the tail does not exist for
/// ring-0 exceptions.
fn ring3_tail(frame: &ExceptionFrame) -> u32 {
    // SAFETY: guaranteed by the caller's RPL check; the CPU pushed the
    // tail above the common frame on the TSS stack.
    unsafe { &*(core::ptr::addr_of!(*frame) as *const Ring3ExceptionFrame) }.user_esp
}

/// The interrupted user SS of a ring-3 exception; see [`ring3_tail`].
fn ring3_user_ss(frame: &ExceptionFrame) -> u32 {
    // SAFETY: same contract as ring3_tail.
    unsafe { &*(core::ptr::addr_of!(*frame) as *const Ring3ExceptionFrame) }.user_ss
}

/// ESP of the interrupted context. Ring 0: five frame words (vector,
/// error code, EIP, CS, EFLAGS) sit between the stub-saved ESP and the
/// interrupted stack. Ring 3: the interrupted stack is the user stack
/// — report the ESP the CPU pushed in the ring-3 tail, not arithmetic
/// on the TSS stack.
fn interrupted_esp(frame: &ExceptionFrame, user_esp: u32) -> u32 {
    if frame.cs & 3 != 0 {
        user_esp
    } else {
        frame.esp + 5 * 4
    }
}

// --- Exception stubs ------------------------------------------------------
//
// Single source of truth: the vector table below drives both the generated
// assembly and the Rust-side ERROR_CODE_VECTORS, so the two cannot drift
// apart. `true` = the CPU pushes an error code for this vector (the stub
// must not add one); `false` = the stub pushes a zero placeholder so every
// frame shares one layout.
//
// The `true` set is exactly the exceptions the x86 architecture enters
// with an error code on the stack: 8, 10-14 and 17, plus 21 (#CP), 29
// (#VC) and 30 (#SX), which need CET / SEV-ES / SVM and cannot fire in
// this kernel today. The CPU leaves the upper 16 bits of the pushed
// value undefined; we store the raw push.

/// Expands to the list of vectors tagged `true` in a
/// `define_exception_stubs!` table.
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

/// One stub invocation line per vector: EXC_STUB_ERR when the CPU pushes
/// the error code, EXC_STUB_NOERR otherwise. Only invoked from inside the
/// x86-only `global_asm!` expansion, hence the allow.
#[allow(unused_macros)]
macro_rules! stub_line {
    (true, $vector:literal) => { concat!("EXC_STUB_ERR ", stringify!($vector)) };
    (false, $vector:literal) => { concat!("EXC_STUB_NOERR ", stringify!($vector)) };
}

/// Emits the 32 exception stubs in assembly (with the common tail) and the
/// matching ERROR_CODE_VECTORS list, all from one vector table.
macro_rules! define_exception_stubs {
    ($($vector:literal => $err:tt),* $(,)?) => {
        #[cfg(target_arch = "x86")]
        core::arch::global_asm!(
            ".section .text.exception_stubs, \"ax\"",
            // Stubs for exceptions the CPU does NOT hand an error code:
            // push a zero placeholder first so every frame has the same layout.
            ".macro EXC_STUB_NOERR n",
            ".globl exception_stub_\\n",
            "exception_stub_\\n:",
            "    push 0",
            "    push \\n",
            "    jmp exception_common",
            ".endm",
            // Stubs for exceptions the CPU hands an error code.
            ".macro EXC_STUB_ERR n",
            ".globl exception_stub_\\n",
            "exception_stub_\\n:",
            "    push \\n",
            "    jmp exception_common",
            ".endm",
            "",
            $(stub_line!($err, $vector),)*
            "",
            // Common tail: save registers, clear DF (interrupt gates do
            // not, and Rust code requires it), call the handler, halt forever.
            "exception_common:",
            "    pushad",
            "    cld",
            "    push esp",           // frame pointer: exception_handler(frame)
            "    call {handler}",
            "1:  cli",
            "    hlt",
            "    jmp 1b",
            handler = sym exception_handler,
        );

        /// Vectors whose stubs rely on the CPU-pushed error code; every
        /// other stub pushes a zero placeholder so all frames share one
        /// layout. Generated from the same table as the stubs.
        #[allow(dead_code)]
        const ERROR_CODE_VECTORS: &[u8] = &error_code_vectors!($($vector => $err,)*);
    }
}

define_exception_stubs!(
    0 => false,
    1 => false,
    2 => false,
    3 => false,
    4 => false,
    5 => false,
    6 => false,
    7 => false,
    8 => true,
    9 => false,
    10 => true,
    11 => true,
    12 => true,
    13 => true,
    14 => true,
    15 => false,
    16 => false,
    17 => true,
    18 => false,
    19 => false,
    20 => false,
    21 => true,
    22 => false,
    23 => false,
    24 => false,
    25 => false,
    26 => false,
    27 => false,
    28 => false,
    29 => true,
    30 => true,
    31 => false,
);

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;
    use core::ptr::addr_of;

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

    /// Every name is non-empty and distinct, and the vectors x86 leaves
    /// architecturally reserved are visibly labeled. We use SDM mnemonics
    /// for the exceptions modern hardware defines (18-21, 29, 30).
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

    /// The 8-byte x86 gate descriptor as `lidt` consumes it: offset low@0,
    /// selector@2, reserved@4, type/attr@5, offset high@6.
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

    /// A user gate differs from a kernel gate in exactly the DPL bits of
    /// the type/attr byte (0x8E -> 0xEE).
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

    /// Gate::new splits the handler address into the two halves the
    /// descriptor stores: low word at byte 0, high word at byte 6.
    #[test]
    fn gate_offset_round_trips() {
        for handler in [0usize, 1, 0xFFFF, 0x1_0000, 0x0010_0000, 0xDEAD_BEEF] {
            let gate = Gate::new(handler);
            let low = gate.offset_low;
            let high = gate.offset_high;
            assert_eq!((high as usize) << 16 | low as usize, handler);
        }
    }

    /// Exactly the CPU exception vectors that push an error code; every
    /// other stub must push the zero placeholder instead. The constant is
    /// generated from the same table as the stubs, so this pins that table
    /// against the x86 error-code set.
    #[test]
    fn error_code_vectors_match_cpu_pushed_set() {
        assert_eq!(
            ERROR_CODE_VECTORS,
            &[8u8, 10, 11, 12, 13, 14, 17, 21, 29, 30][..]
        );
    }

    /// The exception frame is 13 u32s; the ring-3 tail adds the
    /// interrupted ESP/SS pair the CPU pushes, following the same order
    /// the iret frame uses.
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
        let ring3 = Ring3ExceptionFrame { frame, user_esp: 0, user_ss: 0 };
        let rbase = addr_of!(ring3) as usize;
        assert_eq!(addr_of!(ring3.frame) as usize - rbase, 0);
        assert_eq!(addr_of!(ring3.user_esp) as usize - rbase, 13 * 4);
        assert_eq!(addr_of!(ring3.user_ss) as usize - rbase, 14 * 4);
    }

    /// The interrupted-ESP reconstruction: ring 0 counts five frame
    /// words; ring 3 must report the user ESP from the tail, not the
    /// TSS stack.
    #[test]
    fn interrupted_esp_is_user_esp_for_ring3() {
        let mut frame = zero_frame();
        frame.esp = 0x8013_A000; // the TSS esp0, where the stub runs
        frame.cs = 0x08; // ring 0: reconstructed from the stub's stack
        assert_eq!(interrupted_esp(&frame, 0), 0x8013_A000 + 5 * 4);
        frame.cs = 0x1B; // ring 3: the pushed user ESP wins
        assert_eq!(interrupted_esp(&frame, 0x0030_1000), 0x0030_1000);
        assert_ne!(interrupted_esp(&frame, 0x0030_1000), 0x8013_A000 + 5 * 4);
        frame.cs = 0x07; // only the low two bits decide
        assert_eq!(interrupted_esp(&frame, 0x0030_1000), 0x0030_1000);
    }

    /// The IDTR limit is the offset of the last valid byte: table size
    /// minus one. This checks the actual function `init` feeds to `lidt`.
    #[test]
    fn idt_limit_is_last_valid_byte_offset() {
        assert_eq!(idt_limit(), 0x7FF);
    }
}
