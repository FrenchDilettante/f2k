//! The context switch: the swap assembly and a new thread's first
//! instructions.
//!
//! [`swap_context`] moves the processor from one thread to another:
//! it saves the caller's nonvolatile registers and `esp` into a
//! switch frame on the old thread's kernel stack, installs the new
//! thread's stack top as the TSS `esp0`, rewrites the TEB
//! descriptor's base, loads CR3 when the process changes, and
//! resumes the new thread. [`THREAD_STARTUP`] is a fresh thread's
//! first instructions, reached as the planted return address of the
//! initial switch: it zeroes the registers, lowers the level, calls
//! the system routine, and a user thread then enters ring 3 from
//! its planted trap frame.
//!
//! Load-bearing discipline: `cli` spans the CR3 load and the `esp`
//! switch — kernel stacks live in a per-process window, so the old
//! stack dies at the CR3 load and the new one is not mapped until it
//! happens. One resume tail (`popfd`; `ret`) serves both frame
//! shapes: a saved frame returns into the resume label, a fresh
//! frame's planted return address is the startup stub.

// --- Pinned machine-state offsets -----------------------------------------
//
// The assembly addresses a thread's machine state and its process's
// scheduling record through these byte offsets; the thread record's
// layout tests pin them to the real `#[repr(C)]` layouts.

/// The `state` byte's offset in the thread record: the swap writes
/// Running here before anything else observes the new thread. Host
/// tests pin this to the thread record's `#[repr(C)]` layout.
pub const THREAD_STATE_OFF: u32 = 0;

/// The owner-pointer field's offset in the thread record: pointer
/// identity between the two threads' owners decides the CR3 load.
/// Host tests pin this to the thread record's `#[repr(C)]` layout.
pub const THREAD_PROCESS_OFF: u32 = 4;

/// The saved-esp field's offset in the thread record: what a switch
/// stores the old thread's switch frame at and loads the new
/// thread's stack from. Host tests pin this to the thread record's
/// `#[repr(C)]` layout.
pub const THREAD_KERNEL_STACK_OFF: u32 = 8;

/// The stack-top field's offset in the thread record: the gate-slot
/// top that becomes the TSS ring-0 stack pointer at every switch.
/// Host tests pin this to the thread record's `#[repr(C)]` layout.
pub const THREAD_INITIAL_STACK_OFF: u32 = 12;

/// The TEB-page field's offset in the thread record: the base the
/// switch writes into the TEB descriptor (0 for kernel and idle
/// threads). Host tests pin this to the thread record's
/// `#[repr(C)]` layout.
pub const THREAD_TEB_VA_OFF: u32 = 16;

/// The directory-base offset inside the scheduling record, read
/// only when the process changes.
pub const PROCESS_DIR_PHYS_OFF: u32 = 0;

/// The TEB descriptor's base-byte offsets inside the GDT, derived
/// from the selector: 15:0 at +2, 23:16 at +4, 31:24 at +7.
const TEB_BASE_LO_OFF: u32 = crate::cpu::gdt::TEB_SELECTOR as u32 + 2;
const TEB_BASE_MID_OFF: u32 = crate::cpu::gdt::TEB_SELECTOR as u32 + 4;
const TEB_BASE_HI_OFF: u32 = crate::cpu::gdt::TEB_SELECTOR as u32 + 7;

// Only the pointers themselves cross the boundary (the asm consumes
// them through the pinned offsets above), and the thread record is
// `#[repr(C)]`, so the pointer ABI is sound.
#[cfg(target_arch = "x86")]
unsafe extern "C" {
/// Switch the processor from `old` to `new`, entered at the
/// dispatch level with interrupts enabled. Never "returns" in the
/// calling thread's present: the return path executes in whichever
/// thread a later switch resumes here.
    pub fn swap_context(old: *mut super::thread::Thread, new: *mut super::thread::Thread);

    /// The startup stub's address, planted by the frame builder as a
    /// fresh thread's switch-frame return address. Address-only; the
    /// stub is never called from Rust.
    #[link_name = "thread_startup"]
    pub static THREAD_STARTUP: u8;
}

// The swap. cdecl: [esp+4] = old, [esp+8] = new; eax/ecx/edx are
// scratch, edi/esi hold the two thread pointers. The switch frame,
// lowest word first: captured EFLAGS, the resume label, then the
// saved nonvolatiles (ebp nearest the frame, so a stack walk finds
// it first).
#[cfg(target_arch = "x86")]
core::arch::global_asm!(
    ".section .text.swap_context, \"ax\"",
    ".global swap_context",
    "swap_context:",
    // Save the caller's nonvolatiles first, while their caller
    // values are still in the registers.
    "    push ebx",
    "    push esi",
    "    push edi",
    "    push ebp",
    // The switch frame's return-address slot: pushed by the asm
    // itself, so every saved frame resumes through the same label.
    "    mov eax, offset .Lresume",
    "    push eax",
    "    pushfd",
    // Six words pushed: the cdecl arguments now sit at [esp+28]
    // and [esp+32].
    "    mov edi, [esp + 28]",
    "    mov esi, [esp + 32]",
    // The one data effect with IF still per the caller: the new
    // thread must read Running before the dispatcher context is
    // released.
    "    mov byte ptr [esi + {state_off}], {running}",
    // From here until the new esp is live no interrupt may run.
    // Order: save the old esp, install the new esp0, rewrite the
    // TEB base, load CR3 (only on a process change), switch esp.
    "    cli",
    "    mov [edi + {kstack_off}], esp",
    "    mov eax, [esi + {init_stack_off}]",
    "    mov edx, offset TSS",
    "    mov [edx + 4], eax",
    "    mov eax, [esi + {teb_off}]",
    "    mov edx, offset GDT",
    "    mov [edx + {teb_lo}], ax",
    "    shr eax, 16",
    "    mov [edx + {teb_mid}], al",
    "    shr eax, 8",
    "    mov [edx + {teb_hi}], al",
    "    mov eax, [edi + {process_off}]",
    "    cmp eax, [esi + {process_off}]",
    "    je 1f",
    "    mov eax, [esi + {process_off}]",
    "    add eax, {dir_phys_off}",
    "    mov eax, [eax]",
    "    mov cr3, eax",
    "1:",
    // The new stack is mapped in the CR3 just loaded; from here
    // interrupts are safe again.
    "    mov esp, [esi + {kstack_off}]",
    "    sti",
    "    popfd",
    "    ret",
    // Resumed frames land here: restore the new thread's saved
    // nonvolatiles in reverse push order and return into its Rust
    // caller (the cdecl arguments stay for the caller to pop).
    ".Lresume:",
    "    pop ebp",
    "    pop edi",
    "    pop esi",
    "    pop ebx",
    "    ret",
    state_off = const THREAD_STATE_OFF,
    kstack_off = const THREAD_KERNEL_STACK_OFF,
    init_stack_off = const THREAD_INITIAL_STACK_OFF,
    teb_off = const THREAD_TEB_VA_OFF,
    process_off = const THREAD_PROCESS_OFF,
    dir_phys_off = const PROCESS_DIR_PHYS_OFF,
    teb_lo = const TEB_BASE_LO_OFF,
    teb_mid = const TEB_BASE_MID_OFF,
    teb_hi = const TEB_BASE_HI_OFF,
    running = const super::thread::ThreadState::Running as u8,
);

// The startup stub: a fresh thread's first instructions. Entry esp
// is the system-routine word of the planted ladder; no caller frame
// exists, so the registers are zeroed first. After the flag test
// nothing may touch the stack except the popad/iretd exit (the
// ladder is consumed).
#[cfg(target_arch = "x86")]
core::arch::global_asm!(
    ".section .text.thread_startup, \"ax\"",
    ".global thread_startup",
    "thread_startup:",
    // No caller's saved-register frame exists on a fresh stack.
    "    xor ebx, ebx",
    "    xor esi, esi",
    "    xor edi, edi",
    "    xor ebp, ebp",
    "    call {lower}",
    "    pop eax",
    "    call eax",
    "    add esp, 8",
    "    pop ecx",
    "    test ecx, ecx",
    "    jz .Lno_context",
    // User thread: load the fixed segment set, then leave through
    // the shared frame's exit tail (popad over the eight register
    // words, drop the vector and error pad, iretd into ring 3).
    "    mov ax, {user_data}",
    "    mov ds, ax",
    "    mov es, ax",
    "    mov ax, {teb}",
    "    mov fs, ax",
    "    xor eax, eax",
    "    mov gs, ax",
    "    popad",
    "    add esp, 8",
    "    iretd",
    // A kernel thread's system routine returned: no user context
    // exists to enter. Halt with interrupts disabled after the
    // report.
    ".Lno_context:",
    "    cli",
    "    jmp {bug}",
    user_data = const crate::cpu::gdt::USER_DATA_SELECTOR | 3,
    teb = const crate::cpu::gdt::TEB_SELECTOR | 3,
    lower = sym fresh_thread_level,
    bug = sym startup_no_user_context,
);

// --- The startup stub's callees ---------------------------------------------

/// A fresh thread adopts an empty level ledger: passive, no pending
/// pairs, interrupts enabled (cdecl, called from the startup stub).
/// The previous thread's pairs live on its own stack and ledger.
#[cfg(target_arch = "x86")]
unsafe extern "C" fn fresh_thread_level() {
    crate::interrupt::irql::state_mut().begin_thread();
}

/// A kernel thread's system routine returned with no user context to
/// enter: report the bug on the serial line and halt. Never returns;
/// the stub jumps here with interrupts already disabled.
#[cfg(target_arch = "x86")]
unsafe extern "C" fn startup_no_user_context() -> ! {
    crate::serial_println!("F2K: BUG: a kernel thread's system routine returned with no user context");
    crate::halt()
}

// --- The switch's data decisions -------------------------------------------
//
// The pure half of the swap: every decision the assembly acts on,
// as a plain function over the two thread records, host-testable.

/// One switch's decisions: what the assembly will write and load.
pub struct SwitchPlan {
    /// Whether the two threads belong to one process.
    pub same_process: bool,
    /// The directory base to load into CR3 — only when the process
    /// changed; a same-process switch loads nothing.
    pub cr3: Option<u32>,
    /// The base written into the TEB segment descriptor: the new
    /// thread's own TEB page, on every switch.
    pub teb_base: u32,
    /// The value installed as the TSS `esp0`: the new thread's stack
    /// top (never its saved mid-syscall stack pointer — a gate
    /// entry starts at the top).
    pub esp0: u32,
    /// The value loaded as the new `esp`: the new thread's saved
    /// kernel-stack pointer.
    pub new_kernel_esp: u32,
}

/// Compute the switch's data decisions. Refuses (panics) when a DPC
/// routine is active: switching would abandon its frames
/// mid-routine. The caller passes the flag.
pub fn switch_plan(old: &super::thread::Thread, new: &super::thread::Thread, dpc_active: bool) -> SwitchPlan {
    assert!(
        !dpc_active,
        "context switch attempted while a DPC routine is active"
    );
    let same_process = core::ptr::eq(old.process, new.process);
    SwitchPlan {
        same_process,
        cr3: if same_process {
            None
        } else {
            // SAFETY: an attached thread's owner outlives it; the
            // accessor reads the leading directory-base field.
            Some(unsafe { (*new.process).dir_phys() })
        },
        teb_base: new.teb_va,
        esp0: new.initial_stack,
        new_kernel_esp: new.kernel_stack,
    }
}

/// Rewrite a TEB descriptor entry's base bytes to `teb`: a complete
/// base rewrite touching no other byte. The host-side oracle for
/// the assembly's three stores.
pub fn teb_entry_after_edit(entry: u64, teb: u32) -> u64 {
    let mut bytes = entry.to_le_bytes();
    bytes[2..4].copy_from_slice(&(teb as u16).to_le_bytes());
    bytes[4] = (teb >> 16) as u8;
    bytes[7] = (teb >> 24) as u8;
    u64::from_le_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu::gdt::{make_entry, TEB_SELECTOR};
    use crate::sched::process::SchedProcess;
    use crate::sched::thread::{Thread, ThreadState};
    use crate::user::thread_teb_va;

    /// Two threads of one process and a third of another, with
    /// machine state filled in.
    fn threads() -> (&'static mut Thread, &'static mut Thread, &'static mut Thread) {
        let p1 = Box::leak(Box::new(SchedProcess::new(0x0090_0000, 8)));
        let p2 = Box::leak(Box::new(SchedProcess::new(0x00B0_0000, 8)));
        p1.init();
        p2.init();
        let of = |process: *mut SchedProcess, teb: u32, slot: u32| {
            let t = Box::leak(Box::new(Thread::empty()));
            // SAFETY: the process is leaked at its final address.
            unsafe { t.attach_to(&mut *process) };
            t.teb_va = teb;
            t.initial_stack = crate::mem::paging::gate_slot_top(slot);
            t.kernel_stack = t.initial_stack - 84;
            t
        };
        (
            of(p1 as *mut SchedProcess, thread_teb_va(0), 0),
            of(p1 as *mut SchedProcess, thread_teb_va(1), 1),
            of(p2 as *mut SchedProcess, thread_teb_va(0), 0),
        )
    }

    // C2: the CR3 and TEB decisions are pure functions of the pair.

/// A cross-process switch loads the new process's directory; a
/// same-process switch loads nothing but still re-points the TEB
/// descriptor (threads of one process never share a TEB); `esp0`
/// is always the new thread's stack top.
    #[test]
    fn cr3_follows_the_process_and_the_teb_follows_the_thread() {
        let (a, same, cross) = threads();

        let same_process = switch_plan(a, same, false);
        assert!(same_process.same_process);
        assert_eq!(same_process.cr3, None);
        assert_eq!(same_process.teb_base, thread_teb_va(1));
        assert_eq!(same_process.esp0, same.initial_stack);
        assert_eq!(same_process.new_kernel_esp, same.kernel_stack);

        let cross_process = switch_plan(a, cross, false);
        assert!(!cross_process.same_process);
        assert_eq!(cross_process.cr3, Some(0x00B0_0000));
        assert_eq!(cross_process.teb_base, thread_teb_va(0));
    }

    // C1's plantable half: the saved stack pointer's shape.

    /// A never-run thread's `kernel_stack` is exactly its planted
    /// switch frame (the frame builder's invariant), and `esp0` is
    /// never the mid-stack value: a gate entry starts at the top,
    /// a switch-in starts at the saved frame.
    #[test]
    fn the_saved_stack_pointer_is_the_planted_frame_not_the_top() {
        let (a, _same, _cross) = threads();
        // The builder's contract: kernel_stack points at a valid
        // planted switch frame, esp0 at the slot top.
        assert_eq!(a.kernel_stack, a.initial_stack - 84);
        assert_ne!(a.kernel_stack, a.initial_stack);

        let plan = switch_plan(a, a, false);
        assert_eq!(plan.new_kernel_esp, a.kernel_stack);
        assert_eq!(plan.esp0, a.initial_stack);
    }

    // C5: the DPC-active refusal.

    /// A switch attempted while a DPC routine is active is refused:
    /// the plan panics before any state moves.
    #[test]
    fn a_switch_under_an_active_dpc_routine_is_refused() {
        let (a, _same, cross) = threads();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            switch_plan(a, cross, true)
        }));
        assert!(result.is_err());
    }

    // C3's dispatcher half: the caller-side install.

/// The selected thread takes the current slot; the processor is
/// marked idle exactly when it is the idle thread. The
/// Standby-to-Running state write is the swap's own effect.
    #[test]
    fn the_dispatcher_adopts_the_selected_thread() {
        use crate::sched::dispatcher::Dispatcher;
        let (idle, _same, worker) = threads();
        idle.state = ThreadState::Running;

        let mut dispatcher = Dispatcher::zeroed();
        dispatcher.init();
        // The boot install: the idle thread is current.
        dispatcher.install_idle_thread(idle);
        assert!(core::ptr::eq(dispatcher.current_thread(), idle as *mut Thread));
        assert!(dispatcher.processor_idle());

        // Nothing schedulable: the loop stays in the idle call.
        assert!(!dispatcher.has_schedulable());

        // Readying the worker selects it into the standby slot;
        // adoption installs it as current and un-marks the idle
        // processor.
        dispatcher.make_ready(worker);
        assert!(dispatcher.has_schedulable());
        let selected = dispatcher.select_next();
        assert!(core::ptr::eq(selected, worker as *mut Thread));
        dispatcher.enter(selected);
        assert!(core::ptr::eq(dispatcher.current_thread(), worker as *mut Thread));
        assert!(dispatcher.next_thread().is_null());
        assert!(!dispatcher.processor_idle());

        // Adopting the idle thread marks the processor idle again.
        dispatcher.enter(idle as *mut Thread);
        assert!(dispatcher.processor_idle());
    }

    // B6: the TEB descriptor edit's byte offsets.

/// The three base-byte stores rewrite exactly the base: the edited
/// entry equals a freshly packed entry for the same base.
    #[test]
    fn the_teb_edit_rewrites_only_the_base_bytes() {
        assert_eq!((TEB_SELECTOR >> 3) as usize, 6);
        assert_eq!(TEB_BASE_LO_OFF, TEB_SELECTOR as u32 + 2);
        assert_eq!(TEB_BASE_MID_OFF, TEB_SELECTOR as u32 + 4);
        assert_eq!(TEB_BASE_HI_OFF, TEB_SELECTOR as u32 + 7);

        for base in [0u32, 0x0031_0000, 0x0080_1000, 0x009F_F000] {
            let entry = make_entry(crate::user::TEB_PAGE, 0xFFF, 0xF3, 0x4);
            let edited = teb_entry_after_edit(entry, base);
            assert_eq!(edited, make_entry(base, 0xFFF, 0xF3, 0x4), "base {base:#x}");
        }
    }
}
