//! The context switch: the swap assembly and a new thread's first instructions.
//!
//! [`swap_context`] moves the processor from one thread to another: it saves the caller's
//! nonvolatile registers and `esp` into a switch frame on the old thread's kernel stack, saves its
//! floating-point state (x87, MXCSR and the XMM registers) into its record (restoring the new
//! thread's), installs the new thread's stack top as the TSS `esp0`, rewrites the TEB descriptor's
//! base, loads CR3 when the address space changes, and resumes the new thread. [`THREAD_STARTUP`]
//! is a fresh thread's first instructions, reached as the planted return address of the initial
//! switch: it zeroes the registers, lowers the level, calls the system routine, and a user thread
//! then enters ring 3 from its planted trap frame.
//!
//! The address space a thread runs on is its address-space process's (see [`super::attach`]): its
//! owner's, or while attached the process it attached to. The switch compares the two threads'
//! address-space processes, not their owners, and loads the incoming one's directory: a thread
//! attached to another process, switched away and back, resumes on the directory it attached to.
//! CR3 always holds the running thread's address-space directory (an attach moves both together,
//! masked), which debug builds check wherever a thread resumes.
//!
//! Load-bearing discipline: `cli` spans everything from the old `esp`'s save to the new one's load
//! — the `esp0`, the TEB descriptor, the CR3 load — so no interrupt lands on a half-installed
//! thread. Kernel stacks are mapped in every address space (the kernel stack region's tables are
//! shared), so both stacks stay mapped across the CR3 load. One resume tail (`popfd`; `ret`) serves
//! both frame shapes: a saved frame returns into the resume label, a fresh frame's planted return
//! address is the startup stub.

// --- Pinned machine-state offsets -----------------------------------------
//
// The assembly addresses a thread's machine state and its process's scheduling record through these
// byte offsets; the thread record's layout tests pin them to the real `#[repr(C)]` layouts.

/// The `state` byte's offset in the thread record: the swap writes Running here before anything
/// else observes the new thread. Host tests pin this to the thread record's `#[repr(C)]` layout.
pub const THREAD_STATE_OFF: u32 = 0;

/// The saved-esp field's offset in the thread record: what a switch stores the old thread's switch
/// frame at and loads the new thread's stack from. Host tests pin this to the thread record's
/// `#[repr(C)]` layout.
pub const THREAD_KERNEL_STACK_OFF: u32 = 8;

/// The stack-top field's offset in the thread record: the gate-slot top that becomes the TSS ring-0
/// stack pointer at every switch. Host tests pin this to the thread record's `#[repr(C)]` layout.
pub const THREAD_INITIAL_STACK_OFF: u32 = 12;

/// The TEB-page field's offset in the thread record: the base the switch writes into the TEB
/// descriptor (0 for kernel and idle threads). Host tests pin this to the thread record's
/// `#[repr(C)]` layout.
pub const THREAD_TEB_VA_OFF: u32 = 16;

/// The address-space pointer's offset in the thread record: pointer identity between the two
/// threads' address-space processes decides the CR3 load, and the incoming one's names the
/// directory. Host tests pin this to the thread record's `#[repr(C)]` layout.
pub const THREAD_SPACE_OFF: u32 = 20;

/// The saved floating-point state's offset in the thread record (taken from the layout itself:
/// nothing else depends on where it sits, so it is not pinned to a number; the record's layout
/// keeps it 16-byte aligned, as `fxsave` needs).
pub const THREAD_FPU_OFF: u32 = core::mem::offset_of!(super::thread::Thread, fpu) as u32;

/// The directory-base offset inside the scheduling record, read only when the address space
/// changes.
pub const PROCESS_DIR_PHYS_OFF: u32 = 0;

/// The TEB descriptor's base-byte offsets inside the GDT, derived from the selector: 15:0 at +2,
/// 23:16 at +4, 31:24 at +7.
const TEB_BASE_LO_OFF: u32 = crate::cpu::gdt::TEB_SELECTOR as u32 + 2;
const TEB_BASE_MID_OFF: u32 = crate::cpu::gdt::TEB_SELECTOR as u32 + 4;
const TEB_BASE_HI_OFF: u32 = crate::cpu::gdt::TEB_SELECTOR as u32 + 7;

// Only the records' addresses cross the boundary, as opaque pointers: the asm consumes them through
// the pinned offsets above, which the thread record's `#[repr(C)]` prefix holds to.
#[cfg(target_arch = "x86")]
unsafe extern "C" {
    /// The swap itself (see [`swap_context`]).
    #[link_name = "swap_context"]
    fn swap_context_asm(old: *mut core::ffi::c_void, new: *mut core::ffi::c_void);

    /// The startup stub's address, planted by the frame builder as a fresh thread's switch-frame
    /// return address. Address-only; the stub is never called from Rust.
    #[link_name = "thread_startup"]
    pub static THREAD_STARTUP: u8;
}

/// Switch the processor from `old` to `new`, entered at the dispatch level with interrupts enabled.
/// Never "returns" in the calling thread's present: the return path executes when a later switch
/// resumes `old`, which debug builds check runs on its address-space directory.
///
/// # Safety
///
/// Both threads are live records; `new`'s switch frame is planted (fresh) or saved (resumed), and
/// the dispatcher has adopted it as the running thread.
#[cfg(target_arch = "x86")]
pub unsafe fn swap_context(old: *mut super::thread::Thread, new: *mut super::thread::Thread) {
    // SAFETY: the caller's contract.
    unsafe { swap_context_asm(old.cast(), new.cast()) };
    // SAFETY: `old` runs again: its record is live.
    debug_assert_on_own_space(unsafe { &*old });
}

/// Debug builds: CR3 holds `thread`'s address-space directory — `thread` being the one that runs.
#[cfg(target_arch = "x86")]
fn debug_assert_on_own_space(thread: &super::thread::Thread) {
    if cfg!(debug_assertions) {
        let cr3: u32;
        // SAFETY: reading CR3 has no side effect.
        unsafe { core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack)) };
        // SAFETY: a running thread's address-space process outlives its scope on it.
        let dir_phys = unsafe { (*thread.space).dir_phys() };
        assert_eq!(
            crate::mem::paging::directory_cr3(cr3),
            dir_phys,
            "a thread resumes on its address-space directory"
        );
    }
}

// The swap. cdecl: [esp+4] = old, [esp+8] = new; eax/ecx/edx are scratch, edi/esi hold the two
// thread pointers. The switch frame, lowest word first: captured EFLAGS, the resume label, then the
// saved nonvolatiles (ebp nearest the frame, so a stack walk finds it first).
#[cfg(target_arch = "x86")]
core::arch::global_asm!(
    ".section .text.swap_context, \"ax\"",
    ".global swap_context",
    "swap_context:",
    // Save the caller's nonvolatiles first, while their caller values are still in the registers.
    "    push ebx",
    "    push esi",
    "    push edi",
    "    push ebp",
    // The switch frame's return-address slot: pushed by the asm itself, so every saved frame
    // resumes through the same label.
    "    mov eax, offset .Lresume",
    "    push eax",
    "    pushfd",
    // Six words pushed: the cdecl arguments now sit at [esp+28] and [esp+32].
    "    mov edi, [esp + 28]",
    "    mov esi, [esp + 32]",
    // The one data effect with IF still per the caller: the new thread must read Running before the
    // dispatcher context is released.
    "    mov byte ptr [esi + {state_off}], {running}",
    // From here until the new esp is live no interrupt may run. Order: save the old esp, install
    // the new esp0, rewrite the TEB base, load CR3 (only on an address-space change), switch esp.
    "    cli",
    // The floating-point state: the old thread's saved, the new thread's restored (`fxrstor`
    // replaces the whole unit's state, so nothing of the old thread's survives the switch). Both
    // records are kernel statics, mapped in every directory.
    "    fxsave [edi + {fpu_off}]",
    "    fxrstor [esi + {fpu_off}]",
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
    "    mov eax, [edi + {space_off}]",
    "    cmp eax, [esi + {space_off}]",
    "    je 1f",
    "    mov eax, [esi + {space_off}]",
    "    add eax, {dir_phys_off}",
    "    mov eax, [eax]",
    "    mov cr3, eax",
    "1:",
    // The new thread is fully installed; from here interrupts are safe again.
    "    mov esp, [esi + {kstack_off}]",
    "    sti",
    "    popfd",
    "    ret",
    // Resumed frames land here: restore the new thread's saved nonvolatiles in reverse push order
    // and return into its Rust caller (the cdecl arguments stay for the caller to pop).
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
    fpu_off = const THREAD_FPU_OFF,
    space_off = const THREAD_SPACE_OFF,
    dir_phys_off = const PROCESS_DIR_PHYS_OFF,
    teb_lo = const TEB_BASE_LO_OFF,
    teb_mid = const TEB_BASE_MID_OFF,
    teb_hi = const TEB_BASE_HI_OFF,
    running = const super::thread::ThreadState::Running as u8,
);

// The startup stub: a fresh thread's first instructions. Entry esp is the system-routine word of
// the planted ladder; no caller frame exists, so the registers are zeroed first. After the flag
// test nothing may touch the stack except the popad/iretd exit (the ladder is consumed).
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
    // User thread: load the fixed segment set, then leave through the shared frame's exit tail
    // (popad over the eight register words, drop the vector and error pad, iretd into ring 3).
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
    // A kernel thread's system routine returned: no user context exists to enter. Halt with
    // interrupts disabled after the report.
    ".Lno_context:",
    "    cli",
    "    jmp {bug}",
    user_data = const crate::cpu::gdt::USER_DATA_SELECTOR | 3,
    teb = const crate::cpu::gdt::TEB_SELECTOR | 3,
    lower = sym fresh_thread_level,
    bug = sym startup_no_user_context,
);

// --- The startup stub's callees ---------------------------------------------

/// A fresh thread adopts an empty level ledger: passive, no pending pairs, interrupts enabled
/// (cdecl, called from the startup stub). The previous thread's pairs live on its own stack and
/// ledger.
#[cfg(target_arch = "x86")]
unsafe extern "C" fn fresh_thread_level() {
    crate::pcr::pcr().begin_thread();
    // SAFETY: the dispatcher adopted this thread before the switch into it: its record is live.
    debug_assert_on_own_space(unsafe { &*crate::sched::idle::dispatcher().current_thread() });
}

/// A kernel thread's system routine returned with no user context to enter: report the bug on the
/// serial line and halt. Never returns; the stub jumps here with interrupts already disabled.
#[cfg(target_arch = "x86")]
unsafe extern "C" fn startup_no_user_context() -> ! {
    crate::serial_println!(
        "F2K: BUG: a kernel thread's system routine returned with no user context"
    );
    crate::halt()
}

// --- The switch's data decisions -------------------------------------------
//
// The pure half of the swap: every decision the assembly acts on, as a plain function over the two
// thread records, host-testable.

/// One switch's decisions: what the assembly will write and load.
pub struct SwitchPlan {
    /// Whether the two threads run on one address space (their address-space processes are one).
    pub same_space: bool,
    /// The directory base to load into CR3 — the new thread's address-space process's, only when
    /// the address space changes; a switch within one loads nothing.
    pub cr3: Option<u32>,
    /// The base written into the TEB segment descriptor: the new thread's own TEB page, on every
    /// switch.
    pub teb_base: u32,
    /// The value installed as the TSS `esp0`: the new thread's stack top (never its saved
    /// mid-syscall stack pointer — a gate entry starts at the top).
    pub esp0: u32,
    /// The value loaded as the new `esp`: the new thread's saved kernel-stack pointer.
    pub new_kernel_esp: u32,
}

/// Compute the switch's data decisions. Refuses (panics) when a DPC routine is active: switching
/// would abandon its frames mid-routine. The caller passes the flag.
pub fn switch_plan(
    old: &super::thread::Thread,
    new: &super::thread::Thread,
    dpc_active: bool,
) -> SwitchPlan {
    assert!(
        !dpc_active,
        "context switch attempted while a DPC routine is active"
    );
    let same_space = core::ptr::eq(old.space, new.space);
    SwitchPlan {
        same_space,
        cr3: if same_space {
            None
        } else {
            // SAFETY: a thread's address-space process outlives its scope on it (the owner, its
            // thread); the accessor reads the leading directory-base field.
            Some(unsafe { (*new.space).dir_phys() })
        },
        teb_base: new.teb_va,
        esp0: new.initial_stack,
        new_kernel_esp: new.kernel_stack,
    }
}

/// Rewrite a TEB descriptor entry's base bytes to `teb`: a complete base rewrite touching no other
/// byte — the host-side model of the assembly's three stores.
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
    use crate::sched::testkit::Rec;
    use crate::sched::thread::{Thread, ThreadState};
    use crate::user::thread_teb_va;

    /// Two threads of one process and a third of another, with machine state filled in.
    fn threads() -> (Rec<Thread>, Rec<Thread>, Rec<Thread>) {
        crate::sched::testkit::dispatcher();
        let p1 = Box::leak(Box::new(SchedProcess::new(0x0090_0000, 8)));
        let p2 = Box::leak(Box::new(SchedProcess::new(0x00B0_0000, 8)));
        let of = |process: *mut SchedProcess, teb: u32, slot: u32| {
            let mut t = crate::sched::testkit::thread(process);
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

    /// A cross-process switch loads the new process's directory; a same-process switch loads
    /// nothing but still re-points the TEB descriptor (threads of one process never share a TEB);
    /// `esp0` is always the new thread's stack top.
    #[test]
    fn cr3_follows_the_process_and_the_teb_follows_the_thread() {
        let (a, same, cross) = threads();

        let same_process = switch_plan(&a, &same, false);
        assert!(same_process.same_space);
        assert_eq!(same_process.cr3, None);
        assert_eq!(same_process.teb_base, thread_teb_va(1));
        assert_eq!(same_process.esp0, same.initial_stack);
        assert_eq!(same_process.new_kernel_esp, same.kernel_stack);

        let cross_process = switch_plan(&a, &cross, false);
        assert!(!cross_process.same_space);
        assert_eq!(cross_process.cr3, Some(0x00B0_0000));
        assert_eq!(cross_process.teb_base, thread_teb_va(0));
    }

    /// A thread attached to another process switches as that process's threads do: away from its
    /// own process's threads it loads the attached directory, and back to it from them it loads
    /// it again — never its owner's — while between it and the attached process's threads nothing
    /// is loaded. Detached, it switches as its owner's thread again.
    #[test]
    fn cr3_follows_the_attached_address_space() {
        let (mut attacher, own_sibling, of_target) = threads();
        // SAFETY: the target's record is leaked; the thread is attached to its own process.
        let target = unsafe { &*of_target.process };
        assert_eq!(attacher.attach_space(target), Some(0x00B0_0000));

        let back_from_sibling = switch_plan(&own_sibling, &attacher, false);
        assert_eq!(
            back_from_sibling.cr3,
            Some(0x00B0_0000),
            "resumes on the attached directory"
        );
        let to_sibling = switch_plan(&attacher, &own_sibling, false);
        assert_eq!(to_sibling.cr3, Some(0x0090_0000));
        assert!(switch_plan(&of_target, &attacher, false).same_space);
        assert_eq!(switch_plan(&attacher, &of_target, false).cr3, None);

        attacher.detach_space();
        assert_eq!(
            switch_plan(&of_target, &attacher, false).cr3,
            Some(0x0090_0000)
        );
        assert!(switch_plan(&own_sibling, &attacher, false).same_space);
    }

    // C1's plantable half: the saved stack pointer's shape.

    /// A never-run thread's `kernel_stack` is exactly its planted switch frame (the frame builder's
    /// invariant), and `esp0` is never the mid-stack value: a gate entry starts at the top, a
    /// switch-in starts at the saved frame.
    #[test]
    fn the_saved_stack_pointer_is_the_planted_frame_not_the_top() {
        let (a, _same, _cross) = threads();
        // The builder's contract: kernel_stack points at a valid planted switch frame, esp0 at the
        // slot top.
        assert_eq!(a.kernel_stack, a.initial_stack - 84);
        assert_ne!(a.kernel_stack, a.initial_stack);

        let plan = switch_plan(&a, &a, false);
        assert_eq!(plan.new_kernel_esp, a.kernel_stack);
        assert_eq!(plan.esp0, a.initial_stack);
    }

    // C5: the DPC-active refusal.

    /// A switch attempted while a DPC routine is active is refused: the plan panics before any
    /// state moves.
    #[test]
    fn a_switch_under_an_active_dpc_routine_is_refused() {
        let (a, _same, cross) = threads();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            switch_plan(&a, &cross, true)
        }));
        assert!(result.is_err());
    }

    // C3's dispatcher half: the caller-side install.

    /// The selected thread takes the current slot; the processor is marked idle exactly when it is
    /// the idle thread. The Standby-to-Running state write is the swap's own effect.
    #[test]
    fn the_dispatcher_adopts_the_selected_thread() {
        let (mut idle, _same, worker) = threads();
        idle.state = ThreadState::Running;

        let dispatcher = crate::sched::testkit::installed();
        // The boot install: the idle thread is current.
        dispatcher.install_idle_thread(idle.id());
        assert_eq!(dispatcher.current_thread(), idle.as_ptr());
        assert!(dispatcher.processor_idle());

        // Nothing schedulable: the loop stays in the idle call.
        assert!(!dispatcher.has_schedulable());

        // Readying the worker selects it into the standby slot; adoption installs it as current and
        // un-marks the idle processor.
        dispatcher.make_ready(worker);
        assert!(dispatcher.has_schedulable());
        let selected = dispatcher.select_next();
        assert_eq!(selected, Some(worker.id()));
        dispatcher.enter(worker.id());
        assert_eq!(dispatcher.current_thread(), worker.as_ptr());
        assert!(dispatcher.next_thread().is_none());
        assert!(!dispatcher.processor_idle());

        // Adopting the idle thread marks the processor idle again.
        dispatcher.enter(idle.id());
        assert!(dispatcher.processor_idle());
    }

    // B6: the TEB descriptor edit's byte offsets.

    /// The three base-byte stores rewrite exactly the base: the edited entry equals a freshly
    /// packed entry for the same base.
    #[test]
    fn the_teb_edit_rewrites_only_the_base_bytes() {
        assert_eq!((TEB_SELECTOR >> 3) as usize, 6);
        assert_eq!(TEB_BASE_LO_OFF, TEB_SELECTOR as u32 + 2);
        assert_eq!(TEB_BASE_MID_OFF, TEB_SELECTOR as u32 + 4);
        assert_eq!(TEB_BASE_HI_OFF, TEB_SELECTOR as u32 + 7);

        for base in [0u32, 0x7FFD_E000, 0x7FFD_D000, 0x7FF9_E000] {
            let entry = make_entry(crate::user::TEB_PAGE, 0xFFF, 0xF3, 0x4);
            let edited = teb_entry_after_edit(entry, base);
            assert_eq!(edited, make_entry(base, 0xFFF, 0xF3, 0x4), "base {base:#x}");
        }
    }
}
