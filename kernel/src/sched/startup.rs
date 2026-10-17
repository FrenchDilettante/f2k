//! The startup frame builder: a fresh thread's first kernel stack contents, as pure layout.
//!
//! The ladder the switch and the startup stub consume, computed from the stack top alone: a trap
//! frame carrying the thread's initial user state (user threads), the four words the stub pops as
//! its arguments, and the switch frame — EFLAGS lowest, the startup stub's address above — whose
//! base becomes the thread's saved stack pointer. Pure arithmetic, host-tested; only the planting
//! touches memory.

#[cfg(target_arch = "x86")]
use super::thread::Thread;
use crate::cpu::gdt::{USER_CODE_SELECTOR, USER_DATA_SELECTOR};
use crate::user::{TrapFrame, USER_EFLAGS};

/// The EFLAGS word every planted switch frame carries: bit 1 plus the interrupt flag — a fresh
/// thread starts with interrupts enabled.
pub const PLANTED_EFLAGS: u32 = USER_EFLAGS;

/// A fresh thread's start parameters.
pub struct StartParams {
    /// The system routine the startup stub calls first (the thread-creation surface's function;
    /// never returns for user threads).
    pub system_routine: u32,
    /// The start routine, passed to the system routine as its first argument.
    pub start_routine: u32,
    /// The context word, passed to the system routine as its second argument.
    pub start_context: u32,
    /// The thread's initial user-mode state, or `None` for a kernel thread (whose system routine
    /// returning is a bug: the stub halts).
    pub user: Option<UserStart>,
}

/// A user thread's initial user-mode state: the entry point and the stack top it runs on.
pub struct UserStart {
    pub eip: u32,
    pub esp: u32,
}

/// The planted trap frame for a user thread's initial state: GP slots zeroed (kernel pointers must
/// not leak into user mode), no vector or error code, RPL 3 in both segment slots, interrupts
/// enabled.
pub fn user_trap_frame(user: &UserStart) -> TrapFrame {
    TrapFrame {
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
        eip: user.eip,
        cs: USER_CODE_SELECTOR as u32 | 3,
        eflags: PLANTED_EFLAGS,
        user_esp: user.esp,
        user_ss: USER_DATA_SELECTOR as u32 | 3,
    }
}

/// The planted word ladder: every word's address and value, computed from the stack top. Pure data;
/// [`plant`] writes it.
pub struct StartupLadder {
    /// The trap frame's base address (user threads only; the frame itself is planted there).
    pub trap_frame_at: Option<u32>,
    /// The planted trap frame (user threads only).
    pub trap_frame: Option<TrapFrame>,
    /// The user-context flag's address and value: 1 when a trap frame follows above, 0 otherwise.
    pub user_context_flag_at: u32,
    pub user_context_flag: u32,
    /// The system-routine word: the stub pops it into the register it calls through.
    pub system_routine_at: u32,
    pub system_routine: u32,
    /// The start-routine word: the system routine's first argument, already in cdecl
    /// stack-argument position.
    pub start_routine_at: u32,
    pub start_routine: u32,
    /// The context word: the system routine's second argument.
    pub start_context_at: u32,
    pub start_context: u32,
    /// The switch frame's return-address slot: the startup stub's address, one word above the
    /// EFLAGS.
    pub ret_at: u32,
    pub ret: u32,
    /// The EFLAGS word: the lowest planted word.
    pub eflags_at: u32,
    pub eflags: u32,
}

impl StartupLadder {
    /// The switch frame's base: the EFLAGS word, the lowest planted word. This is the thread's
    /// `kernel_stack` after the build — the value the first switch loads as the new `esp`.
    pub fn switch_frame_at(&self) -> u32 {
        self.eflags_at
    }

    /// The stub's entry stack: the system-routine word, eight bytes above the switch frame's base.
    pub fn stub_entry_esp(&self) -> u32 {
        self.system_routine_at
    }

    /// Every planted address, ascending: the bounds and no-overlap discipline (each word is planted
    /// exactly once).
    pub fn planted_addresses(&self) -> [u32; 6] {
        let mut words = [
            self.user_context_flag_at,
            self.start_context_at,
            self.start_routine_at,
            self.system_routine_at,
            self.ret_at,
            self.eflags_at,
        ];
        words.sort_unstable();
        words
    }
}

/// Compute the word ladder for a thread whose kernel-stack top is `stack_top`. User and kernel
/// threads build the same ladder except for the trap-frame rung, which only a user thread has.
pub fn build_ladder(stack_top: u32, params: &StartParams, startup_addr: u32) -> StartupLadder {
    let (trap_frame_at, trap_frame, flag_at) = match &params.user {
        Some(user) => (
            Some(stack_top - core::mem::size_of::<TrapFrame>() as u32),
            Some(user_trap_frame(user)),
            stack_top - (core::mem::size_of::<TrapFrame>() as u32 + 4),
        ),
        None => (None, None, stack_top - 4),
    };

    let start_context_at = flag_at - 4;
    let start_routine_at = start_context_at - 4;
    let system_routine_at = start_routine_at - 4;
    let ret_at = system_routine_at - 4;
    let eflags_at = ret_at - 4;

    StartupLadder {
        trap_frame_at,
        trap_frame,
        user_context_flag_at: flag_at,
        user_context_flag: if params.user.is_some() { 1 } else { 0 },
        system_routine_at,
        system_routine: params.system_routine,
        start_routine_at,
        start_routine: params.start_routine,
        start_context_at,
        start_context: params.start_context,
        ret_at,
        ret: startup_addr,
        eflags_at,
        eflags: PLANTED_EFLAGS,
    }
}

/// Plant the ladder on the thread's kernel stack and set its saved stack pointer. Target only: the
/// words are written to the stack the switch will load.
///
/// # Safety
///
/// `thread.initial_stack` names the top of the thread's own kernel-stack slot, mapped in the
/// current address space, with nothing on it.
#[cfg(target_arch = "x86")]
pub unsafe fn plant(thread: &mut Thread, params: &StartParams) {
    let stack_top = thread.initial_stack;
    let startup_addr = core::ptr::addr_of!(super::switch::THREAD_STARTUP) as u32;
    let mut ladder = build_ladder(stack_top, params, startup_addr);

    let word = |addr: u32, value: u32| {
        // SAFETY: the address is inside the thread's freshly mapped slot, word-aligned, written
        // exactly once by this builder.
        unsafe { core::ptr::write_volatile(addr as *mut u32, value) };
    };

    if let Some(at) = ladder.trap_frame_at {
        // The ladder owns the frame; planting hands it over.
        if let Some(frame) = ladder.trap_frame.take() {
            // SAFETY: the frame base is 4-byte aligned (the stack top is page-aligned) and inside
            // the slot, written once here.
            unsafe { core::ptr::write_volatile(at as *mut TrapFrame, frame) };
        }
    }
    word(ladder.user_context_flag_at, ladder.user_context_flag);
    word(ladder.start_context_at, ladder.start_context);
    word(ladder.start_routine_at, ladder.start_routine);
    word(ladder.system_routine_at, ladder.system_routine);
    word(ladder.ret_at, ladder.ret);
    word(ladder.eflags_at, ladder.eflags);

    thread.kernel_stack = ladder.switch_frame_at();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mem::paging::{gate_slot_base, gate_slot_top, GATE_SLOT_STRIDE, PAGE_SIZE};

    /// A ladder's parameters, with distinct recognizable values.
    fn params(user: Option<UserStart>) -> StartParams {
        StartParams {
            system_routine: 0xAAAA_0001,
            start_routine: 0xBBBB_0002,
            start_context: 0xCCCC_0003,
            user,
        }
    }

    const STARTUP: u32 = 0x00DE_0001;

    // A1: the user-thread word offsets.

    /// A user thread's ladder: the trap frame in the 15 words below the top, the argument words in
    /// pop order below it, the switch frame below those (EFLAGS lowest), and the stub's entry esp
    /// eight bytes above the switch frame's base.
    #[test]
    fn user_thread_frame_word_offsets() {
        let top = gate_slot_top(3);
        let ladder = build_ladder(
            top,
            &params(Some(UserStart {
                eip: 0x0040_1234,
                esp: 0x0030_8000,
            })),
            STARTUP,
        );

        assert_eq!(ladder.trap_frame_at, Some(top - 60));
        assert_eq!(ladder.user_context_flag_at, top - 64);
        assert_eq!(ladder.start_context_at, top - 68);
        assert_eq!(ladder.start_routine_at, top - 72);
        assert_eq!(ladder.system_routine_at, top - 76);
        assert_eq!(ladder.ret_at, top - 80);
        assert_eq!(ladder.eflags_at, top - 84);
        assert_eq!(ladder.switch_frame_at(), top - 84);

        // The stub's entry stack is the system-routine word: the switch's `popfd; ret` consumes the
        // two switch-frame words and lands exactly there.
        assert_eq!(ladder.stub_entry_esp(), ladder.system_routine_at);
        assert_eq!(ladder.switch_frame_at() + 8, ladder.stub_entry_esp());

        // The cdecl positions: at the stub's call the two argument words sit in argument position
        // above the consumed system word — the routine first, the context second.
        assert_eq!(ladder.start_routine_at, ladder.system_routine_at + 4);
        assert_eq!(ladder.start_context_at, ladder.system_routine_at + 8);
    }

    // A2: the planted switch frame.

    /// The switch frame's words: EFLAGS with bit 1 and the interrupt flag, and the startup stub's
    /// address in the return slot — what the first switch's uniform tail consumes.
    #[test]
    fn planted_switch_frame() {
        let top = gate_slot_top(0);
        let ladder = build_ladder(
            top,
            &params(Some(UserStart {
                eip: 0x0040_1234,
                esp: 0x0030_8000,
            })),
            STARTUP,
        );
        assert_eq!(ladder.eflags, PLANTED_EFLAGS);
        assert_eq!(PLANTED_EFLAGS, 0x0202);
        assert_eq!(ladder.eflags & 1 << 1, 1 << 1, "bit 1 must be set");
        assert_eq!(
            ladder.eflags & 1 << 9,
            1 << 9,
            "the interrupt flag must be set"
        );
        assert_eq!(ladder.ret, STARTUP);
        // The return slot sits directly above the EFLAGS word: the `popfd` then `ret` order.
        assert_eq!(ladder.ret_at, ladder.eflags_at + 4);
    }

    // A3: the planted trap frame's contents.

    /// The trap frame carries the thread's initial user state with RPL 3 in both segment slots,
    /// interrupts enabled, and nothing else: the register slots are zeroed (kernel pointers must
    /// not leak into user mode) and no vector or error code is set.
    #[test]
    fn planted_trap_frame_contents() {
        let frame = user_trap_frame(&UserStart {
            eip: 0x0040_1234,
            esp: 0x0030_8000,
        });
        assert_eq!(frame.eip, 0x0040_1234);
        assert_eq!(frame.user_esp, 0x0030_8000);
        assert_eq!(frame.cs, 0x1B);
        assert_eq!(frame.user_ss, 0x23);
        assert_eq!(frame.cs & 3, 3);
        assert_eq!(frame.user_ss & 3, 3);
        assert_eq!(frame.eflags, 0x0202);
        assert_eq!(frame.vector, 0);
        assert_eq!(frame.error_code, 0);
        for gp in [
            frame.edi, frame.esi, frame.ebp, frame.esp, frame.ebx, frame.edx, frame.ecx, frame.eax,
        ] {
            assert_eq!(gp, 0);
        }
        assert_eq!(core::mem::size_of::<TrapFrame>(), 60);
    }

    // A4: the user-context flag and the argument words.

    /// The four words below the trap frame: the flag says a user context follows, and the argument
    /// words carry the start parameters in the exact order the stub pops them.
    #[test]
    fn user_context_flag_and_argument_words() {
        let top = gate_slot_top(1);
        let ladder = build_ladder(
            top,
            &params(Some(UserStart {
                eip: 0x0040_1234,
                esp: 0x0030_8000,
            })),
            STARTUP,
        );
        assert_eq!(ladder.user_context_flag, 1);
        assert_eq!(ladder.system_routine, 0xAAAA_0001);
        assert_eq!(ladder.start_routine, 0xBBBB_0002);
        assert_eq!(ladder.start_context, 0xCCCC_0003);
        // One pop (the system routine) plus the cdecl 8-byte argument drop leaves the esp exactly
        // at the flag word: the stub's documented consumption.
        assert_eq!(ladder.stub_entry_esp() + 4 + 8, ladder.user_context_flag_at);
    }

    // A5: the kernel-thread variant.

    /// A kernel thread's ladder is the identical argument ladder minus the trap-frame rung, with
    /// the flag saying there is no user context — the stub halts if the system routine returns.
    #[test]
    fn kernel_thread_variant_drops_the_trap_frame() {
        let top = gate_slot_top(2);
        let ladder = build_ladder(top, &params(None), STARTUP);
        assert!(ladder.trap_frame_at.is_none());
        assert!(ladder.trap_frame.is_none());
        assert_eq!(ladder.user_context_flag, 0);
        assert_eq!(ladder.user_context_flag_at, top - 4);
        assert_eq!(ladder.start_context_at, top - 8);
        assert_eq!(ladder.start_routine_at, top - 12);
        assert_eq!(ladder.system_routine_at, top - 16);
        assert_eq!(ladder.ret_at, top - 20);
        assert_eq!(ladder.eflags_at, top - 24);
        assert_eq!(ladder.switch_frame_at(), top - 24);
        // The same entry invariant as the user variant.
        assert_eq!(ladder.switch_frame_at() + 8, ladder.stub_entry_esp());
    }

    // A6: the thread's stack pointers (the data the builder sets).

    /// After a build, the thread's saved stack pointer is the switch frame's base — the lowest
    /// planted word — and the stack top (what becomes `esp0`) is untouched above it. The host
    /// models the pointer arithmetic the target's `plant` performs.
    #[test]
    fn the_threads_saved_stack_pointer_is_the_switch_frame() {
        let user = build_ladder(
            gate_slot_top(0),
            &params(Some(UserStart {
                eip: 0x0040_1234,
                esp: 0x0030_8000,
            })),
            STARTUP,
        );
        let kernel = build_ladder(gate_slot_top(0), &params(None), STARTUP);
        assert_eq!(user.switch_frame_at(), gate_slot_top(0) - 84);
        assert_eq!(kernel.switch_frame_at(), gate_slot_top(0) - 24);
        for ladder in [&user, &kernel] {
            assert!(ladder.switch_frame_at() < gate_slot_top(0));
            // Nothing is planted below the switch frame: the full remaining stack is free for the
            // system routine.
            assert!(ladder.planted_addresses()[0] == ladder.eflags_at);
        }
    }

    // A7: the frame fits the slot.

    /// Every planted word lies inside the thread's slot, above the guard page and below the top,
    /// and no two planted words share an address: the builder never writes the guard page (a kernel
    /// stack overrun faults instead of corrupting the slot below).
    #[test]
    fn the_frame_fits_the_slot() {
        for index in [0u32, 1, 7, 112] {
            let top = gate_slot_top(index);
            let base = gate_slot_base(index);
            let ladder = build_ladder(
                top,
                &params(Some(UserStart {
                    eip: 0x0040_1234,
                    esp: 0x0030_8000,
                })),
                STARTUP,
            );

            let mut words = ladder.planted_addresses();
            assert!(
                &words[0] >= &(base + PAGE_SIZE),
                "below the guard page's top"
            );
            assert!(words.last().unwrap() < &top, "past the stack top");
            if let Some(frame_at) = ladder.trap_frame_at {
                assert!(frame_at >= base + PAGE_SIZE && frame_at < top);
            }
            // No overlaps: strictly ascending once sorted, with no repeated address.
            words.sort_unstable();
            for pair in words.windows(2) {
                assert_ne!(pair[0], pair[1], "a planted word overlaps");
            }
            assert_eq!(words.len(), 6);
            // The trap frame's 15 words and the 6 ladder words are disjoint ranges: the highest
            // ladder word sits below the frame's base.
            if let Some(frame_at) = ladder.trap_frame_at {
                assert!(
                    words.last().unwrap() < &frame_at,
                    "ladder words inside the frame"
                );
            }
        }
        // The stride and slot arithmetic the bounds rely on.
        assert_eq!(GATE_SLOT_STRIDE, 0x9000);
        assert_eq!(gate_slot_top(0), crate::mem::paging::GATE_STACK_TOP);
    }
}
