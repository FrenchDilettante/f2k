//! The startup frame builder: a fresh thread's first kernel stack contents, as pure layout.
//!
//! What the switch and the startup stub consume, as `#[repr(C)]` records planted at the stack top
//! ([`InitialFrame`], [`UserInitialFrame`]): a trap frame carrying the thread's initial user state
//! (user threads), the four words the stub pops as its arguments, and the switch frame — EFLAGS
//! lowest, the startup stub's address above — whose base becomes the thread's saved stack pointer.
//! The layouts are host-tested; only the planting touches memory.

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

/// A user thread's initial user-mode state: the entry point, the stack top it runs on, and its
/// integer registers — zero, unless the thread's creator gave a CONTEXT (NtCreateThread's: the main
/// thread's EAX names the image's entry point for kernel32's BaseProcessStartThunk, a child's EAX
/// and EBX its start address and parameter for BaseThreadStartThunk).
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct UserStart {
    pub eip: u32,
    pub esp: u32,
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
    pub esi: u32,
    pub edi: u32,
    pub ebp: u32,
}

/// A created thread's user stack, as its creator allocated it (NtCreateThread's INITIAL_TEB):
/// StackBase (one past its top), StackLimit (the lowest committed byte, above the guard page) and
/// StackAllocationBase (the reservation's base, which the thread's record keeps so the reservation
/// goes back once the record is reused).
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct InitialStack {
    pub base: u32,
    pub limit: u32,
    pub allocation_base: u32,
}

/// The planted trap frame for a user thread's initial state: the GP slots the start gives (zero
/// otherwise: kernel pointers must not leak into user mode), no vector or error code, RPL 3 in both
/// segment slots, interrupts enabled.
pub fn user_trap_frame(user: &UserStart) -> TrapFrame {
    TrapFrame {
        edi: user.edi,
        esi: user.esi,
        ebp: user.ebp,
        esp: 0,
        ebx: user.ebx,
        edx: user.edx,
        ecx: user.ecx,
        eax: user.eax,
        vector: 0,
        error_code: 0,
        eip: user.eip,
        cs: USER_CODE_SELECTOR as u32 | 3,
        eflags: PLANTED_EFLAGS,
        user_esp: user.esp,
        user_ss: USER_DATA_SELECTOR as u32 | 3,
    }
}

/// A fresh thread's first kernel-stack contents, lowest word first: the switch frame the first
/// switch into the thread consumes (`popfd`, then `ret` into the startup stub), then the words the
/// stub consumes as its arguments. Planted once, at the top of the thread's kernel stack (a user
/// thread's under its trap frame: [`UserInitialFrame`]); its base becomes the thread's saved stack
/// pointer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct InitialFrame {
    /// The switch frame's EFLAGS word, its base.
    pub eflags: u32,
    /// The switch frame's return address: the startup stub's.
    pub ret: u32,
    /// The system routine, which the stub pops into the register it calls through: the stub's
    /// entry stack pointer is this word's address.
    pub system_routine: u32,
    /// The system routine's first argument, already in cdecl stack-argument position.
    pub start_routine: u32,
    /// The system routine's second argument.
    pub start_context: u32,
    /// The user-context flag the stub pops after the call: 1 when a trap frame follows above, 0
    /// otherwise.
    pub user_context: u32,
}

/// A user thread's first kernel-stack contents: the initial frame, then the trap frame carrying
/// its initial user state, which the stub leaves through (`popad`, the vector and error pad
/// dropped, `iretd`).
#[repr(C)]
pub struct UserInitialFrame {
    pub frame: InitialFrame,
    pub trap: TrapFrame,
}

/// A thread's initial frame: the start parameters in the stub's argument words, the startup stub's
/// address `startup_addr` as the switch frame's return address.
pub fn initial_frame(params: &StartParams, startup_addr: u32) -> InitialFrame {
    InitialFrame {
        eflags: PLANTED_EFLAGS,
        ret: startup_addr,
        system_routine: params.system_routine,
        start_routine: params.start_routine,
        start_context: params.start_context,
        user_context: params.user.is_some() as u32,
    }
}

/// The bytes a thread's first kernel-stack contents take below its stack top: the initial frame,
/// and a user thread's trap frame above it.
pub fn planted_size(params: &StartParams) -> u32 {
    match params.user {
        Some(_) => core::mem::size_of::<UserInitialFrame>() as u32,
        None => core::mem::size_of::<InitialFrame>() as u32,
    }
}

/// Plant the thread's first kernel-stack contents at the top of its stack and set its saved stack
/// pointer to their base. Target only: the frame is written to the stack the switch will load.
///
/// # Safety
///
/// `thread.initial_stack` names the top of the thread's own kernel-stack slot, mapped in the
/// current address space, with nothing on it.
#[cfg(target_arch = "x86")]
pub unsafe fn plant(thread: &mut Thread, params: &StartParams) {
    let base = thread.initial_stack - planted_size(params);
    let startup_addr = core::ptr::addr_of!(super::switch::THREAD_STARTUP) as u32;
    let frame = initial_frame(params, startup_addr);
    // SAFETY: the caller's contract: `base` lies inside the thread's freshly mapped slot (the
    // frame is far smaller than it), 4-byte aligned below the page-aligned top, and nothing else
    // reaches the slot until the thread first runs.
    unsafe {
        match &params.user {
            Some(user) => (base as *mut UserInitialFrame).write(UserInitialFrame {
                frame,
                trap: user_trap_frame(user),
            }),
            None => (base as *mut InitialFrame).write(frame),
        }
    }
    thread.kernel_stack = base;
}

#[cfg(test)]
mod tests {
    use core::mem::{offset_of, size_of};

    use super::*;
    use crate::mem::paging::{gate_slot_base, gate_slot_top, GATE_SLOT_STRIDE, PAGE_SIZE};

    /// A thread's parameters, with distinct recognizable values.
    fn params(user: Option<UserStart>) -> StartParams {
        StartParams {
            system_routine: 0xAAAA_0001,
            start_routine: 0xBBBB_0002,
            start_context: 0xCCCC_0003,
            user,
        }
    }

    /// A user thread's start, with the entry point and stack its tests use.
    fn user() -> Option<UserStart> {
        Some(UserStart {
            eip: 0x0040_1234,
            esp: 0x0012_8000,
            ..Default::default()
        })
    }

    const STARTUP: u32 = 0x00DE_0001;

    // A1: the user-thread word offsets.

    /// A user thread's first contents: the trap frame in the 15 words below the top, the argument
    /// words in pop order below it, the switch frame below those (EFLAGS lowest), and the stub's
    /// entry esp eight bytes above the switch frame's base.
    #[test]
    fn user_thread_frame_word_offsets() {
        assert_eq!(size_of::<InitialFrame>(), 6 * 4);
        assert_eq!(size_of::<UserInitialFrame>(), 21 * 4);
        assert_eq!(planted_size(&params(user())), 84);
        // Relative to the stack top, which the frame ends at.
        let below_top = |offset: usize| 84 - offset;
        assert_eq!(below_top(offset_of!(UserInitialFrame, trap)), 60);
        let frame = offset_of!(UserInitialFrame, frame);
        assert_eq!(
            below_top(frame + offset_of!(InitialFrame, user_context)),
            64
        );
        assert_eq!(
            below_top(frame + offset_of!(InitialFrame, start_context)),
            68
        );
        assert_eq!(
            below_top(frame + offset_of!(InitialFrame, start_routine)),
            72
        );
        assert_eq!(
            below_top(frame + offset_of!(InitialFrame, system_routine)),
            76
        );
        assert_eq!(below_top(frame + offset_of!(InitialFrame, ret)), 80);
        assert_eq!(below_top(frame + offset_of!(InitialFrame, eflags)), 84);

        // The stub's entry stack is the system-routine word: the switch's `popfd; ret` consumes
        // the two switch-frame words and lands exactly there.
        assert_eq!(offset_of!(InitialFrame, system_routine), 8);

        // The cdecl positions: at the stub's call the two argument words sit in argument position
        // above the consumed system word — the routine first, the context second.
        assert_eq!(offset_of!(InitialFrame, start_routine), 8 + 4);
        assert_eq!(offset_of!(InitialFrame, start_context), 8 + 8);
    }

    // A2: the planted switch frame.

    /// The switch frame's words: EFLAGS with bit 1 and the interrupt flag, and the startup stub's
    /// address in the return slot — what the first switch's uniform tail consumes.
    #[test]
    fn planted_switch_frame() {
        let frame = initial_frame(&params(user()), STARTUP);
        assert_eq!(frame.eflags, PLANTED_EFLAGS);
        assert_eq!(PLANTED_EFLAGS, 0x0202);
        assert_eq!(frame.eflags & 1 << 1, 1 << 1, "bit 1 must be set");
        assert_eq!(
            frame.eflags & 1 << 9,
            1 << 9,
            "the interrupt flag must be set"
        );
        assert_eq!(frame.ret, STARTUP);
        // The return slot sits directly above the EFLAGS word: the `popfd` then `ret` order.
        assert_eq!(offset_of!(InitialFrame, eflags), 0);
        assert_eq!(offset_of!(InitialFrame, ret), 4);
    }

    // A3: the planted trap frame's contents.

    /// The trap frame carries the thread's initial user state with RPL 3 in both segment slots,
    /// interrupts enabled, and nothing else: the register slots are zeroed (kernel pointers must
    /// not leak into user mode) and no vector or error code is set.
    #[test]
    fn planted_trap_frame_contents() {
        let frame = user_trap_frame(&user().unwrap());
        assert_eq!(frame.eip, 0x0040_1234);
        assert_eq!(frame.user_esp, 0x0012_8000);
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
        assert_eq!(size_of::<TrapFrame>(), 60);
        // A start with registers (a CONTEXT's) carries them into the frame.
        let frame = user_trap_frame(&UserStart {
            eip: 0x7C4E_1000,
            esp: 0x0012_FFFC,
            eax: 0x0040_1000,
            ebx: 0x1234,
            ..Default::default()
        });
        assert_eq!(
            (frame.eip, frame.user_esp, frame.eax, frame.ebx),
            (0x7C4E_1000, 0x0012_FFFC, 0x0040_1000, 0x1234)
        );
        assert_eq!(
            (frame.ecx, frame.edx, frame.esi, frame.edi, frame.ebp, frame.esp),
            (0, 0, 0, 0, 0, 0)
        );
    }

    // A4: the user-context flag and the argument words.

    /// The words above the stub's entry: the flag says a user context follows, and the argument
    /// words carry the start parameters in the exact order the stub pops them.
    #[test]
    fn user_context_flag_and_argument_words() {
        let frame = initial_frame(&params(user()), STARTUP);
        assert_eq!(frame.user_context, 1);
        assert_eq!(frame.system_routine, 0xAAAA_0001);
        assert_eq!(frame.start_routine, 0xBBBB_0002);
        assert_eq!(frame.start_context, 0xCCCC_0003);
        // One pop (the system routine) plus the cdecl 8-byte argument drop leaves the esp exactly
        // at the flag word, and its pop at the trap frame: the stub's documented consumption.
        assert_eq!(
            offset_of!(InitialFrame, system_routine) + 4 + 8,
            offset_of!(InitialFrame, user_context)
        );
        assert_eq!(
            offset_of!(InitialFrame, user_context) + 4,
            offset_of!(UserInitialFrame, trap)
        );
    }

    // A5: the kernel-thread variant.

    /// A kernel thread's contents are the identical initial frame without the trap frame above
    /// it, with the flag saying there is no user context — the stub halts if the system routine
    /// returns.
    #[test]
    fn kernel_thread_variant_drops_the_trap_frame() {
        let frame = initial_frame(&params(None), STARTUP);
        assert_eq!(frame.user_context, 0);
        assert_eq!(planted_size(&params(None)), 24);
        // The flag is the top word, the switch frame's base six words below the top.
        assert_eq!(offset_of!(InitialFrame, user_context) + 4, 24);
    }

    // A6: the thread's stack pointers (the data the builder sets).

    /// After a build, the thread's saved stack pointer is the switch frame's base — the lowest
    /// planted word — and the stack top (what becomes `esp0`) is untouched above it. The host
    /// models the pointer arithmetic the target's `plant` performs.
    #[test]
    fn the_threads_saved_stack_pointer_is_the_switch_frame() {
        let top = gate_slot_top(0);
        assert_eq!(top - planted_size(&params(user())), top - 84);
        assert_eq!(top - planted_size(&params(None)), top - 24);
    }

    // A7: the frame fits the slot.

    /// The planted frame lies inside the thread's slot, above the guard page and ending at the
    /// top: the builder never writes the guard page (a kernel stack overrun faults instead of
    /// corrupting the slot below).
    #[test]
    fn the_frame_fits_the_slot() {
        for index in [0u32, 1, 7, 112] {
            let top = gate_slot_top(index);
            let base = gate_slot_base(index);
            for start in [params(user()), params(None)] {
                let planted = top - planted_size(&start);
                assert!(planted >= base + PAGE_SIZE, "below the guard page's top");
                assert!(planted < top);
                assert_eq!(planted % 4, 0, "word-aligned");
            }
        }
        // The stride and slot arithmetic the bounds rely on.
        assert_eq!(GATE_SLOT_STRIDE, 0x9000);
        assert_eq!(gate_slot_top(0), crate::mem::paging::GATE_STACK_TOP);
    }
}
