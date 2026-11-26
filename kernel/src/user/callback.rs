//! User-mode callbacks: the kernel calling into user mode and waiting for the answer (Windows
//! 2000's KeUserModeCallback, KiCallUserMode and NtCallbackReturn), the way win32k reaches a window
//! procedure.
//!
//! [`call_user_mode`] copies the input block below the issuing level's user stack pointer, under a
//! four-word header (a dummy return slot, the API number, the block's address and length), saves
//! the kernel's place in a [`CallbackFrame`] on the kernel stack, and leaves for ntdll's
//! KiUserCallbackDispatcher, which calls `PEB.KernelCallbackTable[api]`. Leaving moves the
//! thread's stack top (its `initial_stack`, the TSS `esp0`) down to just below the frame: the
//! callback's system calls enter there, a nested level under the frames that issued it, and may
//! issue callbacks of their own. The frames chain through the thread record's `callback_stack`
//! (KTHREAD's CallbackStack).
//!
//! NtCallbackReturn ([`callback_return`]) pops the innermost frame: the stack top goes back, and
//! the issuer resumes with the routine's output block (a user address, which the issuer probes and
//! copies) and status; the nested level's frames are given up. With no callback outstanding it is
//! STATUS_NO_CALLBACK_ACTIVE. The exit to user mode goes through the service exit's windows, as
//! Windows 2000's KiCallUserMode leaves through KiServiceExit: a pending dispatch and the user-APC
//! delivery (an armed APC runs before the callback's routine, at its level).
//!
//! An exception in the callback is dispatched in user mode along the thread's SEH chain, which goes
//! on into the issuer's user frames. The dispatcher's own registration pops the callback when an
//! unwind passes through it: NtCallbackReturn with STATUS_CALLBACK_POP_STACK, which also makes the
//! issuing level's return to user mode resume the unwind where it made that call. So the issuer
//! gets the status, finishes and returns, and no kernel frame is left behind (Windows 2000 itself
//! leaves them until the thread ends; later versions pop them this way). A thread that ends inside
//! a callback, at whatever depth, gives up the levels under it with its kernel stack.
//!
//! A callback needs [`CALLBACK_ROOM`] of kernel stack below the issuer: a GUI thread's large stack
//! grows to give it ([`crate::mem::kstacks::grow`]); when it cannot (an ordinary stack, or a large
//! one at its 104 KiB) the callback is refused with STATUS_STACK_OVERFLOW (Windows 2000's answer
//! when its kernel stack cannot grow further).
//!
//! The thread's stack words change at the dispatch level, the TSS's `esp0` with them, as the
//! context switch installs them: they are the running thread's, on its own processor.

use super::TrapFrame;
use crate::status::*;

#[cfg(feature = "callback-smoke")]
pub mod smoke;

/// The kernel stack a callback needs below its issuer: Windows 2000's KERNEL_LARGE_STACK_COMMIT,
/// what KiCallUserMode makes sure of before it leaves.
pub const CALLBACK_ROOM: u32 = 12 * 1024;

/// The header under the input block on the user stack: KiUserCallbackDispatcher's dummy return
/// slot, the API number, the block's address and its length.
pub const HEADER_WORDS: usize = 4;

/// The room left between the issuer's saved stack pointer and the callback level's stack top.
pub const LEVEL_GAP: u32 = 16;

/// What a callback level's first exit to user mode pops: the saved segments (GS, FS, ES, DS, as the
/// gate stubs keep them below the frame) and the trap frame.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct EntryImage {
    pub segments: [u32; 4],
    pub frame: TrapFrame,
}

/// The image's size: the assembly copies it in dwords.
pub const ENTRY_IMAGE_SIZE: u32 = core::mem::size_of::<EntryImage>() as u32;

const _: () = assert!(ENTRY_IMAGE_SIZE == 76);

/// An outstanding callback's frame, on the issuer's kernel stack (KiCallUserMode's).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CallbackFrame {
    /// The issuer's kernel stack pointer, its nonvolatile registers above it: where the return
    /// resumes. The assembly stores it first.
    pub saved_esp: u32,
    /// The issuing level's stack top, which the return puts back.
    pub initial_stack: u32,
    /// The next outer callback's frame, zero for none.
    pub previous: u32,
    /// The routine's output block, as NtCallbackReturn gave it: a user address and a length.
    pub output: u32,
    pub length: u32,
}

const _: () = assert!(core::mem::offset_of!(CallbackFrame, saved_esp) == 0);

/// The thread record's words a callback moves: its stack top and its innermost callback frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stacks {
    pub initial_stack: u32,
    pub callback_stack: u32,
}

/// A callback's entry: `frame` (at `at`) records the issuing level's stack top and the next outer
/// frame, and becomes the innermost; the stack top moves to `top`, the new level's.
pub fn enter(stacks: &mut Stacks, frame: &mut CallbackFrame, at: u32, top: u32) {
    frame.initial_stack = stacks.initial_stack;
    frame.previous = stacks.callback_stack;
    stacks.callback_stack = at;
    stacks.initial_stack = top;
}

/// A callback's return: the issuing level's stack top and the next outer frame come back.
pub fn leave(stacks: &mut Stacks, frame: &CallbackFrame) {
    stacks.initial_stack = frame.initial_stack;
    stacks.callback_stack = frame.previous;
}

/// The callback level's stack top for an issuer whose saved stack pointer is `saved_esp`: below it
/// by [`LEVEL_GAP`] at least, 16-byte aligned (the assembly computes the same).
pub const fn level_top(saved_esp: u32) -> u32 {
    (saved_esp - LEVEL_GAP) & !15
}

/// The trap frame of a level whose stack top is `top`: the gate's entry builds it right under it.
pub const fn trap_frame_below(top: u32) -> u32 {
    top - core::mem::size_of::<TrapFrame>() as u32
}

/// Whether a callback issued at kernel stack pointer `esp` has room, the stack's lowest mapped
/// byte at `limit`.
pub fn has_room(esp: u32, limit: u32) -> bool {
    esp.checked_sub(limit)
        .is_some_and(|room| room >= CALLBACK_ROOM)
}

/// The user stack a callback starts on: the input block, dword-rounded, below the issuing level's
/// dword-aligned stack pointer, and the header under it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserImage {
    /// Where the callback's ESP starts: the header.
    pub esp: u32,
    /// Where the input block goes.
    pub input: u32,
    pub header: [u32; HEADER_WORDS],
}

/// The user stack image for an `length`-byte input to API `api` below `user_esp`.
pub fn user_image(user_esp: u32, api: u32, length: u32) -> UserImage {
    let input = (user_esp & !3).wrapping_sub(length.wrapping_add(3) & !3);
    UserImage {
        esp: input.wrapping_sub(4 * HEADER_WORDS as u32),
        input,
        header: [0, api, input, length],
    }
}

/// What a callback answers its issuer: the routine's status (or the refusal's), and its output
/// block (a user address and a length, zero for none), for the issuer to probe and copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reply {
    pub status: NtStatus,
    pub output: u32,
    pub length: u32,
}

impl Reply {
    /// A callback that never ran: `status` and no output.
    pub fn refused(status: NtStatus) -> Reply {
        Reply {
            status,
            output: 0,
            length: 0,
        }
    }
}

#[cfg(target_arch = "x86")]
#[cfg_attr(not(feature = "callback-smoke"), allow(unused_imports))]
pub use target::{call_user_mode, call_user_mode_with_room, outstanding};

#[cfg(target_arch = "x86")]
mod target {
    use super::*;
    use crate::level::{raised, At, Dispatch, Passive};
    use crate::sched::DISPATCHER;
    use crate::user::args::UserPtr;

    unsafe extern "C" {
        /// Save the issuer's place in `frame`, move to the callback level and enter user mode with
        /// `image`; returns the status NtCallbackReturn resumes it with.
        fn f2k_call_user_mode(frame: *mut CallbackFrame, image: *const EntryImage) -> u32;
        /// Resume the issuer saved at `saved_esp` with `status`.
        fn f2k_callback_resume(saved_esp: u32, status: u32) -> !;
    }

    /// The running thread's stack words.
    fn stacks(dispatch: &mut At<Dispatch>) -> Stacks {
        let record = DISPATCHER
            .get(dispatch)
            .thread(crate::sched::current_thread());
        Stacks {
            initial_stack: record.initial_stack,
            callback_stack: record.callback_stack,
        }
    }

    /// Install `stacks` as the running thread's: its record's words and the processor's ring-0
    /// stack.
    fn install(dispatch: &mut At<Dispatch>, stacks: Stacks) {
        let record = DISPATCHER
            .get(dispatch)
            .thread_mut(crate::sched::current_thread());
        record.initial_stack = stacks.initial_stack;
        record.callback_stack = stacks.callback_stack;
        crate::pcr::pcr()
            .tables
            .set_ring0_stack(stacks.initial_stack, dispatch);
    }

    /// The assembly's call-out, on its way to user mode: `frame` becomes the innermost callback,
    /// and the stack top moves to `top`.
    extern "C" fn callback_enter(frame: *mut CallbackFrame, top: u32) {
        raised::<Dispatch, _>(|dispatch| {
            let mut words = stacks(dispatch);
            // SAFETY: the issuer's frame, on this kernel stack above the assembly's, live until the
            // callback returns; nothing else reaches it meanwhile.
            let frame_ref = unsafe { &mut *frame };
            debug_assert_eq!(
                top,
                level_top(frame_ref.saved_esp),
                "the assembly's level top"
            );
            enter(&mut words, frame_ref, frame as u32, top);
            install(dispatch, words);
        });
    }

    /// How many callbacks the running thread has outstanding (the smoke boot's check).
    #[cfg_attr(not(feature = "callback-smoke"), allow(dead_code))]
    pub fn outstanding() -> u32 {
        let mut at = raised::<Dispatch, _>(|dispatch| stacks(dispatch).callback_stack);
        let mut count = 0;
        while at != 0 {
            count += 1;
            // SAFETY: an outstanding callback's frame, on this thread's kernel stack, above the
            // running code.
            at = unsafe { (*(at as *const CallbackFrame)).previous };
        }
        count
    }

    /// The running thread's kernel stack pointer.
    fn kernel_esp() -> u32 {
        let esp: u32;
        // SAFETY: reads a register.
        unsafe { core::arch::asm!("mov {}, esp", out(reg) esp, options(nomem, nostack)) };
        esp
    }

    /// KeUserModeCallback: call `PEB.KernelCallbackTable[api]` in user mode with a copy of `input`
    /// (its parts one after the other, one block) and wait for its answer (see the module notes).
    /// The running thread is in a system service (the passive level's token is its), and holds
    /// nothing a nested system call could want. Refused with STATUS_STACK_OVERFLOW when the kernel
    /// stack lacks [`CALLBACK_ROOM`], with STATUS_ACCESS_VIOLATION when the user stack or the TEB
    /// cannot be written.
    pub fn call_user_mode(passive: &mut At<Passive>, api: u32, input: &[&[u8]]) -> Reply {
        call_user_mode_with_room(passive, api, input, 0)
    }

    /// [`call_user_mode`], the block `room` bytes longer than `input`: room after the input for the
    /// routine to write into (its contents whatever the user stack held there), which its output
    /// block may then point at (`__fnOUTSTRING`'s buffer).
    pub fn call_user_mode_with_room(
        _passive: &mut At<Passive>,
        api: u32,
        input: &[&[u8]],
        room: u32,
    ) -> Reply {
        let (words, gate, teb) = raised::<Dispatch, _>(|dispatch| {
            let record = DISPATCHER
                .get(dispatch)
                .thread(crate::sched::current_thread());
            (
                Stacks {
                    initial_stack: record.initial_stack,
                    callback_stack: record.callback_stack,
                },
                record.gate_stack,
                record.teb_va,
            )
        });
        // The issuing level's trap frame, the gate's, and the segments the stub saved under it.
        let at = trap_frame_below(words.initial_stack);
        // SAFETY: the running thread entered its current level from user mode through a gate, which
        // built the frame right under the level's stack top and the four segment words under it;
        // they stay put while the thread runs above them. Read by value: the frame's own borrow is
        // its service's.
        let mut image = unsafe {
            EntryImage {
                segments: core::ptr::read((at - 16) as *const [u32; 4]),
                frame: core::ptr::read(at as *const TrapFrame),
            }
        };
        assert_eq!(
            image.frame.cs & 3,
            3,
            "a callback is issued from a system call"
        );
        assert!(
            !crate::sched::attach::running_attached(),
            "a callback runs on its own process's address space"
        );

        // A GUI thread's large stack grows to make the room (Windows 2000's MmGrowKernelStack);
        // an ordinary one, or one grown all it may, refuses the callback.
        let esp = kernel_esp();
        if !has_room(esp, gate.limit()) {
            let mut grown = gate;
            if !grown.is_large()
                || !crate::mem::kstacks::grow(&mut grown, esp.saturating_sub(CALLBACK_ROOM))
            {
                return Reply::refused(STATUS_STACK_OVERFLOW);
            }
            raised::<Dispatch, _>(|dispatch| {
                DISPATCHER
                    .get(dispatch)
                    .thread_mut(crate::sched::current_thread())
                    .gate_stack = grown;
            });
        }
        let length: usize = input.iter().map(|part| part.len()).sum();
        let Some(length) = u32::try_from(length)
            .ok()
            .and_then(|length| length.checked_add(room))
        else {
            return Reply::refused(STATUS_ACCESS_VIOLATION);
        };
        let user = user_image(image.frame.user_esp, api, length);
        let exception_list = UserPtr::<u32>::at(teb);
        let Ok(chain) = exception_list.read() else {
            return Reply::refused(STATUS_ACCESS_VIOLATION);
        };
        // The pages under the user stack pointer touched top down, so that a block longer than a
        // page grows the stack one guard at a time, as the routine's own frames would.
        let page_mask = !(crate::mem::paging::PAGE_SIZE - 1);
        let mut page = Some(image.frame.user_esp.wrapping_sub(1) & page_mask);
        while let Some(at) = page.filter(|&at| at >= user.esp & page_mask) {
            if super::super::syscall::write_user(at.max(user.esp), &[0]).is_err() {
                return Reply::refused(STATUS_ACCESS_VIOLATION);
            }
            page = at.checked_sub(crate::mem::paging::PAGE_SIZE);
        }
        let mut at = user.input;
        for part in input {
            if super::super::syscall::write_user(at, part).is_err() {
                return Reply::refused(STATUS_ACCESS_VIOLATION);
            }
            at += part.len() as u32;
        }
        if UserPtr::at(user.esp).write(user.header).is_err() {
            return Reply::refused(STATUS_ACCESS_VIOLATION);
        }
        image.frame.eip = crate::exec::modules::callback_dispatcher();
        image.frame.user_esp = user.esp;

        // The service exit's windows, as KiServiceExit's: a pending dispatch, then an armed user
        // APC, which runs first (a terminated thread's exit APC ends the thread here).
        crate::sched::dispatcher::deliver_pending();
        super::super::apc::deliver(&mut image.frame);

        let mut frame = CallbackFrame::default();
        let status = {
            // Masked from the frame's link to the `iretd` (and from the return to here): the stack
            // top and the TSS change together, and no switch comes between.
            let _masked = crate::pcr::pcr().mask_guard();
            // SAFETY: `frame` and `image` are this function's, live across the call; the callback
            // level starts below this frame, and its return resumes exactly here.
            unsafe { f2k_call_user_mode(&raw mut frame, &raw const image) }
        };
        // The return wrote the frame through the address the assembly was handed.
        let status = NtStatus(status);
        // The chain head as it was (the dispatcher's own registration gone with the callback),
        // unless an unwind popped it: the unwind keeps the chain itself.
        if status != STATUS_CALLBACK_POP_STACK {
            let _ = exception_list.write(chain);
        }
        Reply {
            status,
            output: frame.output,
            length: frame.length,
        }
    }

    /// NtCallbackReturn's pop, for the innermost callback: the output block recorded, the issuing
    /// level's stack top back, and the issuer resumed. With STATUS_CALLBACK_POP_STACK, the issuing
    /// level's return to user mode resumes the caller's context (`current`, its segments under it).
    pub(super) fn pop(
        current: *const TrapFrame,
        output: u32,
        length: u32,
        status: u32,
    ) -> NtStatus {
        let at = raised::<Dispatch, _>(|dispatch| stacks(dispatch).callback_stack);
        if at == 0 {
            return STATUS_NO_CALLBACK_ACTIVE;
        }
        // SAFETY: the innermost callback's frame, on this kernel stack above the running level.
        let frame = unsafe { &mut *(at as *mut CallbackFrame) };
        frame.output = output;
        frame.length = length;
        if status == STATUS_CALLBACK_POP_STACK.0 {
            let issuing = trap_frame_below(frame.initial_stack) - 16;
            // SAFETY: both images are the gates' (frame and saved segments), on this kernel stack;
            // the issuing level's is not running, and the issuer that resumes reads it afresh.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    (current as u32 - 16) as *const EntryImage,
                    issuing as *mut EntryImage,
                    1,
                )
            };
        }
        let saved_esp = raised::<Dispatch, _>(|dispatch| {
            let mut words = stacks(dispatch);
            leave(&mut words, frame);
            install(dispatch, words);
            frame.saved_esp
        });
        // SAFETY: the issuer saved its place at `saved_esp`, above this level's frames, which are
        // given up; the ledger stands as at the issue (a service's: passive, masked).
        unsafe { f2k_callback_resume(saved_esp, status) }
    }

    // The issuer's side: save the nonvolatile registers and the stack pointer in the frame, move
    // the stack top to the callback level (the call-out, at the dispatch level), then build the
    // exit image there and leave through the gates' exit tail. The resume is the frame's: the
    // registers back from the saved stack pointer, and a return with the status.
    core::arch::global_asm!(
        ".section .text.f2k_call_user_mode, \"ax\"",
        ".global f2k_call_user_mode",
        "f2k_call_user_mode:",
        "    push ebp",
        "    push ebx",
        "    push esi",
        "    push edi",
        "    mov esi, [esp + 20]",
        "    mov edi, [esp + 24]",
        "    mov [esi], esp",
        "    mov eax, esp",
        "    sub eax, {gap}",
        "    and eax, -16",
        "    push eax",
        "    push esi",
        "    call {enter}",
        "    add esp, 8",
        "    mov eax, [esi]",
        "    sub eax, {gap}",
        "    and eax, -16",
        "    sub eax, {image}",
        "    mov esp, eax",
        "    mov esi, edi",
        "    mov edi, esp",
        "    mov ecx, {image_words}",
        "    cld",
        "    rep movsd",
        "    pop eax",
        "    mov gs, ax",
        "    pop eax",
        "    mov fs, ax",
        "    pop eax",
        "    mov es, ax",
        "    pop eax",
        "    mov ds, ax",
        "    popad",
        "    add esp, 8",
        "    iretd",
        ".global f2k_callback_resume",
        "f2k_callback_resume:",
        "    mov eax, [esp + 8]",
        "    mov esp, [esp + 4]",
        "    pop edi",
        "    pop esi",
        "    pop ebx",
        "    pop ebp",
        "    ret",
        gap = const LEVEL_GAP,
        image = const ENTRY_IMAGE_SIZE,
        image_words = const ENTRY_IMAGE_SIZE / 4,
        enter = sym callback_enter,
    );
}

/// NtCallbackReturn(Result, ResultLength, Status): the innermost user-mode callback answers its
/// issuer with the output block and the status, and never returns here; STATUS_NO_CALLBACK_ACTIVE
/// with none outstanding.
pub fn callback_return(
    call: &mut crate::nt::call::NtCall,
    output: crate::nt::call::UserAddr,
    length: u32,
    status: u32,
) -> crate::nt::call::NtResult {
    #[cfg(target_arch = "x86")]
    {
        let current: *const TrapFrame = call.frame();
        Err(target::pop(current, output.raw(), length, status))
    }
    #[cfg(not(target_arch = "x86"))]
    {
        let _ = (call, output, length, status);
        Err(STATUS_NO_CALLBACK_ACTIVE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Entry links the frame in front of the chain and moves the stack top; return undoes both,
    /// level by level, back to the thread's own.
    #[test]
    fn the_chain_nests_and_unwinds_level_by_level() {
        let own = Stacks {
            initial_stack: 0xE000_9000,
            callback_stack: 0,
        };
        let mut stacks = own;
        let mut outer = CallbackFrame::default();
        enter(&mut stacks, &mut outer, 0xE000_8800, 0xE000_8700);
        assert_eq!(
            stacks,
            Stacks {
                initial_stack: 0xE000_8700,
                callback_stack: 0xE000_8800
            }
        );
        assert_eq!((outer.initial_stack, outer.previous), (0xE000_9000, 0));

        let mut inner = CallbackFrame::default();
        enter(&mut stacks, &mut inner, 0xE000_8100, 0xE000_8000);
        assert_eq!(
            (inner.initial_stack, inner.previous),
            (0xE000_8700, 0xE000_8800)
        );
        assert_eq!(stacks.callback_stack, 0xE000_8100);

        leave(&mut stacks, &inner);
        assert_eq!(
            stacks,
            Stacks {
                initial_stack: 0xE000_8700,
                callback_stack: 0xE000_8800
            }
        );
        leave(&mut stacks, &outer);
        assert_eq!(stacks, own);
    }

    /// The input block sits under the dword-aligned user stack pointer, rounded up to dwords, the
    /// header (dummy return, API, address, length) under it: KiUserCallbackDispatcher's layout.
    #[test]
    fn the_user_image_puts_the_header_under_the_input() {
        let image = user_image(0x0012_FF02, 0x7F, 10);
        assert_eq!(image.input, 0x0012_FF00 - 12);
        assert_eq!(image.esp, image.input - 16);
        assert_eq!(image.header, [0, 0x7F, image.input, 10]);
        let empty = user_image(0x0012_FF00, 2, 0);
        assert_eq!(empty.input, 0x0012_FF00);
        assert_eq!(empty.header, [0, 2, 0x0012_FF00, 0]);
    }

    /// The level's stack top is under the issuer's saved stack pointer, aligned, and the gate's
    /// frame (the next entry's) and the exit image fit between it and nothing above.
    #[test]
    fn the_level_starts_under_the_issuer() {
        for saved in [0xE000_8F00, 0xE000_8F0C, 0xE000_8F14] {
            let top = level_top(saved);
            assert!(top + LEVEL_GAP <= saved);
            assert_eq!(top % 16, 0);
            assert!(saved - top < LEVEL_GAP + 16);
        }
        assert_eq!(trap_frame_below(0xE000_8000), 0xE000_8000 - 60);
        assert_eq!(ENTRY_IMAGE_SIZE, 16 + 60);
    }

    /// The room check: the issuer's stack pointer at least CALLBACK_ROOM above the stack's lowest
    /// byte; a pointer below the limit has none.
    #[test]
    fn the_room_check_wants_a_large_stack_commit() {
        let limit = 0xE000_1000;
        assert!(has_room(limit + CALLBACK_ROOM, limit));
        assert!(!has_room(limit + CALLBACK_ROOM - 4, limit));
        assert!(!has_room(limit - 4, limit));
        assert_eq!(CALLBACK_ROOM, 0x3000);
    }

    /// The service with no callback outstanding (and on the host, always).
    #[test]
    fn a_return_with_no_callback_is_refused() {
        let mut frame = TrapFrame::default();
        let mut passive = crate::level::passive_for_test();
        let mut call = crate::nt::call::NtCall::new(&mut frame, &mut passive);
        assert_eq!(
            callback_return(&mut call, crate::nt::call::UserAddr(0), 0, 0),
            Err(STATUS_NO_CALLBACK_ACTIVE)
        );
        assert_eq!(STATUS_NO_CALLBACK_ACTIVE.0, 0xC000_0258);
        assert_eq!(STATUS_CALLBACK_POP_STACK.0, 0xC000_0423);
        assert_eq!(STATUS_STACK_OVERFLOW.0, 0xC000_00FD);
    }

    /// The refusal answers no output.
    #[test]
    fn a_refused_callback_has_no_output() {
        let reply = Reply::refused(STATUS_STACK_OVERFLOW);
        assert_eq!((reply.output, reply.length), (0, 0));
    }
}
