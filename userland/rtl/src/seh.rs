//! Structured exception handling's user-mode half, as Windows 2000's ntdll runs it: the search of a
//! thread's handlers for an exception (RtlDispatchException) and the unwind a handler that takes
//! one asks for (RtlUnwind), with x86 NT's semantics.
//!
//! A thread's handlers form a chain of registration records on its stack, `{next, handler}`, its
//! head in the TEB's first word (`fs:[0]`) and its end the all-ones marker. The kernel hands every
//! exception to ntdll's KiUserExceptionDispatcher with its EXCEPTION_RECORD and CONTEXT written on
//! the user stack; the dispatcher calls [`dispatch`], and resumes the context (NtContinue) when a
//! handler continued execution, or raises the exception's second chance (NtRaiseException,
//! FirstChance FALSE: the process ends with the code) when none did.
//!
//! **The search** walks the chain head to end. A frame outside the thread's stack (the TEB's
//! StackLimit and StackBase) or misaligned stops it with EXCEPTION_STACK_INVALID (Windows 2000 has
//! no SafeSEH: the handler's own address is not checked). Each handler is called as the platform
//! calls it, `handler(record, frame, context, dispatcher_context)`, through ExecuteHandler2's
//! equivalent ([`Frames::execute_handler`]), which pushes a registration of the dispatcher's own
//! around the call, the frame it calls for saved beside it. An exception raised while a handler
//! runs reaches that registration first: its handler answers ExceptionNestedException with the
//! frame in the DispatcherContext ([`own_frame_handler`]), and the outer search marks the record
//! EXCEPTION_NESTED_CALL until it passes that frame again (x86 NT skips nothing: the frames between
//! are searched again, flagged). A handler that continues execution resumes the context, unless
//! the exception is noncontinuable: that raises STATUS_NONCONTINUABLE_EXCEPTION, the original
//! chained to it. A disposition that is none of the four raises STATUS_INVALID_DISPOSITION.
//!
//! **The unwind** calls every handler from the head down to the target frame once more, the record
//! marked EXCEPTION_UNWINDING (and EXCEPTION_EXIT_UNWIND for no target), unlinking each frame after
//! its call. RtlUnwind ignores its TargetIp on x86: it returns to its caller. A second unwind that
//! starts while a handler runs for the first reaches the first's own registration: its handler
//! answers ExceptionCollidedUnwind with the frame being unwound, and the second unwind goes on past
//! that frame. A target below the head (already passed) raises STATUS_INVALID_UNWIND_TARGET, a
//! frame outside the stack STATUS_BAD_STACK. With no target (an exit unwind) the walk runs to the
//! chain's end and the exception then takes its second chance.
//!
//! Everything here is over [`Frames`]: ntdll's implementation is the calling thread's memory and
//! TEB, the host tests' a fake stack whose handlers are closures that raise and unwind as C code
//! does.

/// The chain's end marker.
pub const END_OF_CHAIN: u32 = 0xFFFF_FFFF;

/// The exception flags.
pub const EXCEPTION_NONCONTINUABLE: u32 = 0x01;
pub const EXCEPTION_UNWINDING: u32 = 0x02;
pub const EXCEPTION_EXIT_UNWIND: u32 = 0x04;
pub const EXCEPTION_STACK_INVALID: u32 = 0x08;
pub const EXCEPTION_NESTED_CALL: u32 = 0x10;
/// Either unwind flag: the handler is called for an unwind, not a search.
pub const EXCEPTION_UNWIND: u32 = EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND;

/// The handlers' dispositions.
pub const EXCEPTION_CONTINUE_EXECUTION: u32 = 0;
pub const EXCEPTION_CONTINUE_SEARCH: u32 = 1;
pub const EXCEPTION_NESTED_EXCEPTION: u32 = 2;
pub const EXCEPTION_COLLIDED_UNWIND: u32 = 3;

/// The codes the walks raise themselves.
pub const STATUS_NONCONTINUABLE_EXCEPTION: u32 = 0xC000_0025;
pub const STATUS_INVALID_DISPOSITION: u32 = 0xC000_0026;
pub const STATUS_UNWIND: u32 = 0xC000_0027;
pub const STATUS_BAD_STACK: u32 = 0xC000_0028;
pub const STATUS_INVALID_UNWIND_TARGET: u32 = 0xC000_0029;

/// The most parameters a record carries.
pub const EXCEPTION_MAXIMUM_PARAMETERS: usize = 15;

/// sizeof(CONTEXT) on x86, and the CONTEXT_FULL flags (control, integer, segments).
pub const CONTEXT_SIZE: usize = 0x2CC;
pub const CONTEXT_FULL: u32 = 0x0001_0007;

/// An EXCEPTION_RECORD, as the platform lays it out (80 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExceptionRecord {
    pub code: u32,
    pub flags: u32,
    /// The chained record (the exception this one was raised over), or null.
    pub record: u32,
    pub address: u32,
    pub count: u32,
    pub information: [u32; EXCEPTION_MAXIMUM_PARAMETERS],
}

impl ExceptionRecord {
    /// A record of `code` with `flags`, chained to `chained`, without parameters (the walks' own
    /// raises, and RtlRaiseStatus's).
    pub const fn status(code: u32, flags: u32, chained: u32) -> ExceptionRecord {
        ExceptionRecord {
            code,
            flags,
            record: chained,
            address: 0,
            count: 0,
            information: [0; EXCEPTION_MAXIMUM_PARAMETERS],
        }
    }
}

/// The record's field offsets.
pub mod record {
    pub const CODE: u32 = 0x00;
    pub const FLAGS: u32 = 0x04;
    pub const RECORD: u32 = 0x08;
    pub const ADDRESS: u32 = 0x0C;
    pub const COUNT: u32 = 0x10;
}

/// What the walks need of the thread they run on.
pub trait Frames {
    /// A dword of the thread's memory (a registration record, the exception record's fields).
    fn read(&self, address: u32) -> u32;
    /// Write a dword of the thread's memory.
    fn write(&self, address: u32, value: u32);
    /// The chain's head (`fs:[0]`).
    fn head(&self) -> u32;
    /// Make `frame` the chain's head.
    fn set_head(&self, frame: u32);
    /// The thread's stack: its TEB's StackLimit and StackBase.
    fn stack_limits(&self) -> (u32, u32);
    /// Call `handler` for `frame` as ExecuteHandler2 does: a registration of the dispatcher's own
    /// pushed on the chain for the call, its handler [`own_frame_handler`]'s (the collided-unwind
    /// one for an unwind's call, the nested-exception one for a search's), `frame` saved beside it;
    /// `dispatcher` the DispatcherContext the handler (or the one a nested exception reaches) may
    /// write. The handler's disposition.
    fn execute_handler(
        &self,
        unwind: bool,
        record: u32,
        frame: u32,
        context: u32,
        dispatcher: &mut u32,
        handler: u32,
    ) -> u32;
    /// RtlRaiseException of a noncontinuable exception of `code`, no parameters, `chained` its
    /// chained record. A noncontinuable exception never resumes its raiser.
    fn raise_chained(&self, code: u32, chained: u32) -> !;
}

/// Whether `frame` may be a registration record of the thread whose stack runs from `low` to
/// `high`: aligned, and its two words inside the stack.
fn frame_valid(frame: u32, low: u32, high: u32) -> bool {
    frame & 3 == 0 && frame >= low && frame.checked_add(8).is_some_and(|end| end <= high)
}

/// Set (or clear) `bits` in the flags of the record at `record`.
fn mark(thread: &impl Frames, record: u32, bits: u32, set: bool) {
    let flags = thread.read(record + record::FLAGS);
    thread.write(
        record + record::FLAGS,
        if set { flags | bits } else { flags & !bits },
    );
}

/// RtlDispatchException: offer the exception (`record`, `context`: user addresses) to the
/// thread's handlers, head first. True when one continued execution (the context, possibly edited,
/// resumes); false when none took it, or the chain is broken (the exception's second chance).
pub fn dispatch(thread: &impl Frames, record: u32, context: u32) -> bool {
    let (low, high) = thread.stack_limits();
    let mut nested = 0u32;
    let mut frame = thread.head();
    while frame != END_OF_CHAIN {
        if !frame_valid(frame, low, high) {
            mark(thread, record, EXCEPTION_STACK_INVALID, true);
            return false;
        }
        let handler = thread.read(frame + 4);
        let mut dispatcher = 0u32;
        let disposition =
            thread.execute_handler(false, record, frame, context, &mut dispatcher, handler);
        // Past the frame a nested exception's handler was running for: no longer nested.
        if frame == nested {
            mark(thread, record, EXCEPTION_NESTED_CALL, false);
            nested = 0;
        }
        match disposition {
            EXCEPTION_CONTINUE_EXECUTION => {
                if thread.read(record + record::FLAGS) & EXCEPTION_NONCONTINUABLE != 0 {
                    thread.raise_chained(STATUS_NONCONTINUABLE_EXCEPTION, record);
                }
                return true;
            }
            EXCEPTION_CONTINUE_SEARCH => {
                if thread.read(record + record::FLAGS) & EXCEPTION_STACK_INVALID != 0 {
                    return false;
                }
            }
            EXCEPTION_NESTED_EXCEPTION => {
                mark(thread, record, EXCEPTION_NESTED_CALL, true);
                if dispatcher > nested {
                    nested = dispatcher;
                }
            }
            _ => thread.raise_chained(STATUS_INVALID_DISPOSITION, record),
        }
        frame = thread.read(frame);
    }
    false
}

/// How an unwind ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unwound {
    /// The target became the chain's head (or, unwinding to the chain's end, the chain emptied):
    /// RtlUnwind returns to its caller (NtContinue of its context).
    Continue,
    /// The chain ended before the target (an exit unwind always): the exception takes its second
    /// chance.
    SecondChance,
}

/// RtlUnwind's walk: mark `record` unwinding (an exit unwind with no `target`), then call every
/// handler from the head down to `target` with it, each frame unlinked after its call. `context`
/// is RtlUnwind's own, the one the handlers get.
pub fn unwind(thread: &impl Frames, target: u32, record: u32, context: u32) -> Unwound {
    let unwinding = if target == 0 {
        EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND
    } else {
        EXCEPTION_UNWINDING
    };
    mark(thread, record, unwinding, true);
    let (low, high) = thread.stack_limits();
    let mut frame = thread.head();
    while frame != END_OF_CHAIN {
        if frame == target {
            return Unwound::Continue;
        }
        if target != 0 && target < frame {
            thread.raise_chained(STATUS_INVALID_UNWIND_TARGET, record);
        }
        if !frame_valid(frame, low, high) {
            thread.raise_chained(STATUS_BAD_STACK, record);
        }
        let handler = thread.read(frame + 4);
        let mut dispatcher = 0u32;
        match thread.execute_handler(true, record, frame, context, &mut dispatcher, handler) {
            EXCEPTION_CONTINUE_SEARCH => {}
            // Another unwind is running this frame's handler: go on past that frame.
            EXCEPTION_COLLIDED_UNWIND => frame = dispatcher,
            _ => thread.raise_chained(STATUS_INVALID_DISPOSITION, record),
        }
        let prior = frame;
        frame = thread.read(prior);
        thread.set_head(thread.read(prior));
    }
    if target == END_OF_CHAIN {
        Unwound::Continue
    } else {
        Unwound::SecondChance
    }
}

/// The handler of the registration [`Frames::execute_handler`] pushes around a handler's call
/// (ExecuteHandler2's ExceptionHandler and UnwindHandler): `own` is that registration, its third
/// word the frame whose handler is running. Around a search's call (`unwind_call` false) an
/// exception searched for is nested in that handler: ExceptionNestedException. Around an unwind's
/// call an unwind passing through collides with it: ExceptionCollidedUnwind. Either way the
/// DispatcherContext at `dispatcher` gets the running handler's frame. Anything else passes on.
pub fn own_frame_handler(
    thread: &impl Frames,
    unwind_call: bool,
    record: u32,
    own: u32,
    dispatcher: u32,
) -> u32 {
    let unwinding = thread.read(record + record::FLAGS) & EXCEPTION_UNWIND != 0;
    let disposition = match (unwind_call, unwinding) {
        (false, false) => EXCEPTION_NESTED_EXCEPTION,
        (true, true) => EXCEPTION_COLLIDED_UNWIND,
        _ => return EXCEPTION_CONTINUE_SEARCH,
    };
    thread.write(dispatcher, thread.read(own + 8));
    disposition
}

#[cfg(test)]
mod tests;
