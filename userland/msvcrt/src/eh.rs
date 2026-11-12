//! C++ exception handling, as Visual C++ 6 compiles it for x86 (`/GX`) and Windows 2000's msvcrt
//! runs it: the frame handler of every function with C++ unwind state (`__CxxFrameHandler`), the
//! throw (`_CxxThrowException`), and terminate.
//!
//! The compiler's side is public through igorsk's "Reversing Microsoft Visual C++ Part I: Exception
//! Handling" (OpenRCE, 2006), whose structures the layouts below follow, and Vishal Kochhar's "How
//! a C++ compiler implements exception handling" (CodeProject, 2002):
//!
//! - **The frame.** A function with objects to destroy or a try block registers a handler on
//!   `fs:[0]` from its prologue (inline, or through `_EH_prolog`, src/seh.s): its registration at
//!   EBP-0xC, its unwind state (the "try level") at EBP-4, and, in a function with a try block, its
//!   ESP at EBP-0x10 ([`CxxFrame`]). The handler is a thunk, `mov eax, <FuncInfo>; jmp
//!   __CxxFrameHandler`. The function keeps its state current as it builds and destroys objects and
//!   enters and leaves try blocks.
//! - **The tables.** The FuncInfo ([`FuncInfo`]) holds the unwind map, one entry per state: the
//!   state it falls back to and the action (an object's destruction) that does it. And the
//!   try-block map: each try block's range of states, the highest state of its catch blocks, and
//!   its handlers in order ([`HandlerType`]), each the type it catches, its adjectives (reference,
//!   const, volatile), where its catch object lives in the frame, and its catch block, a funclet of
//!   the function. A try block nested in another comes before it.
//! - **The throw.** `throw x` builds the object and calls `_CxxThrowException(&x, &ThrowInfo)`,
//!   which raises 0xE06D7363 (EXCEPTION_NONCONTINUABLE) with three parameters: the magic number
//!   0x19930520, the object and its [`ThrowInfo`]: its destructor and the types it can be caught as
//!   ([`CatchableType`]: the type itself, its public unambiguous bases, `void *` for a pointer),
//!   each with the displacement to that sub-object and its copy constructor. `throw;` calls it with
//!   two nulls: the frame handler takes the exception the thread is handling in their place.
//!
//! The frame handler's search ([`find_handler`]) takes the first handler of the first try block
//! holding the frame's state that one of the exception's catchable types matches (by the
//! descriptor, or its decorated name, the reference and cv rules of [`type_match`]); `catch (...)`
//! matches anything, a structured exception that is no C++ one too, as Visual C++ 6's does
//! (crt's capture: RaiseException and an access violation reach `catch (...)`). A match never
//! returns ([`catch_it`]): the catch object is built (a reference to the object, a bitwise copy or
//! the copy constructor's), the frames above are unwound (RtlUnwind: their destructors and
//! `__finally` blocks run), then the function's own objects inside the try block, its state set to
//! the catch block's, and the catch block called. When the catch block ends, the exception object
//! is destroyed and the function resumes where the catch block said, its ESP the frame's.
//!
//! A catch block runs on the stack below the exception's dispatch, so the thrown object, still in
//! the thrower's frame, outlives it. It runs under a guard of its own on `fs:[0]` ([`CatchGuard`]),
//! which keeps the thread's list of the catch blocks running (the innermost's exception is what
//! `throw;` rethrows):
//!
//! - an exception thrown inside the catch block reaches the guard first, which searches the try
//!   blocks nested in the catch block; one it finds there is taken with the unwind stopping at the
//!   guard (the catch block goes on). The function's own registration searches the rest;
//! - an unwind passing the guard (the catch block left by an exception caught outside it, or a
//!   longjmp) ends the catch block: the exception object is destroyed unless it is the one being
//!   rethrown, and the frame's ESP slot (which a catch block with a try block of its own sets to
//!   its own stack) is put back;
//! - an exception object no longer held by any catch block running is destroyed: a `throw;` caught
//!   inside the catch block that held it does not destroy it twice.
//!
//! An exception nothing catches reaches the process's top-level filter, which the DLL's attach
//! installs ([`install_unhandled_filter`], as msvcrt imports SetUnhandledExceptionFilter for): a
//! C++ exception there calls terminate.

use core::ffi::{c_void, CStr};
use core::sync::atomic::AtomicPtr;
use core::sync::atomic::Ordering::Relaxed;

use crate::thread;

/// The exception code a C++ throw raises: 'msc' with the customer bit and the error severity.
pub const CXX_EXCEPTION: u32 = 0xE06D_7363;
/// The magic number of Visual C++ 6's exception tables: a FuncInfo's first word, a throw's first
/// parameter.
pub const CXX_MAGIC: u32 = 0x1993_0520;
/// A throw's parameter count: the magic number, the object, its ThrowInfo.
pub const CXX_PARAMETERS: u32 = 3;

/// HandlerType's adjectives (`catch (const T &)`: const and reference).
pub const HT_IS_CONST: u32 = 0x1;
pub const HT_IS_VOLATILE: u32 = 0x2;
pub const HT_IS_REFERENCE: u32 = 0x8;
/// CatchableType's properties: a type copied bitwise (a scalar or a pointer), one caught only by
/// reference, one with a virtual base (its copy constructor takes a third argument).
pub const CT_IS_SIMPLE_TYPE: u32 = 0x1;
pub const CT_BY_REFERENCE_ONLY: u32 = 0x2;
pub const CT_HAS_VIRTUAL_BASE: u32 = 0x4;
/// ThrowInfo's attributes: the thrown object const, volatile.
pub const TI_IS_CONST: u32 = 0x1;
pub const TI_IS_VOLATILE: u32 = 0x2;

/// The FuncInfo a function's handler thunk names: its unwind map and its try-block map.
///
/// igorsk's "Reversing Microsoft Visual C++ Part I" (OpenRCE, 2006), `struct FuncInfo`:
///
/// ```text
/// DWORD magicNumber;                 // 0x19930520
/// int maxState;                      // the unwind map's entries
/// const UnwindMapEntry *pUnwindMap;
/// DWORD nTryBlocks;
/// const TryBlockMapEntry *pTryBlockMap;
/// DWORD nIPMapEntries;               // unused on x86
/// void *pIPtoStateMap;               // unused on x86
/// ```
#[repr(C)]
pub struct FuncInfo {
    pub magic: u32,
    pub max_state: i32,
    pub unwind_map: *const UnwindMapEntry,
    pub try_blocks: u32,
    pub try_block_map: *const TryBlockMapEntry,
    pub ip_map_entries: u32,
    pub ip_to_state_map: *const c_void,
}

/// An unwind map entry: the state it falls back to, and the action (a funclet destroying the
/// state's object, or null) that does it. igorsk's `struct UnwindMapEntry`:
///
/// ```text
/// int toState;
/// void (*action)();
/// ```
#[repr(C)]
pub struct UnwindMapEntry {
    pub to_state: i32,
    pub action: *const c_void,
}

/// A try block: its states, the highest state of its catch blocks (which follow it), and its
/// handlers. igorsk's `struct TryBlockMapEntry`:
///
/// ```text
/// int tryLow;
/// int tryHigh;
/// int catchHigh;
/// int nCatches;
/// const HandlerType *pHandlerArray;
/// ```
#[repr(C)]
pub struct TryBlockMapEntry {
    pub try_low: i32,
    pub try_high: i32,
    pub catch_high: i32,
    pub catches: i32,
    pub handlers: *const HandlerType,
}

/// A catch block: the type it catches (null for `catch (...)`), its adjectives, where its catch
/// object sits from the frame's base (0: it has none), and its funclet. igorsk's `struct
/// HandlerType`:
///
/// ```text
/// DWORD adjectives;          // 0x01: const, 0x02: volatile, 0x08: reference
/// TypeDescriptor *pType;
/// int dispCatchObj;
/// void *addressOfHandler;
/// ```
#[repr(C)]
pub struct HandlerType {
    pub adjectives: u32,
    pub type_descriptor: *const TypeDescriptor,
    pub catch_object: i32,
    pub handler: *const c_void,
}

/// A thrown object's description, the third parameter of a throw: its attributes, its
/// destructor (null for none), and the types it can be caught as. igorsk's "Reversing Microsoft
/// Visual C++ Part I", `struct ThrowInfo`:
///
/// ```text
/// DWORD attributes;                 // 0x01: const, 0x02: volatile
/// void (*pmfnUnwind)();             // the destructor, __thiscall
/// int (*pForwardCompat)();
/// CatchableTypeArray *pCatchableTypeArray;
/// ```
#[repr(C)]
pub struct ThrowInfo {
    pub attributes: u32,
    pub unwind: *const c_void,
    pub forward_compat: *const c_void,
    pub catchable_types: *const CatchableTypeArray,
}

/// The types a thrown object can be caught as, its own first. igorsk's `struct
/// CatchableTypeArray`:
///
/// ```text
/// int nCatchableTypes;
/// CatchableType *arrayOfCatchableTypes[];
/// ```
#[repr(C)]
pub struct CatchableTypeArray<const N: usize = 0> {
    pub count: i32,
    pub types: [*const CatchableType; N],
}

/// One type a thrown object can be caught as: the sub-object's displacement, its size, and how a
/// catch by value copies it. igorsk's `struct CatchableType`:
///
/// ```text
/// DWORD properties;          // 0x01: simple type, 0x02: by reference only, 0x04: virtual base
/// TypeDescriptor *pType;
/// PMD thisDisplacement;      // the sub-object, from the object
/// int sizeOrOffset;          // its size
/// void (*copyFunction)();    // its copy constructor, __thiscall; null: a bitwise copy
/// ```
#[repr(C)]
pub struct CatchableType {
    pub properties: u32,
    pub type_descriptor: *const TypeDescriptor,
    pub this_displacement: Pmd,
    pub size: i32,
    pub copy_function: *const c_void,
}

/// A pointer-to-member displacement: where a sub-object sits in an object. igorsk's "Reversing
/// Microsoft Visual C++ Part II: Classes, Methods and RTTI" (OpenRCE, 2006), `struct PMD`:
///
/// ```text
/// int mdisp;   // the member's displacement
/// int pdisp;   // the vbtable pointer's displacement, -1 for none
/// int vdisp;   // the displacement inside the vbtable
/// ```
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Pmd {
    pub mdisp: i32,
    pub pdisp: i32,
    pub vdisp: i32,
}

/// A type's descriptor, which `typeid` answers as its `type_info`: the type_info vftable, the
/// undecorated name once `name()` made it, and the decorated name, NUL-terminated (`N` its bytes
/// for msvcrt's own; the compiler's are read through pointers). igorsk's "Reversing Microsoft
/// Visual C++ Part I", `struct TypeDescriptor`:
///
/// ```text
/// const void *pVFTable;      // type_info's
/// void *spare;               // the undecorated name, made by name()
/// char name[];               // ".H", ".?AVclass@@"
/// ```
#[repr(C)]
pub struct TypeDescriptor<const N: usize = 0> {
    pub vftable: *const c_void,
    pub spare: AtomicPtr<u8>,
    pub name: [u8; N],
}

// SAFETY: a descriptor's vftable and name are never written; its spare is an atomic.
unsafe impl<const N: usize> Sync for TypeDescriptor<N> {}
// SAFETY: msvcrt's own tables are read-only, their pointers to read-only data.
unsafe impl Sync for ThrowInfo {}
// SAFETY: as ThrowInfo's.
unsafe impl Sync for CatchableType {}
// SAFETY: as ThrowInfo's.
unsafe impl<const N: usize> Sync for CatchableTypeArray<N> {}

/// The frame a function with C++ unwind state builds, from its ESP slot to its saved EBP; the
/// registration a frame handler is handed is its `next`. igorsk's "Reversing Microsoft Visual C++
/// Part I", `struct EHRegistrationNode` and the slot before it:
///
/// ```text
/// [ebp-0x10]  the function's ESP (a function with a try block)
/// [ebp-0x0c]  EHRegistrationNode *pNext;
/// [ebp-0x08]  FARPROC handler;
/// [ebp-0x04]  int state;
/// [ebp]       the saved EBP
/// ```
#[repr(C)]
pub struct CxxFrame {
    pub esp: usize,
    pub next: usize,
    pub handler: usize,
    pub state: i32,
    pub ebp: usize,
}

/// Whether `handler` catches the thrown object as `catchable`, a type of `throw`'s: `catch (...)`
/// (no type, or a nameless one) catches anything; otherwise the types are the same descriptor or
/// have the same decorated name (a type's descriptor is the module's own: one thrown from another
/// module has another); a type caught only by reference needs a reference handler, and a const or
/// volatile object a handler as qualified.
///
/// # Safety
///
/// The tables' type descriptors are null or descriptors with their names.
pub unsafe fn type_match(
    handler: &HandlerType,
    catchable: &CatchableType,
    throw: &ThrowInfo,
) -> bool {
    // SAFETY: the caller's contract.
    let Some(wanted) = (unsafe { descriptor_name(handler.type_descriptor) }) else {
        return true;
    };
    if wanted.is_empty() {
        return true;
    }
    if !core::ptr::eq(handler.type_descriptor, catchable.type_descriptor) {
        // SAFETY: the caller's contract.
        let thrown = unsafe { descriptor_name(catchable.type_descriptor) };
        if thrown != Some(wanted) {
            return false;
        }
    }
    if catchable.properties & CT_BY_REFERENCE_ONLY != 0 && handler.adjectives & HT_IS_REFERENCE == 0
    {
        return false;
    }
    if throw.attributes & TI_IS_CONST != 0 && handler.adjectives & HT_IS_CONST == 0 {
        return false;
    }
    if throw.attributes & TI_IS_VOLATILE != 0 && handler.adjectives & HT_IS_VOLATILE == 0 {
        return false;
    }
    true
}

/// A handler that is `catch (...)`: no type, or a nameless one.
///
/// # Safety
///
/// As [`type_match`]'s.
unsafe fn catches_all(handler: &HandlerType) -> bool {
    // SAFETY: the caller's contract.
    unsafe { descriptor_name(handler.type_descriptor) }.is_none_or(|name| name.is_empty())
}

/// The decorated name of the descriptor at `descriptor`, none for null.
///
/// # Safety
///
/// `descriptor` is null or a type descriptor, its name NUL-terminated after it, alive for the
/// program's life (a module's own data).
pub unsafe fn descriptor_name(descriptor: *const TypeDescriptor) -> Option<&'static CStr> {
    if descriptor.is_null() {
        return None;
    }
    // SAFETY: the caller's contract: the name follows the descriptor's two words.
    Some(unsafe { CStr::from_ptr((&raw const (*descriptor).name).cast()) })
}

/// The sub-object `displacement` describes in the object at `object`: past the member's
/// displacement and, through a virtual base, the displacement the object's vbtable gives.
///
/// # Safety
///
/// With a vbtable (`pdisp` not negative), the object's vbtable pointer and the vbtable entry are
/// readable.
pub unsafe fn adjust_pointer(object: usize, displacement: &Pmd) -> usize {
    let mut adjusted = object.wrapping_add(displacement.mdisp as usize);
    if displacement.pdisp >= 0 {
        let at = object.wrapping_add(displacement.pdisp as usize);
        // SAFETY: the caller's contract: the object's vbtable pointer, and its entry.
        let base = unsafe {
            let vbtable = (at as *const usize).read_unaligned();
            (vbtable.wrapping_add(displacement.vdisp as usize) as *const i32).read_unaligned()
        };
        adjusted = adjusted
            .wrapping_add(base as usize)
            .wrapping_add(displacement.pdisp as usize);
    }
    adjusted
}

#[cfg(all(target_arch = "x86", not(test)))]
pub use platform::{install_unhandled_filter, remove_unhandled_filter, throw_exception};

/// The frame handler, the catch blocks' guards and the throw: the target's alone (the host has no
/// exception frames).
#[cfg(all(target_arch = "x86", not(test)))]
mod platform {
    use core::mem::offset_of;

    use rtl::seh::ExceptionRecord;

    use super::*;
    use crate::kernel32;

    /// EXCEPTION_NONCONTINUABLE: a throw's flags.
    const EXCEPTION_NONCONTINUABLE: u32 = rtl::seh::EXCEPTION_NONCONTINUABLE;
    /// EXCEPTION_UNWINDING, and either unwind flag: a handler's call for an unwind.
    const EXCEPTION_UNWINDING: u32 = rtl::seh::EXCEPTION_UNWINDING;
    const EXCEPTION_UNWIND: u32 = rtl::seh::EXCEPTION_UNWIND;
    /// ExceptionContinueSearch: every frame handler's answer when it does not take the exception.
    const CONTINUE_SEARCH: u32 = rtl::seh::EXCEPTION_CONTINUE_SEARCH;

    unsafe extern "C" {
        /// src/seh.s: an unwind action run with EBP `ebp`.
        fn f2k_msvcrt_call_funclet(funclet: *const c_void, ebp: usize) -> usize;
        /// src/seh.s: a catch block run with EBP `ebp` under `guard`; its continuation.
        fn f2k_msvcrt_call_catch(
            funclet: *const c_void,
            ebp: usize,
            guard: *mut CatchGuard,
        ) -> usize;
        /// src/seh.s: the function resumed at `target`, EBP `ebp`, ESP `esp`.
        fn f2k_msvcrt_jump_to_continuation(target: usize, ebp: usize, esp: usize) -> !;
        /// src/seh.s: the guard's handler, its direction flag cleared.
        fn f2k_msvcrt_catch_guard_handler();
    }

    /// An exception record, as the frame handlers read it: its fields one at a time (a dispatched
    /// record carries only its parameters, so the whole EXCEPTION_RECORD may not be there). It is
    /// built over a live record: the dispatch's, or a running catch block's above it.
    #[derive(Clone, Copy, PartialEq, Eq)]
    #[repr(transparent)]
    struct Record(*mut ExceptionRecord);

    impl Record {
        fn code(self) -> u32 {
            // SAFETY: the record is live.
            unsafe { (&raw const (*self.0).code).read() }
        }

        fn flags(self) -> u32 {
            // SAFETY: as `code`'s.
            unsafe { (&raw const (*self.0).flags).read() }
        }

        fn clear_flags(self, flags: u32) {
            // SAFETY: as `code`'s; a dispatched record is the dispatch's own, writable memory.
            unsafe { (&raw mut (*self.0).flags).write(self.flags() & !flags) }
        }

        fn count(self) -> u32 {
            // SAFETY: as `code`'s.
            unsafe { (&raw const (*self.0).count).read() }
        }

        /// Parameter `index`, below the record's count.
        fn parameter(self, index: usize) -> usize {
            // SAFETY: as `code`'s; the record carries its count's parameters.
            unsafe {
                (&raw const (*self.0).information)
                    .cast::<u32>()
                    .add(index)
                    .read() as usize
            }
        }

        /// The thrown object and its ThrowInfo for a C++ exception (both null for `throw;`),
        /// none for any other exception.
        fn thrown(self) -> Option<(usize, *const ThrowInfo)> {
            if self.code() != CXX_EXCEPTION
                || self.count() != CXX_PARAMETERS
                || self.parameter(0) as u32 != CXX_MAGIC
            {
                return None;
            }
            Some((self.parameter(1), self.parameter(2) as *const ThrowInfo))
        }
    }

    /// A function's frame, from the registration its handler is handed. Its fields are read and
    /// written in place: the function's own stack, which the function uses too.
    #[derive(Clone, Copy)]
    struct Frame(*mut CxxFrame);

    impl Frame {
        /// The frame whose registration is at `registration`.
        ///
        /// # Safety
        ///
        /// `registration` is a C++ frame's registration on the calling thread's stack, live while
        /// the Frame is used; the ESP slot is reached only for a function with a try block.
        unsafe fn at(registration: usize) -> Frame {
            Frame((registration - offset_of!(CxxFrame, next)) as *mut CxxFrame)
        }

        fn registration(self) -> usize {
            self.0 as usize + offset_of!(CxxFrame, next)
        }

        /// The function's EBP: its saved EBP's slot.
        fn ebp(self) -> usize {
            self.0 as usize + offset_of!(CxxFrame, ebp)
        }

        fn state(self) -> i32 {
            // SAFETY: `at`'s contract: the frame is live.
            unsafe { (&raw const (*self.0).state).read() }
        }

        fn set_state(self, state: i32) {
            // SAFETY: as `state`'s.
            unsafe { (&raw mut (*self.0).state).write(state) }
        }

        fn esp(self) -> usize {
            // SAFETY: as `state`'s; the function has a try block (it catches).
            unsafe { (&raw const (*self.0).esp).read() }
        }

        fn set_esp(self, esp: usize) {
            // SAFETY: as `esp`'s.
            unsafe { (&raw mut (*self.0).esp).write(esp) }
        }
    }

    /// A FuncInfo and its maps, as slices over the compiler's tables.
    struct Function {
        info: *const FuncInfo,
        unwind: &'static [UnwindMapEntry],
        tries: &'static [TryBlockMapEntry],
    }

    impl Function {
        /// The FuncInfo at `info` and its maps; none for a magic number other than Visual C++ 6's.
        ///
        /// # Safety
        ///
        /// `info` is a FuncInfo of the compiler's, its maps as long as it says, in the image.
        unsafe fn of(info: *const FuncInfo) -> Option<Function> {
            // SAFETY: the caller's contract.
            let tables = unsafe { &*info };
            if tables.magic != CXX_MAGIC {
                return None;
            }
            // SAFETY: the caller's contract: the maps hold `max_state` and `try_blocks` entries.
            unsafe {
                Some(Function {
                    info,
                    unwind: entries(tables.unwind_map, tables.max_state.max(0) as usize),
                    tries: entries(tables.try_block_map, tables.try_blocks as usize),
                })
            }
        }
    }

    /// `count` entries at `at`: none when `count` is 0 or `at` null.
    ///
    /// # Safety
    ///
    /// Otherwise, `at` holds `count` entries for the program's life (the image's tables).
    unsafe fn entries<T>(at: *const T, count: usize) -> &'static [T] {
        if count == 0 || at.is_null() {
            &[]
        } else {
            // SAFETY: the caller's contract.
            unsafe { core::slice::from_raw_parts(at, count) }
        }
    }

    /// A try block's handlers.
    ///
    /// # Safety
    ///
    /// The try block is the compiler's, its handlers as many as it says.
    unsafe fn handlers(try_block: &TryBlockMapEntry) -> &'static [HandlerType] {
        // SAFETY: the caller's contract.
        unsafe { entries(try_block.handlers, try_block.catches.max(0) as usize) }
    }

    /// A ThrowInfo's catchable types.
    ///
    /// # Safety
    ///
    /// The ThrowInfo is a throw's: its array and types the compiler's (or msvcrt's own).
    unsafe fn catchable_types(throw: &ThrowInfo) -> impl Iterator<Item = &'static CatchableType> {
        let array = throw.catchable_types;
        // SAFETY: the caller's contract: the array's count, then its pointers.
        let types: &'static [*const CatchableType] = unsafe {
            if array.is_null() {
                &[]
            } else {
                entries(
                    (&raw const (*array).types).cast(),
                    (*array).count.max(0) as usize,
                )
            }
        };
        // SAFETY: as above: each a catchable type.
        types.iter().map(|&catchable| unsafe { &*catchable })
    }

    /// The program's tables disagree with its frame (a state outside the unwind map, a FuncInfo
    /// of a later compiler's): Windows 2000's msvcrt calls terminate.
    fn inconsistency(reason: &str) -> ! {
        // SAFETY: the arguments are not read: the line shows them as values.
        unsafe { crate::stub::logged(&crate::spec::__CxxFrameHandler, reason, &[0; 4]) };
        terminate()
    }

    /// The calling thread's innermost catch block running, null for none.
    fn innermost_catch() -> *mut CatchGuard {
        thread::with_data(|data| data.catches.load(Relaxed)) as *mut CatchGuard
    }

    fn set_innermost_catch(guard: *mut CatchGuard) {
        thread::with_data(|data| data.catches.store(guard as usize, Relaxed));
    }

    /// A catch block's guard: a registration on `fs:[0]` while the catch block runs (its first
    /// two words), on the stack of the call that runs it ([`call_catch_block`]), and a link of the
    /// thread's list of the catch blocks running. Its layout is F2K's own: Windows 2000's is
    /// msvcrt's private business.
    #[repr(C)]
    struct CatchGuard {
        /// The registration: the next one, the handler (src/seh.s's
        /// `f2k_msvcrt_catch_guard_handler`).
        next: usize,
        handler: usize,
        /// The function whose catch block runs: its registration and FuncInfo, and the try block
        /// whose catch block it is.
        frame: usize,
        info: *const FuncInfo,
        try_block: *const TryBlockMapEntry,
        /// The exception the catch block took (in the dispatch's frame, above the catch block).
        record: Record,
        /// The frame's ESP slot as it was when the catch block started.
        esp: usize,
        /// The catch block running outside this one on the thread, null for none.
        outer: *mut CatchGuard,
    }

    /// __CxxFrameHandler's body (src/seh.s hands it the FuncInfo from EAX): for an unwind, the
    /// function's objects destroyed; for a search, a handler of its try blocks holding its state
    /// that takes the exception (which does not return). ExceptionContinueSearch.
    ///
    /// # Safety
    ///
    /// The dispatcher's call: `record` the exception's, `registration` a C++ frame's on the
    /// thread's stack whose handler names `info`.
    #[unsafe(no_mangle)]
    unsafe extern "C" fn f2k_msvcrt_cxx_frame_handler(
        record: *mut ExceptionRecord,
        registration: usize,
        _context: usize,
        _dispatcher: usize,
        info: *const FuncInfo,
    ) -> u32 {
        let record = Record(record);
        // SAFETY: the caller's contract.
        let frame = unsafe { Frame::at(registration) };
        // SAFETY: the caller's contract: the handler's FuncInfo.
        let Some(function) = (unsafe { Function::of(info) }) else {
            inconsistency("a FuncInfo whose magic number is not Visual C++ 6's (0x19930520)")
        };
        if record.flags() & EXCEPTION_UNWIND != 0 {
            unwind_to_state(frame, &function, -1);
        } else if !function.tries.is_empty() {
            find_handler(record, frame, &function, None);
        }
        CONTINUE_SEARCH
    }

    /// The frame's objects destroyed from its state back to `target` (an enclosing state, or -1),
    /// each state left before its action runs.
    fn unwind_to_state(frame: Frame, function: &Function, target: i32) {
        let mut state = frame.state();
        while state != target {
            let Some(entry) = usize::try_from(state)
                .ok()
                .and_then(|at| function.unwind.get(at))
            else {
                inconsistency("a frame state outside its unwind map")
            };
            state = entry.to_state;
            frame.set_state(state);
            if !entry.action.is_null() {
                // SAFETY: the function's unwind action, called with its frame's EBP.
                unsafe { f2k_msvcrt_call_funclet(entry.action, frame.ebp()) };
            }
        }
    }

    /// The search of the frame's try blocks holding its state, in order, for the first handler
    /// that takes the exception (which does not return). From a catch block's guard, only the
    /// try blocks nested in that catch block: the function's own registration, further on,
    /// searches the rest. A `throw;` stands for the exception of the innermost catch block
    /// running, terminate when there is none.
    fn find_handler(
        record: Record,
        frame: Frame,
        function: &Function,
        guard: Option<*mut CatchGuard>,
    ) {
        let state = frame.state();
        if state < -1 || state >= function.unwind.len() as i32 {
            inconsistency("a frame state outside its unwind map");
        }
        let mut record = record;
        if record.thrown().is_some_and(|(_, throw)| throw.is_null()) {
            let current = innermost_catch();
            if current.is_null() {
                terminate();
            }
            // SAFETY: the innermost running catch block's guard, on the stack above.
            record = unsafe { (*current).record };
        }
        // SAFETY: a guard handed here is a running catch block's, its try block the compiler's.
        let enclosing = guard.map(|guard| unsafe { &*(*guard).try_block });
        for try_block in function.tries {
            if let Some(enclosing) = enclosing {
                if try_block.try_low <= enclosing.try_high
                    || try_block.try_high > enclosing.catch_high
                {
                    continue;
                }
            }
            if state < try_block.try_low || state > try_block.try_high {
                continue;
            }
            // SAFETY: the function's try block.
            for handler in unsafe { handlers(try_block) } {
                match record.thrown() {
                    Some((_, throw)) => {
                        // SAFETY: the throw's ThrowInfo.
                        let throw = unsafe { &*throw };
                        // SAFETY: as above.
                        for catchable in unsafe { catchable_types(throw) } {
                            // SAFETY: the tables' descriptors.
                            if unsafe { type_match(handler, catchable, throw) } {
                                let caught = Caught {
                                    handler,
                                    catchable: Some(catchable),
                                };
                                catch_it(record, frame, function, try_block, caught, guard);
                            }
                        }
                    }
                    // SAFETY: the handler's descriptor.
                    None if unsafe { catches_all(handler) } => {
                        let caught = Caught {
                            handler,
                            catchable: None,
                        };
                        catch_it(record, frame, function, try_block, caught, guard)
                    }
                    None => {}
                }
            }
        }
    }

    /// The handler that takes an exception, and the type it takes it as (none for a structured
    /// exception in `catch (...)`).
    struct Caught<'a> {
        handler: &'a HandlerType,
        catchable: Option<&'a CatchableType>,
    }

    /// The handler takes the exception: its catch object built, the frames above unwound (to the
    /// guard of the catch block searching, or the function's own registration), the try block's
    /// objects destroyed, the catch block run; the function resumed where the catch block says.
    fn catch_it(
        record: Record,
        frame: Frame,
        function: &Function,
        try_block: &TryBlockMapEntry,
        caught: Caught,
        guard: Option<*mut CatchGuard>,
    ) -> ! {
        if let Some(catchable) = caught.catchable {
            build_catch_object(record, frame, caught.handler, catchable);
        }
        let target = guard.map_or(frame.registration(), |guard| guard as usize);
        // SAFETY: the guard or the frame is a registration on this thread's chain, under the
        // dispatch; the frames above it are abandoned once the catch block ends.
        unsafe { kernel32::unwind(target, record.0 as usize) };
        // RtlUnwind marks the record unwinding in place: the exception is a catch block's now,
        // which a `throw;` raises again.
        record.clear_flags(EXCEPTION_UNWINDING);
        unwind_to_state(frame, function, try_block.try_low);
        frame.set_state(try_block.try_high + 1);
        let continuation =
            call_catch_block(record, frame, function, try_block, caught.handler.handler);
        // SAFETY: the catch block's continuation in its function, its stack the one the function
        // (or the catch block around this one) left in the frame's ESP slot.
        unsafe { f2k_msvcrt_jump_to_continuation(continuation, frame.ebp(), frame.esp()) }
    }

    /// The catch object built where the handler says: for a reference, the caught sub-object's
    /// address; for a simple type, its bytes (a pointer adjusted to the sub-object it is caught
    /// as); for a class, its copy constructor's copy, or its bytes when it has none. Nothing for a
    /// handler without one (`catch (T)` whose block names no object).
    fn build_catch_object(
        record: Record,
        frame: Frame,
        handler: &HandlerType,
        catchable: &CatchableType,
    ) {
        let Some((object, _)) = record.thrown() else {
            return;
        };
        // SAFETY: the handler's descriptor.
        if unsafe { catches_all(handler) } || handler.catch_object == 0 {
            return;
        }
        let at = frame.ebp().wrapping_add(handler.catch_object as usize);
        let displacement = &catchable.this_displacement;
        let size = catchable.size.max(0) as usize;
        // SAFETY: the catch object's room in the function's frame and the thrown object, as the
        // compiler's tables lay them out; the copy constructor is the type's, __thiscall.
        unsafe {
            if handler.adjectives & HT_IS_REFERENCE != 0 {
                (at as *mut usize).write_unaligned(adjust_pointer(object, displacement));
            } else if catchable.properties & CT_IS_SIMPLE_TYPE != 0 {
                core::ptr::copy_nonoverlapping(object as *const u8, at as *mut u8, size);
                if size == size_of::<usize>() {
                    let pointer = (at as *const usize).read_unaligned();
                    if pointer != 0 {
                        (at as *mut usize).write_unaligned(adjust_pointer(pointer, displacement));
                    }
                }
            } else {
                let source = adjust_pointer(object, displacement);
                if catchable.copy_function.is_null() {
                    core::ptr::copy_nonoverlapping(source as *const u8, at as *mut u8, size);
                } else if catchable.properties & CT_HAS_VIRTUAL_BASE != 0 {
                    let copy: unsafe extern "thiscall" fn(usize, usize, i32) =
                        core::mem::transmute(catchable.copy_function);
                    copy(at, source, 1);
                } else {
                    let copy: unsafe extern "thiscall" fn(usize, usize) =
                        core::mem::transmute(catchable.copy_function);
                    copy(at, source);
                }
            }
        }
    }

    /// The catch block run under its guard; its continuation. As it ends, the frame's ESP slot is
    /// put back and the exception object destroyed (when no catch block outside still holds it).
    fn call_catch_block(
        record: Record,
        frame: Frame,
        function: &Function,
        try_block: &TryBlockMapEntry,
        handler: *const c_void,
    ) -> usize {
        let mut guard = CatchGuard {
            next: 0,
            handler: f2k_msvcrt_catch_guard_handler as *const () as usize,
            frame: frame.registration(),
            info: function.info,
            try_block,
            record,
            esp: frame.esp(),
            outer: innermost_catch(),
        };
        set_innermost_catch(&raw mut guard);
        // SAFETY: the catch block, called with its frame's EBP; the guard lives on this frame,
        // which the catch block's stack is below, until the call returns.
        let continuation = unsafe { f2k_msvcrt_call_catch(handler, frame.ebp(), &raw mut guard) };
        // SAFETY: the guard is this call's, the innermost running.
        unsafe { leave_catch(&raw mut guard, None) };
        continuation
    }

    /// A catch block ended, normally (`unwinding` none) or by an unwind passing its guard: it
    /// leaves the thread's list, the frame's ESP slot is put back, and the exception object is
    /// destroyed unless the unwind's own exception is it (a `throw;`, or the object thrown again)
    /// or a catch block outside still holds it.
    ///
    /// # Safety
    ///
    /// `guard` is the innermost running catch block's guard.
    unsafe fn leave_catch(guard: *mut CatchGuard, unwinding: Option<Record>) {
        // SAFETY: the caller's contract.
        let guard = unsafe { &*guard };
        set_innermost_catch(guard.outer);
        // SAFETY: the guard's frame is live (its catch block was running).
        let frame = unsafe { Frame::at(guard.frame) };
        frame.set_esp(guard.esp);
        let rethrown = unwinding.is_some_and(|record| {
            record == guard.record
                || match (record.thrown(), guard.record.thrown()) {
                    (Some((0, _)), _) => true,
                    (Some((object, _)), Some((held, _))) => object == held,
                    _ => false,
                }
        });
        if !rethrown {
            // SAFETY: the guard's record lives above the catch block; the outer guards are the
            // running ones.
            unsafe { destroy_exception_object(guard.record, guard.outer) };
        }
    }

    /// The exception object of `record` destroyed (its ThrowInfo's destructor), unless it is no
    /// C++ exception's or a catch block running, `outer` or one outside it, still holds it.
    ///
    /// # Safety
    ///
    /// `record` is live; `outer` is null or a running catch block's guard, as are those outside.
    unsafe fn destroy_exception_object(record: Record, outer: *mut CatchGuard) {
        let Some((object, throw)) = record.thrown() else {
            return;
        };
        if object == 0 || throw.is_null() {
            return;
        }
        let mut guard = outer;
        while !guard.is_null() {
            // SAFETY: the caller's contract: the running catch blocks' guards, on the stack.
            let held = unsafe { &*guard };
            if held
                .record
                .thrown()
                .is_some_and(|(other, _)| other == object)
            {
                return;
            }
            guard = held.outer;
        }
        // SAFETY: the throw's ThrowInfo.
        let destructor = unsafe { (*throw).unwind };
        if !destructor.is_null() {
            // SAFETY: the ThrowInfo's destructor of the object, __thiscall.
            unsafe {
                let destructor: unsafe extern "thiscall" fn(usize) =
                    core::mem::transmute(destructor);
                destructor(object);
            }
        }
    }

    /// The guard's handler (src/seh.s's `f2k_msvcrt_catch_guard_handler` jumps here): for an
    /// unwind, the catch block ended; for a search, the try blocks nested in the catch block
    /// searched. ExceptionContinueSearch.
    ///
    /// # Safety
    ///
    /// The dispatcher's call: `guard` a running catch block's guard.
    #[unsafe(no_mangle)]
    unsafe extern "C" fn f2k_msvcrt_catch_guard(
        record: *mut ExceptionRecord,
        guard: *mut CatchGuard,
        _context: usize,
        _dispatcher: usize,
    ) -> u32 {
        let record = Record(record);
        if record.flags() & EXCEPTION_UNWIND != 0 {
            // SAFETY: the caller's contract; an unwind leaves the catch blocks innermost first.
            unsafe { leave_catch(guard, Some(record)) };
        } else {
            // SAFETY: the caller's contract: the guard's frame is live, its FuncInfo checked.
            let (frame, function) =
                unsafe { (Frame::at((*guard).frame), Function::of((*guard).info)) };
            if let Some(function) = function {
                find_handler(record, frame, &function, Some(guard));
            }
        }
        CONTINUE_SEARCH
    }

    /// _CxxThrowException(object, throw_info): the C++ exception raised, noncontinuable, with the
    /// magic number, the object and its ThrowInfo (two nulls for `throw;`). It is __stdcall on
    /// Windows 2000; it never returns, and its arguments sit where cdecl's do.
    #[unsafe(export_name = "f2k_export__CxxThrowException")]
    pub extern "C" fn throw_exception(object: usize, throw_info: usize) -> ! {
        let parameters = [CXX_MAGIC as usize, object, throw_info];
        kernel32::raise(CXX_EXCEPTION, EXCEPTION_NONCONTINUABLE, &parameters);
        // A noncontinuable exception does not resume its raiser.
        unreachable!()
    }

    /// The top-level filter the C++ one replaced, which it hands what is no C++ exception.
    static PREVIOUS_FILTER: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());

    /// The process's top-level exception filter set to the C++ one, at the DLL's attach.
    pub fn install_unhandled_filter() {
        let previous =
            kernel32::set_unhandled_exception_filter(cxx_unhandled_filter as *const () as usize);
        PREVIOUS_FILTER.store(previous as *mut c_void, Relaxed);
    }

    /// The top-level filter the C++ one replaced put back, at the DLL's detach: the filter is the
    /// DLL's code, which goes with it.
    pub fn remove_unhandled_filter() {
        kernel32::set_unhandled_exception_filter(PREVIOUS_FILTER.load(Relaxed) as usize);
    }

    /// The C++ top-level filter: a C++ exception nothing caught calls terminate; anything else
    /// goes to the filter it replaced (EXCEPTION_CONTINUE_SEARCH with none).
    ///
    /// # Safety
    ///
    /// `pointers` is the exception's EXCEPTION_POINTERS (its record first).
    unsafe extern "system" fn cxx_unhandled_filter(pointers: *const *mut ExceptionRecord) -> i32 {
        // SAFETY: the caller's contract.
        let record = Record(unsafe { pointers.read() });
        if record.thrown().is_some() {
            terminate();
        }
        let previous = PREVIOUS_FILTER.load(Relaxed);
        if previous.is_null() {
            return 0;
        }
        // SAFETY: the filter kernel32 had, a stdcall function of the pointers.
        unsafe {
            let previous: unsafe extern "system" fn(*const *mut ExceptionRecord) -> i32 =
                core::mem::transmute(previous);
            previous(pointers)
        }
    }
}

/// set_terminate: the calling thread's terminate handler replaced; the one it replaces, null for
/// none.
#[unsafe(export_name = "f2k_export_set_terminate")]
pub extern "C" fn set_terminate(handler: Option<extern "C" fn()>) -> Option<extern "C" fn()> {
    let new = handler.map_or(0, |handler| handler as usize);
    let old = thread::with_data(|data| data.terminate.swap(new, Relaxed));
    // SAFETY: the slot holds 0 or a handler set_terminate stored, a function pointer.
    (old != 0).then(|| unsafe { core::mem::transmute::<usize, extern "C" fn()>(old) })
}

/// terminate: the calling thread's terminate handler called, then abort (also after a handler
/// that returns, as crt's capture shows).
#[unsafe(export_name = "f2k_export_terminate")]
pub extern "C" fn terminate() -> ! {
    let handler = thread::with_data(|data| data.terminate.load(Relaxed));
    if handler != 0 {
        // SAFETY: the slot holds a handler set_terminate stored, a function pointer.
        let handler: extern "C" fn() = unsafe { core::mem::transmute(handler) };
        handler();
    }
    crate::startup::abort()
}

/// _purecall: a pure virtual function was called (a constructor or destructor reaching it
/// through its own class's vftable): run-time error R6025, the process ended with 255.
#[unsafe(export_name = "f2k_export__purecall")]
pub extern "C" fn purecall() -> ! {
    crate::startup::runtime_error(crate::startup::R6025_PURE_VIRTUAL)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor<const N: usize>(name: &[u8; N]) -> TypeDescriptor<N> {
        TypeDescriptor {
            vftable: core::ptr::null(),
            spare: AtomicPtr::new(core::ptr::null_mut()),
            name: *name,
        }
    }

    fn erase<const N: usize>(descriptor: &TypeDescriptor<N>) -> *const TypeDescriptor {
        (descriptor as *const TypeDescriptor<N>).cast()
    }

    fn handler(adjectives: u32, descriptor: *const TypeDescriptor) -> HandlerType {
        HandlerType {
            adjectives,
            type_descriptor: descriptor,
            catch_object: 0,
            handler: core::ptr::null(),
        }
    }

    fn catchable(properties: u32, descriptor: *const TypeDescriptor) -> CatchableType {
        CatchableType {
            properties,
            type_descriptor: descriptor,
            this_displacement: Pmd {
                mdisp: 0,
                pdisp: -1,
                vdisp: 0,
            },
            size: 4,
            copy_function: core::ptr::null(),
        }
    }

    fn throw(attributes: u32) -> ThrowInfo {
        ThrowInfo {
            attributes,
            unwind: core::ptr::null(),
            forward_compat: core::ptr::null(),
            catchable_types: core::ptr::null(),
        }
    }

    /// crt's cxxeh `catch` and `derived`: a type matches by its descriptor or, from another
    /// module, its decorated name; `catch (...)` takes anything; a const object (`throw "a
    /// string literal"`) needs a const handler; a type caught only by reference needs a
    /// reference.
    #[test]
    fn handlers_match_as_visual_cpp_6s() {
        let int = descriptor(b".H\0");
        let other_int = descriptor(b".H\0");
        let long = descriptor(b".J\0");
        let chars = descriptor(b".PAD\0");
        let nameless = descriptor(b"\0");
        let (int, other_int, long, chars, nameless) = (
            erase(&int),
            erase(&other_int),
            erase(&long),
            erase(&chars),
            erase(&nameless),
        );
        let reference_only = catchable(CT_BY_REFERENCE_ONLY, int);
        // SAFETY: the descriptors are the test's, named.
        unsafe {
            assert!(type_match(&handler(0, int), &catchable(1, int), &throw(0)));
            assert!(type_match(
                &handler(0, other_int),
                &catchable(1, int),
                &throw(0)
            ));
            assert!(!type_match(
                &handler(0, long),
                &catchable(1, int),
                &throw(0)
            ));
            assert!(type_match(
                &handler(0, core::ptr::null()),
                &catchable(1, int),
                &throw(0)
            ));
            assert!(type_match(
                &handler(0, nameless),
                &catchable(1, int),
                &throw(0)
            ));
            let const_chars = throw(TI_IS_CONST);
            assert!(type_match(
                &handler(HT_IS_CONST, chars),
                &catchable(1, chars),
                &const_chars
            ));
            assert!(!type_match(
                &handler(0, chars),
                &catchable(1, chars),
                &const_chars
            ));
            assert!(!type_match(&handler(0, int), &reference_only, &throw(0)));
            assert!(type_match(
                &handler(HT_IS_REFERENCE, int),
                &reference_only,
                &throw(0)
            ));
            assert!(catches_all(&handler(0, core::ptr::null())));
            assert!(catches_all(&handler(0, nameless)));
            assert!(!catches_all(&handler(0, int)));
        }
    }

    /// A sub-object's address: past its member displacement and, through a virtual base, the
    /// displacement the object's vbtable holds at `vdisp` plus the vbtable pointer's own.
    #[test]
    fn pointers_are_adjusted_through_the_vbtable() {
        let vbtable: [i32; 2] = [-4, 24];
        let object: [usize; 4] = [0, &vbtable as *const [i32; 2] as usize, 0, 0];
        let at = object.as_ptr() as usize;
        let word = size_of::<usize>();
        let member = Pmd {
            mdisp: 8,
            pdisp: -1,
            vdisp: 0,
        };
        let virtual_base = Pmd {
            mdisp: 0,
            pdisp: word as i32,
            vdisp: 4,
        };
        // SAFETY: the object's vbtable pointer and its entries are the test's.
        unsafe {
            assert_eq!(adjust_pointer(at, &member), at + 8);
            assert_eq!(adjust_pointer(at, &virtual_base), at + word + 24);
        }
    }
}
