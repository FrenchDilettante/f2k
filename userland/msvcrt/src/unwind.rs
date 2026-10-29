//! The C runtime's locks let go when an exception unwinds out of a call that holds them, as Windows
//! 2000's msvcrt lets them go in the `__finally` blocks around its locked work.
//!
//! A call that reads or writes its caller's memory under a lock (printf's `%s` over a bad pointer,
//! fgets into a bad buffer) can fault there. When the program's `__except` takes that exception,
//! ntdll's RtlUnwind calls the handler of every registration between the fault and the `__except`
//! with the record marked unwinding, then the `__except` block abandons their frames: no Rust code
//! in them runs again, guards' drops included. So the locks register a frame of their own around
//! the work they guard ([`on_unwind`]), whose handler, called by that unwind, runs the release the
//! drop would have run. The handler does nothing for the search that precedes the unwind: a
//! filter runs with the lock still held, as Windows 2000's does.

/// `body` run with `release` registered to run if an exception's unwind passes the call; what
/// `body` answers. `release` runs on the unwinding thread, deeper on its stack than `body`'s
/// frames, which are still in place but are abandoned once the unwind ends: it may use the state
/// they borrowed, but nothing may borrow it from them again.
#[cfg(all(target_arch = "x86", not(test)))]
pub fn on_unwind<R, F: FnOnce() -> R>(release: &dyn Fn(), body: F) -> R {
    let mut call = Call {
        body: Some(body),
        answer: None,
    };
    // SAFETY: `call` and `release` live on this frame until `registered` returns, which keeps its
    // registration on the chain only meanwhile; `run` and `run_release` take them as what they are.
    unsafe {
        frame::registered(
            run::<F, R>,
            (&raw mut call).cast(),
            run_release,
            (&raw const release).cast(),
        )
    };
    call.answer.expect("the body ran")
}

/// The host has no exception frames: a panic stands in for the exception, its unwind for the
/// SEH unwind, so the tests see `release` run as an exception's unwind runs it.
#[cfg(test)]
pub fn on_unwind<R>(release: &dyn Fn(), body: impl FnOnce() -> R) -> R {
    extern crate std;
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)) {
        Ok(answer) => answer,
        Err(panic) => {
            release();
            std::panic::resume_unwind(panic)
        }
    }
}

/// A host build for another architecture (not the tests'): no exceptions to unwind.
#[cfg(all(not(target_arch = "x86"), not(test)))]
pub fn on_unwind<R>(_release: &dyn Fn(), body: impl FnOnce() -> R) -> R {
    body()
}

/// [`on_unwind`]'s body and its answer, handed to [`run`] through the registered call.
#[cfg(all(target_arch = "x86", not(test)))]
struct Call<F, R> {
    body: Option<F>,
    answer: Option<R>,
}

/// The registered call: the body run, its answer kept.
///
/// # Safety
///
/// `call` is the [`Call`] of `on_unwind`'s frame, no other reference to it in use.
#[cfg(all(target_arch = "x86", not(test)))]
unsafe extern "C" fn run<F: FnOnce() -> R, R>(call: *mut u8) {
    // SAFETY: the caller's contract.
    let call = unsafe { &mut *call.cast::<Call<F, R>>() };
    if let Some(body) = call.body.take() {
        call.answer = Some(body());
    }
}

/// The registration's release: an unwind is passing.
///
/// # Safety
///
/// `release` is the `&dyn Fn()` of `on_unwind`'s frame, still in place under the unwind.
#[cfg(all(target_arch = "x86", not(test)))]
unsafe extern "C" fn run_release(release: *const u8) {
    // SAFETY: the caller's contract.
    let release = unsafe { *release.cast::<&dyn Fn()>() };
    release();
}

#[cfg(all(target_arch = "x86", not(test)))]
mod frame {
    /// EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND: the record's flags in an unwind's handler
    /// call.
    const EXCEPTION_UNWIND: u32 = 0x6;

    /// `call(data)` under a registration of its own on `fs:[0]`, `{next, handler, release,
    /// data for release}`, taken off when `call` returns. The handler calls `release(data)` when
    /// an unwind passes the registration. cdecl.
    ///
    /// # Safety
    ///
    /// `call(data)` and `release(release_data)` are sound calls, the second at any point the
    /// first may be unwound from.
    #[unsafe(naked)]
    pub unsafe extern "C" fn registered(
        _call: unsafe extern "C" fn(*mut u8),
        _data: *mut u8,
        _release: unsafe extern "C" fn(*const u8),
        _release_data: *const u8,
    ) {
        core::arch::naked_asm!(
            "push ebp",
            "mov ebp, esp",
            "push dword ptr [ebp+20]",
            "push dword ptr [ebp+16]",
            "mov eax, offset {handler}",
            "push eax",
            "push dword ptr fs:[0]",
            "mov dword ptr fs:[0], esp",
            "push dword ptr [ebp+12]",
            "call dword ptr [ebp+8]",
            "add esp, 4",
            "mov ecx, dword ptr [esp]",
            "mov dword ptr fs:[0], ecx",
            "mov esp, ebp",
            "pop ebp",
            "ret",
            handler = sym handler,
        )
    }

    /// The registration's handler (cdecl: record, registration, context, dispatcher context):
    /// for an unwind, the registration's release called; ExceptionContinueSearch either way.
    #[unsafe(naked)]
    unsafe extern "C" fn handler() -> u32 {
        core::arch::naked_asm!(
            "mov eax, dword ptr [esp+4]",
            "test dword ptr [eax+4], {unwind}",
            "jz 2f",
            "cld",
            "mov eax, dword ptr [esp+8]",
            "push dword ptr [eax+12]",
            "call dword ptr [eax+8]",
            "add esp, 4",
            "2:",
            "mov eax, 1",
            "ret",
            unwind = const EXCEPTION_UNWIND,
        )
    }
}
