//! A read probe that needs no import and no system service: whether a byte can be read, found by
//! reading it under an exception frame of the probe's own (a `__try` around the touch). For the
//! system DLLs whose Windows 2000 import table holds no memory query of their own to ask
//! (NtQueryVirtualMemory, VirtualQuery, IsBadReadPtr), so their stub routines can show a string
//! argument without risking a fault ([`Probed`]).
//!
//! The probe registers `{next, handler, resume}` on `fs:[0]`, then reads the byte. A fault reaches
//! the handler through ntdll's exception dispatcher; the handler points the faulting context at the
//! resume point with EAX zero and continues execution, so the dispatcher resumes the probe there
//! (no unwind: the probe's registration is still the chain's head). An unwind passing through is
//! not the probe's: the handler searches on. A guard page the read meets is spent, as any access
//! spends it.

use crate::stub::{Memory, LOWEST_MAPPED};

/// The CONTEXT's EAX and EIP (x86).
const CONTEXT_EAX: usize = 0xB0;
const CONTEXT_EIP: usize = 0xB8;

/// Whether the byte at `address` can be read: TRUE (1) or FALSE (0). stdcall, one argument. (A
/// naked function is emitted once, so its resume point can be a named label.)
#[unsafe(naked)]
#[allow(named_asm_labels)]
unsafe extern "system" fn probe_read(_address: usize) -> u32 {
    core::arch::naked_asm!(
        "push ebp",
        "mov ebp, esp",
        "mov eax, offset .Lf2k_probe_resume",
        "push eax",
        "mov eax, offset {handler}",
        "push eax",
        "push dword ptr fs:[0]",
        "mov dword ptr fs:[0], esp",
        "mov ecx, dword ptr [ebp+8]",
        "mov al, byte ptr [ecx]",
        "mov eax, 1",
        // The resume point: EAX 1 after the read, 0 from the handler.
        ".Lf2k_probe_resume:",
        "mov ecx, dword ptr [esp]",
        "mov dword ptr fs:[0], ecx",
        "mov esp, ebp",
        "pop ebp",
        "ret 4",
        handler = sym probe_handler,
    )
}

/// The probe's exception handler (cdecl: record, frame, context, dispatcher context): the context
/// resumed at the registration's resume point with EAX 0 (ExceptionContinueExecution), or, for an
/// unwind, ExceptionContinueSearch.
#[unsafe(naked)]
unsafe extern "C" fn probe_handler() -> u32 {
    core::arch::naked_asm!(
        "mov eax, dword ptr [esp+4]",
        "test dword ptr [eax+4], {unwind}",
        "jnz 2f",
        "mov eax, dword ptr [esp+12]",
        "mov ecx, dword ptr [esp+8]",
        "mov ecx, dword ptr [ecx+8]",
        "mov dword ptr [eax+{eip}], ecx",
        "mov dword ptr [eax+{eax}], 0",
        "xor eax, eax",
        "ret",
        "2:",
        "mov eax, 1",
        "ret",
        unwind = const crate::seh::EXCEPTION_UNWIND,
        eip = const CONTEXT_EIP,
        eax = const CONTEXT_EAX,
    )
}

/// The calling process's memory, as the probe finds it: a byte can be read when reading it does
/// not fault. The lowest 64 KiB are never mapped.
pub struct Probed;

impl Memory for Probed {
    fn readable(&self, address: usize) -> bool {
        // SAFETY: the read is the probe's, under its own exception frame.
        address >= LOWEST_MAPPED && unsafe { probe_read(address) } != 0
    }
}
