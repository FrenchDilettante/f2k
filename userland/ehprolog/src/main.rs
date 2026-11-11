//! ehprolog.exe: calls msvcrt's `_EH_prolog` as a function Visual C++ compiles with /O1 does (its
//! handler in EAX), records the frame it returns with, unlinks the registration and returns
//! through the frame as that function's epilogue does, then prints one line for each check of
//! what it recorded (src/lib.rs) and ends with 0 when all hold.

#![no_std]
#![no_main]

use core::mem::offset_of;

use ehprolog::*;

exe::entry!(main);

/// The calls ehprolog makes, as msvcrt exports them, and its probe.
mod ffi {
    #[link(name = "msvcrt", kind = "raw-dylib", import_name_type = "noprefix")]
    unsafe extern "C" {
        /// Not a C function (msvcrt's src/seh.s): the probe calls it. The import's name is the
        /// symbol's without its first underscore (`noprefix`), so the symbol carries two: an
        /// undecorated import of `_EH_prolog` loses the name's own underscore, `EH_prolog`.
        #[link_name = "__EH_prolog"]
        pub fn eh_prolog();
    }

    unsafe extern "C" {
        /// The assembly below: a function with a C++ frame.
        pub fn f2k_ehprolog_probe(
            record: *mut super::Record,
            eh_prolog: unsafe extern "C" fn(),
            handler: extern "C" fn(usize, usize, usize, usize) -> u32,
        );
    }
}

// f2k_ehprolog_probe(record, eh_prolog, handler), cdecl: a function's prologue as /O1 compiles it
// (`mov eax, <handler>; call _EH_prolog`), the registers at its entry recorded before and the frame
// after, then the epilogue that unlinks the registration and returns through the saved EBP. ECX
// and EDX are set to known values across the call. After the call, the record's address is read
// through the frame ([ebp+8]), where the function's code finds its first argument.
core::arch::global_asm!(
    ".p2align 4",
    ".globl _f2k_ehprolog_probe",
    "_f2k_ehprolog_probe:",
    "    mov eax, dword ptr [esp+4]",
    "    mov dword ptr [eax+{entry_esp}], esp",
    "    mov dword ptr [eax+{entry_ebp}], ebp",
    "    mov ecx, dword ptr fs:[0]",
    "    mov dword ptr [eax+{entry_head}], ecx",
    "    mov ecx, dword ptr [esp+12]",
    "    mov dword ptr [eax+{given_handler}], ecx",
    "    mov dword ptr [eax+{given_argument}], eax",
    "    mov ecx, {ecx_value}",
    "    mov edx, {edx_value}",
    "    mov eax, dword ptr [esp+12]",
    "    call dword ptr [esp+8]",
    "    mov eax, dword ptr [ebp+8]",
    "    mov dword ptr [eax+{argument}], eax",
    "    mov dword ptr [eax+{frame}], ebp",
    "    mov dword ptr [eax+{esp_found}], esp",
    "    mov dword ptr [eax+{ecx_found}], ecx",
    "    mov dword ptr [eax+{edx_found}], edx",
    "    mov ecx, dword ptr fs:[0]",
    "    mov dword ptr [eax+{head}], ecx",
    "    mov ecx, dword ptr [ebp]",
    "    mov dword ptr [eax+{saved_ebp}], ecx",
    "    mov ecx, dword ptr [ebp-4]",
    "    mov dword ptr [eax+{state}], ecx",
    "    mov ecx, dword ptr [ebp-8]",
    "    mov dword ptr [eax+{handler}], ecx",
    "    mov ecx, dword ptr [ebp-12]",
    "    mov dword ptr [eax+{next}], ecx",
    "    mov ecx, dword ptr [ebp-12]",
    "    mov dword ptr fs:[0], ecx",
    "    mov esp, ebp",
    "    pop ebp",
    "    ret",
    entry_esp = const offset_of!(Record, entry_esp),
    entry_ebp = const offset_of!(Record, entry_ebp),
    entry_head = const offset_of!(Record, entry_head),
    given_handler = const offset_of!(Record, given_handler),
    given_argument = const offset_of!(Record, given_argument),
    frame = const offset_of!(Record, frame),
    esp_found = const offset_of!(Record, esp),
    head = const offset_of!(Record, head),
    saved_ebp = const offset_of!(Record, saved_ebp),
    state = const offset_of!(Record, state),
    handler = const offset_of!(Record, handler),
    next = const offset_of!(Record, next),
    ecx_found = const offset_of!(Record, ecx),
    edx_found = const offset_of!(Record, edx),
    argument = const offset_of!(Record, argument),
    ecx_value = const ECX,
    edx_value = const EDX,
);

/// The handler the frame registers, an exception handler's shape: no exception reaches it while
/// the frame is linked, and it would pass one on (ExceptionContinueSearch).
extern "C" fn handler(_record: usize, _frame: usize, _context: usize, _dispatcher: usize) -> u32 {
    1
}

/// fs:[0], the thread's innermost exception registration.
fn registration_head() -> u32 {
    let head: u32;
    // SAFETY: fs is the thread's TEB, whose first dword is the registration chain's head.
    unsafe {
        core::arch::asm!(
            "mov {}, dword ptr fs:[0]",
            out(reg) head,
            options(nostack, readonly, preserves_flags)
        );
    }
    head
}

fn main() -> u32 {
    let mut record = Record::default();
    // SAFETY: the probe writes the record it is given and nothing else, and returns with the
    // registers a cdecl function keeps (EBX, ESI, EDI, EBP) and fs:[0] as it found them when
    // `_EH_prolog` builds the frame its epilogue expects.
    unsafe { ffi::f2k_ehprolog_probe(&mut record, ffi::eh_prolog, handler) };
    let head_after = registration_head();
    let mut code = 0;
    for check in checks(&record, head_after) {
        let _ = exe::stdout().print(format_args!("{check}\r\n"));
        if !check.holds() {
            code = MISMATCH;
        }
    }
    code
}
