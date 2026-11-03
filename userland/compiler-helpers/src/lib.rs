//! What the compiler expects of an MSVC environment without its C runtime, for every image the
//! userland workspace links (the system DLLs, through rtl, and F2K's own programs, through exe):
//! the 64-bit division helpers LLVM calls on i686-*-windows-msvc, `_aulldiv`, `_aullrem`,
//! `_alldiv` and `_allrem`, the stack probe `_chkstk` (and its second name, `_alloca_probe`), and
//! the `_fltused` marker. Only on that target; the division helpers' cores are host-tested.
//!
//! The stack probe is what lets a function's frame reach a page or more. A thread's stack is
//! committed a little at a time: a guard page sits below the committed pages, and touching it
//! commits it and moves the guard a page down. A frame of a page or more, lowered in one step,
//! could skip the guard and fault, so for such a frame LLVM (the target spec's stack probes
//! `none`: its native Windows probe) calls `_chkstk` with the frame's size in EAX, as MSVC's
//! code does, and `_chkstk` touches each page in order and lowers ESP itself. An image that calls
//! it links its own copy, as MSVC programs link the C runtime's; ntdll exports the same routine
//! under both names, as Windows 2000's does.
//!
//! The probe is a handful of instructions with nothing to test on the host. To check it, build a
//! function with a frame of several pages (a local buffer touched at both ends) into a program,
//! see `call __chkstk` in its prologue (`llvm-objdump -d --x86-asm-syntax=intel`), and run it on a
//! thread started with the default stack (its initial commit and the guard page only). Without
//! the probe's touches, the frame's first store lands below the guard page and faults.

#![cfg_attr(not(test), no_std)]

// The helpers' cores are the MSVC environment's (`msvc`, x86 only) and the host tests'.
#[cfg_attr(not(all(target_arch = "x86", target_os = "windows")), allow(dead_code))]
/// Unsigned 64-bit division and remainder by shift and subtract: no 64-bit division instruction
/// exists on i686, and this must not call the helpers it implements. A zero divisor yields zero
/// (the helpers' callers check it first, as Rust's own division does).
fn udivmod(mut dividend: u64, divisor: u64) -> (u64, u64) {
    if divisor == 0 {
        return (0, 0);
    }
    let (mut quotient, mut remainder) = (0u64, 0u64);
    for _ in 0..64 {
        remainder = (remainder << 1) | (dividend >> 63);
        dividend <<= 1;
        quotient <<= 1;
        if remainder >= divisor {
            remainder -= divisor;
            quotient |= 1;
        }
    }
    (quotient, remainder)
}

#[cfg_attr(not(all(target_arch = "x86", target_os = "windows")), allow(dead_code))]
/// Signed 64-bit division and remainder, truncating toward zero (the remainder takes the
/// dividend's sign), through the unsigned core.
fn idivmod(dividend: i64, divisor: i64) -> (i64, i64) {
    let (quotient, remainder) = udivmod(dividend.unsigned_abs(), divisor.unsigned_abs());
    let quotient = if (dividend < 0) != (divisor < 0) {
        (quotient as i64).wrapping_neg()
    } else {
        quotient as i64
    };
    let remainder = if dividend < 0 {
        (remainder as i64).wrapping_neg()
    } else {
        remainder as i64
    };
    (quotient, remainder)
}

#[cfg(all(target_arch = "x86", target_os = "windows"))]
mod msvc {
    //! The MSVC helpers. The division helpers take both operands on the stack (low dword first),
    //! answer in EDX:EAX, and pop the 16 argument bytes; each re-pushes the operands for a cdecl
    //! Rust body. The stack probe has a convention of its own (below).

    extern "C" fn udiv(a: u64, b: u64) -> u64 {
        super::udivmod(a, b).0
    }
    extern "C" fn urem(a: u64, b: u64) -> u64 {
        super::udivmod(a, b).1
    }
    extern "C" fn sdiv(a: i64, b: i64) -> i64 {
        super::idivmod(a, b).0
    }
    extern "C" fn srem(a: i64, b: i64) -> i64 {
        super::idivmod(a, b).1
    }

    macro_rules! helper {
        ($name:ident, $body:ident) => {
            #[unsafe(no_mangle)]
            #[unsafe(naked)]
            pub unsafe extern "C" fn $name() {
                core::arch::naked_asm!(
                    "push dword ptr [esp+16]",
                    "push dword ptr [esp+16]",
                    "push dword ptr [esp+16]",
                    "push dword ptr [esp+16]",
                    "call {body}",
                    "add esp, 16",
                    "ret 16",
                    body = sym $body,
                )
            }
        };
    }
    helper!(_aulldiv, udiv);
    helper!(_aullrem, urem);
    helper!(_alldiv, sdiv);
    helper!(_allrem, srem);

    // _chkstk (`__chkstk`, decorated) and _alloca_probe, one routine under two names: MSVC's x86
    // stack probe. EAX holds the bytes to allocate. Each page from the caller's ESP down to ESP
    // less EAX is touched in order (a read: enough to fire the guard page), then ESP is lowered by
    // EAX and the routine returns to its caller through the return address it saved, the new
    // frame below. Only EAX and the flags change: ECX is saved and restored, EDX untouched (LLVM
    // counts on that, as MSVC's callers do: a fastcall or thiscall prologue, and Rust's own calls
    // on this target, still hold arguments there). Its section is a COMDAT keyed on `__chkstk`, so
    // an image that never calls it leaves it out, as a link takes a library's probe only when
    // it is called.
    core::arch::global_asm!(
        ".section .text$__chkstk,\"xr\",discard,__chkstk",
        ".p2align 4",
        ".globl __chkstk",
        ".globl __alloca_probe",
        "__chkstk:",
        "__alloca_probe:",
        // ECX saved; ECX the caller's ESP (above the saved ECX and the return address).
        "    push ecx",
        "    lea ecx, [esp + 8]",
        "    cmp eax, 0x1000",
        "    jb 2f",
        // A page at a time while a whole page remains: each touch a page below the last.
        "1:",
        "    sub ecx, 0x1000",
        "    sub eax, 0x1000",
        "    test dword ptr [ecx], eax",
        "    cmp eax, 0x1000",
        "    jae 1b",
        // The rest, under a page: the new ESP, touched too.
        "2:",
        "    sub ecx, eax",
        "    test dword ptr [ecx], eax",
        // The new ESP installed (the saved ECX and return address now above it), ECX restored,
        // and back to the caller.
        "    mov eax, esp",
        "    mov esp, ecx",
        "    mov ecx, dword ptr [eax]",
        "    push dword ptr [eax + 4]",
        "    ret",
    );

    /// The marker MSVC objects reference when they use floating point.
    #[unsafe(no_mangle)]
    pub static _fltused: i32 = 0;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsigned_division_matches_u64() {
        for &(a, b) in &[
            (0u64, 1u64),
            (1, 1),
            (u64::MAX, 3),
            (0x1234_5678_9ABC_DEF0, 0x1_0000_0001),
            (7, 1 << 63),
            (u64::MAX, u64::MAX),
        ] {
            assert_eq!(udivmod(a, b), (a / b, a % b), "{a:#x} / {b:#x}");
        }
    }

    #[test]
    fn signed_division_truncates_toward_zero() {
        for &(a, b) in &[
            (7i64, 2i64),
            (-7, 2),
            (7, -2),
            (-7, -2),
            (i64::MIN, 3),
            (i64::MIN + 1, -1),
            (0, -5),
        ] {
            assert_eq!(idivmod(a, b), (a / b, a % b), "{a} / {b}");
        }
        assert_eq!(
            idivmod(i64::MIN, -1),
            (i64::MIN, 0),
            "wraps like the MSVC helper"
        );
    }
}
