//! The runtime library, as Windows 2000's Rtl: the support code the system DLLs link.
//!
//! What every build shares, host-tested: the status mapping ([`status`]: RtlNtStatusToDosError's
//! table, which kernel32 reports every failed system service through), the code pages and their
//! conversions ([`codepage`], [`cp1252`]), the time conversions ([`time`]), the critical sections
//! ([`critsec`]: ntdll's RtlEnterCriticalSection family, over the system it is handed), and the console
//! server's message format and rules ([`console`]: kernel32's side and the kernel's stand-in for
//! csrss share them), and structured exception handling's walks ([`seh`]: ntdll's
//! RtlDispatchException and RtlUnwind, with the CONTEXT and record layouts the kernel writes).
//!
//! On the DLLs' target (i686 Windows) only: what the compiler expects of an MSVC environment without
//! its CRT (the 64-bit division helpers LLVM calls on i686-*-windows-msvc, `_aulldiv`, `_aullrem`,
//! `_alldiv`, `_allrem`, and the `_fltused` marker; their cores are host-tested), the panic
//! handler, and [`sys`], the calling thread's TEB, the gate and the raises.

#![cfg_attr(not(test), no_std)]

pub mod codepage;
pub mod console;
pub mod cp1252;
pub mod critsec;
pub mod seh;
pub mod status;
mod status_table;
#[cfg(all(target_arch = "x86", target_os = "windows", not(test)))]
pub mod sys;
pub mod time;

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
    //! The MSVC helpers: both operands on the stack (low dword first), the result in EDX:EAX, the
    //! callee popping the 16 argument bytes. Each re-pushes the operands for a cdecl Rust body.

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

    /// The marker MSVC objects reference when they use floating point.
    #[unsafe(no_mangle)]
    pub static _fltused: i32 = 0;

    /// A panic in user-mode support code faults the process (an invalid opcode), never the system.
    #[cfg(not(test))]
    #[panic_handler]
    fn panic(_: &core::panic::PanicInfo) -> ! {
        // SAFETY: ud2 raises the invalid-opcode fault; nothing follows it.
        unsafe { core::arch::asm!("ud2", options(noreturn)) }
    }
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
