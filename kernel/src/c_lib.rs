//! C Library Functions for bare-metal
//!
//! Provides C standard library functions needed for linking. These are marked as unsafe because
//! they dereference raw pointers.

use core::ffi::c_void;

/// Memory comparison for bare-metal
#[no_mangle]
pub unsafe extern "C" fn memcmp(s1: *const c_void, s2: *const c_void, n: usize) -> i32 {
    let p1 = s1 as *const u8;
    let p2 = s2 as *const u8;

    for i in 0..n {
        let a = *p1.add(i);
        let b = *p2.add(i);
        if a != b {
            return (a as i32) - (b as i32);
        }
    }
    0
}

/// Memory set and copy for the target: the string instructions, one `rep` each. They must not be
/// Rust loops: the kernel crate builds unoptimized under every test profile (see Cargo.toml), where
/// a `for` over `ptr::add` costs a range step and two precondition checks per byte — every struct
/// move goes through these symbols, so a byte loop makes a thread's creation take milliseconds.
#[cfg(target_arch = "x86")]
core::arch::global_asm!(
    ".section .text.memset, \"ax\"",
    ".global memset",
    ".type memset, @function",
    "memset:",
    "    push edi",
    "    mov edi, [esp + 8]",
    "    mov eax, [esp + 12]",
    "    mov ecx, [esp + 16]",
    "    cld",
    "    rep stosb",
    "    mov eax, [esp + 8]",
    "    pop edi",
    "    ret",
    ".size memset, . - memset",
    ".section .text.memcpy, \"ax\"",
    ".global memcpy",
    ".type memcpy, @function",
    "memcpy:",
    "    push esi",
    "    push edi",
    "    mov edi, [esp + 12]",
    "    mov esi, [esp + 16]",
    "    mov ecx, [esp + 20]",
    "    cld",
    "    rep movsb",
    "    mov eax, [esp + 12]",
    "    pop edi",
    "    pop esi",
    "    ret",
    ".size memcpy, . - memcpy",
    // memmove (what `ptr::copy` and `copy_within` with a non-constant length lower to): forwards
    // unless the destination starts inside the source, then backwards from the last byte with the
    // direction flag set (and cleared again: the kernel runs with it clear).
    ".section .text.memmove, \"ax\"",
    ".global memmove",
    ".type memmove, @function",
    "memmove:",
    "    push esi",
    "    push edi",
    "    mov edi, [esp + 12]",
    "    mov esi, [esp + 16]",
    "    mov ecx, [esp + 20]",
    "    mov eax, edi",
    "    sub eax, esi",
    "    cmp eax, ecx",
    "    jb 2f",
    "    cld",
    "    rep movsb",
    "    jmp 3f",
    "2:",
    "    lea esi, [esi + ecx - 1]",
    "    lea edi, [edi + ecx - 1]",
    "    std",
    "    rep movsb",
    "    cld",
    "3:",
    "    mov eax, [esp + 12]",
    "    pop edi",
    "    pop esi",
    "    ret",
    ".size memmove, . - memmove",
);

/// Memory set for bare-metal (the host build's; the target's is the routine above)
#[cfg(not(target_arch = "x86"))]
#[no_mangle]
pub unsafe extern "C" fn memset(s: *mut c_void, c: i32, n: usize) -> *mut c_void {
    let p = s as *mut u8;
    let byte = c as u8;
    for i in 0..n {
        *p.add(i) = byte;
    }
    s
}

/// Memory copy for bare-metal (the host build's; the target's is the routine above)
#[cfg(not(target_arch = "x86"))]
#[no_mangle]
pub unsafe extern "C" fn memcpy(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    let d = dest as *mut u8;
    let s = src as *const u8;
    for i in 0..n {
        *d.add(i) = *s.add(i);
    }
    dest
}

