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

/// Memory set for bare-metal
#[no_mangle]
pub unsafe extern "C" fn memset(s: *mut c_void, c: i32, n: usize) -> *mut c_void {
    let p = s as *mut u8;
    let byte = c as u8;
    for i in 0..n {
        *p.add(i) = byte;
    }
    s
}

/// Memory copy for bare-metal
#[no_mangle]
pub unsafe extern "C" fn memcpy(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    let d = dest as *mut u8;
    let s = src as *const u8;
    for i in 0..n {
        *d.add(i) = *s.add(i);
    }
    dest
}

/// Memory move for bare-metal: `memcpy` that tolerates overlap, copying backwards when the
/// destination starts inside the source. `ptr::copy`/`copy_within` with a non-constant length lower
/// to this symbol. Target-only: host test builds link the platform's.
#[cfg(target_arch = "x86")]
#[no_mangle]
pub unsafe extern "C" fn memmove(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    let d = dest as *mut u8;
    let s = src as *const u8;
    if (d as usize) <= (s as usize) || (d as usize) >= (s as usize).wrapping_add(n) {
        for i in 0..n {
            *d.add(i) = *s.add(i);
        }
    } else {
        for i in (0..n).rev() {
            *d.add(i) = *s.add(i);
        }
    }
    dest
}
