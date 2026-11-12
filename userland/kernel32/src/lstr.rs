//! The lstr string functions, as Windows 2000's kernel32 makes them: lstrlen, lstrcpy, lstrcpyn and
//! lstrcat, each in its A form (bytes) and its W form (UTF-16 units). Windows 2000 runs each one's
//! work inside `__try`/`__except(EXCEPTION_EXECUTE_HANDLER)`, so a pointer the work cannot read or
//! write, NULL included, answers 0 (lstrlen) or NULL (the others) instead of faulting the caller;
//! the last error is left alone. lstrcmp and lstrcmpi are the locale group's
//! ([`crate::locale`]).
//!
//! The guard is the pointer probes' handler (src/probe.s): `f2k_k32_guarded` registers a frame of
//! theirs, calls the export's body under it, and answers 0 when the body faults. The bodies are
//! Rust, so the host tests run them (without the guard: the host's own memory, and NULL, which a
//! body tests itself before it reads); every access to the caller's memory is volatile, in the
//! order the loop makes it, so a fault leaves exactly the units the copy already wrote. Each is a
//! unit wide (a byte, or a UTF-16 unit through two bytes at any alignment), except lstrcpyA's,
//! which moves four bytes at a time ([`copy_narrow`]). A body abandoned by a fault owns nothing —
//! plain loops over raw addresses — so no destructor is skipped.

/// A body the guard runs: three dword arguments (the export's, the unused ones zero), its answer.
pub(crate) type Body = unsafe extern "C" fn(usize, usize, usize) -> usize;

/// `body(a, b, c)` under the probes' exception frame: its answer, or 0 when it faults.
///
/// # Safety
///
/// The arguments are what the body takes; an address in them may be one the caller cannot reach,
/// which faults inside the guard (on the host, which has no guard, they are the test's own memory
/// or null).
pub(crate) unsafe fn guarded(body: Body, a: usize, b: usize, c: usize) -> usize {
    #[cfg(all(target_arch = "x86", not(test)))]
    {
        unsafe extern "C" {
            /// src/probe.s's guarded call.
            fn f2k_k32_guarded(body: Body, a: usize, b: usize, c: usize) -> usize;
        }
        // SAFETY: the guard calls the body with the arguments, under a frame whose handler takes
        // whatever it raises; the body owns nothing a fault would leak (the contract).
        unsafe { f2k_k32_guarded(body, a, b, c) }
    }
    #[cfg(any(not(target_arch = "x86"), test))]
    {
        // SAFETY: the host tests' own memory, or null, which the bodies test first.
        unsafe { body(a, b, c) }
    }
}

/// A string's unit: a byte (the A forms) or a UTF-16 unit (the W forms), read and written where
/// it is, at any alignment, one volatile byte access at a time.
trait Unit: Copy + PartialEq {
    const SIZE: usize;
    const NUL: Self;

    /// The unit at `at`.
    ///
    /// # Safety
    ///
    /// `at` is readable, or the read faults (inside the guard).
    unsafe fn load(at: usize) -> Self;

    /// Write `self` at `at`.
    ///
    /// # Safety
    ///
    /// `at` is writable, or the write faults (inside the guard).
    unsafe fn store(self, at: usize);
}

impl Unit for u8 {
    const NUL: u8 = 0;
    const SIZE: usize = 1;

    unsafe fn load(at: usize) -> u8 {
        // SAFETY: the contract.
        unsafe { (at as *const u8).read_volatile() }
    }

    unsafe fn store(self, at: usize) {
        // SAFETY: the contract.
        unsafe { (at as *mut u8).write_volatile(self) }
    }
}

impl Unit for u16 {
    const NUL: u16 = 0;
    const SIZE: usize = 2;

    unsafe fn load(at: usize) -> u16 {
        // SAFETY: the contract; a byte array has no alignment to keep.
        u16::from_le_bytes(unsafe { (at as *const [u8; 2]).read_volatile() })
    }

    unsafe fn store(self, at: usize) {
        // SAFETY: the contract; as above.
        unsafe { (at as *mut [u8; 2]).write_volatile(self.to_le_bytes()) }
    }
}

/// The address of unit `index` of the string at `base`.
fn unit_at<U: Unit>(base: usize, index: usize) -> usize {
    base.wrapping_add(index.wrapping_mul(U::SIZE))
}

/// The units before the string's terminator.
///
/// # Safety
///
/// `string` is a readable string, or the read faults (inside the guard).
unsafe fn length<U: Unit>(string: usize) -> usize {
    let mut count = 0;
    // SAFETY: the contract, each unit to the terminator.
    while unsafe { U::load(unit_at::<U>(string, count)) } != U::NUL {
        count += 1;
    }
    count
}

/// Copy the source's units to the destination, each read then written, up to and including its
/// terminator (strcpy's loop).
///
/// # Safety
///
/// As [`length`]'s, the destination writable.
unsafe fn copy<U: Unit>(destination: usize, source: usize) {
    let mut at = 0;
    loop {
        // SAFETY: the contract, unit by unit.
        let unit = unsafe { U::load(unit_at::<U>(source, at)) };
        // SAFETY: as above.
        unsafe { unit.store(unit_at::<U>(destination, at)) };
        if unit == U::NUL {
            return;
        }
        at += 1;
    }
}

/// lstrlen's work: the string's length in units, its terminator left out; 0 for NULL.
unsafe extern "C" fn length_of<U: Unit>(string: usize, _: usize, _: usize) -> usize {
    if string == 0 {
        return 0;
    }
    // SAFETY: the caller's string, under the guard.
    unsafe { length::<U>(string) }
}

/// lstrcpyA's copy, four bytes at a time as Windows 2000's is. The lstr fixture's capture shows its
/// stores are wider than a byte: a copy of "abcdefgh" (its source 4-byte aligned) into a
/// destination three bytes before a no-access page writes none of the three, where lstrcpyW's
/// unit-wide copy leaves "abc". The model, the simplest the capture's lstrcpyA lines agree with:
///
/// - a head, byte by byte (each read then written), until the source is 4-byte aligned, or its
///   terminator is copied;
/// - then the source a dword at a time, each read aligned (so it never crosses into a page the
///   string does not reach): a dword without the terminator is written as one 4-byte store at the
///   destination's matching place, whatever its alignment, so a store that faults writes none of
///   its bytes;
/// - the dword holding the terminator, byte by byte up to and including it, nothing written past
///   it.
///
/// # Safety
///
/// As [`copy`]'s.
unsafe fn copy_narrow(destination: usize, source: usize) {
    let mut at = 0;
    while source.wrapping_add(at) % 4 != 0 {
        // SAFETY: the contract, byte by byte.
        let byte = unsafe { u8::load(source.wrapping_add(at)) };
        // SAFETY: as above.
        unsafe { byte.store(destination.wrapping_add(at)) };
        if byte == 0 {
            return;
        }
        at += 1;
    }
    loop {
        // SAFETY: the contract; the source's dword is aligned, inside one page.
        let dword = unsafe { (source.wrapping_add(at) as *const u32).read_volatile() };
        let bytes = dword.to_le_bytes();
        if let Some(end) = bytes.iter().position(|&byte| byte == 0) {
            for (offset, &byte) in bytes[..=end].iter().enumerate() {
                // SAFETY: the contract, byte by byte.
                unsafe { byte.store(destination.wrapping_add(at + offset)) };
            }
            return;
        }
        // SAFETY: the contract.
        unsafe { store_dword(destination.wrapping_add(at), dword) };
        at += 4;
    }
}

/// Write `dword` at `at`, at any alignment, as one 4-byte store: a fault anywhere in it writes none
/// of its bytes.
///
/// # Safety
///
/// `at`'s four bytes are writable, or the store faults (inside the guard).
unsafe fn store_dword(at: usize, dword: u32) {
    #[cfg(all(target_arch = "x86", not(test)))]
    {
        // SAFETY: the contract; one `mov`, which x86 allows at any alignment.
        unsafe {
            core::arch::asm!(
                "mov dword ptr [{at}], {dword}",
                at = in(reg) at,
                dword = in(reg) dword,
                options(nostack, preserves_flags),
            )
        }
    }
    #[cfg(any(not(target_arch = "x86"), test))]
    {
        // SAFETY: the contract (the host tests' own memory); a byte array has no alignment.
        unsafe { (at as *mut [u8; 4]).write_volatile(dword.to_le_bytes()) }
    }
}

/// lstrcpy's work: the source copied, its terminator too; the destination, or NULL when either is
/// NULL. The A form copies through [`copy_narrow`], the W form unit by unit.
unsafe extern "C" fn copy_into<U: Unit>(destination: usize, source: usize, _: usize) -> usize {
    if destination == 0 || source == 0 {
        return 0;
    }
    // SAFETY: the caller's strings, under the guard.
    unsafe {
        if U::SIZE == 1 {
            copy_narrow(destination, source);
        } else {
            copy::<U>(destination, source);
        }
    }
    destination
}

/// lstrcpyn's work, Windows 2000's loop: each unit read then written, while the count lasts; the
/// terminator copied ends it, and a count spent puts a terminator over the last unit written — at
/// most `count - 1` units and always the terminator, the rest of the buffer untouched (no padding).
/// A count of 0 touches nothing and answers the destination; otherwise NULL when either is NULL.
/// A negative count is a very large one, as the loop counts it down unsigned.
unsafe extern "C" fn copy_counted<U: Unit>(
    destination: usize,
    source: usize,
    count: usize,
) -> usize {
    let mut left = count as u32;
    if left == 0 {
        return destination;
    }
    if destination == 0 || source == 0 {
        return 0;
    }
    let mut at = 0;
    loop {
        let place = unit_at::<U>(destination, at);
        // SAFETY: the caller's strings, under the guard, unit by unit.
        let unit = unsafe { U::load(unit_at::<U>(source, at)) };
        // SAFETY: as above.
        unsafe { unit.store(place) };
        if unit == U::NUL {
            break;
        }
        left -= 1;
        if left == 0 {
            // SAFETY: as above: the unit just written.
            unsafe { U::NUL.store(place) };
            break;
        }
        at += 1;
    }
    destination
}

/// lstrcat's work: the source copied over the destination's terminator, its own terminator too;
/// the destination, or NULL when either is NULL.
unsafe extern "C" fn append<U: Unit>(destination: usize, source: usize, _: usize) -> usize {
    if destination == 0 || source == 0 {
        return 0;
    }
    // SAFETY: the caller's strings, under the guard.
    unsafe {
        let end = length::<U>(destination);
        copy::<U>(unit_at::<U>(destination, end), source);
    }
    destination
}

/// lstrlenA: the string's length in bytes, its terminator left out; 0 for NULL or a string it
/// cannot read.
///
/// # Safety
///
/// None the call relies on: a bad pointer answers 0.
#[unsafe(export_name = "f2k_export_lstrlenA")]
pub unsafe extern "system" fn lstrlen_a(string: *const u8) -> i32 {
    // SAFETY: the body's argument, under the guard.
    unsafe { guarded(length_of::<u8>, string as usize, 0, 0) as i32 }
}

/// lstrlenW: as lstrlenA, in UTF-16 units.
///
/// # Safety
///
/// As lstrlenA's.
#[unsafe(export_name = "f2k_export_lstrlenW")]
pub unsafe extern "system" fn lstrlen_w(string: *const u16) -> i32 {
    // SAFETY: as in `lstrlen_a`.
    unsafe { guarded(length_of::<u16>, string as usize, 0, 0) as i32 }
}

/// lstrcpyA: the source and its terminator copied to the destination; the destination, or NULL for
/// a NULL or a string it cannot read or write (the units written before the fault stay).
///
/// # Safety
///
/// None the call relies on: a bad pointer answers NULL.
#[unsafe(export_name = "f2k_export_lstrcpyA")]
pub unsafe extern "system" fn lstrcpy_a(destination: *mut u8, source: *const u8) -> *mut u8 {
    // SAFETY: the body's arguments, under the guard.
    unsafe { guarded(copy_into::<u8>, destination as usize, source as usize, 0) as *mut u8 }
}

/// lstrcpyW: as lstrcpyA, in UTF-16 units.
///
/// # Safety
///
/// As lstrcpyA's.
#[unsafe(export_name = "f2k_export_lstrcpyW")]
pub unsafe extern "system" fn lstrcpy_w(destination: *mut u16, source: *const u16) -> *mut u16 {
    // SAFETY: as in `lstrcpy_a`.
    unsafe { guarded(copy_into::<u16>, destination as usize, source as usize, 0) as *mut u16 }
}

/// lstrcpynA: at most `count - 1` bytes of the source copied, then always a terminator, nothing
/// padded (see [`copy_counted`]); the destination, or NULL as lstrcpyA's.
///
/// # Safety
///
/// None the call relies on: a bad pointer answers NULL.
#[unsafe(export_name = "f2k_export_lstrcpynA")]
pub unsafe extern "system" fn lstrcpyn_a(
    destination: *mut u8,
    source: *const u8,
    count: i32,
) -> *mut u8 {
    // SAFETY: the body's arguments, under the guard.
    unsafe {
        guarded(
            copy_counted::<u8>,
            destination as usize,
            source as usize,
            count as u32 as usize,
        ) as *mut u8
    }
}

/// lstrcpynW: as lstrcpynA, in UTF-16 units.
///
/// # Safety
///
/// As lstrcpynA's.
#[unsafe(export_name = "f2k_export_lstrcpynW")]
pub unsafe extern "system" fn lstrcpyn_w(
    destination: *mut u16,
    source: *const u16,
    count: i32,
) -> *mut u16 {
    // SAFETY: as in `lstrcpyn_a`.
    unsafe {
        guarded(
            copy_counted::<u16>,
            destination as usize,
            source as usize,
            count as u32 as usize,
        ) as *mut u16
    }
}

/// lstrcatA: the source and its terminator copied over the destination's terminator; the
/// destination, or NULL as lstrcpyA's.
///
/// # Safety
///
/// None the call relies on: a bad pointer answers NULL.
#[unsafe(export_name = "f2k_export_lstrcatA")]
pub unsafe extern "system" fn lstrcat_a(destination: *mut u8, source: *const u8) -> *mut u8 {
    // SAFETY: the body's arguments, under the guard.
    unsafe { guarded(append::<u8>, destination as usize, source as usize, 0) as *mut u8 }
}

/// lstrcatW: as lstrcatA, in UTF-16 units.
///
/// # Safety
///
/// As lstrcatA's.
#[unsafe(export_name = "f2k_export_lstrcatW")]
pub unsafe extern "system" fn lstrcat_w(destination: *mut u16, source: *const u16) -> *mut u16 {
    // SAFETY: as in `lstrcat_a`.
    unsafe { guarded(append::<u16>, destination as usize, source as usize, 0) as *mut u16 }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A unit read and written at an odd address keeps its bytes in order.
    #[test]
    fn wide_units_go_through_any_alignment() {
        let mut bytes = [0u8; 5];
        let at = bytes.as_mut_ptr() as usize + 1;
        unsafe { 0x4E2Du16.store(at) };
        assert_eq!(bytes, [0, 0x2D, 0x4E, 0, 0]);
        assert_eq!(unsafe { u16::load(at) }, 0x4E2D);
    }

    /// lstrcpyA's copy, from a source at each alignment into a destination at each: the head byte
    /// by byte, then whole dwords, then the terminator's dword byte by byte; the bytes past the
    /// terminator untouched.
    #[test]
    fn the_narrow_copy_stops_at_the_terminator() {
        let text = b"abcdefghij\0";
        for shift in 0..4 {
            let mut source = [0xEEu8; 20];
            source[shift..shift + text.len()].copy_from_slice(text);
            for offset in 0..4 {
                let mut buffer = [b'Z'; 20];
                unsafe {
                    copy_narrow(
                        buffer.as_mut_ptr() as usize + offset,
                        source.as_ptr() as usize + shift,
                    )
                };
                let mut expected = [b'Z'; 20];
                expected[offset..offset + text.len()].copy_from_slice(text);
                assert_eq!(buffer, expected, "source +{shift}, destination +{offset}");
            }
        }
    }

    /// lstrcpyn's loop: the count spent puts the terminator over the last unit written; the
    /// source's terminator ends it first when it fits.
    #[test]
    fn the_counted_copy_ends_in_a_terminator() {
        let copied = |count: u32| {
            let mut buffer = [b'Z'; 8];
            let answer = unsafe {
                copy_counted::<u8>(
                    buffer.as_mut_ptr() as usize,
                    b"abcde\0".as_ptr() as usize,
                    count as usize,
                )
            };
            assert_eq!(answer, buffer.as_ptr() as usize);
            buffer
        };
        assert_eq!(&copied(0), b"ZZZZZZZZ");
        assert_eq!(&copied(1), b"\0ZZZZZZZ");
        assert_eq!(&copied(5), b"abcd\0ZZZ");
        assert_eq!(&copied(6), b"abcde\0ZZ");
        assert_eq!(&copied(u32::MAX), b"abcde\0ZZ");
    }
}
