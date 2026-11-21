//! The registry call that reads a key's listing with everything a subkey has: RegEnumKeyEx, W
//! and A, as Windows 2000's advapi32 runs it over ntdll's NtEnumerateKey (KEY_NODE_INFORMATION: a
//! subkey's name, class and last write). Like the other registry calls it returns its error and
//! leaves the last error alone; a non-NULL lpReserved is ERROR_INVALID_PARAMETER.
//!
//! What a short buffer leaves is what the registry fixture's `enumex` block captures of Windows
//! 2000: RegEnumKeyExW checks the name first, and a name buffer that does not hold the name and its
//! terminator is ERROR_MORE_DATA with the name and its count untouched; RegEnumKeyExA converts, and
//! writes what fits of a name too long, terminated, its count untouched.

use rtl::pod::Pod;
use rtl::status::{STATUS_BUFFER_OVERFLOW, STATUS_BUFFER_TOO_SMALL};
use rtl::winerror::{
    ERROR_INVALID_HANDLE,
    ERROR_INVALID_PARAMETER,
    ERROR_MORE_DATA,
    ERROR_NOACCESS,
    ERROR_SUCCESS,
};

use crate::imports::{self as nt, Answer, HeapBlock};
use crate::registry::{block, error, give, map};
use crate::{caller_bytes_mut, Out};

/// The information class the calls read.
const KEY_NODE_INFORMATION: u32 = 1;

/// Where KEY_NODE_INFORMATION's fields are: the last write, the class's offset and length, the
/// name's length, the name.
const NODE_CLASS_OFFSET: usize = 12;
const NODE_CLASS_LENGTH: usize = 16;
const NODE_NAME_LENGTH: usize = 20;
const NODE_NAME: u32 = 24;

/// The buffer a reply is read into first; one that does not fit goes to a heap block of its size.
const LOCAL: usize = 512;

#[repr(C, align(8))]
struct Local([u8; LOCAL]);

/// An information class's reply, read whole.
struct Reply {
    local: Local,
    heap: Option<HeapBlock>,
    length: usize,
}

impl Reply {
    /// The reply `service` gives: read into the local buffer, or, when the service says it takes
    /// more, again into a heap block of the size it said. A failure is its status's error (an
    /// answer grown between the two reads ERROR_MORE_DATA).
    fn read(mut service: impl FnMut(&mut [u8]) -> Answer) -> Result<Reply, u32> {
        let mut reply = Reply {
            local: Local([0; LOCAL]),
            heap: None,
            length: 0,
        };
        let mut answer = service(&mut reply.local.0);
        if matches!(
            answer.status.0,
            STATUS_BUFFER_OVERFLOW | STATUS_BUFFER_TOO_SMALL
        ) {
            let mut whole = block(answer.length as usize)?;
            answer = service(whole.bytes_mut());
            reply.heap = Some(whole);
        }
        answer.status.ok().map_err(error)?;
        reply.length = answer.length as usize;
        Ok(reply)
    }

    /// The reply's bytes.
    fn bytes(&self) -> &[u8] {
        let all = match &self.heap {
            Some(whole) => whole.bytes(),
            None => &self.local.0[..],
        };
        &all[..self.length.min(all.len())]
    }

    /// The dword at `at` (zero past the reply's end).
    fn word(&self, at: usize) -> u32 {
        u32::read_from(self.bytes(), at).unwrap_or(0)
    }

    /// The `length` bytes at `offset` (none of them past the reply's end).
    fn piece(&self, offset: u32, length: u32) -> &[u8] {
        let rest = self.bytes().get(offset as usize..).unwrap_or(&[]);
        &rest[..rest.len().min(length as usize)]
    }

    /// The UTF-16 text of `length` bytes at `offset`.
    fn text(&self, offset: u32, length: u32) -> &[u16] {
        units(self.piece(offset, length))
    }
}

/// `bytes` as UTF-16 units, an odd last byte left out (the replies put their names and classes at
/// even offsets of an 8-aligned buffer).
fn units(bytes: &[u8]) -> &[u16] {
    // SAFETY: any two bytes make a unit; `align_to` puts only whole, aligned units in the middle.
    let (head, units, _) = unsafe { bytes.align_to::<u16>() };
    if head.is_empty() {
        units
    } else {
        &[]
    }
}

/// `text` and its terminator into `buffer`, which holds them, as UTF-16 (little-endian).
fn put_wide(buffer: &mut [u8], text: &[u16]) {
    for (pair, unit) in buffer
        .as_chunks_mut::<2>()
        .0
        .iter_mut()
        .zip(text.iter().chain([&0]))
    {
        *pair = unit.to_le_bytes();
    }
}

/// `text` and its terminator into the caller's buffer at `at`, as UTF-16: ERROR_NOACCESS for a
/// null one.
///
/// # Safety
///
/// `at` is null, or holds `text.len() + 1` units the call may write.
unsafe fn give_wide(at: *mut u16, text: &[u16]) -> Result<(), u32> {
    // SAFETY: the caller's contract.
    let buffer = unsafe { caller_bytes_mut(at.cast(), 2 * (text.len() + 1)) };
    put_wide(buffer.ok_or(ERROR_NOACCESS)?, text);
    Ok(())
}

/// `text` into `buffer` in the ANSI code page, terminated: its length in bytes. When `buffer`
/// does not hold it and its terminator, what fits of it goes in, terminated (nothing in an empty
/// buffer), and the answer is none.
fn put_ansi(buffer: &mut [u8], text: &[u16]) -> Option<u32> {
    let size = nt::unicode_to_multi_byte_size(text) as usize;
    if size < buffer.len() {
        let written = nt::unicode_to_multi_byte(&mut buffer[..size], text);
        buffer[written] = 0;
        return Some(written as u32);
    }
    if let Some(room) = buffer.len().checked_sub(1) {
        let written = nt::unicode_to_multi_byte(&mut buffer[..room], text);
        buffer[written] = 0;
    }
    None
}

/// The caller's ANSI buffer at `at` of `room` bytes: ERROR_NOACCESS for a null one with room.
///
/// # Safety
///
/// `at` is null or holds `room` bytes the call may write.
unsafe fn ansi_buffer<'a>(at: *mut u8, room: u32) -> Result<&'a mut [u8], u32> {
    // SAFETY: the caller's contract.
    unsafe { caller_bytes_mut(at, room as usize) }.ok_or(ERROR_NOACCESS)
}

/// The NT key `key` stands for (a predefined key's, opened at its first use).
fn nt_key(key: u32) -> Result<u32, u32> {
    if key == 0 {
        return Err(ERROR_INVALID_HANDLE);
    }
    map(key)
}

/// Subkey `index` of `key`: its KEY_NODE_INFORMATION.
struct Node(Reply);

impl Node {
    fn of(key: u32, index: u32) -> Result<Node, u32> {
        let key = nt_key(key)?;
        Reply::read(|buffer| nt::enumerate_key_answer(key, index, KEY_NODE_INFORMATION, buffer))
            .map(Node)
    }

    fn last_write(&self) -> u64 {
        u64::read_from(self.0.bytes(), 0).unwrap_or(0)
    }

    fn name(&self) -> &[u16] {
        self.0.text(NODE_NAME, self.0.word(NODE_NAME_LENGTH))
    }

    fn class(&self) -> &[u16] {
        self.0.text(
            self.0.word(NODE_CLASS_OFFSET),
            self.0.word(NODE_CLASS_LENGTH),
        )
    }
}

/// The checks RegEnumKeyEx makes before it looks at the key: lpReserved NULL, a name count, and a
/// class count with a class buffer.
fn enum_key_ex_arguments(
    reserved: *mut u32,
    count: Option<&Out<'_, u32>>,
    class: bool,
    class_count: Option<&Out<'_, u32>>,
) -> Result<(), u32> {
    if !reserved.is_null() || count.is_none() || (class && class_count.is_none()) {
        return Err(ERROR_INVALID_PARAMETER);
    }
    Ok(())
}

/// The answer's code: ERROR_SUCCESS or the error.
fn code(answer: Result<(), u32>) -> u32 {
    answer.err().unwrap_or(ERROR_SUCCESS)
}

/// RegEnumKeyExW: subkey `index` of `key` (the subkeys in their names' order): its name and,
/// when asked, its class, each with its terminator, their lengths in units written back, and its
/// last write. A buffer that does not hold a name and its terminator is ERROR_MORE_DATA, nothing
/// written; ERROR_NO_MORE_ITEMS past the last subkey.
///
/// # Safety
///
/// `name` holds `*count` units, `class` (null or) `*class_count`; the out parameters are writable
/// or null.
#[allow(clippy::too_many_arguments)]
#[unsafe(export_name = "f2k_export_RegEnumKeyExW")]
pub unsafe extern "system" fn reg_enum_key_ex_w(
    key: u32,
    index: u32,
    name: *mut u16,
    count: *mut u32,
    reserved: *mut u32,
    class: *mut u16,
    class_count: *mut u32,
    last_write: *mut u64,
) -> u32 {
    // SAFETY: the caller's out parameters.
    let (mut count, mut class_count, mut last_write) = unsafe {
        (
            Out::optional(count),
            Out::optional(class_count),
            Out::optional(last_write),
        )
    };
    code((|| {
        enum_key_ex_arguments(
            reserved,
            count.as_ref(),
            !class.is_null(),
            class_count.as_ref(),
        )?;
        let count = count.as_mut().ok_or(ERROR_INVALID_PARAMETER)?;
        let node = Node::of(key, index)?;
        let (text, class_text) = (node.name(), node.class());
        if count.get() as usize <= text.len() {
            return Err(ERROR_MORE_DATA);
        }
        let class_room = class_count.as_ref().map_or(0, Out::get) as usize;
        if !class.is_null() && class_room <= class_text.len() {
            return Err(ERROR_MORE_DATA);
        }
        // SAFETY: the name buffer holds more units than the name has.
        unsafe { give_wide(name, text) }?;
        count.set(text.len() as u32);
        if !class.is_null() {
            // SAFETY: the class buffer holds more units than the class has.
            unsafe { give_wide(class, class_text) }?;
        }
        give(class_count.as_mut(), class_text.len() as u32);
        if let Some(last_write) = last_write.as_mut() {
            last_write.set(node.last_write());
        }
        Ok(())
    })())
}

/// RegEnumKeyExA: RegEnumKeyExW's name and class converted, their lengths in bytes. A buffer that
/// does not hold a name and its terminator gets what fits of it, terminated: ERROR_MORE_DATA, the
/// count untouched.
///
/// # Safety
///
/// As RegEnumKeyExW's, the buffers' sizes in bytes.
#[allow(clippy::too_many_arguments)]
#[unsafe(export_name = "f2k_export_RegEnumKeyExA")]
pub unsafe extern "system" fn reg_enum_key_ex_a(
    key: u32,
    index: u32,
    name: *mut u8,
    count: *mut u32,
    reserved: *mut u32,
    class: *mut u8,
    class_count: *mut u32,
    last_write: *mut u64,
) -> u32 {
    // SAFETY: the caller's out parameters.
    let (mut count, mut class_count, mut last_write) = unsafe {
        (
            Out::optional(count),
            Out::optional(class_count),
            Out::optional(last_write),
        )
    };
    code((|| {
        enum_key_ex_arguments(
            reserved,
            count.as_ref(),
            !class.is_null(),
            class_count.as_ref(),
        )?;
        let count = count.as_mut().ok_or(ERROR_INVALID_PARAMETER)?;
        let node = Node::of(key, index)?;
        // SAFETY: the name buffer holds the bytes its count says.
        let buffer = unsafe { ansi_buffer(name, count.get()) }?;
        let length = put_ansi(buffer, node.name()).ok_or(ERROR_MORE_DATA)?;
        count.set(length);
        if !class.is_null() {
            let room = class_count.as_ref().map_or(0, Out::get);
            // SAFETY: the class buffer holds the bytes its count says.
            let buffer = unsafe { ansi_buffer(class, room) }?;
            let length = put_ansi(buffer, node.class()).ok_or(ERROR_MORE_DATA)?;
            give(class_count.as_mut(), length);
        } else {
            give(
                class_count.as_mut(),
                nt::unicode_to_multi_byte_size(node.class()),
            );
        }
        if let Some(last_write) = last_write.as_mut() {
            last_write.set(node.last_write());
        }
        Ok(())
    })())
}

#[cfg(test)]
mod tests {
    use rtl::testing::utf16_bytes;

    use super::*;
    use crate::imports::host::{KEY_CLASSES, KEY_REPLY};

    /// The F2K tree's handle, as the services are given it (any handle: the stand-ins answer
    /// whatever the test sets).
    const KEY: u32 = 0x3C8;
    use rtl::winerror::ERROR_NO_MORE_ITEMS;

    fn reply(bytes: Vec<u8>) {
        KEY_REPLY.with(|reply| *reply.borrow_mut() = Ok(bytes));
    }

    fn status(status: u32) {
        KEY_REPLY.with(|reply| *reply.borrow_mut() = Err(status));
    }

    fn word(bytes: &mut Vec<u8>, value: u32) {
        bytes.extend(value.to_le_bytes());
    }

    /// A subkey's KEY_NODE_INFORMATION: its name, then its class.
    fn node(name: &str, class: &str) -> Vec<u8> {
        let (name, class) = (utf16_bytes(name), utf16_bytes(class));
        let mut bytes = 0x01D0_0000_1234_5678u64.to_le_bytes().to_vec();
        word(&mut bytes, 0);
        word(&mut bytes, 24 + name.len() as u32);
        word(&mut bytes, class.len() as u32);
        word(&mut bytes, name.len() as u32);
        bytes.extend(name);
        bytes.extend(class);
        bytes
    }

    const CC: u16 = 0xCCCC;

    /// RegEnumKeyExW(index, `room` units, the class asked for or not): the answer, the count, the
    /// name buffer, the class buffer and its count, the time.
    fn enum_ex_w(room: u32, class: bool) -> (u32, u32, Vec<u16>, Vec<u16>, u32, u64) {
        let (mut name, mut classes) = (vec![CC; 64], vec![CC; 64]);
        let (mut count, mut class_count, mut time) = (room, 64u32, 0xF2F2u64);
        // SAFETY: the tests' own buffers, of the sizes given.
        let ret = unsafe {
            reg_enum_key_ex_w(
                KEY,
                0,
                name.as_mut_ptr(),
                &mut count,
                core::ptr::null_mut(),
                if class {
                    classes.as_mut_ptr()
                } else {
                    core::ptr::null_mut()
                },
                if class {
                    &mut class_count
                } else {
                    core::ptr::null_mut()
                },
                &mut time,
            )
        };
        (ret, count, name, classes, class_count, time)
    }

    /// RegEnumKeyExW as the capture: the name and its class with their counts and the time; a
    /// buffer short of the terminator ERROR_MORE_DATA with nothing written; the end and a bad
    /// handle as their statuses' errors; a non-NULL lpReserved ERROR_INVALID_PARAMETER.
    #[test]
    fn enum_key_ex_w_answers_as_the_capture() {
        reply(node("Alpha", "F2Kclass"));
        let (ret, count, name, class, class_count, time) = enum_ex_w(64, true);
        assert_eq!((ret, count, class_count), (0, 5, 8));
        assert_eq!(&name[..6], &rtl::testing::wide_z("Alpha")[..]);
        assert_eq!(&class[..9], &rtl::testing::wide_z("F2Kclass")[..]);
        assert_eq!(time, 0x01D0_0000_1234_5678);
        assert_eq!(KEY_CLASSES.with(|c| c.borrow().last().copied()), Some(1));
        for room in [0, 3, 5] {
            let (ret, count, name, ..) = enum_ex_w(room, false);
            assert_eq!((ret, count), (ERROR_MORE_DATA, room), "{room}");
            assert!(name.iter().all(|&unit| unit == CC));
        }
        let (ret, count, ..) = enum_ex_w(6, false);
        assert_eq!((ret, count), (0, 5));
        status(0x8000_001A);
        let (ret, count, name, ..) = enum_ex_w(64, false);
        assert_eq!((ret, count, name[0]), (ERROR_NO_MORE_ITEMS, 64, CC));
        status(0xC000_0008);
        assert_eq!(enum_ex_w(64, false).0, ERROR_INVALID_HANDLE);
        let mut count = 64;
        let mut name = [0u16; 64];
        // SAFETY: the tests' own buffers.
        let ret = unsafe {
            reg_enum_key_ex_w(
                KEY,
                0,
                name.as_mut_ptr(),
                &mut count,
                &mut count,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        assert_eq!(ret, ERROR_INVALID_PARAMETER);
    }

    /// RegEnumKeyExA writes what fits of a name too long, terminated, its count untouched; the
    /// whole name and its count when it fits, the class's too.
    #[test]
    fn enum_key_ex_a_writes_what_fits() {
        reply(node("Alpha", "F2Kclass"));
        let call = |room: u32, class: bool| {
            let (mut name, mut classes) = ([0xCCu8; 64], [0xCCu8; 64]);
            let (mut count, mut class_count) = (room, 64u32);
            // SAFETY: the tests' own buffers, of the sizes given.
            let ret = unsafe {
                reg_enum_key_ex_a(
                    KEY,
                    0,
                    name.as_mut_ptr(),
                    &mut count,
                    core::ptr::null_mut(),
                    if class {
                        classes.as_mut_ptr()
                    } else {
                        core::ptr::null_mut()
                    },
                    &mut class_count,
                    core::ptr::null_mut(),
                )
            };
            (ret, count, name, classes, class_count)
        };
        let (ret, count, name, classes, class_count) = call(64, true);
        assert_eq!((ret, count, class_count), (0, 5, 8));
        assert_eq!(&name[..6], b"Alpha\0");
        assert_eq!(&classes[..9], b"F2Kclass\0");
        let (ret, count, name, ..) = call(0, false);
        assert_eq!((ret, count, name[0]), (ERROR_MORE_DATA, 0, 0xCC));
        let (ret, count, name, ..) = call(3, false);
        assert_eq!(
            (ret, count, &name[..4]),
            (ERROR_MORE_DATA, 3, &b"Al\0\xCC"[..])
        );
        let (ret, count, name, ..) = call(5, false);
        assert_eq!(
            (ret, count, &name[..5]),
            (ERROR_MORE_DATA, 5, &b"Alph\0"[..])
        );
        let (ret, count, name, ..) = call(6, false);
        assert_eq!((ret, count, &name[..6]), (0, 5, &b"Alpha\0"[..]));
    }

    /// A reply longer than the local buffer is read again whole, into a block of its size.
    #[test]
    fn a_long_reply_is_read_whole() {
        reply(node("Alpha", &"c".repeat(300)));
        KEY_CLASSES.with(|classes| classes.borrow_mut().clear());
        let (ret, count, name, ..) = enum_ex_w(64, false);
        assert_eq!(
            (ret, count, &name[..6]),
            (0, 5, &rtl::testing::wide_z("Alpha")[..])
        );
        assert_eq!(KEY_CLASSES.with(|c| c.borrow().clone()), [1, 1]);
    }
}
