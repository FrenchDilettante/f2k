//! The registry calls that read a key's listing with everything an entry has, and the key's own
//! counts: RegEnumKeyEx, RegEnumValue and RegQueryInfoKey, W and A, as Windows 2000's advapi32
//! runs them over ntdll's NtEnumerateKey (KEY_NODE_INFORMATION: a subkey's name, class and last
//! write), NtEnumerateValueKey (KEY_VALUE_FULL_INFORMATION: a value's name, type and data) and
//! NtQueryKey (KEY_FULL_INFORMATION). Like the other registry calls they return their error and
//! leave the last error alone; a non-NULL lpReserved is ERROR_INVALID_PARAMETER.
//!
//! What a short buffer leaves is what the registry fixture's `enumex` and `enumvalue` blocks
//! capture of Windows 2000:
//!
//! - RegEnumKeyExW and RegEnumValueW check the name first: a name buffer that does not hold the
//!   name and its terminator is ERROR_MORE_DATA with the name and its count untouched (RegEnumValue
//!   tells the value's type and size all the same). RegEnumValueW then writes the name and its
//!   count before it checks the data: data that does not fit is ERROR_MORE_DATA with the name
//!   written, the data untouched, its type and size told.
//! - The A calls convert. RegEnumKeyExA writes what fits of a name too long, terminated, its count
//!   untouched. RegEnumValueA checks the data first (its ANSI size: data that does not fit is
//!   ERROR_MORE_DATA, the type and that size told, nothing written), writes it, then the name: what
//!   fits of one too long, terminated, ERROR_MORE_DATA.
//!
//! A string value's data (REG_SZ, REG_EXPAND_SZ, REG_MULTI_SZ) reaches the A calls converted to the
//! ANSI code page, its sizes the ANSI ones, as RegQueryValueExA's do.

use rtl::pod::Pod;
use rtl::status::{STATUS_BUFFER_OVERFLOW, STATUS_BUFFER_TOO_SMALL};
use rtl::winerror::{
    ERROR_INSUFFICIENT_BUFFER,
    ERROR_INVALID_HANDLE,
    ERROR_INVALID_PARAMETER,
    ERROR_MORE_DATA,
    ERROR_NOACCESS,
    ERROR_SUCCESS,
};

use crate::imports::{self as nt, Answer, HeapBlock};
use crate::registry::{block, error, give, is_text, map, query_buffer};
use crate::{caller_bytes_mut, Out};

/// The information classes the calls read.
const KEY_NODE_INFORMATION: u32 = 1;
const KEY_FULL_INFORMATION: u32 = 2;
const KEY_VALUE_FULL_INFORMATION: u32 = 1;

/// Where KEY_NODE_INFORMATION's fields are: the last write, the class's offset and length, the
/// name's length, the name.
const NODE_CLASS_OFFSET: usize = 12;
const NODE_CLASS_LENGTH: usize = 16;
const NODE_NAME_LENGTH: usize = 20;
const NODE_NAME: u32 = 24;

/// Where KEY_VALUE_FULL_INFORMATION's fields are: the type, the data's offset and length, the
/// name's length, the name.
const FULL_KIND: usize = 4;
const FULL_DATA_OFFSET: usize = 8;
const FULL_DATA_LENGTH: usize = 12;
const FULL_NAME_LENGTH: usize = 16;
const FULL_NAME: u32 = 20;

/// Where KEY_FULL_INFORMATION's fields are: the class's offset and length, then the counts and
/// longest sizes (in bytes), one dword each.
const KEY_CLASS_OFFSET: usize = 12;
const KEY_CLASS_LENGTH: usize = 16;
const KEY_SUBKEYS: usize = 20;
const KEY_MAX_NAME: usize = 24;
const KEY_MAX_CLASS: usize = 28;
const KEY_VALUES: usize = 32;
const KEY_MAX_VALUE_NAME: usize = 36;
const KEY_MAX_VALUE_DATA: usize = 40;

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

/// Value `index` of `key`: its KEY_VALUE_FULL_INFORMATION.
struct Value(Reply);

impl Value {
    fn of(key: u32, index: u32) -> Result<Value, u32> {
        let key = nt_key(key)?;
        Reply::read(|buffer| {
            nt::enumerate_value_key(key, index, KEY_VALUE_FULL_INFORMATION, buffer)
        })
        .map(Value)
    }

    fn kind(&self) -> u32 {
        self.0.word(FULL_KIND)
    }

    fn name(&self) -> &[u16] {
        self.0.text(FULL_NAME, self.0.word(FULL_NAME_LENGTH))
    }

    fn data(&self) -> &[u8] {
        self.0
            .piece(self.0.word(FULL_DATA_OFFSET), self.0.word(FULL_DATA_LENGTH))
    }

    /// The data's size as the A calls hand it: a string's in the ANSI code page.
    fn ansi_size(&self) -> u32 {
        if is_text(self.kind()) {
            nt::unicode_to_multi_byte_size(units(self.data()))
        } else {
            self.data().len() as u32
        }
    }

    /// The data as the A calls hand it, into `buffer`, which holds its ANSI size.
    fn put_ansi_data(&self, buffer: &mut [u8]) {
        if is_text(self.kind()) {
            nt::unicode_to_multi_byte(buffer, units(self.data()));
        } else {
            buffer[..self.data().len()].copy_from_slice(self.data());
        }
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

/// The checks RegEnumValue makes before it looks at the key: lpReserved NULL, a name count, and a
/// size with data.
fn enum_value_arguments(
    reserved: *mut u32,
    count: Option<&Out<'_, u32>>,
    data: *mut u8,
    size: *mut u32,
) -> Result<(), u32> {
    if !reserved.is_null() || count.is_none() || (!data.is_null() && size.is_null()) {
        return Err(ERROR_INVALID_PARAMETER);
    }
    Ok(())
}

/// RegEnumValueW: value `index` of `key` (the values in the order they were first set): its
/// name with its terminator and its length in units, its type, its data's size and, when it fits,
/// its data. A name buffer that does not hold the name and its terminator is ERROR_MORE_DATA,
/// the name untouched (the type and the size told); data that does not fit is ERROR_MORE_DATA,
/// the name written and the data untouched. ERROR_NO_MORE_ITEMS past the last value.
///
/// # Safety
///
/// `name` holds `*count` units, `data` (null or) `*size` bytes; the out parameters are writable or
/// null.
#[allow(clippy::too_many_arguments)]
#[unsafe(export_name = "f2k_export_RegEnumValueW")]
pub unsafe extern "system" fn reg_enum_value_w(
    key: u32,
    index: u32,
    name: *mut u16,
    count: *mut u32,
    reserved: *mut u32,
    kind: *mut u32,
    data: *mut u8,
    size: *mut u32,
) -> u32 {
    if let Err(code) = enum_value_arguments(
        reserved,
        // SAFETY: the caller's count, only looked at for null.
        unsafe { Out::optional(count) }.as_ref(),
        data,
        size,
    ) {
        return code;
    }
    // SAFETY: the caller's out parameters and data buffer.
    let (mut count, mut kind, (data, mut size)) = unsafe {
        (
            Out::optional(count),
            Out::optional(kind),
            query_buffer(data, size),
        )
    };
    code((|| {
        let count = count.as_mut().ok_or(ERROR_INVALID_PARAMETER)?;
        let value = Value::of(key, index)?;
        let (text, bytes) = (value.name(), value.data());
        give(kind.as_mut(), value.kind());
        give(size.as_mut(), bytes.len() as u32);
        if count.get() as usize <= text.len() {
            return Err(ERROR_MORE_DATA);
        }
        // SAFETY: the name buffer holds more units than the name has.
        unsafe { give_wide(name, text) }?;
        count.set(text.len() as u32);
        match data {
            Some(data) if data.len() < bytes.len() => Err(ERROR_MORE_DATA),
            Some(data) => {
                data[..bytes.len()].copy_from_slice(bytes);
                Ok(())
            }
            None => Ok(()),
        }
    })())
}

/// RegEnumValueA: RegEnumValueW's name and string data converted, the sizes the ANSI ones. Data
/// that does not fit is ERROR_MORE_DATA, the type and size told and nothing written; then the
/// data is written, and a name buffer that does not hold the name and its terminator gets what
/// fits of it, terminated: ERROR_MORE_DATA, the count untouched.
///
/// # Safety
///
/// As RegEnumValueW's, the name buffer's size in bytes.
#[allow(clippy::too_many_arguments)]
#[unsafe(export_name = "f2k_export_RegEnumValueA")]
pub unsafe extern "system" fn reg_enum_value_a(
    key: u32,
    index: u32,
    name: *mut u8,
    count: *mut u32,
    reserved: *mut u32,
    kind: *mut u32,
    data: *mut u8,
    size: *mut u32,
) -> u32 {
    if let Err(code) = enum_value_arguments(
        reserved,
        // SAFETY: the caller's count, only looked at for null.
        unsafe { Out::optional(count) }.as_ref(),
        data,
        size,
    ) {
        return code;
    }
    // SAFETY: the caller's out parameters and data buffer.
    let (mut count, mut kind, (data, mut size)) = unsafe {
        (
            Out::optional(count),
            Out::optional(kind),
            query_buffer(data, size),
        )
    };
    code((|| {
        let count = count.as_mut().ok_or(ERROR_INVALID_PARAMETER)?;
        let value = Value::of(key, index)?;
        let ansi = value.ansi_size();
        give(kind.as_mut(), value.kind());
        give(size.as_mut(), ansi);
        if let Some(data) = data {
            let data = data.get_mut(..ansi as usize).ok_or(ERROR_MORE_DATA)?;
            value.put_ansi_data(data);
        }
        // SAFETY: the name buffer holds the bytes its count says.
        let buffer = unsafe { ansi_buffer(name, count.get()) }?;
        let length = put_ansi(buffer, value.name()).ok_or(ERROR_MORE_DATA)?;
        count.set(length);
        Ok(())
    })())
}

/// The out parameters RegQueryInfoKey fills besides the class: the subkeys' count, the longest
/// subkey name and class (in characters), the values' count, the longest value name (in
/// characters) and data (in bytes), the security descriptor's size and the last write.
struct Counts<'a> {
    subkeys: Option<Out<'a, u32>>,
    max_subkey: Option<Out<'a, u32>>,
    max_class: Option<Out<'a, u32>>,
    values: Option<Out<'a, u32>>,
    max_value_name: Option<Out<'a, u32>>,
    max_value_data: Option<Out<'a, u32>>,
    security: Option<Out<'a, u32>>,
    last_write: Option<Out<'a, u64>>,
}

impl Counts<'_> {
    /// Fill them from the key's KEY_FULL_INFORMATION. F2K's keys have no security descriptor: its
    /// size is zero.
    fn give(&mut self, reply: &Reply) {
        give(self.subkeys.as_mut(), reply.word(KEY_SUBKEYS));
        give(self.max_subkey.as_mut(), reply.word(KEY_MAX_NAME) / 2);
        give(self.max_class.as_mut(), reply.word(KEY_MAX_CLASS) / 2);
        give(self.values.as_mut(), reply.word(KEY_VALUES));
        give(
            self.max_value_name.as_mut(),
            reply.word(KEY_MAX_VALUE_NAME) / 2,
        );
        give(self.max_value_data.as_mut(), reply.word(KEY_MAX_VALUE_DATA));
        give(self.security.as_mut(), 0);
        if let Some(last_write) = self.last_write.as_mut() {
            last_write.set(u64::read_from(reply.bytes(), 0).unwrap_or(0));
        }
    }
}

/// `key`'s KEY_FULL_INFORMATION, the call's arguments checked first: lpReserved NULL, a class
/// count with a class buffer.
fn key_full(
    key: u32,
    reserved: *mut u32,
    class: bool,
    class_count: Option<&Out<'_, u32>>,
) -> Result<Reply, u32> {
    if !reserved.is_null() || (class && class_count.is_none()) {
        return Err(ERROR_INVALID_PARAMETER);
    }
    let key = nt_key(key)?;
    Reply::read(|buffer| nt::query_key(key, KEY_FULL_INFORMATION, buffer))
}

/// The class's text in a KEY_FULL_INFORMATION.
fn full_class(reply: &Reply) -> &[u16] {
    reply.text(reply.word(KEY_CLASS_OFFSET), reply.word(KEY_CLASS_LENGTH))
}

/// Room the server's private reply buffer leaves for the class: a longer one changes which error
/// a short caller's buffer gets.
const SERVER_CLASS_ROOM: usize = 128;

/// RegQueryInfoKeyW: the class with its terminator (its length in units written back), the counts
/// and longest sizes (names and classes in characters, data in bytes) and the last write. A class
/// buffer short of the terminator: the length in characters, nothing written,
/// ERROR_INSUFFICIENT_BUFFER (ERROR_INVALID_PARAMETER past the server's private buffer); a zero
/// count reads the length alone.
///
/// # Safety
///
/// `class` holds `*class_count` units or is null; the out parameters are writable or null.
#[allow(clippy::too_many_arguments)]
#[unsafe(export_name = "f2k_export_RegQueryInfoKeyW")]
pub unsafe extern "system" fn reg_query_info_key_w(
    key: u32,
    class: *mut u16,
    class_count: *mut u32,
    reserved: *mut u32,
    subkeys: *mut u32,
    max_subkey: *mut u32,
    max_class: *mut u32,
    values: *mut u32,
    max_value_name: *mut u32,
    max_value_data: *mut u32,
    security: *mut u32,
    last_write: *mut u64,
) -> u32 {
    // SAFETY: the caller's out parameters.
    let (mut class_count, mut counts) = unsafe {
        (
            Out::optional(class_count),
            Counts {
                subkeys: Out::optional(subkeys),
                max_subkey: Out::optional(max_subkey),
                max_class: Out::optional(max_class),
                values: Out::optional(values),
                max_value_name: Out::optional(max_value_name),
                max_value_data: Out::optional(max_value_data),
                security: Out::optional(security),
                last_write: Out::optional(last_write),
            },
        )
    };
    code((|| {
        let reply = key_full(key, reserved, !class.is_null(), class_count.as_ref())?;
        let text = full_class(&reply);
        let room = class_count.as_ref().map_or(0, Out::get) as usize;
        if !class.is_null() && room != 0 {
            if room <= text.len() {
                give(class_count.as_mut(), text.len() as u32);
                return Err(if 2 * text.len() > SERVER_CLASS_ROOM {
                    ERROR_INVALID_PARAMETER
                } else {
                    ERROR_INSUFFICIENT_BUFFER
                });
            }
            // SAFETY: the class buffer holds more units than the class has.
            unsafe { give_wide(class, text) }?;
        }
        give(class_count.as_mut(), text.len() as u32);
        counts.give(&reply);
        Ok(())
    })())
}

/// RegQueryInfoKeyA: the class converted, its length in bytes written back; a buffer that does not
/// hold it gets what fits, terminated, the capacity minus one and ERROR_MORE_DATA; a null buffer or
/// a zero count reads the length in characters alone. The other counts as RegQueryInfoKeyW's.
///
/// # Safety
///
/// As RegQueryInfoKeyW's, the class buffer's size in bytes.
#[allow(clippy::too_many_arguments)]
#[unsafe(export_name = "f2k_export_RegQueryInfoKeyA")]
pub unsafe extern "system" fn reg_query_info_key_a(
    key: u32,
    class: *mut u8,
    class_count: *mut u32,
    reserved: *mut u32,
    subkeys: *mut u32,
    max_subkey: *mut u32,
    max_class: *mut u32,
    values: *mut u32,
    max_value_name: *mut u32,
    max_value_data: *mut u32,
    security: *mut u32,
    last_write: *mut u64,
) -> u32 {
    // SAFETY: the caller's out parameters.
    let (mut class_count, mut counts) = unsafe {
        (
            Out::optional(class_count),
            Counts {
                subkeys: Out::optional(subkeys),
                max_subkey: Out::optional(max_subkey),
                max_class: Out::optional(max_class),
                values: Out::optional(values),
                max_value_name: Out::optional(max_value_name),
                max_value_data: Out::optional(max_value_data),
                security: Out::optional(security),
                last_write: Out::optional(last_write),
            },
        )
    };
    code((|| {
        let reply = key_full(key, reserved, !class.is_null(), class_count.as_ref())?;
        let text = full_class(&reply);
        let room = class_count.as_ref().map_or(0, Out::get);
        if !class.is_null() && room != 0 {
            let cap = room.min(0xFFFF);
            // SAFETY: the class buffer holds the bytes its count says.
            let buffer = unsafe { ansi_buffer(class, cap) }?;
            match put_ansi(buffer, text) {
                Some(written) => give(class_count.as_mut(), written),
                None => {
                    give(class_count.as_mut(), cap - 1);
                    counts.give(&reply);
                    return Err(ERROR_MORE_DATA);
                }
            }
        } else {
            give(class_count.as_mut(), text.len() as u32);
        }
        counts.give(&reply);
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
    const REG_SZ: u32 = 1;
    const REG_DWORD: u32 = 4;

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

    /// A value's KEY_VALUE_FULL_INFORMATION: its name, then its data.
    fn full(name: &str, kind: u32, data: &[u8]) -> Vec<u8> {
        let name = utf16_bytes(name);
        let mut bytes = Vec::new();
        word(&mut bytes, 0);
        word(&mut bytes, kind);
        word(&mut bytes, 20 + name.len() as u32);
        word(&mut bytes, data.len() as u32);
        word(&mut bytes, name.len() as u32);
        bytes.extend(name);
        bytes.extend(data);
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

    /// What RegEnumValueW/A left: the answer, the count, the name buffer, the type, the size and
    /// the data buffer.
    type Left<T> = (u32, u32, Vec<T>, u32, u32, Vec<u8>);

    const UNSET: u32 = 0xF2F2_F2F2;

    /// RegEnumValueW with `room` units of name and `data` bytes of data (none: NULL data).
    fn enum_value_w(room: u32, data: Option<u32>) -> Left<u16> {
        let (mut name, mut buffer) = (vec![CC; 64], vec![0xCCu8; 1024]);
        let (mut count, mut kind, mut size) = (room, UNSET, data.unwrap_or(0));
        // SAFETY: the tests' own buffers, of the sizes given.
        let ret = unsafe {
            reg_enum_value_w(
                KEY,
                0,
                name.as_mut_ptr(),
                &mut count,
                core::ptr::null_mut(),
                &mut kind,
                if data.is_some() {
                    buffer.as_mut_ptr()
                } else {
                    core::ptr::null_mut()
                },
                &mut size,
            )
        };
        (ret, count, name, kind, size, buffer)
    }

    /// RegEnumValueA, as [`enum_value_w`].
    fn enum_value_a(room: u32, data: Option<u32>) -> Left<u8> {
        let (mut name, mut buffer) = (vec![0xCCu8; 64], vec![0xCCu8; 1024]);
        let (mut count, mut kind, mut size) = (room, UNSET, data.unwrap_or(0));
        // SAFETY: the tests' own buffers, of the sizes given.
        let ret = unsafe {
            reg_enum_value_a(
                KEY,
                0,
                name.as_mut_ptr(),
                &mut count,
                core::ptr::null_mut(),
                &mut kind,
                if data.is_some() {
                    buffer.as_mut_ptr()
                } else {
                    core::ptr::null_mut()
                },
                &mut size,
            )
        };
        (ret, count, name, kind, size, buffer)
    }

    fn data5() -> Vec<u8> {
        utf16_bytes("data!\0")
    }

    /// RegEnumValueW as the capture's solo key: a name buffer short of the terminator
    /// ERROR_MORE_DATA, the type and size told, nothing written; data short ERROR_MORE_DATA with
    /// the name written; NULL data the size alone.
    #[test]
    fn enum_value_w_checks_the_name_then_the_data() {
        reply(full("value", REG_SZ, &data5()));
        for room in [0, 3, 5] {
            let (ret, count, name, kind, size, buffer) = enum_value_w(room, Some(1024));
            assert_eq!(
                (ret, count, kind, size),
                (ERROR_MORE_DATA, room, REG_SZ, 12)
            );
            assert!(name.iter().all(|&unit| unit == CC) && buffer[0] == 0xCC);
        }
        let (ret, count, name, kind, size, buffer) = enum_value_w(6, Some(1024));
        assert_eq!((ret, count, kind, size), (0, 5, REG_SZ, 12));
        assert_eq!(&name[..6], &rtl::testing::wide_z("value")[..]);
        assert_eq!(&buffer[..12], &data5()[..]);
        let (ret, count, _, _, size, _) = enum_value_w(64, None);
        assert_eq!((ret, count, size), (0, 5, 12));
        for room in [0, 2] {
            let (ret, count, name, kind, size, buffer) = enum_value_w(64, Some(room));
            assert_eq!((ret, count, kind, size), (ERROR_MORE_DATA, 5, REG_SZ, 12));
            assert_eq!(name[5], 0);
            assert_eq!(&buffer[..2], [0xCC, 0xCC]);
        }
        let (ret, count, name, ..) = enum_value_w(3, Some(2));
        assert_eq!((ret, count, name[0]), (ERROR_MORE_DATA, 3, CC));
        reply(full("Dword", REG_DWORD, &[0x78, 0x56, 0x34, 0x12]));
        let (ret, _, _, kind, size, buffer) = enum_value_w(64, Some(1024));
        assert_eq!(
            (ret, kind, size, &buffer[..4]),
            (0, 4, 4, &[0x78, 0x56, 0x34, 0x12][..])
        );
        status(0x8000_001A);
        let (ret, count, _, kind, size, _) = enum_value_w(64, Some(1024));
        assert_eq!(
            (ret, count, kind, size),
            (ERROR_NO_MORE_ITEMS, 64, UNSET, 1024)
        );
    }

    /// RegEnumValueA as the capture's solo key: the data checked first (its ANSI size, 6), then
    /// written, then what fits of the name, terminated.
    #[test]
    fn enum_value_a_checks_the_data_then_the_name() {
        reply(full("value", REG_SZ, &data5()));
        let (ret, count, name, kind, size, buffer) = enum_value_a(0, Some(1024));
        assert_eq!((ret, count, kind, size), (ERROR_MORE_DATA, 0, REG_SZ, 6));
        assert_eq!((name[0], &buffer[..6]), (0xCC, &b"data!\0"[..]));
        let (ret, count, name, ..) = enum_value_a(3, Some(1024));
        assert_eq!((ret, count, &name[..3]), (ERROR_MORE_DATA, 3, &b"va\0"[..]));
        let (ret, count, name, ..) = enum_value_a(5, Some(1024));
        assert_eq!(
            (ret, count, &name[..5]),
            (ERROR_MORE_DATA, 5, &b"valu\0"[..])
        );
        let (ret, count, name, _, size, buffer) = enum_value_a(6, Some(6));
        assert_eq!((ret, count, size), (0, 5, 6));
        assert_eq!(
            (&name[..6], &buffer[..6]),
            (&b"value\0"[..], &b"data!\0"[..])
        );
        for room in [0, 2] {
            let (ret, count, name, kind, size, buffer) = enum_value_a(64, Some(room));
            assert_eq!((ret, count, kind, size), (ERROR_MORE_DATA, 64, REG_SZ, 6));
            assert_eq!((name[0], buffer[0]), (0xCC, 0xCC));
        }
        let (ret, count, _, _, size, _) = enum_value_a(64, None);
        assert_eq!((ret, count, size), (0, 5, 6));
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

    /// RegQueryInfoKeyW/A: the class and its count, the counts, the longest sizes in characters
    /// (the data's in bytes).
    #[test]
    fn query_info_key_answers_the_counts() {
        let mut bytes = 0u64.to_le_bytes().to_vec();
        for value in [0, 44, 0, 1, 6, 0, 5, 12, 26] {
            word(&mut bytes, value);
        }
        reply(bytes);
        let mut counts = [UNSET; 8];
        let mut class = [CC; 8];
        let mut class_count = 8u32;
        let [subkeys, max_subkey, max_class, values, max_name, max_data, _, _] = &mut counts;
        // SAFETY: the tests' own buffers.
        let ret = unsafe {
            reg_query_info_key_w(
                KEY,
                class.as_mut_ptr(),
                &mut class_count,
                core::ptr::null_mut(),
                subkeys,
                max_subkey,
                max_class,
                values,
                max_name,
                max_data,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        assert_eq!((ret, class_count, class[0]), (0, 0, 0));
        assert_eq!(counts[..6], [1, 3, 0, 5, 6, 26]);
        let mut ansi = [0xCCu8; 8];
        let mut values = UNSET;
        class_count = 8;
        // SAFETY: the tests' own buffers.
        let ret = unsafe {
            reg_query_info_key_a(
                KEY,
                ansi.as_mut_ptr(),
                &mut class_count,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut values,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        assert_eq!((ret, class_count, ansi[0], values), (0, 0, 0, 5));
        // SAFETY: a non-NULL lpReserved.
        let ret = unsafe {
            reg_query_info_key_w(
                KEY,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut values,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        assert_eq!(ret, ERROR_INVALID_PARAMETER);
    }

    /// A KEY_FULL_INFORMATION reply with the class `class` and the given counts.
    fn full_info(
        class: &str,
        subkeys: u32,
        max_name: u32,
        values: u32,
        max_vname: u32,
        max_vdata: u32,
    ) -> Vec<u8> {
        let class_bytes = utf16_bytes(class);
        let mut bytes = 0u64.to_le_bytes().to_vec();
        for value in [
            0,
            44,
            class_bytes.len() as u32,
            subkeys,
            max_name,
            0,
            values,
            max_vname,
            max_vdata,
        ] {
            word(&mut bytes, value);
        }
        bytes.extend(class_bytes);
        bytes
    }

    /// RegQueryInfoKeyW with `room` units of class buffer: the answer, the count, the buffer.
    fn info_w(room: u32, class: bool) -> (u32, u32, Vec<u16>) {
        let mut buffer = vec![CC; 128];
        let mut count = room;
        // SAFETY: the tests' own buffers.
        let ret = unsafe {
            reg_query_info_key_w(
                KEY,
                if class {
                    buffer.as_mut_ptr()
                } else {
                    core::ptr::null_mut()
                },
                &mut count,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        (ret, count, buffer)
    }

    /// RegQueryInfoKeyA, as [`info_w`], the class buffer in bytes.
    fn info_a(room: u32, class: bool) -> (u32, u32, Vec<u8>) {
        let mut buffer = vec![0xCCu8; 128];
        let mut count = room;
        // SAFETY: the tests' own buffers.
        let ret = unsafe {
            reg_query_info_key_a(
                KEY,
                if class {
                    buffer.as_mut_ptr()
                } else {
                    core::ptr::null_mut()
                },
                &mut count,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        (ret, count, buffer)
    }

    /// RegQueryInfoKeyW's class: fits written with its length in units; short of the terminator
    /// the length in characters, nothing written, ERROR_INSUFFICIENT_BUFFER
    /// (ERROR_INVALID_PARAMETER past the server's private buffer); zero count or null buffer the
    /// length alone.
    #[test]
    fn query_info_key_w_answers_the_class() {
        reply(full_info("F2Kclass", 1, 6, 5, 12, 26));
        let (ret, count, buffer) = info_w(9, true);
        assert_eq!((ret, count), (0, 8));
        assert_eq!(&buffer[..9], &rtl::testing::wide_z("F2Kclass")[..]);
        let (ret, count, buffer) = info_w(8, true);
        assert_eq!((ret, count), (ERROR_INSUFFICIENT_BUFFER, 8));
        assert!(buffer.iter().all(|&unit| unit == CC));
        let (ret, count, buffer) = info_w(0, true);
        assert_eq!((ret, count), (0, 8));
        assert!(buffer.iter().all(|&unit| unit == CC));
        let (ret, count, _) = info_w(64, false);
        assert_eq!((ret, count), (0, 8));
        reply(full_info(&"c".repeat(65), 0, 0, 0, 0, 0));
        let (ret, count, buffer) = info_w(10, true);
        assert_eq!((ret, count), (ERROR_INVALID_PARAMETER, 65));
        assert!(buffer.iter().all(|&unit| unit == CC));
        let (ret, count, buffer) = info_w(66, true);
        assert_eq!((ret, count), (0, 65));
        assert_eq!(&buffer[..66], &rtl::testing::wide_z(&"c".repeat(65))[..]);
        let mut count = 8u32;
        let mut buffer = [CC; 8];
        // SAFETY: the tests' own buffers.
        let ret = unsafe {
            reg_query_info_key_w(
                KEY,
                buffer.as_mut_ptr(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        assert_eq!(ret, ERROR_INVALID_PARAMETER);
        assert_eq!(count, 8);
    }

    /// RegQueryInfoKeyA's class: converted with its length in bytes when it fits; what fits of it,
    /// terminated, the capacity minus one and ERROR_MORE_DATA when not; zero count or null buffer
    /// the length in characters alone.
    #[test]
    fn query_info_key_a_answers_the_class() {
        reply(full_info("F2Kclass", 1, 6, 5, 12, 26));
        let (ret, count, buffer) = info_a(9, true);
        assert_eq!((ret, count), (0, 8));
        assert_eq!(&buffer[..9], b"F2Kclass\0");
        let (ret, count, buffer) = info_a(8, true);
        assert_eq!((ret, count), (ERROR_MORE_DATA, 7));
        assert_eq!(&buffer[..8], b"F2Kclas\0");
        let (ret, count, buffer) = info_a(1, true);
        assert_eq!((ret, count), (ERROR_MORE_DATA, 0));
        assert_eq!(&buffer[..1], b"\0");
        let (ret, count, buffer) = info_a(0, true);
        assert_eq!((ret, count), (0, 8));
        assert!(buffer.iter().all(|&b| b == 0xCC));
        let (ret, count, _) = info_a(64, false);
        assert_eq!((ret, count), (0, 8));
    }
}
