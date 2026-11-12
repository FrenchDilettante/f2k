//! Run-time type information as Visual C++ 6 compiles it (`/GR`): `typeid` and `type_info`.
//!
//! A type's `type_info` is its type descriptor ([`TypeDescriptor`]): type_info's vftable, the
//! undecorated name once `name()` made it, and the decorated name (".H", ".?AVDerived@@"). A
//! polymorphic object's vftable is preceded by its complete object locator, whose descriptor is the
//! object's dynamic type: `typeid(*p)` compiles into `__RTtypeid(p)`, and a null `p` throws
//! bad_typeid ("Attempted a typeid of NULL pointer!", as crt's capture shows). igorsk's "Reversing
//! Microsoft Visual C++ Part II: Classes, Methods and RTTI" (OpenRCE, 2006) describes the layouts.
//!
//! type_info's members are __thiscall (the object in ECX, the callee popping the rest): their
//! bodies here are `extern "thiscall"`, whatever the export spec's convention (the stubs').
//! `==` and `!=` compare the decorated names, `before` orders them (strcmp); `raw_name` answers the
//! decorated name, `name` the undecorated one ([`undecorate`]), made on its first call and kept in
//! the descriptor, freed by the destructor.

use core::ffi::{c_void, CStr};
use core::sync::atomic::Ordering::{AcqRel, Acquire};

use crate::eh::{descriptor_name, TypeDescriptor};

/// A polymorphic object's complete object locator, the word before its vftable: where the
/// vftable's sub-object sits in the complete object, and the complete object's type. igorsk's
/// "Reversing Microsoft Visual C++ Part II", `struct RTTICompleteObjectLocator`:
///
/// ```text
/// DWORD signature;                            // 0
/// DWORD offset;                               // the sub-object's offset in the complete object
/// DWORD cdOffset;                             // the constructor displacement's offset
/// struct TypeDescriptor *pTypeDescriptor;     // the complete class's
/// struct RTTIClassHierarchyDescriptor *pClassDescriptor;
/// ```
#[repr(C)]
pub struct CompleteObjectLocator {
    pub signature: u32,
    pub offset: u32,
    pub cd_offset: u32,
    pub type_descriptor: *const TypeDescriptor,
    pub class_descriptor: *const c_void,
}

// SAFETY: msvcrt's own locators are read-only, their pointers to read-only data.
unsafe impl Sync for CompleteObjectLocator {}

/// A decorated type name undecorated, as Windows 2000's msvcrt's `type_info::name` answers it
/// (crt's capture: "int", "class Derived", "class Base *"): `raw` is the descriptor's name less its
/// leading dot. The names of Visual C++'s decoration that a type's descriptor carries: the
/// fundamental types, classes, structs, unions and enums by their (scoped, possibly template)
/// names, pointers and references with their cv-qualifiers, written as Visual C++'s undecorator
/// writes them ("char const *", "class std::list<int,class std::allocator<int> >"). None for the
/// rest (function pointers, arrays, member pointers): the caller falls back to the decorated name.
pub fn undecorate(raw: &[u8], out: &mut Text) -> Option<()> {
    let mut parser = Parser {
        input: raw,
        at: 0,
        names: Names::new(),
    };
    if parser.peek() == Some(b'?') {
        // A class type's descriptor: "?A" (no cv-qualifier) and the type.
        parser.at += 1;
        let cv = parser.next()?;
        parser.data_type(out)?;
        out.push(cv_suffix(cv)?);
    } else {
        parser.data_type(out)?;
    }
    (parser.at == raw.len() && !out.overflowed).then_some(())
}

/// Text built in place: a name being undecorated.
pub struct Text {
    bytes: [u8; 256],
    len: usize,
    overflowed: bool,
}

impl Text {
    pub const fn new() -> Text {
        Text {
            bytes: [0; 256],
            len: 0,
            overflowed: false,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    fn push(&mut self, text: &[u8]) {
        match self.bytes.get_mut(self.len..self.len + text.len()) {
            Some(room) => {
                room.copy_from_slice(text);
                self.len += text.len();
            }
            None => self.overflowed = true,
        }
    }

    fn ends_with(&self, byte: u8) -> bool {
        self.as_bytes().last() == Some(&byte)
    }
}

impl Default for Text {
    fn default() -> Text {
        Text::new()
    }
}

/// The names a decoration may refer back to by a digit, in the order they appeared (ten at most);
/// a template's arguments have their own.
struct Names {
    text: Text,
    ends: [usize; 10],
    count: usize,
}

impl Names {
    const fn new() -> Names {
        Names {
            text: Text::new(),
            ends: [0; 10],
            count: 0,
        }
    }

    fn add(&mut self, name: &[u8]) {
        if self.count < self.ends.len() {
            self.text.push(name);
            self.ends[self.count] = self.text.len;
            self.count += 1;
        }
    }

    fn get(&self, index: usize) -> Option<&[u8]> {
        if index >= self.count {
            return None;
        }
        let start = if index == 0 { 0 } else { self.ends[index - 1] };
        self.text.as_bytes().get(start..self.ends[index])
    }
}

/// The cv-qualifier a decoration's letter gives, as the undecorator writes it after its type.
fn cv_suffix(letter: u8) -> Option<&'static [u8]> {
    match letter {
        b'A' => Some(b""),
        b'B' => Some(b" const"),
        b'C' => Some(b" volatile"),
        b'D' => Some(b" const volatile"),
        _ => None,
    }
}

struct Parser<'a> {
    input: &'a [u8],
    at: usize,
    names: Names,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.input.get(self.at).copied()
    }

    fn next(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.at += 1;
        Some(byte)
    }

    /// A data type.
    fn data_type(&mut self, out: &mut Text) -> Option<()> {
        let fundamental: &[u8] = match self.next()? {
            b'C' => b"signed char",
            b'D' => b"char",
            b'E' => b"unsigned char",
            b'F' => b"short",
            b'G' => b"unsigned short",
            b'H' => b"int",
            b'I' => b"unsigned int",
            b'J' => b"long",
            b'K' => b"unsigned long",
            b'M' => b"float",
            b'N' => b"double",
            b'O' => b"long double",
            b'X' => b"void",
            b'_' => match self.next()? {
                b'D' => b"__int8",
                b'E' => b"unsigned __int8",
                b'F' => b"__int16",
                b'G' => b"unsigned __int16",
                b'H' => b"__int32",
                b'I' => b"unsigned __int32",
                b'J' => b"__int64",
                b'K' => b"unsigned __int64",
                b'N' => b"bool",
                b'W' => b"wchar_t",
                _ => return None,
            },
            kind @ (b'T' | b'U' | b'V') => {
                out.push(match kind {
                    b'T' => b"union ",
                    b'U' => b"struct ",
                    _ => b"class ",
                });
                return self.qualified_name(out);
            }
            b'W' => {
                // The enum's underlying type, a digit ('4': int); the undecorator writes "enum".
                if !self.next()?.is_ascii_digit() {
                    return None;
                }
                out.push(b"enum ");
                return self.qualified_name(out);
            }
            kind @ (b'P' | b'Q' | b'R' | b'S' | b'A' | b'B') => {
                // A pointer (P, Q const, R volatile, S both) or a reference (A, B volatile): the
                // pointee's cv-qualifier, then the pointee.
                let pointee_cv = cv_suffix(self.next()?)?;
                self.data_type(out)?;
                out.push(pointee_cv);
                out.push(match kind {
                    b'A' | b'B' => b" &",
                    _ => b" *",
                });
                out.push(match kind {
                    b'Q' => b" const",
                    b'R' | b'B' => b" volatile",
                    b'S' => b" const volatile",
                    _ => b"",
                });
                return Some(());
            }
            _ => return None,
        };
        out.push(fundamental);
        Some(())
    }

    /// A scoped name: its parts innermost first, each ended by '@', the list by another;
    /// written outermost first, joined by "::".
    fn qualified_name(&mut self, out: &mut Text) -> Option<()> {
        let mut parts = Text::new();
        let mut ends = [0usize; 16];
        let mut count = 0;
        while self.peek()? != b'@' {
            self.name_part(&mut parts)?;
            *ends.get_mut(count)? = parts.len;
            count += 1;
        }
        self.at += 1;
        for index in (0..count).rev() {
            let start = if index == 0 { 0 } else { ends[index - 1] };
            out.push(&parts.as_bytes()[start..ends[index]]);
            if index != 0 {
                out.push(b"::");
            }
        }
        (!parts.overflowed).then_some(())
    }

    /// One part of a scoped name: an identifier, a name seen before (a digit), or a template's
    /// name and arguments ("?$name@args@").
    fn name_part(&mut self, out: &mut Text) -> Option<()> {
        match self.peek()? {
            digit @ b'0'..=b'9' => {
                self.at += 1;
                let name = self.names.get(usize::from(digit - b'0'))?;
                out.push(name);
            }
            b'?' => {
                if self.input.get(self.at + 1) != Some(&b'$') {
                    return None;
                }
                self.at += 2;
                let start = out.len;
                let outer = core::mem::replace(&mut self.names, Names::new());
                let name = self.identifier()?;
                self.names.add(name);
                out.push(name);
                out.push(b"<");
                let mut first = true;
                while self.peek()? != b'@' {
                    if !first {
                        out.push(b",");
                    }
                    first = false;
                    self.template_argument(out)?;
                }
                self.at += 1;
                if out.ends_with(b'>') {
                    out.push(b" ");
                }
                out.push(b">");
                self.names = outer;
                self.names.add(out.as_bytes().get(start..)?);
            }
            _ => {
                let name = self.identifier()?;
                self.names.add(name);
                out.push(name);
            }
        }
        Some(())
    }

    /// A template argument: a type, or an integer ("$0" and its encoded number).
    fn template_argument(&mut self, out: &mut Text) -> Option<()> {
        if self.peek()? != b'$' {
            return self.data_type(out);
        }
        self.at += 1;
        if self.next()? != b'0' {
            return None;
        }
        let negative = self.peek()? == b'?';
        if negative {
            self.at += 1;
        }
        let value = self.encoded_number()?;
        if negative {
            out.push(b"-");
        }
        let mut digits = [0u8; 20];
        let mut at = digits.len();
        let mut rest = value;
        loop {
            at -= 1;
            digits[at] = b'0' + (rest % 10) as u8;
            rest /= 10;
            if rest == 0 {
                break;
            }
        }
        out.push(&digits[at..]);
        Some(())
    }

    /// A decorated number: a digit for 1 to 10, or hexadecimal digits written 'A' to 'P' and
    /// ended by '@'.
    fn encoded_number(&mut self) -> Option<u64> {
        let first = self.next()?;
        if first.is_ascii_digit() {
            return Some(u64::from(first - b'0') + 1);
        }
        let mut value = 0u64;
        let mut digit = first;
        loop {
            match digit {
                b'A'..=b'P' => value = value.checked_mul(16)? + u64::from(digit - b'A'),
                b'@' => return Some(value),
                _ => return None,
            }
            digit = self.next()?;
        }
    }

    /// An identifier, ended by '@' (consumed).
    fn identifier(&mut self) -> Option<&'a [u8]> {
        let input: &'a [u8] = self.input;
        let start = self.at;
        let length = input.get(start..)?.iter().position(|&byte| byte == b'@')?;
        if length == 0 {
            return None;
        }
        self.at += length + 1;
        input.get(start..start + length)
    }
}

/// The undecorated name of the descriptor at `descriptor`: made on the first call (a block of
/// the C runtime's heap) and kept in the descriptor's spare word; the decorated name less its dot
/// where the decoration is one [`undecorate`] does not read (logged). Null when the heap has no
/// room.
///
/// # Safety
///
/// `descriptor` is a type descriptor, its name NUL-terminated after it.
pub unsafe fn type_name(descriptor: *const TypeDescriptor) -> *const u8 {
    // SAFETY: the caller's contract.
    let spare = unsafe { &(*descriptor).spare };
    let made = spare.load(Acquire);
    if !made.is_null() {
        return made;
    }
    // SAFETY: the caller's contract.
    let raw = unsafe { descriptor_name(descriptor) }.map_or(&b""[..], CStr::to_bytes);
    let raw = raw.strip_prefix(b".").unwrap_or(raw);
    let mut text = Text::new();
    let name = if undecorate(raw, &mut text).is_some() {
        text.as_bytes()
    } else {
        // SAFETY: no arguments are read.
        unsafe {
            crate::stub::logged(
                &crate::spec::type_info_name,
                "a decorated type name F2K does not undecorate (its decoration answered)",
                &[],
            )
        };
        raw
    };
    let block = crate::heap::allocate(name.len() + 1, true);
    if block.is_null() {
        return core::ptr::null();
    }
    // SAFETY: a fresh block of `name.len() + 1` zeroed bytes.
    unsafe { core::ptr::copy_nonoverlapping(name.as_ptr(), block, name.len()) };
    match spare.compare_exchange(core::ptr::null_mut(), block, AcqRel, Acquire) {
        Ok(_) => block,
        Err(other) => {
            // Another thread made it first: its block is the one kept.
            // SAFETY: the block is this call's, unshared.
            unsafe { crate::heap::release(block) };
            other
        }
    }
}

/// Two descriptors' decorated names compared (strcmp's sign), past their leading dots.
///
/// # Safety
///
/// Both are type descriptors.
pub unsafe fn compare(
    left: *const TypeDescriptor,
    right: *const TypeDescriptor,
) -> core::cmp::Ordering {
    // SAFETY: the caller's contract.
    let (left, right) = unsafe { (descriptor_name(left), descriptor_name(right)) };
    fn bytes(name: Option<&CStr>) -> &[u8] {
        name.map_or(&b""[..], CStr::to_bytes)
            .get(1..)
            .unwrap_or(b"")
    }
    bytes(left).cmp(bytes(right))
}

#[cfg(all(target_arch = "x86", not(test)))]
mod platform {
    use core::sync::atomic::AtomicPtr;

    use super::*;
    use crate::eh::{throw_exception, CatchableType, CatchableTypeArray, Pmd, ThrowInfo};

    /// type_info::operator==: the two types' decorated names the same.
    ///
    /// # Safety
    ///
    /// `this` and `other` are type_infos.
    #[unsafe(export_name = "f2k_export_type_info_eq")]
    unsafe extern "thiscall" fn type_info_eq(
        this: *const TypeDescriptor,
        other: *const TypeDescriptor,
    ) -> i32 {
        // SAFETY: the caller's contract.
        i32::from(unsafe { compare(this, other) }.is_eq())
    }

    /// type_info::operator!=.
    ///
    /// # Safety
    ///
    /// As `type_info_eq`'s.
    #[unsafe(export_name = "f2k_export_type_info_ne")]
    unsafe extern "thiscall" fn type_info_ne(
        this: *const TypeDescriptor,
        other: *const TypeDescriptor,
    ) -> i32 {
        // SAFETY: the caller's contract.
        i32::from(unsafe { compare(this, other) }.is_ne())
    }

    /// type_info::before: the type's decorated name before the other's.
    ///
    /// # Safety
    ///
    /// As `type_info_eq`'s.
    #[unsafe(export_name = "f2k_export_type_info_before")]
    unsafe extern "thiscall" fn type_info_before(
        this: *const TypeDescriptor,
        other: *const TypeDescriptor,
    ) -> i32 {
        // SAFETY: the caller's contract.
        i32::from(unsafe { compare(this, other) }.is_lt())
    }

    /// type_info::name: the undecorated name.
    ///
    /// # Safety
    ///
    /// `this` is a type_info.
    #[unsafe(export_name = "f2k_export_type_info_name")]
    unsafe extern "thiscall" fn type_info_name(this: *const TypeDescriptor) -> *const u8 {
        // SAFETY: the caller's contract.
        unsafe { type_name(this) }
    }

    /// type_info::raw_name: the decorated name.
    ///
    /// # Safety
    ///
    /// `this` is a type_info.
    #[unsafe(export_name = "f2k_export_type_info_raw_name")]
    unsafe extern "thiscall" fn type_info_raw_name(this: *const TypeDescriptor) -> *const u8 {
        // SAFETY: the caller's contract: the name follows the descriptor's two words.
        unsafe { (&raw const (*this).name).cast() }
    }

    /// type_info::~type_info: the undecorated name name() made given back.
    ///
    /// # Safety
    ///
    /// `this` is a type_info no other thread uses.
    #[unsafe(export_name = "f2k_export_type_info_destructor")]
    unsafe extern "thiscall" fn type_info_destructor(this: *const TypeDescriptor) {
        // SAFETY: the caller's contract.
        let made = unsafe { (*this).spare.swap(core::ptr::null_mut(), AcqRel) };
        if !made.is_null() {
            // SAFETY: the block type_name made.
            unsafe { crate::heap::release(made) };
        }
    }

    /// type_info's vftable for msvcrt's own descriptors: the scalar deleting destructor.
    #[repr(C)]
    struct TypeInfoVftable {
        destructor: unsafe extern "thiscall" fn(*mut TypeDescriptor, u32) -> *mut TypeDescriptor,
    }

    /// type_info's scalar deleting destructor: the destructor, and the object given back when
    /// `flags`' low bit says so.
    unsafe extern "thiscall" fn type_info_delete(
        this: *mut TypeDescriptor,
        flags: u32,
    ) -> *mut TypeDescriptor {
        // SAFETY: the caller's contract: a type_info being destroyed.
        unsafe {
            type_info_destructor(this);
            if flags & 1 != 0 {
                crate::heap::release(this.cast());
            }
        }
        this
    }

    static TYPE_INFO_VFTABLE: TypeInfoVftable = TypeInfoVftable {
        destructor: type_info_delete,
    };

    /// An object of class `exception` as Visual C++ 6's eh.h lays it out (bad_typeid adds
    /// nothing): its vftable, its message, whether the message is the object's to free.
    #[repr(C)]
    struct Exception {
        vftable: *const unsafe extern "thiscall" fn(),
        what: *const u8,
        free: i32,
    }

    /// bad_typeid's vftable, after its complete object locator: the scalar deleting destructor,
    /// `what`.
    #[repr(C)]
    struct ExceptionVftable {
        locator: &'static CompleteObjectLocator,
        destructor: unsafe extern "thiscall" fn(*mut Exception, u32) -> *mut Exception,
        what: unsafe extern "thiscall" fn(*const Exception) -> *const u8,
    }

    /// exception::~exception (bad_typeid's): its message given back when it is the object's.
    unsafe extern "thiscall" fn exception_destructor(this: *mut Exception) {
        // SAFETY: the caller's contract: an exception object being destroyed.
        unsafe {
            if (*this).free != 0 {
                crate::heap::release((*this).what.cast_mut());
            }
        }
    }

    /// The scalar deleting destructor.
    unsafe extern "thiscall" fn exception_delete(
        this: *mut Exception,
        flags: u32,
    ) -> *mut Exception {
        // SAFETY: the caller's contract.
        unsafe {
            exception_destructor(this);
            if flags & 1 != 0 {
                crate::heap::release(this.cast());
            }
        }
        this
    }

    /// exception::what: the message.
    unsafe extern "thiscall" fn exception_what(this: *const Exception) -> *const u8 {
        // SAFETY: the caller's contract.
        unsafe { (*this).what }
    }

    /// A copy (a catch by value) with `vftable`, the class it is caught as: the message shared, not
    /// the copy's to free.
    ///
    /// # Safety
    ///
    /// `this` is room for an object, `other` an object.
    unsafe fn copy(
        this: *mut Exception,
        other: *const Exception,
        vftable: &'static ExceptionVftable,
    ) {
        // SAFETY: the caller's contract.
        unsafe {
            this.write(Exception {
                vftable: (&raw const vftable.destructor).cast(),
                what: (*other).what,
                free: 0,
            })
        };
    }

    /// bad_typeid's copy constructor.
    unsafe extern "thiscall" fn bad_typeid_copy(this: *mut Exception, other: *const Exception) {
        // SAFETY: the caller's contract.
        unsafe { copy(this, other, &BAD_TYPEID_VFTABLE) }
    }

    /// exception's copy constructor: a bad_typeid caught as an exception by value is sliced.
    unsafe extern "thiscall" fn exception_copy(this: *mut Exception, other: *const Exception) {
        // SAFETY: the caller's contract.
        unsafe { copy(this, other, &EXCEPTION_VFTABLE) }
    }

    static BAD_TYPEID_TYPE: TypeDescriptor<17> = TypeDescriptor {
        vftable: (&raw const TYPE_INFO_VFTABLE).cast(),
        spare: AtomicPtr::new(core::ptr::null_mut()),
        name: *b".?AVbad_typeid@@\0",
    };
    static EXCEPTION_TYPE: TypeDescriptor<16> = TypeDescriptor {
        vftable: (&raw const TYPE_INFO_VFTABLE).cast(),
        spare: AtomicPtr::new(core::ptr::null_mut()),
        name: *b".?AVexception@@\0",
    };

    static BAD_TYPEID_LOCATOR: CompleteObjectLocator = CompleteObjectLocator {
        signature: 0,
        offset: 0,
        cd_offset: 0,
        type_descriptor: (&raw const BAD_TYPEID_TYPE).cast(),
        class_descriptor: core::ptr::null(),
    };

    static BAD_TYPEID_VFTABLE: ExceptionVftable = ExceptionVftable {
        locator: &BAD_TYPEID_LOCATOR,
        destructor: exception_delete,
        what: exception_what,
    };

    static EXCEPTION_LOCATOR: CompleteObjectLocator = CompleteObjectLocator {
        signature: 0,
        offset: 0,
        cd_offset: 0,
        type_descriptor: (&raw const EXCEPTION_TYPE).cast(),
        class_descriptor: core::ptr::null(),
    };

    static EXCEPTION_VFTABLE: ExceptionVftable = ExceptionVftable {
        locator: &EXCEPTION_LOCATOR,
        destructor: exception_delete,
        what: exception_what,
    };

    /// A catchable type of bad_typeid's: the whole object, copied by `copy`.
    const fn catchable(descriptor: *const TypeDescriptor, copy: *const c_void) -> CatchableType {
        CatchableType {
            properties: 0,
            type_descriptor: descriptor,
            this_displacement: Pmd {
                mdisp: 0,
                pdisp: -1,
                vdisp: 0,
            },
            size: size_of::<Exception>() as i32,
            copy_function: copy,
        }
    }

    static BAD_TYPEID_CATCHABLE: CatchableType = catchable(
        (&raw const BAD_TYPEID_TYPE).cast(),
        bad_typeid_copy as *const c_void,
    );
    static EXCEPTION_CATCHABLE: CatchableType = catchable(
        (&raw const EXCEPTION_TYPE).cast(),
        exception_copy as *const c_void,
    );
    static BAD_TYPEID_TYPES: CatchableTypeArray<2> = CatchableTypeArray {
        count: 2,
        types: [
            &raw const BAD_TYPEID_CATCHABLE,
            &raw const EXCEPTION_CATCHABLE,
        ],
    };

    /// bad_typeid's ThrowInfo: its destructor, and its types (bad_typeid, exception).
    static BAD_TYPEID_THROW: ThrowInfo = ThrowInfo {
        attributes: 0,
        unwind: exception_destructor as *const c_void,
        forward_compat: core::ptr::null(),
        catchable_types: (&raw const BAD_TYPEID_TYPES).cast(),
    };

    /// __RTtypeid(object): the type_info of a polymorphic object's dynamic type, from the
    /// complete object locator before its vftable; bad_typeid thrown for a null object.
    ///
    /// # Safety
    ///
    /// `object` is null or a polymorphic object compiled with /GR (its vftable's locator there).
    #[unsafe(export_name = "f2k_export___RTtypeid")]
    unsafe extern "C" fn rt_typeid(
        object: *const *const *const CompleteObjectLocator,
    ) -> *const TypeDescriptor {
        if object.is_null() {
            let mut error = Exception {
                vftable: (&raw const BAD_TYPEID_VFTABLE.destructor).cast(),
                what: c"Attempted a typeid of NULL pointer!".as_ptr().cast(),
                free: 0,
            };
            // The object lives on this frame, which the catch block's stack is below.
            throw_exception(
                (&raw mut error) as usize,
                (&raw const BAD_TYPEID_THROW) as usize,
            )
        }
        // SAFETY: the caller's contract: the object's vftable, its locator in the word before it.
        unsafe { (**(*object).sub(1)).type_descriptor }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn undecorated(raw: &'static [u8]) -> Option<String> {
        let mut text = Text::new();
        undecorate(raw, &mut text)?;
        Some(String::from_utf8(text.as_bytes().to_vec()).unwrap())
    }

    /// crt's cxxeh `typeid`: the names of its descriptors as Windows 2000's type_info::name
    /// answers them.
    #[test]
    fn the_captured_names() {
        assert_eq!(
            undecorated(b"?AVDerived@@").as_deref(),
            Some("class Derived")
        );
        assert_eq!(undecorated(b"H").as_deref(), Some("int"));
        assert_eq!(undecorated(b"PAVBase@@").as_deref(), Some("class Base *"));
        assert_eq!(
            undecorated(b"PAVDerived@@").as_deref(),
            Some("class Derived *")
        );
    }

    /// The rest of what a type's descriptor carries, as Visual C++'s undecorator writes it:
    /// cv-qualifiers after their type, scopes outermost first, template arguments without spaces
    /// but between closing brackets, names seen before by their digit.
    #[test]
    fn the_decoration_of_types() {
        let cases: [(&[u8], &str); 12] = [
            (b"PBD", "char const *"),
            (b"QAH", "int * const"),
            (b"PAPAD", "char * *"),
            (b"AAVThing@@", "class Thing &"),
            (b"_J", "__int64"),
            (b"?AUPOINT@@", "struct POINT"),
            (b"?ATU@@", "union U"),
            (b"?AW4Color@@", "enum Color"),
            (b"?AVInner@Outer@@", "class Outer::Inner"),
            (b"?AV?$list@HV?$allocator@H@std@@@std@@", "class std::list<int,class std::allocator<int> >"),
            (b"?AV?$Array@H$0BA@@@", "class Array<int,16>"),
            (
                b"?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@",
                "class std::basic_string<char,struct std::char_traits<char>,class std::allocator<char> >",
            ),
        ];
        for (raw, name) in cases {
            assert_eq!(
                undecorated(raw).as_deref(),
                Some(name),
                "{}",
                String::from_utf8_lossy(raw)
            );
        }
        assert_eq!(undecorated(b"P6AXXZ"), None);
        assert_eq!(undecorated(b"?AVUnended"), None);
    }

    /// == compares the decorated names, before orders them: "Base" before "Derived".
    #[test]
    fn descriptors_compare_by_name() {
        let base = TypeDescriptor {
            vftable: core::ptr::null(),
            spare: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
            name: *b".?AVBase@@\0",
        };
        let derived = TypeDescriptor {
            vftable: core::ptr::null(),
            spare: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
            name: *b".?AVDerived@@\0",
        };
        let (base, derived): (*const TypeDescriptor, *const TypeDescriptor) =
            ((&raw const base).cast(), (&raw const derived).cast());
        // SAFETY: the test's descriptors.
        unsafe {
            assert!(compare(base, base).is_eq());
            assert!(compare(base, derived).is_lt());
            assert!(compare(derived, base).is_gt());
        }
    }
}
