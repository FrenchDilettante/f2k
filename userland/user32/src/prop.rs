//! Window properties: SetPropW/A, GetPropW/A and RemovePropW/A, over win32k's property services
//! ([`imports`]: NtUserSetProp, NtUserRemoveProp and NtUserBuildPropList).
//!
//! A property's name is a string or an atom in the low word of the pointer (MAKEINTATOM). The
//! window manager names properties by atom, so user32 turns a string into its global atom first,
//! as Windows 2000's user32 does, through kernel32: SetProp adds the atom (GlobalAddAtom, a
//! reference counted for each set), GetProp and RemoveProp only look it up (GlobalFindAtom: a name
//! with no atom names no property, the lookup's ERROR_FILE_NOT_FOUND left as the last error), and
//! RemoveProp gives the reference back (GlobalDeleteAtom) once a property was removed with data.
//! So "#291" and MAKEINTATOM(291) name one property, a name matches in either case, and a name's
//! atom outlives a property it named while some set's reference is left (the props capture).
//!
//! A SetProp the window manager refuses gives its atom's reference back, its own error kept:
//! the props capture finds no atom after SetPropW on a NULL or destroyed window.

use rtl::window::PropSet;

use crate::{answered, imports};

/// Whether a property's name is a string (its pointer's high word not zero) rather than an atom.
fn is_string(name: usize) -> bool {
    name >> 16 != 0
}

/// SetProp's body: the window's property `name` (a string of the form `wide` says, or an atom) set
/// to `data`; FALSE with the last error of the atom's refusal (kernel32's: ERROR_INVALID_NAME for
/// the empty name, ERROR_INVALID_PARAMETER for one past 255 characters) or of the window
/// manager's (ERROR_INVALID_WINDOW_HANDLE, ERROR_INVALID_PARAMETER for atom 0, a NULL name's).
fn set_prop(window: usize, name: usize, data: usize, wide: bool) -> u32 {
    let string = is_string(name);
    let atom = if string {
        let atom = imports::global_add_atom(name, wide);
        if atom == 0 {
            return 0;
        }
        atom
    } else {
        name as u16
    };
    let set = imports::set_prop(window, atom, data as u32);
    if set.is_err() && string {
        imports::global_delete_atom(atom);
    }
    answered(set).is_some() as u32
}

/// The atom a name to look up names: a string's, as the global table has it (none when it has
/// none, kernel32's last error set), an atom as it is.
fn find_atom(name: usize, wide: bool) -> Option<u16> {
    if !is_string(name) {
        return Some(name as u16);
    }
    let atom = imports::global_find_atom(name, wide);
    (atom != 0).then_some(atom)
}

/// The properties read at once without the heap.
const STACK_PROPS: usize = 32;

/// The data of the window's property `atom`, as the window manager lists the window's properties
/// (none for no such property); none, with 1400, for a handle naming no window, or with
/// ERROR_NOT_ENOUGH_MEMORY when a long list finds no room in the heap.
fn find_prop(window: usize, atom: u16) -> Option<Option<u32>> {
    let find = |list: &[PropSet]| {
        list.iter()
            .find(|p| p.atom == u32::from(atom) && atom != 0)
            .map(|p| p.data)
    };
    let mut list = [PropSet::default(); STACK_PROPS];
    let count = answered(imports::build_prop_list(window, &mut list))?;
    if count <= STACK_PROPS {
        return Some(find(&list[..count]));
    }
    // A longer list, in a block of the heap; the window's own properties cannot change under the
    // call but through the program's own threads, so a list grown since is read as far as fits.
    let Some(mut block) = imports::HeapBlock::new(count * core::mem::size_of::<PropSet>()) else {
        return crate::failed(crate::ERROR_NOT_ENOUGH_MEMORY);
    };
    let bytes = block.bytes_mut();
    // SAFETY: the heap's blocks are 8-aligned, the block holds `count` PROPSETs, and zeroed bytes
    // are a PROPSET (plain integers), which the slice borrows for no longer than the block lives.
    let list =
        unsafe { core::slice::from_raw_parts_mut(bytes.as_mut_ptr() as *mut PropSet, count) };
    let written = answered(imports::build_prop_list(window, list))?;
    Some(find(&list[..written.min(count)]))
}

/// GetProp's body: the data of the window's property `name`; NULL when the window has none of
/// that name (the last error untouched, but for a name with no atom: see the module notes), or
/// with 1400 for a handle naming no window.
fn get_prop(window: usize, name: usize, wide: bool) -> usize {
    let Some(atom) = find_atom(name, wide) else {
        return 0;
    };
    find_prop(window, atom).flatten().unwrap_or(0) as usize
}

/// RemoveProp's body: the window's property `name` taken off, its data answered; NULL when the
/// window has none of that name. A string's reference to its atom is given back when the
/// property had data.
fn remove_prop(window: usize, name: usize, wide: bool) -> usize {
    let Some(atom) = find_atom(name, wide) else {
        return 0;
    };
    let Some(data) = answered(imports::remove_prop(window, atom)) else {
        return 0;
    };
    if data != 0 && is_string(name) {
        imports::global_delete_atom(atom);
    }
    data as usize
}

/// SetPropW: see [`set_prop`]; the name a wide string or an atom.
#[unsafe(export_name = "f2k_export_SetPropW")]
pub extern "system" fn set_prop_w(window: usize, name: usize, data: usize) -> u32 {
    set_prop(window, name, data, true)
}

/// SetPropA: see [`set_prop`]; the name an ANSI string or an atom.
#[unsafe(export_name = "f2k_export_SetPropA")]
pub extern "system" fn set_prop_a(window: usize, name: usize, data: usize) -> u32 {
    set_prop(window, name, data, false)
}

/// GetPropW: see [`get_prop`].
#[unsafe(export_name = "f2k_export_GetPropW")]
pub extern "system" fn get_prop_w(window: usize, name: usize) -> usize {
    get_prop(window, name, true)
}

/// GetPropA: see [`get_prop`].
#[unsafe(export_name = "f2k_export_GetPropA")]
pub extern "system" fn get_prop_a(window: usize, name: usize) -> usize {
    get_prop(window, name, false)
}

/// RemovePropW: see [`remove_prop`].
#[unsafe(export_name = "f2k_export_RemovePropW")]
pub extern "system" fn remove_prop_w(window: usize, name: usize) -> usize {
    remove_prop(window, name, true)
}

/// RemovePropA: see [`remove_prop`].
#[unsafe(export_name = "f2k_export_RemovePropA")]
pub extern "system" fn remove_prop_a(window: usize, name: usize) -> usize {
    remove_prop(window, name, false)
}

#[cfg(test)]
mod tests {
    use rtl::testing::wide_z;

    use super::*;
    use crate::class::{register_class_a, WndClass};
    use crate::imports::host::{atom_references, procedure, LAST_ERROR};

    const UNSET: u32 = 0xF2F2_F2F2;

    fn arm() {
        LAST_ERROR.with(|error| error.set(UNSET));
    }

    fn last_error() -> u32 {
        LAST_ERROR.with(|error| error.get())
    }

    /// A hidden pop-up of a class of the tests' own.
    fn window() -> usize {
        fn quiet(_: u32, _: u32, _: u32, _: i32) -> i32 {
            0
        }
        let class = WndClass {
            wnd_proc: procedure(quiet) as usize,
            instance: 0x40_0000,
            class_name: c"F2KProps".as_ptr() as usize,
            ..WndClass::default()
        };
        // SAFETY: a WNDCLASSA of the tests' own.
        unsafe { register_class_a(&class) };
        let class = wide_z("F2KProps");
        crate::window::create_window_ex_w(
            0,
            class.as_ptr(),
            core::ptr::null(),
            0x8000_0000,
            0,
            0,
            320,
            200,
            0,
            0,
            0x40_0000,
            0,
        )
    }

    /// The props capture's string and refs blocks: a property set by a wide name is read by the
    /// narrow one and in other case, replaced, removed (its data, then NULL with no error while
    /// the name's atom is left); each SetProp adds a reference to the name's atom, each RemoveProp
    /// with data gives one back, and a name with no atom left is ERROR_FILE_NOT_FOUND.
    ///
    /// Pins: user32.SetPropW, user32.SetPropA, user32.GetPropW, user32.GetPropA,
    /// user32.RemovePropW, user32.RemovePropA
    #[test]
    fn by_name() {
        let h = window();
        let one = wide_z("F2KPropsOne");
        let one_w = one.as_ptr() as usize;
        let one_a = c"F2KPropsOne".as_ptr() as usize;
        let other_case = wide_z("f2kpropsONE");
        arm();
        assert_eq!(set_prop_w(h, one_w, 0x1111), 1);
        assert_eq!(get_prop_w(h, one_w), 0x1111);
        assert_eq!(get_prop_a(h, one_a), 0x1111);
        assert_eq!(get_prop_w(h, other_case.as_ptr() as usize), 0x1111);
        assert_eq!(set_prop_a(h, one_a, 0x3333), 1);
        assert_eq!(get_prop_w(h, one_w), 0x3333);
        assert_eq!(atom_references("F2KPropsOne"), 2);
        assert_eq!(remove_prop_w(h, one_w), 0x3333);
        assert_eq!(atom_references("F2KPropsOne"), 1);
        assert_eq!(get_prop_w(h, one_w), 0);
        assert_eq!(remove_prop_a(h, one_a), 0);
        assert_eq!(last_error(), UNSET);

        let two = wide_z("F2KPropsTwo");
        assert_eq!(set_prop_w(h, two.as_ptr() as usize, 0x2222), 1);
        assert_eq!(remove_prop_a(h, c"f2kpropstwo".as_ptr() as usize), 0x2222);
        assert_eq!(atom_references("F2KPropsTwo"), 0);
        assert_eq!(get_prop_w(h, two.as_ptr() as usize), 0);
        assert_eq!(last_error(), 2);
    }

    /// The props capture's atom and errors blocks: "#291" and MAKEINTATOM(291) name one property;
    /// a NULL or destroyed window is 1400 for SetProp, its atom given back; the empty name is
    /// ERROR_INVALID_NAME, a 300-character one ERROR_INVALID_PARAMETER; a NULL name is
    /// ERROR_INVALID_PARAMETER for SetProp and nothing at all for the others.
    ///
    /// Pins: user32.SetPropW, user32.GetPropW, user32.GetPropA, user32.RemovePropW,
    /// user32.RemovePropA
    #[test]
    fn by_atom_and_the_errors() {
        let h = window();
        let number = wide_z("#291");
        assert_eq!(set_prop_w(h, number.as_ptr() as usize, 0x6666), 1);
        assert_eq!(get_prop_w(h, 291), 0x6666);
        assert_eq!(get_prop_a(h, c"#291".as_ptr() as usize), 0x6666);
        assert_eq!(remove_prop_a(h, c"#291".as_ptr() as usize), 0x6666);
        assert_eq!(get_prop_w(h, 291), 0);

        let name = wide_z("F2KPropsOne");
        arm();
        assert_eq!(set_prop_w(0, name.as_ptr() as usize, 1), 0);
        assert_eq!(last_error(), 1400);
        assert_eq!(atom_references("F2KPropsOne"), 0);
        let empty = wide_z("");
        assert_eq!(set_prop_w(h, empty.as_ptr() as usize, 0xAAAA), 0);
        assert_eq!(last_error(), 123);
        let long = wide_z(&"abcdefghijklmnopqrstuvwxyz".repeat(12)[..300]);
        assert_eq!(get_prop_w(h, long.as_ptr() as usize), 0);
        assert_eq!(last_error(), 87);
        arm();
        assert_eq!(set_prop_w(h, 0, 0x9999), 0);
        assert_eq!(last_error(), 87);
        arm();
        assert_eq!(get_prop_w(h, 0), 0);
        assert_eq!(remove_prop_w(h, 0), 0);
        assert_eq!(last_error(), UNSET);
    }
}
