//! The environment services beyond a variable's get and set: the whole block, the wide set, and
//! expansion.
//!
//! GetEnvironmentStrings and GetEnvironmentStringsW hand out the block as it stands: each call
//! writes the process's variables (see [`super::environment`]) into the block's region of user
//! memory — `NAME=value` entries, each NUL-terminated, a final NUL — the narrow form in code page
//! 1252, the wide form in UTF-16, and returns its address; freeing it changes nothing. A program
//! reads the variables set before its call, as on the platform (whose block is a fresh copy).

/// The narrow block's region: room for the store and its final terminator.
pub const BLOCK_A: u32 = 0x0034_0000;
/// The wide block's region.
pub const BLOCK_W: u32 = 0x0035_0000;
/// The regions' sizes in pages.
pub const BLOCK_A_PAGES: u32 = 3;
pub const BLOCK_W_PAGES: u32 = 5;

/// Map the two block regions, zeroed (the empty block): the process's staging step.
#[cfg(target_arch = "x86")]
pub fn map_blocks() {
    use crate::mem::paging;
    for (base, pages) in [(BLOCK_A, BLOCK_A_PAGES), (BLOCK_W, BLOCK_W_PAGES)] {
        for page in 0..pages {
            let frame = paging::allocate_frame_phys();
            paging::init_frame(frame, 0, &[]);
            paging::map_user_page(base + page * paging::PAGE_SIZE, frame, true);
        }
    }
}

/// Write the current block at `base` in `unit`-byte characters (1: code page 1252 bytes; 2: UTF-16).
#[cfg(target_arch = "x86")]
fn write_block(base: u32, unit: u32) -> u32 {
    use crate::user::syscall::write_user;
    let environment = crate::process::current_mut().environment_mut();
    let mut at = base;
    let mut put = |byte: u8| {
        let _ = if unit == 1 {
            write_user(at, &[byte])
        } else {
            write_user(at, &crate::compat::cp1252::MB_TO_WC[byte as usize].to_le_bytes())
        };
        at += unit;
    };
    let mut any = false;
    for entry in environment.each() {
        any = true;
        entry.iter().for_each(|&b| put(b));
        put(0);
    }
    if !any {
        put(0);
    }
    put(0);
    base
}

/// GetEnvironmentStrings: the narrow block.
pub fn svc_get_environment_strings(frame: &mut crate::user::TrapFrame, _args: &[u32]) {
    #[cfg(target_arch = "x86")]
    {
        frame.eax = write_block(BLOCK_A, 1);
    }
    #[cfg(not(target_arch = "x86"))]
    {
        frame.eax = 0;
    }
}

/// GetEnvironmentStringsW: the wide block.
pub fn svc_get_environment_strings_w(frame: &mut crate::user::TrapFrame, _args: &[u32]) {
    #[cfg(target_arch = "x86")]
    {
        frame.eax = write_block(BLOCK_W, 2);
    }
    #[cfg(not(target_arch = "x86"))]
    {
        frame.eax = 0;
    }
}

/// Expand `%NAME%` references in `source` through `lookup`: a defined name becomes its value, any
/// other reference (and a `%` with no closing one) stays as written. Returns the expansion's bytes
/// through `out`.
pub fn expand(source: &[u8], lookup: impl Fn(&[u8]) -> Option<&[u8]>, mut out: impl FnMut(u8)) {
    let mut i = 0;
    while i < source.len() {
        if source[i] == b'%' {
            if let Some(close) = source[i + 1..].iter().position(|&b| b == b'%') {
                let name = &source[i + 1..i + 1 + close];
                if let Some(value) = (!name.is_empty()).then(|| lookup(name)).flatten() {
                    value.iter().for_each(|&b| out(b));
                } else {
                    source[i..i + close + 2].iter().for_each(|&b| out(b));
                }
                i += close + 2;
                continue;
            }
        }
        out(source[i]);
        i += 1;
    }
}

/// ExpandEnvironmentStringsA: the expansion and its terminator into the caller's buffer when it
/// fits; the size it needs (terminator included) either way. ERROR_NOACCESS for an unreadable
/// source.
pub fn svc_expand_environment_strings_a(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    #[cfg(target_arch = "x86")]
    {
        use crate::user::syscall::{read_user, write_user};
        let (source, buffer, size) = (args[0], args[1], args[2]);
        frame.eax = 0;
        let mut text = [0u8; 1024];
        let mut len = 0;
        loop {
            let mut byte = [0u8];
            if read_user(source + len as u32, &mut byte).is_err() {
                return crate::user::teb::set_last_error(crate::compat::error::ERROR_NOACCESS);
            }
            if byte[0] == 0 || len == text.len() {
                break;
            }
            text[len] = byte[0];
            len += 1;
        }
        let environment = crate::process::current_mut().environment_mut();
        let mut needed = 0u32;
        expand(&text[..len], |name| environment.get(name), |b| {
            if needed < size {
                let _ = write_user(buffer + needed, &[b]);
            }
            needed += 1;
        });
        if needed < size {
            let _ = write_user(buffer + needed, &[0]);
        }
        frame.eax = needed + 1;
    }
    #[cfg(not(target_arch = "x86"))]
    {
        let _ = args;
        frame.eax = 0;
    }
}

/// SetEnvironmentVariableW: the wide name and value, through code page 1252, as
/// SetEnvironmentVariableA sets them.
pub fn svc_set_environment_variable_w(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    #[cfg(target_arch = "x86")]
    {
        use crate::compat::environment::EnvironmentError;
        use crate::compat::error::{ERROR_INVALID_PARAMETER, ERROR_NOACCESS, ERROR_NOT_ENOUGH_MEMORY};
        use crate::user::syscall::read_user;
        use crate::user::teb::set_last_error;
        let (name, value) = (args[0], args[1]);
        frame.eax = 0;
        let read_unit = |at: u32| -> Option<u16> {
            let mut wide = [0u8; 2];
            read_user(at, &mut wide).ok()?;
            Some(u16::from_le_bytes(wide))
        };
        let wide_len = |at: u32| -> Option<usize> {
            (0..0x8000).find_map(|i| match read_unit(at + 2 * i as u32) {
                Some(0) => Some(Some(i)),
                Some(_) => None,
                None => Some(None),
            })?
        };
        if name == 0 {
            return set_last_error(ERROR_INVALID_PARAMETER);
        }
        let Some(name_len) = wide_len(name) else {
            return set_last_error(ERROR_NOACCESS);
        };
        if name_len > 260 {
            return set_last_error(ERROR_INVALID_PARAMETER);
        }
        let mut name_bytes = [0u8; 260];
        for (i, byte) in name_bytes[..name_len].iter_mut().enumerate() {
            *byte = crate::compat::cp1252::wc_to_mb(read_unit(name + 2 * i as u32).unwrap_or(0));
        }
        let environment = crate::process::current_mut().environment_mut();
        let result = if value == 0 {
            environment.set(&name_bytes[..name_len], None)
        } else {
            let Some(value_len) = wide_len(value) else {
                return set_last_error(ERROR_NOACCESS);
            };
            environment.reserve(&name_bytes[..name_len], value_len).map(|slot| {
                for (i, byte) in slot.iter_mut().enumerate() {
                    *byte = crate::compat::cp1252::wc_to_mb(read_unit(value + 2 * i as u32).unwrap_or(0));
                }
            })
        };
        match result {
            Ok(()) => frame.eax = 1,
            Err(EnvironmentError::InvalidName) => set_last_error(ERROR_INVALID_PARAMETER),
            Err(EnvironmentError::Full) => set_last_error(ERROR_NOT_ENOUGH_MEMORY),
        }
    }
    #[cfg(not(target_arch = "x86"))]
    {
        let _ = args;
        frame.eax = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expanded(source: &str) -> String {
        let mut out = Vec::new();
        expand(
            source.as_bytes(),
            |name| name.eq_ignore_ascii_case(b"F2KCRT").then_some(&b"crt value"[..]),
            |b| out.push(b),
        );
        String::from_utf8(out).unwrap()
    }

    /// The capture's expansion, and the literal cases.
    #[test]
    fn references_expand_or_stay() {
        assert_eq!(expanded("[%F2KCRT%] [%F2KNOSUCH%]"), "[crt value] [%F2KNOSUCH%]");
        assert_eq!(expanded("[%F2KCRT%] [%F2KNOSUCH%]").len() + 1, 26);
        assert_eq!(expanded("100%"), "100%");
        assert_eq!(expanded("%%"), "%%");
        assert_eq!(expanded("%f2kcrt%"), "crt value");
    }
}
