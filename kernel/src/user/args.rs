//! The arguments a system service's generated wrapper decodes a system call's argument block into
//! (`nt`): handles, pointers into the caller's memory, and typed pointers.
//!
//! User memory is reached only through the fault-tolerant copy (`read_user` / `write_user`), so
//! every accessor can fail with a [`Fault`], which the NT services report as
//! STATUS_ACCESS_VIOLATION.

// The system services later work adds decode their arguments into these: NtClose takes
// a handle alone so far.
#![allow(dead_code)]

use core::marker::PhantomData;

use crate::user::syscall::{read_user, write_user};

/// The process a service is serving: the caller's, borrowed for as long as the service holds it
/// (the one place the services take it from).
#[cfg(target_arch = "x86")]
pub fn calling_process() -> &'static mut crate::process::Process {
    crate::process::current_mut()
}

/// A transfer the caller's memory refused: an unmapped or protected page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fault;

/// A handle argument.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Handle(pub u32);

impl Handle {
    /// The handle's value.
    pub fn raw(self) -> u32 {
        self.0
    }
}

/// An untyped pointer into the caller's memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserAddr(pub u32);

impl UserAddr {
    /// The address.
    pub fn raw(self) -> u32 {
        self.0
    }

    pub fn is_null(self) -> bool {
        self.0 == 0
    }

    /// The address `by` bytes on (wrapping, as the caller's arithmetic would).
    pub fn offset(self, by: u32) -> UserAddr {
        UserAddr(self.0.wrapping_add(by))
    }

    /// Read `bytes.len()` bytes from it; a fault when they cannot be read.
    pub fn read(self, bytes: &mut [u8]) -> Result<(), Fault> {
        read_user(self.0, bytes).map_err(|_| Fault)
    }

    /// Write `bytes` to it; a fault when they cannot be written.
    pub fn write(self, bytes: &[u8]) -> Result<(), Fault> {
        write_user(self.0, bytes).map_err(|_| Fault)
    }
}

/// A value a typed pointer can carry: plain little-endian bytes.
pub trait Plain: Copy {
    /// Its size in bytes.
    const SIZE: usize;
    /// Its bytes, into `out` (`SIZE` long).
    fn encode(self, out: &mut [u8]);
    /// It, from `bytes` (`SIZE` long).
    fn decode(bytes: &[u8]) -> Self;
}

macro_rules! plain {
    ($($t:ty),*) => {$(
        impl Plain for $t {
            const SIZE: usize = core::mem::size_of::<$t>();
            fn encode(self, out: &mut [u8]) {
                out.copy_from_slice(&self.to_le_bytes());
            }
            fn decode(bytes: &[u8]) -> Self {
                let mut raw = [0u8; core::mem::size_of::<$t>()];
                raw.copy_from_slice(bytes);
                <$t>::from_le_bytes(raw)
            }
        }
    )*};
}
plain!(u8, u16, u32, i32, u64);

/// A pointer to one `T` in the caller's memory.
#[derive(Debug, PartialEq, Eq)]
pub struct UserPtr<T> {
    addr: u32,
    pointee: PhantomData<T>,
}

impl<T> Clone for UserPtr<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for UserPtr<T> {}

impl<T: Plain> UserPtr<T> {
    /// The pointer at `addr`.
    pub fn at(addr: u32) -> Self {
        UserPtr {
            addr,
            pointee: PhantomData,
        }
    }

    /// The pointer, untyped.
    pub fn addr(self) -> UserAddr {
        UserAddr(self.addr)
    }

    pub fn is_null(self) -> bool {
        self.addr == 0
    }

    /// The value it points to; a fault when it cannot be read.
    pub fn read(self) -> Result<T, Fault> {
        let mut raw = [0u8; 8];
        let raw = &mut raw[..T::SIZE];
        self.addr().read(raw)?;
        Ok(T::decode(raw))
    }

    /// Store `value` where it points; a fault when it cannot be written.
    pub fn write(self, value: T) -> Result<(), Fault> {
        let mut raw = [0u8; 8];
        let raw = &mut raw[..T::SIZE];
        value.encode(raw);
        self.addr().write(raw)
    }

    /// Store `value` where it points, when it points anywhere (an optional out parameter).
    pub fn write_optional(self, value: T) -> Result<(), Fault> {
        if self.is_null() {
            Ok(())
        } else {
            self.write(value)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::{NtStatus, STATUS_ACCESS_VIOLATION};
    use crate::user::syscall::host::{install, Installed, UserMemory};

    /// Mapped user memory at [BASE, BASE + len): anything else faults.
    struct Pages {
        base: u32,
        bytes: std::vec::Vec<u8>,
    }

    impl UserMemory for Pages {
        fn read(&self, pointer: u32, bytes: &mut [u8]) -> Result<(), NtStatus> {
            let start = pointer
                .checked_sub(self.base)
                .ok_or(STATUS_ACCESS_VIOLATION)? as usize;
            let slice = self
                .bytes
                .get(start..start + bytes.len())
                .ok_or(STATUS_ACCESS_VIOLATION)?;
            bytes.copy_from_slice(slice);
            Ok(())
        }

        fn write(&mut self, pointer: u32, bytes: &[u8]) -> Result<(), NtStatus> {
            let start = pointer
                .checked_sub(self.base)
                .ok_or(STATUS_ACCESS_VIOLATION)? as usize;
            let slice = self
                .bytes
                .get_mut(start..start + bytes.len())
                .ok_or(STATUS_ACCESS_VIOLATION)?;
            slice.copy_from_slice(bytes);
            Ok(())
        }
    }

    const BASE: u32 = 0x0040_0000;

    /// A mapped page at BASE; the page after it faults.
    fn pages() -> (std::rc::Rc<core::cell::RefCell<Pages>>, Installed) {
        let memory = std::rc::Rc::new(core::cell::RefCell::new(Pages {
            base: BASE,
            bytes: std::vec![0xAA; 4096],
        }));
        let installed = install(memory.clone());
        (memory, installed)
    }

    #[test]
    fn plain_values_round_trip_through_typed_pointers() {
        let (_memory, _installed) = pages();
        let ptr = UserPtr::<u32>::at(BASE + 8);
        ptr.write(0x1234_5678).unwrap();
        assert_eq!(ptr.read(), Ok(0x1234_5678));
        assert_eq!(UserPtr::<u16>::at(BASE + 8).read(), Ok(0x5678));
        assert_eq!(UserPtr::<u32>::at(0).write_optional(1), Ok(()));
        assert_eq!(UserPtr::<u32>::at(0x10).read(), Err(Fault));
    }
}
