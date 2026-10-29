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

use rtl::pod::Pod;

use crate::user::syscall::{probe_user_range, read_user, write_user};

/// The process a service is serving: the caller's, shared with its other threads (the one place
/// the services take it from).
#[cfg(target_arch = "x86")]
pub fn calling_process() -> &'static crate::process::Process {
    crate::process::current()
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

    /// Check that the `length` bytes from it are the caller's to write, before the call acts: a
    /// fault for a range reaching past the caller's half of the address space (or wrapping), as
    /// the platform's probes refuse it. The memory itself is not touched (a later copy may still
    /// fault on a page that is not mapped); a null address passes.
    pub fn probe(self, length: u32) -> Result<(), Fault> {
        probe_user_range(self.0, length).map_err(|_| Fault)
    }

    /// Read `units.len()` UTF-16 units from it (a counted string's buffer); a fault when they
    /// cannot be read.
    pub fn read_units(self, units: &mut [u16]) -> Result<(), Fault> {
        /// The units copied at a time, through a buffer on the stack.
        const CHUNK: usize = 256;
        let mut at = self;
        let mut buffer = [0u16; CHUNK];
        for chunk in units.chunks_mut(CHUNK) {
            let bytes = &mut buffer.as_bytes_mut()[..2 * chunk.len()];
            at.read(bytes)?;
            at = at.offset(bytes.len() as u32);
            chunk.copy_from_slice(&buffer[..chunk.len()]);
        }
        Ok(())
    }

    /// The pointer, typed: a `T` lives at it.
    pub fn cast<T: Pod>(self) -> UserPtr<T> {
        UserPtr::at(self.0)
    }
}

/// A pointer to one `T` in the caller's memory: an integer, or an NT structure laid out as the
/// caller's (`rtl::nt`'s 32-bit forms), read and written whole.
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

impl<T: Pod> UserPtr<T> {
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
        let mut value = T::zeroed();
        self.addr().read(value.as_bytes_mut())?;
        Ok(value)
    }

    /// Store `value` where it points; a fault when it cannot be written.
    pub fn write(self, value: T) -> Result<(), Fault> {
        self.addr().write(value.as_bytes())
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
    use rtl::nt::ClientId;

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

    #[test]
    fn structures_round_trip_whole() {
        let (memory, _installed) = pages();
        let ptr = UserPtr::<ClientId<u32>>::at(BASE + 0x10);
        let id = ClientId {
            unique_process: 0x2C,
            unique_thread: 0x30,
        };
        ptr.write(id).unwrap();
        assert_eq!(
            &memory.borrow().bytes[0x10..0x18],
            &[0x2C, 0, 0, 0, 0x30, 0, 0, 0]
        );
        assert_eq!(ptr.read(), Ok(id));
        assert_eq!(UserAddr(BASE + 0x10).cast::<ClientId<u32>>(), ptr);
        assert_eq!(UserPtr::<ClientId<u32>>::at(BASE + 4092).read(), Err(Fault));
    }

    #[test]
    fn units_read_in_any_number() {
        let (memory, _installed) = pages();
        for (i, byte) in memory.borrow_mut().bytes[..1200].iter_mut().enumerate() {
            *byte = ((i / 2) as u8).wrapping_add((i % 2) as u8 * 0x10);
        }
        let mut units = [0u16; 600];
        UserAddr(BASE).read_units(&mut units).unwrap();
        assert!(units
            .iter()
            .enumerate()
            .all(|(i, &unit)| unit == u16::from_le_bytes([i as u8, (i as u8).wrapping_add(0x10)])));
        assert_eq!(UserAddr(BASE).read_units(&mut []), Ok(()));
        assert_eq!(UserAddr(BASE + 4090).read_units(&mut [0; 4]), Err(Fault));
    }

    #[test]
    fn probes_refuse_the_system_half() {
        assert_eq!(UserAddr(BASE).probe(4096), Ok(()));
        assert_eq!(UserAddr(0).probe(8), Ok(()));
        assert_eq!(UserAddr(0xFFFF_FFF0).probe(0x20), Err(Fault));
        assert_eq!(
            UserAddr(crate::user::syscall::USER_PROBE_LIMIT).probe(1),
            Err(Fault)
        );
    }
}
