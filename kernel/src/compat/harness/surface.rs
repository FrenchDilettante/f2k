//! The export surface under test: the kernel's service handlers, run on the host against a memory
//! the scenario stages.
//!
//! Scenarios call exports the way the binaries do: by name, with dword arguments, reading the EAX
//! result. [`Fixture`] runs the registry's handler (`kernel32::SERVICES`) through a trap frame and
//! checks every call's argument count against the export's prototype ([`SIGNATURES`], from the
//! export spec) — the stdcall discipline the callers' pushes assume.
//!
//! The handlers move caller bytes through the user-copy primitives (`user::syscall::read_user` /
//! `write_user`), which on the host read and write the [`HostMemory`] the fixture installs for its
//! thread: a scenario stages its arguments there and reads the results back, and an unmapped
//! address fails as it does on the target.
//!
//! Only the handlers [`HOST_RUNNABLE`] lists run here: the rest of the registry's work lives in
//! kernel state the host does not build (the scheduler, the handle table, the volume, the live
//! address space and its heaps, the process exit), and the exports that are not the registry's
//! (the natives, user-mode bodies on the calling thread's TEB, and the unimplemented stubs) run in
//! the DLL. Calling one panics; the fixtures (tests/<fixture>/output.txt) pin those.

use std::cell::{RefCell, RefMut};
use std::rc::Rc;

use crate::compat::kernel32::SERVICES;
use crate::user::syscall::host::{self, UserMemory};
use crate::user::syscall::STATUS_ACCESS_VIOLATION;
use crate::user::TrapFrame;

/// One argument of a prototype.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Arg {
    /// A value: a handle, a count, flags, a code address.
    Value(&'static str),
    /// A pointer into caller memory.
    Pointer(&'static str),
}

/// An export's public prototype: its arguments, in push order reversed (the first is at the
/// lowest address).
pub struct Signature {
    pub export: &'static str,
    pub args: &'static [Arg],
}

use Arg::{Pointer as P, Value as V};

// The public prototypes, `SIGNATURES`: one per export, generated from the export spec
// (userland/kernel32/exports.toml) by the build script.
include!(concat!(env!("OUT_DIR"), "/kernel32_signatures.rs"));

const fn sig(export: &'static str, args: &'static [Arg]) -> Signature {
    Signature { export, args }
}

/// The public prototype of `export`.
pub fn signature(export: &str) -> &'static Signature {
    SIGNATURES
        .iter()
        .find(|signature| signature.export == export)
        .unwrap_or_else(|| panic!("no prototype for {export}"))
}

/// The registry's handlers the host runs: the ones whose work is the caller's memory and the
/// surface's constants (the kept scenarios' exports).
const HOST_RUNNABLE: [&str; 8] = [
    "SetFilePointer",
    "GetACP",
    "GetOEMCP",
    "GetCPInfo",
    "MultiByteToWideChar",
    "WideCharToMultiByte",
    "LCMapStringW",
    "GetStringTypeW",
];

fn registry_entry(export: &str) -> Option<(&'static str, u32, crate::user::syscall::ServiceFn)> {
    SERVICES.iter().find(|(name, ..)| *name == export).copied()
}

/// Run the registry's handler for `export`.
fn registry(export: &str, args: &[u32]) -> u32 {
    let (_, arg_bytes, service) = registry_entry(export).expect("a registry export");
    let dwords = arg_bytes as usize / 4;
    assert!(
        args.len() <= dwords,
        "{export}: {} arguments, the registry's block holds {dwords}",
        args.len()
    );
    let mut block = [0u32; crate::user::syscall::MAX_ARG_BYTES / 4];
    block[..args.len()].copy_from_slice(args);
    let mut frame = TrapFrame {
        edi: 0,
        esi: 0,
        ebp: 0,
        esp: 0,
        ebx: 0,
        edx: 0,
        ecx: 0,
        eax: 0xDEAD_BEEF,
        vector: 0,
        error_code: 0,
        eip: 0,
        cs: 0,
        eflags: 0,
        user_esp: 0,
        user_ss: 0,
    };
    service(&mut frame, &block[..dwords]);
    frame.eax
}

/// A scenario's user memory: mapped regions, each its own bytes. An access must lie inside one
/// region; anything else fails with STATUS_ACCESS_VIOLATION, as an unmapped page does.
#[derive(Default)]
pub struct HostMemory {
    regions: Vec<(u32, Vec<u8>)>,
}

impl HostMemory {
    /// Write `bytes` at `pointer` (which must be mapped).
    pub fn write(&mut self, pointer: u32, bytes: &[u8]) -> Result<(), u32> {
        UserMemory::write(self, pointer, bytes)
    }

    /// Map `size` zeroed bytes at `base`.
    pub fn map(&mut self, base: u32, size: u32) {
        assert!(
            !self.regions.iter().any(|(start, bytes)| {
                (base as u64) < *start as u64 + bytes.len() as u64
                    && (*start as u64) < base as u64 + size as u64
            }),
            "{base:#x}+{size:#x} overlaps a mapped region"
        );
        self.regions.push((base, vec![0; size as usize]));
    }

    /// The region holding [pointer, pointer + length) and the offset into it.
    fn locate(&self, pointer: u32, length: usize) -> Option<(usize, usize)> {
        self.regions
            .iter()
            .position(|(start, bytes)| {
                pointer >= *start
                    && pointer as u64 + length as u64 <= *start as u64 + bytes.len() as u64
            })
            .map(|index| (index, (pointer - self.regions[index].0) as usize))
    }

    /// The `length` bytes at `pointer` (which must be mapped).
    pub fn bytes(&self, pointer: u32, length: u32) -> Vec<u8> {
        let mut bytes = vec![0; length as usize];
        self.read(pointer, &mut bytes)
            .unwrap_or_else(|_| panic!("{pointer:#x}+{length:#x} is not mapped"));
        bytes
    }

    /// The little-endian dword at `pointer`.
    pub fn u32_at(&self, pointer: u32) -> u32 {
        u32::from_le_bytes(self.bytes(pointer, 4).try_into().unwrap())
    }

    /// The NUL-terminated string at `pointer`, without its terminator.
    pub fn c_string(&self, pointer: u32) -> Vec<u8> {
        let (index, offset) = self
            .locate(pointer, 1)
            .unwrap_or_else(|| panic!("{pointer:#x} is not mapped"));
        let bytes = &self.regions[index].1[offset..];
        let end = bytes
            .iter()
            .position(|&b| b == 0)
            .expect("the string ends inside its region");
        bytes[..end].to_vec()
    }
}

impl UserMemory for HostMemory {
    fn read(&self, pointer: u32, bytes: &mut [u8]) -> Result<(), u32> {
        let (index, offset) = self
            .locate(pointer, bytes.len())
            .ok_or(STATUS_ACCESS_VIOLATION)?;
        bytes.copy_from_slice(&self.regions[index].1[offset..offset + bytes.len()]);
        Ok(())
    }

    fn write(&mut self, pointer: u32, bytes: &[u8]) -> Result<(), u32> {
        let (index, offset) = self
            .locate(pointer, bytes.len())
            .ok_or(STATUS_ACCESS_VIOLATION)?;
        self.regions[index].1[offset..offset + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }
}

/// Scenario memory: where fixtures stage buffers and strings.
pub const SCRATCH_BASE: u32 = 0x0400_0000;
const SCRATCH_SIZE: u32 = 0x0004_0000;

/// An address nothing is ever mapped at.
pub const UNMAPPED: u32 = 0x0600_0000;

/// A scenario's world: its user memory, installed for the thread while the fixture lives.
pub struct Fixture {
    memory: Rc<RefCell<HostMemory>>,
    _installed: host::Installed,
    scratch_next: u32,
}

impl Default for Fixture {
    fn default() -> Fixture {
        Fixture::new()
    }
}

impl Fixture {
    /// A fresh user memory with its scratch region mapped.
    pub fn new() -> Fixture {
        let memory = Rc::new(RefCell::new(HostMemory::default()));
        memory.borrow_mut().map(SCRATCH_BASE, SCRATCH_SIZE);
        let installed = host::install(memory.clone());
        Fixture {
            memory,
            _installed: installed,
            scratch_next: SCRATCH_BASE,
        }
    }

    /// Call `export`; the argument count must be its prototype's.
    pub fn call(&mut self, export: &str, args: &[u32]) -> u32 {
        let expected = signature(export).args.len();
        assert_eq!(args.len(), expected, "{export} takes {expected} arguments");
        if registry_entry(export).is_none() {
            panic!("{export} is target-only on the host: it is not a kernel-served export");
        }
        if !HOST_RUNNABLE.contains(&export) {
            panic!("{export} is target-only on the host: its handler runs on live kernel state");
        }
        registry(export, args)
    }

    /// The scenario's user memory.
    pub fn memory(&mut self) -> RefMut<'_, HostMemory> {
        self.memory.borrow_mut()
    }

    /// `length` zeroed scratch bytes, 16-byte aligned; their address.
    pub fn buffer(&mut self, length: u32) -> u32 {
        let address = self.scratch_next;
        self.scratch_next = (address + length.max(1)).next_multiple_of(16);
        assert!(
            self.scratch_next <= SCRATCH_BASE + SCRATCH_SIZE,
            "scratch exhausted"
        );
        address
    }

    /// `bytes` staged in scratch memory; their address.
    pub fn stage(&mut self, bytes: &[u8]) -> u32 {
        let address = self.buffer(bytes.len() as u32);
        self.memory().write(address, bytes).unwrap();
        address
    }

    /// `text` staged NUL-terminated; its address.
    pub fn c_string(&mut self, text: &[u8]) -> u32 {
        let mut bytes = text.to_vec();
        bytes.push(0);
        self.stage(&bytes)
    }

    /// `units` staged as UTF-16LE (no terminator added); their address.
    pub fn wide(&mut self, units: &[u16]) -> u32 {
        let bytes: Vec<u8> = units.iter().flat_map(|unit| unit.to_le_bytes()).collect();
        self.stage(&bytes)
    }

    /// The `count` UTF-16 units at `address`.
    pub fn wide_at(&mut self, address: u32, count: u32) -> Vec<u16> {
        self.memory()
            .bytes(address, 2 * count)
            .chunks(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The prototypes cover the registry, once each, and every host-runnable export is the
    /// registry's.
    #[test]
    fn prototypes_cover_the_registry() {
        for (name, ..) in SERVICES.iter().filter(|(name, ..)| *name != "RtlUnwind") {
            assert_eq!(
                SIGNATURES.iter().filter(|s| s.export == *name).count(),
                1,
                "{name}"
            );
        }
        for name in HOST_RUNNABLE {
            assert!(registry_entry(name).is_some(), "{name}");
        }
    }

    /// The handlers' copies reach the fixture's memory: a write lands, a read comes back, and an
    /// unmapped address fails as on the target.
    #[test]
    fn the_copies_reach_the_fixtures_memory() {
        use crate::user::syscall::{read_user, write_user};
        let mut fixture = Fixture::new();
        let buffer = fixture.buffer(4);
        write_user(buffer, b"F2K!").unwrap();
        assert_eq!(fixture.memory().bytes(buffer, 4), b"F2K!");
        let mut back = [0; 4];
        read_user(buffer, &mut back).unwrap();
        assert_eq!(&back, b"F2K!");
        assert_eq!(read_user(UNMAPPED, &mut back), Err(STATUS_ACCESS_VIOLATION));
        assert_eq!(
            read_user(SCRATCH_BASE + SCRATCH_SIZE - 2, &mut back),
            Err(STATUS_ACCESS_VIOLATION)
        );
        drop(fixture);
        assert_eq!(
            read_user(buffer, &mut back),
            Err(STATUS_ACCESS_VIOLATION),
            "uninstalled with the fixture"
        );
    }

    /// A target-only export refuses loudly.
    #[test]
    #[should_panic(expected = "target-only on the host")]
    fn target_only_exports_refuse_loudly() {
        Fixture::new().call("GetTickCount", &[]);
    }

    /// The fixture checks the argument count against the prototype.
    #[test]
    #[should_panic(expected = "takes 1 arguments")]
    fn the_fixture_checks_argument_counts() {
        Fixture::new().call("GetStdHandle", &[]);
    }
}
