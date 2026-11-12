//! The hal.dll-named entry points over the internal [`Hal`] interface: the export surface a
//! Windows 2000 driver imports from hal.dll, catalogued in `kernel/hal_exports.toml`, where
//! each record is marked implemented (`native`) or a stub whose reason names the slice that
//! lands it (the L6 DMA/MMIO slice, the APIC/MP slice).
//!
//! F2K compiles the layer into the kernel image, so on target each record's body is the
//! `f2k_export_<name>` symbol defined in [`symbols`], stdcall, kept in the link by the generated
//! `HAL_EXPORTS` table (the build script emits it from the spec into `.rodata.hal_exports`) —
//! where the `.sys` loader resolves hal.dll imports by the spec's names. Off-target the bodies
//! are the plain functions here, generic over the port-I/O seam ([`Io`]) or the [`Hal`] trait,
//! so the host tests run them against simulated registers and a fake platform:
//!
//! - **Port access** ([`read_port_uchar`] and the word/dword/buffer forms) and **memory-mapped
//!   register access** ([`read_register_uchar`] and its forms, volatile reads/writes): the
//!   driver-facing primitives.
//! - **Interrupts:** [`get_interrupt_vector`] (the vector query over the routing table in
//!   [`crate::dev::routing`]) and the enable/disable over the [`Hal`] trait.
//! - **Clock/RTC:** [`query_real_time_clock`], [`set_time_increment`].
//! - **Bus data:** HalGetBusData/HalSetBusData over the PCI config seam ([`crate::hw::pci`]).
//! - The stubs: common buffers, `MmMapIoSpace`, `HalRequestIpi`, `HalStartNextProcessor` — each
//!   fails the way the export fails and names its slice in a comment.

// The symbol wrappers call these on target; the host tests call them directly.
#![cfg_attr(not(test), allow(dead_code))]

use core::ffi::c_void;

use super::{Hal, Io, INPUT_FREQUENCY_HZ};
use crate::dev::routing;
use crate::hw::pci::{self, PirqRoutes};
use crate::interrupt::irql::Irql;

// --- The public contract's types and constants -------------------------------------------------

/// The documented `INTERFACE_TYPE` values the vector query takes.
pub const INTERFACE_INTERNAL: i32 = 0;
pub const INTERFACE_ISA: i32 = 1;
pub const INTERFACE_PCI_BUS: i32 = 5;

/// The documented `KINTERRUPT_MODE` values.
pub const LEVEL_SENSITIVE: i32 = 0;
pub const LATCHED: i32 = 1;

/// The documented `TIME_FIELDS`: eight 16-bit fields.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
#[repr(C)]
pub struct TimeFields {
    pub year: u16,
    pub month: u16,
    pub day: u16,
    pub hour: u16,
    pub minute: u16,
    pub second: u16,
    pub milliseconds: u16,
    pub weekday: u16,
}

// --- Port access --------------------------------------------------------------------------------

/// READ_PORT_UCHAR: one byte from a port.
pub fn read_port_uchar<IoT: Io>(io: &mut IoT, port: u16) -> u8 {
    io.read(port)
}

/// READ_PORT_USHORT: one word from a port, in a single access.
pub fn read_port_ushort<IoT: Io>(io: &mut IoT, port: u16) -> u16 {
    io.read_word(port)
}

/// READ_PORT_ULONG: one dword from a port, in a single access.
pub fn read_port_ulong<IoT: Io>(io: &mut IoT, port: u16) -> u32 {
    io.read_dword(port)
}

/// WRITE_PORT_UCHAR: one byte to a port.
pub fn write_port_uchar<IoT: Io>(io: &mut IoT, port: u16, value: u8) {
    io.out(port, value)
}

/// WRITE_PORT_USHORT: one word to a port, in a single access.
pub fn write_port_ushort<IoT: Io>(io: &mut IoT, port: u16, value: u16) {
    io.out_word(port, value)
}

/// WRITE_PORT_ULONG: one dword to a port, in a single access.
pub fn write_port_ulong<IoT: Io>(io: &mut IoT, port: u16, value: u32) {
    io.out_dword(port, value)
}

/// READ_PORT_BUFFER_UCHAR: `buffer.len()` bytes from a port.
pub fn read_port_buffer_uchar<IoT: Io>(io: &mut IoT, port: u16, buffer: &mut [u8]) {
    for byte in buffer.iter_mut() {
        *byte = io.read(port);
    }
}

/// READ_PORT_BUFFER_USHORT: `buffer.len()` words from a port.
pub fn read_port_buffer_ushort<IoT: Io>(io: &mut IoT, port: u16, buffer: &mut [u16]) {
    for word in buffer.iter_mut() {
        *word = io.read_word(port);
    }
}

/// READ_PORT_BUFFER_ULONG: `buffer.len()` dwords from a port.
pub fn read_port_buffer_ulong<IoT: Io>(io: &mut IoT, port: u16, buffer: &mut [u32]) {
    for dword in buffer.iter_mut() {
        *dword = io.read_dword(port);
    }
}

/// WRITE_PORT_BUFFER_UCHAR: `buffer` bytes to a port.
pub fn write_port_buffer_uchar<IoT: Io>(io: &mut IoT, port: u16, buffer: &[u8]) {
    for &byte in buffer {
        io.out(port, byte);
    }
}

/// WRITE_PORT_BUFFER_USHORT: `buffer` words to a port.
pub fn write_port_buffer_ushort<IoT: Io>(io: &mut IoT, port: u16, buffer: &[u16]) {
    for &word in buffer {
        io.out_word(port, word);
    }
}

/// WRITE_PORT_BUFFER_ULONG: `buffer` dwords to a port.
pub fn write_port_buffer_ulong<IoT: Io>(io: &mut IoT, port: u16, buffer: &[u32]) {
    for &dword in buffer {
        io.out_dword(port, dword);
    }
}

// --- Memory-mapped register access ---------------------------------------------------------------

/// READ_REGISTER_UCHAR: one byte from a memory-mapped register (a volatile read).
pub fn read_register_uchar(register: *const u8) -> u8 {
    // SAFETY: the caller names a mapped device register; a volatile read is the whole access.
    unsafe { core::ptr::read_volatile(register) }
}

/// READ_REGISTER_USHORT.
pub fn read_register_ushort(register: *const u16) -> u16 {
    // SAFETY: as above.
    unsafe { core::ptr::read_volatile(register) }
}

/// READ_REGISTER_ULONG.
pub fn read_register_ulong(register: *const u32) -> u32 {
    // SAFETY: as above.
    unsafe { core::ptr::read_volatile(register) }
}

/// WRITE_REGISTER_UCHAR: one byte to a memory-mapped register (a volatile write).
pub fn write_register_uchar(register: *mut u8, value: u8) {
    // SAFETY: as above.
    unsafe { core::ptr::write_volatile(register, value) }
}

/// WRITE_REGISTER_USHORT.
pub fn write_register_ushort(register: *mut u16, value: u16) {
    // SAFETY: as above.
    unsafe { core::ptr::write_volatile(register, value) }
}

/// WRITE_REGISTER_ULONG.
pub fn write_register_ulong(register: *mut u32, value: u32) {
    // SAFETY: as above.
    unsafe { core::ptr::write_volatile(register, value) }
}

/// READ_REGISTER_BUFFER_UCHAR: `buffer` bytes from consecutive registers.
pub fn read_register_buffer_uchar(register: *const u8, buffer: &mut [u8]) {
    for (index, byte) in buffer.iter_mut().enumerate() {
        // SAFETY: the caller names the range's base; each read is volatile.
        *byte = unsafe { core::ptr::read_volatile(register.add(index)) };
    }
}

/// READ_REGISTER_BUFFER_USHORT.
pub fn read_register_buffer_ushort(register: *const u16, buffer: &mut [u16]) {
    for (index, word) in buffer.iter_mut().enumerate() {
        // SAFETY: as above.
        *word = unsafe { core::ptr::read_volatile(register.add(index)) };
    }
}

/// READ_REGISTER_BUFFER_ULONG.
pub fn read_register_buffer_ulong(register: *const u32, buffer: &mut [u32]) {
    for (index, dword) in buffer.iter_mut().enumerate() {
        // SAFETY: as above.
        *dword = unsafe { core::ptr::read_volatile(register.add(index)) };
    }
}

/// WRITE_REGISTER_BUFFER_UCHAR: `buffer` bytes to consecutive registers.
pub fn write_register_buffer_uchar(register: *mut u8, buffer: &[u8]) {
    for (index, &byte) in buffer.iter().enumerate() {
        // SAFETY: as above.
        unsafe { core::ptr::write_volatile(register.add(index), byte) };
    }
}

/// WRITE_REGISTER_BUFFER_USHORT.
pub fn write_register_buffer_ushort(register: *mut u16, buffer: &[u16]) {
    for (index, &word) in buffer.iter().enumerate() {
        // SAFETY: as above.
        unsafe { core::ptr::write_volatile(register.add(index), word) };
    }
}

/// WRITE_REGISTER_BUFFER_ULONG.
pub fn write_register_buffer_ulong(register: *mut u32, buffer: &[u32]) {
    for (index, &dword) in buffer.iter().enumerate() {
        // SAFETY: as above.
        unsafe { core::ptr::write_volatile(register.add(index), dword) };
    }
}

// --- Interrupts
// -----------------------------------------------------------------------------------

/// HalGetInterruptVector's core, over the routing table: for the ISA and the other legacy
/// interface types the bus interrupt level is the ISA line itself; for PCIBus the level is the
/// interrupt pin and the vector the slot (device << 3 | function), routed through the PIRQ
/// table. Returns the system vector with the line's IRQL and affinity; a translation that fails
/// (a line outside the band, an unrouted pin) returns vector 0 with affinity 0.
pub fn get_interrupt_vector(
    routes: Option<&PirqRoutes>,
    interface_type: i32,
    bus: u32,
    level: u32,
    vector: u32,
) -> (u8, Irql, u32) {
    let answer = if interface_type == INTERFACE_PCI_BUS {
        let (dev, func) = pci::slot_parts(vector);
        routing::route_interrupt(routes, bus as u8, dev, func, level as u8).map(|interrupt| {
            (
                interrupt.vector,
                routing::line_irql(interrupt.isa_line),
                routing::ALL_PROCESSORS,
            )
        })
    } else {
        routing::line_vector(level as u8).map(|line| (line.vector, line.irql, line.affinity))
    };
    match answer {
        Some((vector, irql, affinity)) => (vector, irql, affinity),
        None => (0, Irql(0), 0),
    }
}

/// HalEnableSystemInterrupt's core: unmask the vector's line; false when the platform cannot.
pub fn enable_system_interrupt<H: Hal>(hal: &H, vector: u8) -> bool {
    hal.enable_system_interrupt(vector)
}

/// HalDisableSystemInterrupt's core: mask the vector's line.
pub fn disable_system_interrupt<H: Hal>(hal: &H, vector: u8) {
    hal.disable_system_interrupt(vector)
}

// --- Interval clock and real-time clock
// -------------------------------------------------------------

/// HalQueryRealTimeClock's core: the clock's date and time as `TIME_FIELDS`; `None` when the
/// clock reads no valid date.
pub fn query_real_time_clock<H: Hal>(hal: &H) -> Option<TimeFields> {
    hal.query_real_time_clock().map(|time| TimeFields {
        year: time.year,
        month: time.month as u16,
        day: time.day as u16,
        hour: time.hour as u16,
        minute: time.minute as u16,
        second: time.second as u16,
        milliseconds: 0,
        weekday: 0,
    })
}

/// HalSetTimeIncrement's core: program the interval timer at the period nearest `desired`
/// (100 ns units) and return the increment actually set — the programmed period in 100 ns
/// units.
pub fn set_time_increment<H: Hal>(hal: &H, desired: u32) -> u32 {
    hal.set_time_increment(desired);
    let clocks = hal.interval_timer_period() as u64;
    ((clocks * 10_000_000 + INPUT_FREQUENCY_HZ as u64 / 2) / INPUT_FREQUENCY_HZ as u64) as u32
}

/// HalSetRealTimeClock's stub: false. The CMOS write path lands with the clock slice that
/// needs it (hw::rtc today only reads).
pub fn set_real_time_clock(_time_fields: &TimeFields) -> bool {
    false
}

// --- DMA, MMIO mapping, multi-processor: the stubs
// ---------------------------------------------------

/// HalAllocateCommonBuffer's stub: null, with a zero logical address. The L6 DMA/MMIO slice
/// (mem/dma.rs) lands it: a common buffer over the pool, translated to its bus address.
pub fn allocate_common_buffer(
    _adapter: *mut c_void,
    _length: u32,
    logical_address: *mut u64,
    _cache_enabled: bool,
) -> *mut c_void {
    if !logical_address.is_null() {
        // SAFETY: the caller names the out-parameter.
        unsafe { *logical_address = 0 };
    }
    core::ptr::null_mut()
}

/// HalFreeCommonBuffer's stub: nothing. The L6 DMA/MMIO slice (mem/dma.rs) frees what it
/// allocated.
pub fn free_common_buffer(
    _adapter: *mut c_void,
    _length: u32,
    _logical_address: u64,
    _cache_enabled: bool,
) {
}

/// HalGetDmaAlignmentRequirement: 1 on x86 — no alignment requirement past the natural one.
pub fn get_dma_alignment_requirement() -> u32 {
    1
}

/// MmMapIoSpace's stub: null. The L6 DMA/MMIO slice (mem/dma.rs) lands it: mapping a device's
/// MMIO range into the reserved kernel region.
pub fn mm_map_io_space(
    _physical_address: u64,
    _number_of_bytes: u32,
    _cache_enable: bool,
) -> *mut c_void {
    core::ptr::null_mut()
}

/// HalRequestIpi's stub: nothing. The APIC slice lands it: the IPI through the local APIC's
/// interrupt command register, to the processors in `mask`.
pub fn request_ipi(_mask: u32) {}

/// HalStartNextProcessor's stub: false. The APIC/MP slice lands it: starting the next processor
/// through its local APIC.
pub fn start_next_processor(_loader_block: *mut c_void, _processor_state: *mut c_void) -> bool {
    false
}

// --- The target's bodies
// ---------------------------------------------------------------------------

/// The hal.dll-named entry points as symbols: each spec record's `f2k_export_<name>`, stdcall,
/// over the real port space and the kernel's platform. The generated `HAL_EXPORTS` table below
/// keeps every one of them in the link.
#[cfg(target_arch = "x86")]
mod symbols {
    use super::*;
    use crate::hal::{Ports, PLATFORM};

    /// One entry point: the symbol the spec's record names, calling the body above.
    macro_rules! entry {
        ($name:ident($($arg:ident: $ty:ty),* $(,)?) -> $ret:ty = $body:expr) => {
            #[no_mangle]
            pub extern "stdcall" fn $name($($arg: $ty),*) -> $ret {
                $body
            }
        };
    }

    /// A caller-supplied buffer as a slice, empty when the pointer is null.
    fn buffer<T>(pointer: *mut T, count: u32) -> &'static mut [T] {
        if pointer.is_null() {
            &mut []
        } else {
            // SAFETY: the caller names `count` elements of its buffer, which outlives the call.
            unsafe { core::slice::from_raw_parts_mut(pointer, count as usize) }
        }
    }

    /// A caller-supplied const buffer as a slice.
    fn const_buffer<T>(pointer: *const T, count: u32) -> &'static [T] {
        if pointer.is_null() {
            &[]
        } else {
            // SAFETY: as above.
            unsafe { core::slice::from_raw_parts(pointer, count as usize) }
        }
    }

    entry!(f2k_export_READ_PORT_UCHAR(port: *const u8) -> u8 =
        read_port_uchar(&mut Ports, port as u16));
    entry!(f2k_export_READ_PORT_USHORT(port: *const u16) -> u16 =
        read_port_ushort(&mut Ports, port as u16));
    entry!(f2k_export_READ_PORT_ULONG(port: *const u32) -> u32 =
        read_port_ulong(&mut Ports, port as u16));
    entry!(f2k_export_WRITE_PORT_UCHAR(port: *mut u8, value: u8) -> () =
        write_port_uchar(&mut Ports, port as u16, value));
    entry!(f2k_export_WRITE_PORT_USHORT(port: *mut u16, value: u16) -> () =
        write_port_ushort(&mut Ports, port as u16, value));
    entry!(f2k_export_WRITE_PORT_ULONG(port: *mut u32, value: u32) -> () =
        write_port_ulong(&mut Ports, port as u16, value));
    entry!(f2k_export_READ_PORT_BUFFER_UCHAR(port: *const u8, buf: *mut u8, count: u32) -> () =
        read_port_buffer_uchar(&mut Ports, port as u16, buffer(buf, count)));
    entry!(f2k_export_READ_PORT_BUFFER_USHORT(port: *const u16, buf: *mut u16, count: u32) -> () =
        read_port_buffer_ushort(&mut Ports, port as u16, buffer(buf, count)));
    entry!(f2k_export_READ_PORT_BUFFER_ULONG(port: *const u32, buf: *mut u32, count: u32) -> () =
        read_port_buffer_ulong(&mut Ports, port as u16, buffer(buf, count)));
    entry!(f2k_export_WRITE_PORT_BUFFER_UCHAR(port: *mut u8, buf: *const u8, count: u32) -> () =
        write_port_buffer_uchar(&mut Ports, port as u16, const_buffer(buf, count)));
    entry!(f2k_export_WRITE_PORT_BUFFER_USHORT(port: *mut u16, buf: *const u16, count: u32) -> () =
        write_port_buffer_ushort(&mut Ports, port as u16, const_buffer(buf, count)));
    entry!(f2k_export_WRITE_PORT_BUFFER_ULONG(port: *mut u32, buf: *const u32, count: u32) -> () =
        write_port_buffer_ulong(&mut Ports, port as u16, const_buffer(buf, count)));

    entry!(f2k_export_READ_REGISTER_UCHAR(register: *const u8) -> u8 =
        read_register_uchar(register));
    entry!(f2k_export_READ_REGISTER_USHORT(register: *const u16) -> u16 =
        read_register_ushort(register));
    entry!(f2k_export_READ_REGISTER_ULONG(register: *const u32) -> u32 =
        read_register_ulong(register));
    entry!(f2k_export_WRITE_REGISTER_UCHAR(register: *mut u8, value: u8) -> () =
        write_register_uchar(register, value));
    entry!(f2k_export_WRITE_REGISTER_USHORT(register: *mut u16, value: u16) -> () =
        write_register_ushort(register, value));
    entry!(f2k_export_WRITE_REGISTER_ULONG(register: *mut u32, value: u32) -> () =
        write_register_ulong(register, value));
    entry!(f2k_export_READ_REGISTER_BUFFER_UCHAR(register: *const u8, buf: *mut u8, count: u32) -> () =
        read_register_buffer_uchar(register, buffer(buf, count)));
    entry!(f2k_export_READ_REGISTER_BUFFER_USHORT(register: *const u16, buf: *mut u16, count: u32) -> () =
        read_register_buffer_ushort(register, buffer(buf, count)));
    entry!(f2k_export_READ_REGISTER_BUFFER_ULONG(register: *const u32, buf: *mut u32, count: u32) -> () =
        read_register_buffer_ulong(register, buffer(buf, count)));
    entry!(f2k_export_WRITE_REGISTER_BUFFER_UCHAR(register: *mut u8, buf: *const u8, count: u32) -> () =
        write_register_buffer_uchar(register, const_buffer(buf, count)));
    entry!(f2k_export_WRITE_REGISTER_BUFFER_USHORT(register: *mut u16, buf: *const u16, count: u32) -> () =
        write_register_buffer_ushort(register, const_buffer(buf, count)));
    entry!(f2k_export_WRITE_REGISTER_BUFFER_ULONG(register: *mut u32, buf: *const u32, count: u32) -> () =
        write_register_buffer_ulong(register, const_buffer(buf, count)));

    entry!(f2k_export_HalGetInterruptVector(
        interface_type: i32, bus: u32, level: u32, vector: u32,
        irql: *mut u8, affinity: *mut u32,
    ) -> u32 = {
        let (vector, line_irql, affinity_out) =
            get_interrupt_vector(pci::routes(), interface_type, bus, level, vector);
        if !irql.is_null() {
            // SAFETY: the caller names the out-parameter.
            unsafe { *irql = line_irql.0 };
        }
        if !affinity.is_null() {
            // SAFETY: as above.
            unsafe { *affinity = affinity_out };
        }
        vector as u32
    });
    // The level and the trigger mode are the kernel's to honor at connect; the export enables
    // the line.
    entry!(f2k_export_HalEnableSystemInterrupt(vector: u32, _irql: u8, _mode: i32) -> bool =
        enable_system_interrupt(&PLATFORM, vector as u8));
    entry!(f2k_export_HalDisableSystemInterrupt(vector: u32, irql: *mut u8) -> () = {
        if !irql.is_null() {
            // SAFETY: the caller names the out-parameter; it takes the level the processor
            // stood at, as the contract's old-IRQL out does.
            unsafe { *irql = crate::pcr::pcr().current().0 };
        }
        disable_system_interrupt(&PLATFORM, vector as u8);
    });

    entry!(f2k_export_HalQueryRealTimeClock(time_fields: *mut TimeFields) -> bool = {
        match query_real_time_clock(&PLATFORM) {
            Some(fields) => {
                if !time_fields.is_null() {
                    // SAFETY: the caller names the out-parameter.
                    unsafe { *time_fields = fields };
                }
                true
            }
            None => false,
        }
    });
    entry!(f2k_export_HalSetRealTimeClock(time_fields: *const TimeFields) -> bool = {
        if time_fields.is_null() {
            return false;
        }
        // SAFETY: the caller names its fields.
        set_real_time_clock(unsafe { &*time_fields })
    });
    entry!(f2k_export_HalSetTimeIncrement(desired_increment: u32) -> u32 =
        set_time_increment(&PLATFORM, desired_increment));

    entry!(f2k_export_HalAllocateCommonBuffer(
        adapter: *mut c_void, length: u32, logical_address: *mut u64, cache_enabled: bool,
    ) -> *mut c_void = allocate_common_buffer(adapter, length, logical_address, cache_enabled));
    entry!(f2k_export_HalFreeCommonBuffer(
        adapter: *mut c_void, length: u32, logical_address: u64, cache_enabled: bool,
    ) -> () = free_common_buffer(adapter, length, logical_address, cache_enabled));
    entry!(f2k_export_HalGetDmaAlignmentRequirement() -> u32 = get_dma_alignment_requirement());

    entry!(f2k_export_HalGetBusData(
        bus_data_type: i32, bus: u32, slot: u32, buf: *mut u8, length: u32,
    ) -> u32 = {
        let mut cfg = pci::PortsConfig::new(Ports);
        pci::get_bus_data(&mut cfg, pci::devices(), bus_data_type, bus, slot, buffer(buf, length))
    });
    entry!(f2k_export_HalSetBusData(
        bus_data_type: i32, bus: u32, slot: u32, buf: *const u8, length: u32,
    ) -> u32 = {
        let mut cfg = pci::PortsConfig::new(Ports);
        pci::set_bus_data(&mut cfg, pci::devices(), bus_data_type, bus, slot, const_buffer(buf, length))
    });
    entry!(f2k_export_HalGetBusDataByOffset(
        bus_data_type: i32, bus: u32, slot: u32, buf: *mut u8, offset: u32, length: u32,
    ) -> u32 = {
        let mut cfg = pci::PortsConfig::new(Ports);
        pci::get_bus_data_by_offset(&mut cfg, pci::devices(), bus_data_type, bus, slot, buffer(buf, length), offset)
    });
    entry!(f2k_export_HalSetBusDataByOffset(
        bus_data_type: i32, bus: u32, slot: u32, buf: *const u8, offset: u32, length: u32,
    ) -> u32 = {
        let mut cfg = pci::PortsConfig::new(Ports);
        pci::set_bus_data_by_offset(&mut cfg, pci::devices(), bus_data_type, bus, slot, const_buffer(buf, length), offset)
    });

    entry!(f2k_export_MmMapIoSpace(
        physical_address: u64, number_of_bytes: u32, cache_enable: bool,
    ) -> *mut c_void = mm_map_io_space(physical_address, number_of_bytes, cache_enable));

    entry!(f2k_export_HalRequestIpi(mask: u32) -> () = request_ipi(mask));
    entry!(f2k_export_HalStartNextProcessor(
        loader_block: *mut c_void, processor_state: *mut c_void,
    ) -> bool = start_next_processor(loader_block, processor_state));
}

// The generated table keeping every spec body in the link (kernel/hal_exports.toml →
// OUT_DIR/hal_exports.rs), on target. `Kept` comes from the kernel's own exports module.
#[cfg(target_arch = "x86")]
use crate::exports::Kept;

#[cfg(target_arch = "x86")]
include!(concat!(env!("OUT_DIR"), "/hal_exports.rs"));

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::vec::Vec;

    use super::*;
    use crate::hal::CivilTime;
    use crate::interrupt::irql::Irql;

    /// A simulated port space: each port is a queue — a write pushes a byte, a read pops one
    /// (the device end of a data port), and the word/dword accesses span consecutive bytes.
    #[derive(Default)]
    struct FakePorts {
        ports: BTreeMap<u16, std::collections::VecDeque<u8>>,
    }

    impl FakePorts {
        fn push(&mut self, port: u16, byte: u8) {
            self.ports.entry(port).or_default().push_back(byte);
        }

        fn pop(&mut self, port: u16) -> u8 {
            self.ports
                .get_mut(&port)
                .and_then(|queue| queue.pop_front())
                .unwrap_or(0)
        }
    }

    impl Io for FakePorts {
        fn out(&mut self, port: u16, byte: u8) {
            self.push(port, byte);
        }

        fn read(&mut self, port: u16) -> u8 {
            self.pop(port)
        }

        fn read_word(&mut self, port: u16) -> u16 {
            u16::from_le_bytes([self.pop(port), self.pop(port)])
        }

        fn out_word(&mut self, port: u16, word: u16) {
            for byte in word.to_le_bytes() {
                self.push(port, byte);
            }
        }

        fn read_dword(&mut self, port: u16) -> u32 {
            u32::from_le_bytes([
                self.pop(port),
                self.pop(port),
                self.pop(port),
                self.pop(port),
            ])
        }

        fn out_dword(&mut self, port: u16, value: u32) {
            for byte in value.to_le_bytes() {
                self.push(port, byte);
            }
        }
    }

    /// A fake platform: the interrupt steps logged, a fixed clock reading and timer period.
    struct FakePlatform {
        log: RefCell<Vec<(&'static str, u8)>>,
        time: Option<CivilTime>,
        period: u16,
        set_increment: RefCell<Option<u32>>,
    }

    impl FakePlatform {
        fn new() -> Self {
            FakePlatform {
                log: RefCell::new(Vec::new()),
                time: Some(CivilTime {
                    year: 2026,
                    month: 11,
                    day: 12,
                    hour: 9,
                    minute: 41,
                    second: 7,
                }),
                period: 11_949,
                set_increment: RefCell::new(None),
            }
        }
    }

    impl Hal for FakePlatform {
        fn initialize_interrupts(&self) {}

        fn begin_system_interrupt(&self, _vector: u8) -> bool {
            true
        }

        fn end_system_interrupt(&self, _vector: u8) {}

        fn enable_system_interrupt(&self, vector: u8) -> bool {
            self.log.borrow_mut().push(("enable", vector));
            true
        }

        fn disable_system_interrupt(&self, vector: u8) {
            self.log.borrow_mut().push(("disable", vector));
        }

        fn system_interrupt_enabled(&self, _vector: u8) -> bool {
            true
        }

        fn system_interrupt_requested(&self, _vector: u8) -> bool {
            false
        }

        fn interrupts_in_service_clear(&self) -> bool {
            true
        }

        fn with_lines_masked<R>(&self, f: impl FnOnce() -> R) -> R {
            f()
        }

        fn set_time_increment(&self, increment: u32) {
            *self.set_increment.borrow_mut() = Some(increment);
        }

        fn interval_timer_count(&self) -> u16 {
            0
        }

        fn interval_timer_period(&self) -> u16 {
            self.period
        }

        fn query_real_time_clock(&self) -> Option<CivilTime> {
            self.time
        }

        fn await_cmos_mailbox(&self, _index: u8, _reads: u32, _announce: impl FnOnce()) -> bool {
            false
        }

        fn graphics_mode_set(&self) -> bool {
            false
        }
    }

    /// The port access runs through the Io seam: byte, word and dword, single and buffer forms.
    #[test]
    fn port_access_runs_through_the_io_seam() {
        let mut io = FakePorts::default();
        write_port_uchar(&mut io, 0x60, 0xA5);
        write_port_ushort(&mut io, 0xCF8, 0x1234);
        write_port_ulong(&mut io, 0xCFC, 0xDEAD_BEEF);
        assert_eq!(read_port_uchar(&mut io, 0x60), 0xA5);
        assert_eq!(read_port_ushort(&mut io, 0xCF8), 0x1234);
        assert_eq!(read_port_ulong(&mut io, 0xCFC), 0xDEAD_BEEF);

        let bytes = [0x11u8, 0x22, 0x33];
        write_port_buffer_uchar(&mut io, 0x300, &bytes);
        let mut read_back = [0u8; 3];
        read_port_buffer_uchar(&mut io, 0x300, &mut read_back);
        assert_eq!(read_back, bytes);

        let words = [0xBEEFu16, 0xCAFE];
        write_port_buffer_ushort(&mut io, 0x304, &words);
        let mut words_back = [0u16; 2];
        read_port_buffer_ushort(&mut io, 0x304, &mut words_back);
        assert_eq!(words_back, words);

        let dwords = [0x1234_5678u32, 0x9ABC_DEF0];
        write_port_buffer_ulong(&mut io, 0x308, &dwords);
        let mut dwords_back = [0u32; 2];
        read_port_buffer_ulong(&mut io, 0x308, &mut dwords_back);
        assert_eq!(dwords_back, dwords);
    }

    /// The memory-mapped register access is volatile against the named range, single and
    /// buffer forms.
    #[test]
    fn register_access_is_volatile_over_the_range() {
        let mut registers = [0u32; 4];
        write_register_ulong(registers.as_mut_ptr(), 0xAABB_CCDD);
        assert_eq!(read_register_ulong(registers.as_ptr()), 0xAABB_CCDD);
        write_register_uchar(registers.as_mut_ptr() as *mut u8, 0x5A);
        assert_eq!(read_register_uchar(registers.as_ptr() as *const u8), 0x5A);
        assert_eq!(
            read_register_ushort(registers.as_ptr() as *const u16),
            0xCC5A
        );

        let written = [0x1111_2222u32, 0x3333_4444];
        write_register_buffer_ulong(registers.as_mut_ptr(), &written);
        let mut read_back = [0u32; 2];
        read_register_buffer_ulong(registers.as_ptr(), &mut read_back);
        assert_eq!(read_back, written);

        let bytes = [0x01u8, 0x02, 0x03];
        write_register_buffer_uchar(registers.as_mut_ptr() as *mut u8, &bytes);
        let mut bytes_back = [0u8; 3];
        read_register_buffer_uchar(registers.as_ptr() as *const u8, &mut bytes_back);
        assert_eq!(bytes_back, bytes);

        let words = [0xBEEFu16, 0xFEED];
        write_register_buffer_ushort(registers.as_mut_ptr() as *mut u16, &words);
        let mut words_back = [0u16; 2];
        read_register_buffer_ushort(registers.as_ptr() as *const u16, &mut words_back);
        assert_eq!(words_back, words);
    }

    /// The vector query: an ISA line maps to its band vector, IRQL and affinity; a line past the
    /// band fails with a zero affinity; a PCI slot/pin routes through the PIRQ table.
    #[test]
    fn the_vector_query_maps_lines_and_routes_pci_pins() {
        // PIRQB -> IRQ 10.
        let routes = PirqRoutes([0x80, 0x0A, 0x80, 0x80]);

        let (vector, irql, affinity) =
            get_interrupt_vector(Some(&routes), INTERFACE_ISA, 0, 10, 10);
        assert_eq!(vector, 0x3A);
        assert_eq!(irql, routing::line_irql(10));
        assert_eq!(affinity, routing::ALL_PROCESSORS);

        let (vector, irql, affinity) =
            get_interrupt_vector(Some(&routes), INTERFACE_ISA, 0, 16, 16);
        assert_eq!((vector, affinity), (0, 0), "a line past the band fails");
        assert_eq!(irql, Irql(0));

        // PCIBus: level = pin 1, vector = slot (dev 1, func 3) = 0x0B; the rotation routes it to
        // PIRQB, IRQ 10.
        let (vector, irql, affinity) =
            get_interrupt_vector(Some(&routes), INTERFACE_PCI_BUS, 0, 1, 0x0B);
        assert_eq!(vector, 0x3A);
        assert_eq!(irql, routing::line_irql(10));
        assert_eq!(affinity, routing::ALL_PROCESSORS);

        // An unrouted pin fails: dev 2 pin 1 selects PIRQC, which is disabled here.
        let (vector, _, affinity) =
            get_interrupt_vector(Some(&routes), INTERFACE_PCI_BUS, 0, 1, 0x10);
        assert_eq!((vector, affinity), (0, 0), "PIRQC is disabled");
    }

    /// The enable and disable reach the platform.
    #[test]
    fn enable_and_disable_reach_the_platform() {
        let platform = FakePlatform::new();
        assert!(enable_system_interrupt(&platform, 0x3A));
        disable_system_interrupt(&platform, 0x3A);
        assert_eq!(
            *platform.log.borrow(),
            [("enable", 0x3A), ("disable", 0x3A)]
        );
    }

    /// The clock: the RTC reading maps to TIME_FIELDS, and the time increment reports the
    /// programmed period in 100 ns units.
    #[test]
    fn the_clock_and_rtc_queries_run_over_the_platform() {
        let platform = FakePlatform::new();
        let fields = query_real_time_clock(&platform).expect("the fake clock reads a date");
        assert_eq!(
            fields,
            TimeFields {
                year: 2026,
                month: 11,
                day: 12,
                hour: 9,
                minute: 41,
                second: 7,
                milliseconds: 0,
                weekday: 0,
            }
        );

        let set = set_time_increment(&platform, 100_000);
        assert_eq!(*platform.set_increment.borrow(), Some(100_000));
        // The fake's period is the captured divisor 11_949: its period is the captured 100_144
        // in 100 ns units.
        assert_eq!(set, 100_144);

        let mut no_clock = FakePlatform::new();
        no_clock.time = None;
        assert_eq!(query_real_time_clock(&no_clock), None);
        assert!(!set_real_time_clock(&fields), "the stub fails");
        assert_eq!(get_dma_alignment_requirement(), 1);
    }

    /// The stubs fail the way their exports fail and name their slices.
    #[test]
    fn the_stubs_fail_and_name_their_work() {
        let mut logical = 0xFFFF_FFFF_FFFF_FFFFu64;
        let buffer = allocate_common_buffer(core::ptr::null_mut(), 4096, &mut logical, true);
        assert!(buffer.is_null());
        assert_eq!(logical, 0);
        free_common_buffer(core::ptr::null_mut(), 4096, 0, true);
        assert!(mm_map_io_space(0xE000_0000, 0x1000, false).is_null());
        request_ipi(0xFFFF_FFFF);
        assert!(!start_next_processor(
            core::ptr::null_mut(),
            core::ptr::null_mut()
        ));
    }

    /// The catalog and the bodies agree: every record in kernel/hal_exports.toml has a name, a
    /// group, and an impl — a native body or a stub with a nonempty reason naming its work — and
    /// every record's `f2k_export_<body>` symbol is defined in this file.
    #[test]
    fn every_catalogued_entry_point_has_its_body_here() {
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let spec_text =
            std::fs::read_to_string(manifest.join("hal_exports.toml")).expect("the spec reads");
        let source_text =
            std::fs::read_to_string(manifest.join("src/hal/exports.rs")).expect("this file reads");

        let quoted = |line: &str, key: &str| -> Option<String> {
            let at = line.find(key)? + key.len();
            let rest = line[at..].trim_start();
            let rest = rest.strip_prefix('"')?;
            let end = rest.find('"')?;
            Some(rest[..end].to_string())
        };

        let mut groups = Vec::new();
        let mut records: Vec<(String, String, Option<String>, Option<String>)> = Vec::new();
        // (name, group, native body, stub reason)
        let mut current: Option<(String, String, Option<String>, Option<String>)> = None;
        for line in spec_text.lines() {
            let line = line.trim();
            if line.starts_with("[[group]]") {
                current = None;
            } else if line.starts_with("[[export]]") {
                if let Some(record) = current.take() {
                    records.push(record);
                }
                current = Some((String::new(), String::new(), None, None));
            } else if let Some(record) = current.as_mut() {
                if let Some(name) = quoted(line, "name = ") {
                    record.0 = name;
                } else if let Some(group) = quoted(line, "group = ") {
                    record.1 = group;
                } else if let Some(body) = quoted(line, "native = ") {
                    record.2 = Some(body);
                } else if let Some(reason) = quoted(line, "stub = ") {
                    record.3 = Some(reason);
                }
            } else if let Some(key) = quoted(line, "key = ") {
                groups.push(key);
            }
        }
        if let Some(record) = current.take() {
            records.push(record);
        }

        assert!(
            records.len() >= 30,
            "the surface carries its families: {}",
            records.len()
        );
        let mut names = Vec::new();
        for (name, group, native, stub) in &records {
            assert!(!name.is_empty(), "every record names its export");
            assert!(groups.contains(group), "{name}: unknown group {group:?}");
            assert!(
                native.is_some() ^ stub.is_some(),
                "{name}: exactly one of implemented (native) or stub-with-named-work"
            );
            if let Some(reason) = stub {
                assert!(!reason.is_empty(), "{name}: the stub names its work");
            }
            let body = native.clone().unwrap_or_else(|| name.clone());
            let symbol = format!("f2k_export_{body}");
            assert!(
                source_text.contains(&symbol),
                "{name}: its body {symbol} is defined in hal/exports.rs"
            );
            names.push(name.clone());
        }
        let mut deduped = names.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(names.len(), deduped.len(), "the export names are unique");
    }
}
