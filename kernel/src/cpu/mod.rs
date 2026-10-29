//! The CPU tables: the GDT (segments, TEB, TSS) and the IDT (exception handlers, the syscall gate,
//! the hardware-vector stubs), plus the diagnostic dump the exception stubs print; and the
//! floating-point unit's setup (`fxsave` and the SSE state).
//!
//! The tables themselves are the processor's: its control region holds them
//! ([`ProcessorTables`]), as Windows 2000's KPCR points at its processor's GDT, IDT and TSS.

use core::cell::UnsafeCell;
use core::mem::offset_of;
use core::sync::atomic::{AtomicBool, Ordering};

pub mod fpu;
pub mod gdt;
pub mod idt;

/// The processor's GDT, task state segment and IDT.
///
/// Once loaded they are the processor's: it reads them behind the compiler's back and writes some
/// of their bits itself (a segment's accessed bit, the TSS descriptor's busy bit), and the context
/// switch's assembly writes the TSS's ring-0 stack and the TEB descriptor's base at every switch,
/// with interrupts masked, at [`TSS_ESP0_OFFSET`] and [`TEB_DESCRIPTOR_OFFSET`]. Rust code writes
/// them once, at boot, through [`ProcessorTables::build`], before they are loaded; afterwards it
/// only reads them, through their addresses.
///
/// Aligned so that each table starts on a 16-byte boundary (the processor's preferred alignment for
/// the descriptor tables is 8).
#[repr(C, align(16))]
pub struct ProcessorTables {
    gdt: UnsafeCell<gdt::Gdt>,
    tss: UnsafeCell<gdt::TaskStateSegment>,
    idt: UnsafeCell<idt::Idt>,
    /// Whether [`ProcessorTables::build`] has handed the tables out.
    built: AtomicBool,
}

// SAFETY: Rust reaches the tables' contents only through `build`, which hands out the one set of
// references, once, at boot, before the tables are loaded; afterwards only the processor and the
// context switch's assembly write them (one processor, interrupts masked for the switch's stores),
// and Rust reads them only through their raw addresses.
unsafe impl Sync for ProcessorTables {}

/// The tables, handed out once to be built.
pub struct TablesToBuild<'a> {
    pub gdt: &'a mut gdt::Gdt,
    pub tss: &'a mut gdt::TaskStateSegment,
    pub idt: &'a mut idt::Idt,
}

impl ProcessorTables {
    /// The tables as the processor control region starts with them: the GDT's fixed segments, a
    /// blank TSS, and an IDT of absent gates.
    pub const fn new() -> Self {
        ProcessorTables {
            gdt: UnsafeCell::new(gdt::INITIAL_GDT),
            tss: UnsafeCell::new(gdt::TaskStateSegment::new()),
            idt: UnsafeCell::new([idt::Gate::ABSENT; idt::IDT_VECTORS]),
            built: AtomicBool::new(false),
        }
    }

    /// The tables, exclusively, to build them before they are loaded.
    ///
    /// # Panics
    ///
    /// They were handed out already: building them twice is a boot-order bug.
    #[allow(clippy::mut_from_ref)] // one hand-out, guarded by `built`
    pub fn build(&self) -> TablesToBuild<'_> {
        assert!(
            !self.built.swap(true, Ordering::AcqRel),
            "the processor's tables built twice"
        );
        // SAFETY: the swap above makes this the one hand-out, and nothing else forms a reference
        // to the tables (see the `Sync` impl): these are the only references, and the processor
        // does not read the tables until they are loaded, after the build.
        unsafe {
            TablesToBuild {
                gdt: &mut *self.gdt.get(),
                tss: &mut *self.tss.get(),
                idt: &mut *self.idt.get(),
            }
        }
    }

    /// The GDT's address, to read it once loaded.
    #[cfg_attr(
        not(any(feature = "fault-test-ud", feature = "fault-test-gp")),
        allow(dead_code)
    )]
    pub fn gdt(&self) -> *const gdt::Gdt {
        self.gdt.get()
    }
}

/// The TSS's ring-0 stack pointer, as a byte offset into [`ProcessorTables`]: what the context
/// switch's assembly installs the incoming thread's stack top at.
pub const TSS_ESP0_OFFSET: u32 =
    (offset_of!(ProcessorTables, tss) + offset_of!(gdt::TaskStateSegment, esp0)) as u32;

/// The TEB descriptor, as a byte offset into [`ProcessorTables`]: what the context switch's
/// assembly rewrites the base of (at [`gdt::SegmentDescriptor`]'s base offsets).
pub const TEB_DESCRIPTOR_OFFSET: u32 =
    offset_of!(ProcessorTables, gdt) as u32 + gdt::TEB_SELECTOR as u32;

/// The operand of `lgdt` and `lidt`: a descriptor table's limit (its size minus one) and its
/// linear base.
#[repr(C, packed)]
pub struct DescriptorTablePointer {
    limit: u16,
    base: u32,
}

impl DescriptorTablePointer {
    /// The pointer to `table`, which must stay where it is for as long as it is loaded.
    pub fn of<T>(table: &T) -> Self {
        DescriptorTablePointer {
            limit: (core::mem::size_of::<T>() - 1) as u16,
            base: core::ptr::from_ref(table) as usize as u32,
        }
    }

    /// The limit: the offset of the table's last byte.
    // Read by the host tests.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn limit(&self) -> u16 {
        self.limit
    }
}

/// Build the processor's tables in its control region and load them: the GDT, the task register
/// and the IDT, so faults print diagnostics on COM1 instead of triple-faulting.
///
/// # Safety
///
/// Boot CPU, ring 0, interrupts disabled, before any code that might raise a CPU exception.
#[cfg(target_arch = "x86")]
pub unsafe fn init() {
    let tables = crate::pcr::pcr().tables.build();
    // SAFETY: the caller's contract; the tables are the control region's, a static.
    unsafe {
        gdt::init(tables.gdt, tables.tss);
        idt::init(tables.idt);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The descriptor-table pointer is the six bytes `lgdt` and `lidt` read: the limit at 0, the
    /// base at 2, the limit the offset of the table's last byte.
    #[test]
    fn the_descriptor_table_pointer_is_six_bytes() {
        assert_eq!(core::mem::size_of::<DescriptorTablePointer>(), 6);
        let gdt = gdt::INITIAL_GDT;
        let pointer = DescriptorTablePointer::of(&gdt);
        let base = core::ptr::addr_of!(pointer) as usize;
        assert_eq!(core::ptr::addr_of!(pointer.limit) as usize - base, 0);
        assert_eq!(core::ptr::addr_of!(pointer.base) as usize - base, 2);
        assert_eq!(pointer.limit(), 55);
        let low = core::ptr::addr_of!(gdt) as usize as u32;
        let stored = pointer.base;
        assert_eq!(stored, low);
    }

    /// The tables' layout: the GDT first, the TSS after it, the IDT 16-byte aligned after both;
    /// the switch's two offsets land on the TSS's `esp0` and the GDT's TEB slot.
    #[test]
    fn the_tables_layout() {
        assert_eq!(offset_of!(ProcessorTables, gdt), 0);
        assert_eq!(offset_of!(ProcessorTables, tss), 56);
        assert_eq!(offset_of!(ProcessorTables, idt) % 16, 0);
        assert_eq!(TSS_ESP0_OFFSET, 56 + 4);
        assert_eq!(TEB_DESCRIPTOR_OFFSET, 6 * 8);
        assert_eq!(core::mem::align_of::<ProcessorTables>(), 16);
    }

    /// The tables are handed out once; a second build is refused.
    #[test]
    fn the_tables_are_built_once() {
        let tables = ProcessorTables::new();
        let built = tables.build();
        built.tss.esp0 = 0x1234;
        let again = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = tables.build();
        }));
        assert!(again.is_err());
    }

    /// The switch's stores, made through the two offsets as the assembly makes them, land in the
    /// TSS's ring-0 stack pointer and the TEB descriptor's base, and nowhere else.
    #[test]
    fn the_switch_offsets_address_the_tables() {
        let tables = ProcessorTables::new();
        let base = core::ptr::from_ref(&tables).cast::<u8>().cast_mut();
        let teb = 0x7FFD_D000u32;
        // SAFETY: both offsets lie inside the tables (pinned above), whose cells admit writes
        // through their address while no reference to the contents is live.
        unsafe {
            base.add(TSS_ESP0_OFFSET as usize)
                .cast::<u32>()
                .write_unaligned(0x8013_A000);
            let descriptor = base.add(TEB_DESCRIPTOR_OFFSET as usize);
            descriptor
                .add(gdt::SegmentDescriptor::BASE_LOW_OFFSET as usize)
                .cast::<u16>()
                .write_unaligned(teb as u16);
            *descriptor.add(gdt::SegmentDescriptor::BASE_MID_OFFSET as usize) = (teb >> 16) as u8;
            *descriptor.add(gdt::SegmentDescriptor::BASE_HIGH_OFFSET as usize) = (teb >> 24) as u8;
        }
        let built = tables.build();
        assert_eq!(built.tss.esp0, 0x8013_A000);
        let mut expected = gdt::INITIAL_GDT;
        expected[6] = gdt::SegmentDescriptor::new(teb, 0xFFF, 0xF3, 0x4);
        assert_eq!(*built.gdt, expected);
    }
}
