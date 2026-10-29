//! Global Descriptor Table.
//!
//! Taken over from the Multiboot loader early so the memory model is ours: flat 4 GiB kernel and
//! user segments, the TSS (its esp0/ss0 give gate entries from ring 3 their ring-0 stack), and the
//! TEB segment — a non-flat user descriptor based at the thread block page, so ring-3 code reaches
//! its per-thread state fs-relative (the CRT installs its exception frames at fs:[0]). The table
//! and the TSS live in the processor control region ([`super::ProcessorTables`]).

/// Selector offsets into the GDT (in bytes; low 3 bits are RPL/TI and stay 0 for kernel access).
/// Pinned to the slot order below and fed to `gdt_load`'s assembly via `const` operands, so nothing
/// can drift.
pub const KERNEL_CODE_SELECTOR: u16 = 0x08;
pub const KERNEL_DATA_SELECTOR: u16 = 0x10;
/// Ring-3 flat code segment (slot 3). Ring-3 entry forms it with RPL 3.
pub const USER_CODE_SELECTOR: u16 = 0x18;
/// Ring-3 flat data segment (slot 4). Ring-3 entry forms it with RPL 3.
pub const USER_DATA_SELECTOR: u16 = 0x20;
/// The TSS descriptor (slot 5); loaded into the task register during init.
pub const TSS_SELECTOR: u16 = 0x28;
/// The TEB segment (slot 6): a user data descriptor based at the thread block page, one page long,
/// DPL 3. Ring-3 entry loads it into FS (with RPL 3); the flat data segments stay in DS/ES/SS.
pub const TEB_SELECTOR: u16 = 0x30;

// Kernel selectors are GDT slot indices times 8: null, kernel code and data are slots 0, 1 and 2;
// user code and data slots 3, 4; the TSS slot 5; the TEB segment slot 6. The RPL/TI bits stay clear
// for kernel access.
const _: () = assert!(
    KERNEL_CODE_SELECTOR == 0x08
        && KERNEL_DATA_SELECTOR == 0x10
        && USER_CODE_SELECTOR == 0x18
        && USER_DATA_SELECTOR == 0x20
        && TSS_SELECTOR == 0x28
        && TEB_SELECTOR == 0x30
);

/// One segment descriptor, in the x86 layout: limit 15:0 | base 15:0 | base 23:16 | access |
/// flags<<4|limit 19:16 | base 31:24.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct SegmentDescriptor(u64);

impl SegmentDescriptor {
    /// The byte offset of the base's bits 31:24 inside a descriptor. The context switch's assembly
    /// rewrites the TEB descriptor's base through the three base offsets.
    pub const BASE_HIGH_OFFSET: u32 = 7;
    /// The byte offset of the base's bits 15:0, a word.
    pub const BASE_LOW_OFFSET: u32 = 2;
    /// The byte offset of the base's bits 23:16.
    pub const BASE_MID_OFFSET: u32 = 4;
    /// The null descriptor (slot 0, and the TSS slot until init builds it).
    pub const NULL: SegmentDescriptor = SegmentDescriptor(0);

    /// Pack one descriptor from its base, limit, access byte and flags nibble.
    #[rustfmt::skip] // keeps the bit-field comments in one column
    pub const fn new(base: u32, limit: u32, access: u8, flags: u8) -> Self {
        // `limit` is the raw 20-bit limit field; the G flag decides whether it counts pages or
        // bytes. With G=1, 0xFFFFF spans the full 4 GiB.
        assert!(
            limit <= 0xFFFFF,
            "limit must fit the 20-bit descriptor field"
        );
        SegmentDescriptor(
            ((base as u64) & 0xFFFF) << 16          // base 15:0
            | (((base >> 16) as u64) & 0xFF) << 32 // base 23:16
            | (((base >> 24) as u64) & 0xFF) << 56 // base 31:24
            | ((limit as u64) & 0xFFFF)            // limit 15:0
            | (((limit >> 16) as u64) & 0xF) << 48 // limit 19:16
            | ((access as u64) & 0xFF) << 40       // access byte
            | ((flags as u64) & 0xF) << 52,        // G/D/L and AVL nibble
        )
    }

    /// The descriptor's 64 bits.
    // Read by the fault-injection diagnostics and the host tests.
    #[cfg_attr(not(test), allow(dead_code))]
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// Rewrite the base, touching no other byte: the three stores the context switch's assembly
    /// makes into the TEB descriptor, at the same offsets.
    // The assembly's host-side model: read by the host tests.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn set_base(&mut self, base: u32) {
        let mut bytes = self.0.to_le_bytes();
        let low = Self::BASE_LOW_OFFSET as usize;
        bytes[low..low + 2].copy_from_slice(&(base as u16).to_le_bytes());
        bytes[Self::BASE_MID_OFFSET as usize] = (base >> 16) as u8;
        bytes[Self::BASE_HIGH_OFFSET as usize] = (base >> 24) as u8;
        self.0 = u64::from_le_bytes(bytes);
    }
}

/// The GDT's slots: null, kernel code and data, user code and data, the TSS, the TEB segment.
pub const GDT_ENTRIES: usize = 7;

/// The Global Descriptor Table.
pub type Gdt = [SegmentDescriptor; GDT_ENTRIES];

/// The TSS descriptor's slot.
const TSS_SLOT: usize = (TSS_SELECTOR >> 3) as usize;

/// The GDT as the processor control region starts with it. Slots 1-4: flat kernel/user code and
/// data (0x9B/0x93/0xFB/0xF3, G=1, D=1). Slot 5 is the TSS descriptor (built at init), slot 6 the
/// TEB segment.
///
/// Quirk: the accessed bit is pre-set because the CPU sets it in the GDT on every segment load —
/// pre-setting keeps the entries stable. The only other architectural write is the busy bit `ltr`
/// sets in the TSS descriptor, which is why the table stays writable. The context switch's
/// assembly rewrites the TEB entry's base bytes at every thread switch.
pub const INITIAL_GDT: Gdt = [
    SegmentDescriptor::NULL,
    SegmentDescriptor::new(0, 0xFFFFF, 0x9B, 0xC),
    SegmentDescriptor::new(0, 0xFFFFF, 0x93, 0xC),
    SegmentDescriptor::new(0, 0xFFFFF, 0xFB, 0xC),
    SegmentDescriptor::new(0, 0xFFFFF, 0xF3, 0xC),
    SegmentDescriptor::NULL,
    teb_descriptor(),
];

/// TSS descriptor: available 32-bit TSS (0x89), byte-granular. The 32-bit-vs-16-bit distinction is
/// the type nibble, so the flags nibble stays clear. Must be non-busy when `ltr` loads it; `ltr`
/// then sets the busy bit in the GDT (see [`INITIAL_GDT`]).
const fn tss_descriptor(base: u32, limit: u32) -> SegmentDescriptor {
    SegmentDescriptor::new(base, limit, 0x89, 0x0)
}

/// TEB segment: ring-3 data (0xF3), byte-granular, one page, based at the thread block page.
const fn teb_descriptor() -> SegmentDescriptor {
    SegmentDescriptor::new(crate::user::TEB_PAGE, 0xFFF, 0xF3, 0x4)
}

/// The 32-bit task state segment. Only ss0:esp0 is used (the ring-0 stack for gate entries from
/// ring 3); the rest belongs to hardware task switching, unused here.
#[allow(dead_code)]
#[repr(C)]
pub struct TaskStateSegment {
    prev_task: u16,
    reserved0: u16,
    /// Ring-0 stack pointer a ring-3 gate entry switches to.
    pub esp0: u32,
    /// Ring-0 stack segment (the kernel data selector).
    pub ss0: u16,
    reserved1: u16,
    esp1: u32,
    ss1: u16,
    reserved2: u16,
    esp2: u32,
    ss2: u16,
    reserved3: u16,
    cr3: u32,
    eip: u32,
    eflags: u32,
    eax: u32,
    ecx: u32,
    edx: u32,
    ebx: u32,
    esp: u32,
    ebp: u32,
    esi: u32,
    edi: u32,
    es: u16,
    reserved_es: u16,
    cs: u16,
    reserved_cs: u16,
    ss: u16,
    reserved_ss: u16,
    ds: u16,
    reserved_ds: u16,
    fs: u16,
    reserved_fs: u16,
    gs: u16,
    reserved_gs: u16,
    ldt: u16,
    reserved_ldt: u16,
    /// Debug trap bit (only bit 0 is defined); zero.
    trap: u16,
    /// Offset one past the last byte of the I/O permission bitmap. With no bitmap in the segment
    /// (set to the TSS size), every port access from ring 3 faults.
    pub iomap_base: u16,
}

impl TaskStateSegment {
    pub const fn new() -> Self {
        Self {
            prev_task: 0,
            reserved0: 0,
            esp0: 0,
            ss0: 0,
            reserved1: 0,
            esp1: 0,
            ss1: 0,
            reserved2: 0,
            esp2: 0,
            ss2: 0,
            reserved3: 0,
            cr3: 0,
            eip: 0,
            eflags: 0,
            eax: 0,
            ecx: 0,
            edx: 0,
            ebx: 0,
            esp: 0,
            ebp: 0,
            esi: 0,
            edi: 0,
            es: 0,
            reserved_es: 0,
            cs: 0,
            reserved_cs: 0,
            ss: 0,
            reserved_ss: 0,
            ds: 0,
            reserved_ds: 0,
            fs: 0,
            reserved_fs: 0,
            gs: 0,
            reserved_gs: 0,
            ldt: 0,
            reserved_ldt: 0,
            trap: 0,
            iomap_base: 0,
        }
    }
}

#[cfg(target_arch = "x86")]
use core::arch::asm;

/// Build the TSS and its descriptor in the processor's tables, load the GDT (reloading every
/// segment register, CS through a far return) and load the task register.
///
/// The TSS's `esp0` starts zero: ring 3 is only ever entered from a user thread, and the switch
/// into that thread installs its gate-stack top first. A gate entry before any install would be a
/// kernel bug (a zero esp0 faults contained, not silently corrupts).
///
/// # Safety
///
/// Boot CPU, ring 0, interrupts disabled; `gdt` and `tss` are the processor control region's
/// tables, which stay in place for the kernel's life.
#[cfg(target_arch = "x86")]
pub unsafe fn init(gdt: &mut Gdt, tss: &mut TaskStateSegment) {
    let size = core::mem::size_of::<TaskStateSegment>();
    gdt[TSS_SLOT] = tss_descriptor(core::ptr::from_mut(tss) as u32, (size - 1) as u32);
    tss.esp0 = 0;
    tss.ss0 = KERNEL_DATA_SELECTOR;
    // No I/O bitmap: every ring-3 port access faults (the smoke and the later syscall layer have
    // no business with ports).
    tss.iomap_base = size as u16;

    let gdtr = super::DescriptorTablePointer::of(gdt);
    // SAFETY: the caller's contract: ring 0, interrupts disabled, and the table stays where the
    // pointer names it. Every selector loaded is a valid flat segment of the new table, and the
    // far return lands on the next instruction with CS reloaded; the two pushes are the frame the
    // `retf` pops, so the stack ends as it began.
    unsafe {
        asm!(
            "lgdt [{gdtr}]",
            "mov ds, {data:x}",
            "mov es, {data:x}",
            "mov fs, {data:x}",
            "mov gs, {data:x}",
            "mov ss, {data:x}",
            // A far return frame: the new CS, then the EIP on top.
            "push {code}",
            "lea {scratch}, [2f]",
            "push {scratch}",
            "retf",
            "2:",
            gdtr = in(reg) &gdtr,
            data = in(reg) KERNEL_DATA_SELECTOR as u32,
            code = const KERNEL_CODE_SELECTOR,
            scratch = out(reg) _,
            options(preserves_flags),
        );
    }
    // SAFETY: the TSS descriptor is in the loaded table and available (non-busy); ltr loads the
    // task register and marks the descriptor busy in the GDT, and has no other effect.
    unsafe {
        asm!("ltr {tss:x}", tss = in(reg) TSS_SELECTOR, options(nostack, preserves_flags));
    }
}

/// Read one descriptor after `init`; the fault-injection paths use it to prove the CPU did not
/// write to the table.
#[cfg(any(feature = "fault-test-ud", feature = "fault-test-gp"))]
pub(crate) fn debug_descriptor(index: usize) -> u64 {
    let gdt = crate::pcr::pcr().tables.gdt();
    // SAFETY: the processor control region's table, live for the kernel's life; init's references
    // to it have ended, and the read is volatile because the processor writes the table itself.
    let gdt = unsafe { core::ptr::read_volatile(gdt) };
    gdt[index].raw()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An independent packing: builds a segment descriptor straight from the x86 layout — 20-bit
    /// limit split across bytes 0-1 and the low nibble of byte 6, 32-bit base split across bytes
    /// 2-3, byte 4 and byte 7, access byte 5, flags nibble in the high half of byte 6. Pres is
    /// always set, D/B always 1, Sys/L always 0.
    fn packed_entry(base: u32, limit: u32, type_field: u8, dpl: u8, gran: bool) -> u64 {
        let limit_hi = ((limit >> 16) & 0xF) as u64;
        let access = (0x80u8 | (dpl << 5) | type_field) as u64;
        let flags = limit_hi | 0x40 | ((gran as u64) << 7);
        (((base >> 24) as u64) << 56)
            | (flags << 48)
            | (access << 40)
            | (((base >> 16) & 0xFF) as u64) << 32
            | ((base & 0xFFFF) as u64) << 16
            | ((limit & 0xFFFF) as u64)
    }

    /// One entry of the GDT the processor control region starts with (tests never run init).
    fn entry(index: usize) -> u64 {
        INITIAL_GDT[index].raw()
    }

    /// A descriptor's bits, packed by the type under test.
    fn make_entry(base: u32, limit: u32, access: u8, flags: u8) -> u64 {
        SegmentDescriptor::new(base, limit, access, flags).raw()
    }

    /// Slots 1-4 are the flat segments (accessed bit pre-set), slot 5 is zero until init builds the
    /// TSS descriptor, slot 6 is the TEB segment (non-flat, one page, DPL 3).
    #[test]
    fn gdt_entries_are_flat_segments() {
        assert_eq!(core::mem::size_of::<Gdt>(), 7 * 8);
        assert_eq!(entry(0), 0); // null descriptor
        assert_eq!(entry(1), 0x00CF_9B00_0000_FFFF); // kernel code, accessed
        assert_eq!(entry(2), 0x00CF_9300_0000_FFFF); // kernel data, accessed
        assert_eq!(entry(3), 0x00CF_FB00_0000_FFFF); // user code, accessed
        assert_eq!(entry(4), 0x00CF_F300_0000_FFFF); // user data, accessed
        assert_eq!(entry(5), 0); // TSS descriptor: built at runtime

        // TEB segment, hand-decoded: base 0x7FFDE000 (bytes 7:0 split across the layout), limit
        // 0xFFF byte-granular, access 0xF3, flags nibble 0x4 (D=1, G=0).
        let teb = entry(6);
        assert_eq!((teb >> 56) & 0xFF, 0x7F); // base 31:24
        assert_eq!((teb >> 32) & 0xFF, 0xFD); // base 23:16
        assert_eq!((teb >> 16) & 0xFFFF, 0xE000); // base 15:0
        assert_eq!(teb & 0xFFFF, 0x0FFF); // limit
        assert_eq!((teb >> 40) & 0xFF, 0xF3); // access byte
        assert_eq!((teb >> 52) & 0xF, 0x4); // flags nibble
        assert_eq!(
            teb_descriptor().raw(),
            packed_entry(crate::user::TEB_PAGE, 0xFFF, 0x13, 3, false)
        );
    }

    /// Selector layout; the ring-3 entry forms CS/SS/FS with RPL 3.
    #[test]
    fn selectors_pin_the_slot_layout() {
        assert_eq!(KERNEL_CODE_SELECTOR, 0x08);
        assert_eq!(KERNEL_DATA_SELECTOR, 0x10);
        assert_eq!(USER_CODE_SELECTOR, 0x18);
        assert_eq!(USER_DATA_SELECTOR, 0x20);
        assert_eq!(TSS_SELECTOR, 0x28);
        assert_eq!(TEB_SELECTOR, 0x30);
        // Ring-3 entry forms (RPL 3 in the low bits).
        assert_eq!(USER_CODE_SELECTOR | 3, 0x1B);
        assert_eq!(USER_DATA_SELECTOR | 3, 0x23);
        assert_eq!(TEB_SELECTOR | 3, 0x33);
        // The limit covers exactly the seven entries; the fault-test selector 0x38 is one past it.
        assert_eq!(core::mem::size_of::<Gdt>() - 1, 55);
        assert_eq!(TSS_SLOT, 5);
    }

    /// The TSS descriptor against an independent packing (access 0x89, non-busy for `ltr`).
    #[test]
    fn tss_descriptor_matches_independent_packing() {
        // Independent packing: byte 6 carries only limit 19:16, the flags nibble stays clear
        // (32-bit-vs-16-bit is the type nibble).
        fn packed_tss(base: u32, limit: u32) -> u64 {
            let limit_hi = ((limit >> 16) & 0xF) as u64;
            (((base >> 24) as u64) << 56)
                | (limit_hi << 48)
                | (0x89u64 << 40)
                | (((base >> 16) & 0xFF) as u64) << 32
                | ((base & 0xFFFF) as u64) << 16
                | ((limit & 0xFFFF) as u64)
        }
        for &(base, limit) in &[
            (0u32, 0x67u32),
            (0x0012_3456, 0x67),
            (0xFFFF_0000, 0x1_2345),
        ] {
            assert_eq!(tss_descriptor(base, limit).raw(), packed_tss(base, limit));
        }
        // Hand-decoded per the byte layout.
        assert_eq!(
            tss_descriptor(0x0012_3456, 0x67).raw(),
            0x0000_8912_3456_0067
        );
        // A wide limit lands in byte 6; the flags nibble stays clear.
        let wide = tss_descriptor(0, 0x1_2345).raw();
        assert_eq!((wide >> 48) & 0xF, 1);
        assert_eq!((wide >> 52) & 0xF, 0);
    }

    /// The TSS layout: 104 bytes, selectors in 4-byte slots from 0x48 (a hardware task switch loads
    /// from architectural offsets).
    #[test]
    fn tss_layout_matches_x86() {
        let tss = TaskStateSegment::new();
        let base = core::ptr::addr_of!(tss) as usize;
        assert_eq!(core::mem::size_of::<TaskStateSegment>(), 104);
        assert_eq!(core::ptr::addr_of!(tss.esp0) as usize - base, 0x04);
        assert_eq!(core::ptr::addr_of!(tss.ss0) as usize - base, 0x08);
        assert_eq!(core::ptr::addr_of!(tss.esp1) as usize - base, 0x0C);
        assert_eq!(core::ptr::addr_of!(tss.ss1) as usize - base, 0x10);
        assert_eq!(core::ptr::addr_of!(tss.esp2) as usize - base, 0x14);
        assert_eq!(core::ptr::addr_of!(tss.ss2) as usize - base, 0x18);
        assert_eq!(core::ptr::addr_of!(tss.cr3) as usize - base, 0x1C);
        assert_eq!(core::ptr::addr_of!(tss.eip) as usize - base, 0x20);
        assert_eq!(core::ptr::addr_of!(tss.eflags) as usize - base, 0x24);
        assert_eq!(core::ptr::addr_of!(tss.eax) as usize - base, 0x28);
        assert_eq!(core::ptr::addr_of!(tss.edi) as usize - base, 0x44);
        assert_eq!(core::ptr::addr_of!(tss.es) as usize - base, 0x48);
        assert_eq!(core::ptr::addr_of!(tss.cs) as usize - base, 0x4C);
        assert_eq!(core::ptr::addr_of!(tss.ss) as usize - base, 0x50);
        assert_eq!(core::ptr::addr_of!(tss.ds) as usize - base, 0x54);
        assert_eq!(core::ptr::addr_of!(tss.fs) as usize - base, 0x58);
        assert_eq!(core::ptr::addr_of!(tss.gs) as usize - base, 0x5C);
        assert_eq!(core::ptr::addr_of!(tss.ldt) as usize - base, 0x60);
        assert_eq!(core::ptr::addr_of!(tss.trap) as usize - base, 0x64);
        assert_eq!(core::ptr::addr_of!(tss.iomap_base) as usize - base, 0x66);
    }

    /// The TSS starts with no ring-0 stack: every run path installs its own (per-process for
    /// images, a boot gate stack for the fault stubs) before entering ring 3.
    #[test]
    fn tss_starts_without_a_gate_stack() {
        let tss = TaskStateSegment::new();
        assert_eq!(tss.esp0, 0);
        assert_eq!(tss.ss0, 0); // init sets it to the kernel data selector
    }

    /// make_entry against the independent packing for non-flat inputs: byte-granular, ring-3, high
    /// bases, split limits.
    #[test]
    fn packing_matches_independent_packing() {
        // Limits are raw 20-bit fields (make_entry asserts they fit).
        let cases: &[(u32, u32)] = &[
            (0, 0xF_FFFF),
            (0x1234_5678, 0x0123_45),
            (0xFFFF_0000, 0x000A_BCDE),
            (0x8000_0000, 0x10),
            (0, 0),
        ];
        for &(base, limit) in cases {
            assert_eq!(
                make_entry(base, limit, 0x9B, 0xC),
                packed_entry(base, limit, 0x1B, 0, true),
                "code descriptor base={base:#x} limit={limit:#x}"
            );
            assert_eq!(
                make_entry(base, limit, 0x93, 0xC),
                packed_entry(base, limit, 0x13, 0, true),
                "data descriptor base={base:#x} limit={limit:#x}"
            );
        }
        assert_eq!(
            make_entry(0x10_0000, 0xF_FFFF, 0x9B, 0x4),
            packed_entry(0x10_0000, 0xF_FFFF, 0x1B, 0, false)
        );
        assert_eq!(
            make_entry(0, 0xF_FFFF, 0xFB, 0xC),
            packed_entry(0, 0xF_FFFF, 0x1B, 3, true)
        );
    }

    /// Hand-decoded non-flat descriptor (byte 7 = base 31:24, byte 6 = flags|limit 19:16, byte 5 =
    /// access, byte 4 = base 23:16).
    #[test]
    fn non_flat_descriptor_decodes_correctly() {
        assert_eq!(
            make_entry(0x1234_5678, 0x0123_45, 0x9B, 0xC),
            0x12C1_9B34_5678_2345
        );
    }

    /// The base rewrite (the context switch's three stores into the TEB descriptor) rewrites
    /// exactly the base: the edited entry equals a freshly packed entry for the same base.
    #[test]
    fn set_base_rewrites_only_the_base_bytes() {
        assert_eq!(
            (
                SegmentDescriptor::BASE_LOW_OFFSET,
                SegmentDescriptor::BASE_MID_OFFSET,
                SegmentDescriptor::BASE_HIGH_OFFSET
            ),
            (2, 4, 7)
        );
        for base in [0u32, 0x7FFD_E000, 0x7FFD_D000, 0x7FF9_E000, 0x1234_5678] {
            let mut entry = teb_descriptor();
            entry.set_base(base);
            assert_eq!(
                entry,
                SegmentDescriptor::new(base, 0xFFF, 0xF3, 0x4),
                "base {base:#x}"
            );
        }
    }
}
