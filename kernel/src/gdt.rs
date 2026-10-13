//! Global Descriptor Table.
//!
//! Multiboot loaders boot the kernel with their own GDT, but we take over
//! early so the memory model is ours from the start: a flat 32-bit address
//! space with one kernel code and one kernel data segment, both base 0,
//! limit 4 GiB. This matches the flat protected-mode model Windows 2000
//! runs in. Ring 3 adds the matching pair of user segments (DPL 3) and the
//! TSS descriptor: the task register is loaded during init so privilege
//! changes through an interrupt gate find their ring-0 stack (esp0/ss0).

/// Selector offsets into the GDT (in bytes; low 3 bits are RPL/TI and stay 0
/// for kernel access). Pinned to the slot order below and fed to
/// `gdt_load`'s assembly via `const` operands, so nothing can drift.
pub const KERNEL_CODE_SELECTOR: u16 = 0x08;
pub const KERNEL_DATA_SELECTOR: u16 = 0x10;
/// Ring-3 flat code segment (slot 3). Ring-3 entry forms it with RPL 3.
pub const USER_CODE_SELECTOR: u16 = 0x18;
/// Ring-3 flat data segment (slot 4). Ring-3 entry forms it with RPL 3.
pub const USER_DATA_SELECTOR: u16 = 0x20;
/// The TSS descriptor (slot 5); loaded into the task register during init.
pub const TSS_SELECTOR: u16 = 0x28;

// Kernel selectors are GDT slot indices times 8: null, kernel code and
// data are slots 0, 1 and 2; user code and data slots 3, 4; the TSS
// slot 5. The RPL/TI bits stay clear for kernel access.
const _: () = assert!(
    KERNEL_CODE_SELECTOR == 0x08
        && KERNEL_DATA_SELECTOR == 0x10
        && USER_CODE_SELECTOR == 0x18
        && USER_DATA_SELECTOR == 0x20
        && TSS_SELECTOR == 0x28
);

/// Build one descriptor: base, limit, access byte and flags nibble packed
/// into 64 bits, following the x86 segment descriptor layout:
/// limit 15:0 | base 15:0 | base 23:16 | access | flags<<4|limit 19:16 |
/// base 31:24.
const fn make_entry(base: u32, limit: u32, access: u8, flags: u8) -> u64 {
    // `limit` is the raw 20-bit limit field; the G flag decides whether it
    // counts pages or bytes. With G=1, 0xFFFFF spans the full 4 GiB.
    assert!(limit <= 0xFFFFF, "limit must fit the 20-bit descriptor field");
    ((base as u64) & 0xFFFF) << 16          // base 15:0
        | (((base >> 16) as u64) & 0xFF) << 32 // base 23:16
        | (((base >> 24) as u64) & 0xFF) << 56 // base 31:24
        | ((limit as u64) & 0xFFFF)            // limit 15:0
        | (((limit >> 16) as u64) & 0xF) << 48 // limit 19:16
        | ((access as u64) & 0xFF) << 40       // access byte
        | ((flags as u64) & 0xF) << 52         // G/D/L and AVL nibble
}

/// Null descriptor, kernel code (0x9B: present, ring 0, code, readable,
/// accessed), kernel data (0x93: present, ring 0, data, writable,
/// accessed), user code (0xFB: present, ring 3, code, readable,
/// accessed), user data (0xF3: present, ring 3, data, writable,
/// accessed). G=1, D=1: 4 GiB page-granular 32-bit segments.
///
/// The accessed bit (access byte bit 0) is pre-set on the segment
/// descriptors: the CPU sets it in the GDT itself on every
/// segment-register load, and pre-setting it keeps those entries
/// stable — the only architectural write into this table is the busy
/// bit the CPU sets in the TSS descriptor when `ltr` loads the task
/// register (see `tss_descriptor`), so the table's page stays writable.
/// Slot 5 holds the TSS descriptor, which carries a runtime address
/// and is built by `init` before the table is loaded.
static mut GDT: [u64; 6] = [
    make_entry(0, 0, 0x00, 0x0),
    make_entry(0, 0xFFFFF, 0x9B, 0xC),
    make_entry(0, 0xFFFFF, 0x93, 0xC),
    make_entry(0, 0xFFFFF, 0xFB, 0xC),
    make_entry(0, 0xFFFFF, 0xF3, 0xC),
    0,
];

/// TSS descriptor: present, ring 0, system type "available 32-bit TSS"
/// (0x89), byte-granular. The 32-bit-vs-16-bit distinction lives in the
/// type nibble (9 = available 32-bit; 1 = available 16-bit), so the
/// flags nibble carries no meaning here and stays clear — only its
/// limit 19:16 half is used. The descriptor must be non-busy when
/// `ltr` loads it; the CPU then sets the busy bit (0x89 -> 0x8B) in
/// the GDT itself — the one architectural write into this table, so
/// the GDT page stays writable (the pre-set accessed bits keep the
/// segment descriptors stable).
const fn tss_descriptor(base: u32, limit: u32) -> u64 {
    make_entry(base, limit, 0x89, 0x0)
}

/// The 32-bit task state segment. The CPU consults ss0:esp0 when an
/// interrupt gate switches context from ring 3 to ring 0; every other
/// field belongs to hardware task switching, which this kernel does not
/// use, and stays zero.
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
    /// Offset one past the last byte of the I/O permission bitmap. With
    /// no bitmap in the segment (set to the TSS size), every port
    /// access from ring 3 faults.
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

/// The one TSS, pointed at by the descriptor in GDT slot 5 and loaded
/// into the task register during init.
static mut TSS: TaskStateSegment = TaskStateSegment::new();

#[cfg(target_arch = "x86")]
use core::arch::asm;

/// Size of the dedicated ring-0 stack below.
const RING0_STACK_SIZE: usize = 16 * 1024;

/// The ring-0 stack gate entries from ring 3 switch to (TSS esp0).
/// Keep it generous: exception dumps and (later) syscall handlers run
/// here; the boot stack stays untouched by ring switches.
static mut RING0_STACK: [u8; RING0_STACK_SIZE] = [0; RING0_STACK_SIZE];

// The GDTR the `lgdt` instruction consumes (segment limit + linear base) is
// built on the stack by the assembly helper from its two arguments.

/// Load our GDT, initialize the TSS and load the task register.
///
/// The TSS descriptor is built here (it carries a runtime address),
/// the TSS is pointed at the dedicated ring-0 stack for gate entries
/// from ring 3, and `ltr` makes the CPU use it. Segment registers are
/// reloaded for the new table (CS via a far jump in the assembly
/// helper).
///
/// # Safety
///
/// Must run on the boot CPU in ring 0 with interrupts disabled.
#[cfg(target_arch = "x86")]
pub unsafe fn init() {
    let gdt = core::ptr::addr_of_mut!(GDT) as *mut u64;
    let base = gdt as u32;
    let limit = (core::mem::size_of::<[u64; 6]>() - 1) as u16;
    let tss_addr = core::ptr::addr_of_mut!(TSS) as u32;
    // SAFETY: boot CPU, ring 0, interrupts disabled; the GDT is not
    // loaded yet and these statics have no other accessor.
    unsafe {
        core::ptr::write_volatile(
            gdt.add(5),
            tss_descriptor(tss_addr, (core::mem::size_of::<TaskStateSegment>() - 1) as u32),
        );
        let tss = &mut *core::ptr::addr_of_mut!(TSS);
        tss.esp0 = (core::ptr::addr_of_mut!(RING0_STACK) as *mut u8 as u32)
            + RING0_STACK_SIZE as u32;
        tss.ss0 = KERNEL_DATA_SELECTOR;
        // No I/O bitmap: every ring-3 port access faults (the smoke
        // and the later syscall layer have no business with ports).
        tss.iomap_base = core::mem::size_of::<TaskStateSegment>() as u16;
    }
    // SAFETY: boot CPU, ring 0, interrupts disabled; the GDT is 'static.
    gdt_load(base, limit);
    // SAFETY: the TSS descriptor is in the loaded table and available
    // (non-busy); ltr loads the task register and marks the descriptor
    // busy in the GDT, and has no other effect.
    unsafe {
        asm!("ltr {tss:x}", tss = in(reg) TSS_SELECTOR, options(nostack, preserves_flags));
    }
}

/// Read one descriptor after `init`: the fault-injection boot paths
/// (`fault-test-ud` / `fault-test-gp`) use it to prove the CPU did not
/// write to the read-only table.
#[cfg(any(feature = "fault-test-ud", feature = "fault-test-gp"))]
pub(crate) fn debug_descriptor(index: usize) -> u64 {
    // SAFETY: reads a static array with a constant index at the call site.
    unsafe { core::ptr::read_volatile((core::ptr::addr_of!(GDT) as *const u64).add(index)) }
}

#[cfg(target_arch = "x86")]
unsafe extern "C" {
    /// Builds a GDTR from `base`/`limit`, loads it and reloads all segment
    /// registers.
    fn gdt_load(base: u32, limit: u16);
}

#[cfg(target_arch = "x86")]
core::arch::global_asm!(
    ".section .text.gdt_load, \"ax\"",
    ".global gdt_load",
    "gdt_load:",
    "    sub esp, 6",
    // 2nd arg (limit) is at [esp+14] after the 6-byte GDTR, 1st (base) at [esp+10]
    "    mov ax, [esp + 14]",
    "    mov [esp], ax",             // GDTR.limit
    "    mov eax, [esp + 10]",
    "    mov [esp + 2], eax",        // GDTR.base
    "    lgdt [esp]",
    "    add esp, 6",
    "    mov ax, {data_selector}",
    "    mov ds, ax",
    "    mov es, ax",
    "    mov fs, ax",
    "    mov gs, ax",
    "    mov ss, ax",
    "    mov eax, offset gdt_cs_reloaded",  // far return frame: EIP first,
    "    push {code_selector}",             // then new CS,
    "    push eax",                         // EIP on top for retf
    "    retf",                             // reload CS via the code selector
    "gdt_cs_reloaded:",                     // label is local to this block
    "    ret",
    data_selector = const KERNEL_DATA_SELECTOR,
    code_selector = const KERNEL_CODE_SELECTOR,
);

#[cfg(test)]
mod tests {
    use super::*;

    /// Independent packing oracle: packs a segment descriptor straight from
    /// the x86 layout — 20-bit limit split across bytes 0-1 and the low
    /// nibble of byte 6, 32-bit base split across bytes 2-3, byte 4 and
    /// byte 7, access byte 5, flags nibble in the high half of byte 6.
    /// Pres is always set, D/B always 1, Sys/L always 0.
    fn oracle_entry(base: u32, limit: u32, type_field: u8, dpl: u8, gran: bool) -> u64 {
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

    /// Read one link-time GDT entry (tests never run init).
    fn entry(index: usize) -> u64 {
        // SAFETY: read-only access to the static before any boot code.
        unsafe { core::ptr::read_volatile((core::ptr::addr_of!(GDT) as *const u64).add(index)) }
    }

    /// Flat segments: null descriptor, kernel code (0x9B) and data
    /// (0x93), user code (0xFB) and data (0xF3), all with the accessed
    /// bit pre-set so segment loads never write to the read-only table;
    /// all base 0, 4 GiB, page-granular 32-bit (flags 0xC). Slot 5 is
    /// zero at static time — init fills it with the TSS descriptor.
    #[test]
    fn gdt_entries_are_flat_segments() {
        assert_eq!(core::mem::size_of::<[u64; 6]>(), 6 * 8);
        assert_eq!(entry(0), 0); // null descriptor
        assert_eq!(entry(1), 0x00CF_9B00_0000_FFFF); // kernel code, accessed
        assert_eq!(entry(2), 0x00CF_9300_0000_FFFF); // kernel data, accessed
        assert_eq!(entry(3), 0x00CF_FB00_0000_FFFF); // user code, accessed
        assert_eq!(entry(4), 0x00CF_F300_0000_FFFF); // user data, accessed
        assert_eq!(entry(5), 0); // TSS descriptor: built at runtime
    }

    /// Selector layout: kernel segments in slots 1-2, user segments in
    /// 3-4, TSS in 5; the ring-3 entry forms CS/SS with RPL 3.
    #[test]
    fn selectors_pin_the_slot_layout() {
        assert_eq!(KERNEL_CODE_SELECTOR, 0x08);
        assert_eq!(KERNEL_DATA_SELECTOR, 0x10);
        assert_eq!(USER_CODE_SELECTOR, 0x18);
        assert_eq!(USER_DATA_SELECTOR, 0x20);
        assert_eq!(TSS_SELECTOR, 0x28);
        // Ring-3 entry forms: selectors with RPL 3 in the low bits.
        assert_eq!(USER_CODE_SELECTOR | 3, 0x1B);
        assert_eq!(USER_DATA_SELECTOR | 3, 0x23);
        // The GDT limit covers exactly the six entries (last valid byte).
        assert_eq!(core::mem::size_of::<[u64; 6]>() - 1, 47);
    }

    /// The TSS descriptor agrees with the independent packing oracle:
    /// access byte 0x89 = present, ring 0, system, available 32-bit
    /// TSS (non-busy, so `ltr` accepts it; the CPU sets the busy bit
    /// in the GDT); byte-granular flags nibble with only the 32-bit
    /// TSS bit set.
    #[test]
    fn tss_descriptor_matches_independent_oracle() {
        // Independent oracle: builds the descriptor straight from the
        // byte layout without the code's packer — byte 6 carries only
        // limit 19:16, the flags nibble stays clear (32-bit-vs-16-bit
        // is the type nibble).
        fn tss_oracle(base: u32, limit: u32) -> u64 {
            let limit_hi = ((limit >> 16) & 0xF) as u64;
            (((base >> 24) as u64) << 56)
                | (limit_hi << 48)
                | (0x89u64 << 40)
                | (((base >> 16) & 0xFF) as u64) << 32
                | ((base & 0xFFFF) as u64) << 16
                | ((limit & 0xFFFF) as u64)
        }
        for &(base, limit) in &[(0u32, 0x67u32), (0x0012_3456, 0x67), (0xFFFF_0000, 0x1_2345)] {
            assert_eq!(tss_descriptor(base, limit), tss_oracle(base, limit));
        }
        // Hand-decoded: byte 7 = base 31:24 (0x00), byte 6 = limit
        // 19:16 (0), byte 5 = 0x89, byte 4 = base 23:16 (0x12),
        // bytes 3:2 = base 15:0 (0x3456), bytes 1:0 = limit 15:0
        // (0x0067).
        assert_eq!(tss_descriptor(0x0012_3456, 0x67), 0x0000_8912_3456_0067);
        // A limit spanning more than 16 bits lands in byte 6 without
        // touching the undefined flag bits: limit 19:16 (bits 51:48)
        // is 1, the flags nibble (55:52) stays clear.
        let wide = tss_descriptor(0, 0x1_2345);
        assert_eq!((wide >> 48) & 0xF, 1);
        assert_eq!((wide >> 52) & 0xF, 0);
    }

    /// The TSS matches the x86 layout: 104 bytes, selectors in 4-byte
    /// slots (16-bit selector plus 16 reserved bits) from 0x48 on, so
    /// a hardware task switch loads every field from its architectural
    /// offset.
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

    /// make_entry must agree with the independent oracle for non-flat
    /// inputs too: byte-granular (G=0), ring-3, high bases, split limits.
    #[test]
    fn packing_matches_independent_oracle() {
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
                oracle_entry(base, limit, 0x1B, 0, true),
                "code descriptor base={base:#x} limit={limit:#x}"
            );
            assert_eq!(
                make_entry(base, limit, 0x93, 0xC),
                oracle_entry(base, limit, 0x13, 0, true),
                "data descriptor base={base:#x} limit={limit:#x}"
            );
        }
        assert_eq!(
            make_entry(0x10_0000, 0xF_FFFF, 0x9B, 0x4),
            oracle_entry(0x10_0000, 0xF_FFFF, 0x1B, 0, false)
        );
        assert_eq!(
            make_entry(0, 0xF_FFFF, 0xFB, 0xC),
            oracle_entry(0, 0xF_FFFF, 0x1B, 3, true)
        );
    }

    /// Hand-decoded non-flat descriptor, per the byte layout:
    /// byte7 = 0x12 (base 31:24), byte6 = 0xC1 (flags 0xC, limit 19:16 = 1),
    /// byte5 = 0x9B, byte4 = 0x34 (base 23:16), bytes 3:2 = 0x5678,
    /// bytes 1:0 = 0x2345 (limit 15:0).
    #[test]
    fn non_flat_descriptor_decodes_correctly() {
        assert_eq!(
            make_entry(0x1234_5678, 0x0123_45, 0x9B, 0xC),
            0x12C1_9B34_5678_2345
        );
    }
}
