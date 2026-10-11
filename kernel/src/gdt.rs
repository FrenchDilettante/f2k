//! Global Descriptor Table.
//!
//! Multiboot loaders boot the kernel with their own GDT, but we take over
//! early so the memory model is ours from the start: a flat 32-bit address
//! space with one kernel code and one kernel data segment, both base 0,
//! limit 4 GiB. This matches the flat protected-mode model Windows 2000
//! runs in and keeps the door open for a TSS and user segments later.

/// Selector offsets into the GDT (in bytes; low 3 bits are RPL/TI and stay 0
/// for kernel access). Pinned to the slot order below and fed to
/// `gdt_load`'s assembly via `const` operands, so nothing can drift.
pub const KERNEL_CODE_SELECTOR: u16 = 0x08;
pub const KERNEL_DATA_SELECTOR: u16 = 0x10;

// Kernel selectors are GDT slot indices times 8: null, code and data are
// slots 0, 1 and 2; the RPL/TI bits stay clear for kernel access.
const _: () = assert!(KERNEL_CODE_SELECTOR == 0x08 && KERNEL_DATA_SELECTOR == 0x10);

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
/// accessed). G=1, D=1: 4 GiB page-granular 32-bit segments.
///
/// The accessed bit (access byte bit 0) is pre-set: the CPU sets it in the
/// GDT itself on every segment-register load, and pre-setting it keeps
/// this table read-only — the CPU never needs to write here, which matters
/// once paging maps the table's page read-only.
static GDT: [u64; 3] = [
    make_entry(0, 0, 0x00, 0x0),
    make_entry(0, 0xFFFFF, 0x9B, 0xC),
    make_entry(0, 0xFFFFF, 0x93, 0xC),
];

// The GDTR the `lgdt` instruction consumes (segment limit + linear base) is
// built on the stack by the assembly helper from its two arguments.

/// Load our GDT and reload every segment register (including CS via a far
/// jump, which cannot be done from inline assembly).
///
/// # Safety
///
/// Must run on the boot CPU in ring 0 with interrupts disabled.
#[cfg(target_arch = "x86")]
pub unsafe fn init() {
    let base = core::ptr::addr_of!(GDT) as u32;
    let limit = (core::mem::size_of::<[u64; 3]>() - 1) as u16;
    // SAFETY: boot CPU, ring 0, interrupts disabled; the GDT is 'static.
    gdt_load(base, limit);
}

/// Test hook for the fault-injection boot paths (`fault-test-ud` /
/// `fault-test-gp`): read one descriptor after `init`, so the boot log can
/// prove the CPU did not write to the read-only table.
#[cfg(any(feature = "fault-test-ud", feature = "fault-test-gp"))]
pub(crate) fn debug_descriptor(index: usize) -> u64 {
    // SAFETY: reads a static array with a constant index at the call site.
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(GDT[index])) }
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

    /// Flat kernel segments: null descriptor, then code (0x9B) and data
    /// (0x93) with the accessed bit pre-set, so segment loads never write
    /// to the read-only table. All base 0, 4 GiB, page-granular 32-bit
    /// (flags 0xC).
    #[test]
    fn gdt_entries_are_flat_kernel_segments() {
        assert_eq!(GDT.len(), 3);
        assert_eq!(GDT[0], 0); // null descriptor
        assert_eq!(GDT[1], 0x00CF_9B00_0000_FFFF); // kernel code, accessed
        assert_eq!(GDT[2], 0x00CF_9300_0000_FFFF); // kernel data, accessed
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
