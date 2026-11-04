//! The target side of the VBE driver: the real-mode trampoline the BIOS calls run through, and the
//! graphics-mode entry that maps the framebuffer and paints the desktop.
//!
//! The trampoline owns one run of conventional memory, reserved at boot for it alone
//! ([`crate::mem::bootmem::TRAMPOLINE_FIRST_FRAME`], physical 0x90000-0x9AFFF): no other owner ever
//! holds those frames, so the blob, the BIOS and the kernel write them freely while the mode set
//! runs (and the mode set runs once at a time, [`ModeSet`]). The run is one real-mode segment,
//! 0x9000, which every segment register holds in real mode:
//!
//! | Offset   | Contents                                                                |
//! |----------|-------------------------------------------------------------------------|
//! | `0x0000` | the blob's code ([`vbe_blob`], position-independent)                    |
//! | `0x1000` | the `AX=4F00h` VBE information block (512 bytes)                        |
//! | `0x1200` | the save area ([`SaveArea`]): what the blob is handed, keeps and answers |
//! | `0x2000` | the real-mode stack (its top at `0x3000`)                               |
//! | `0x3000` | the mode-info buffer: a 256-byte block per listed mode, [`MAX_MODES`]   |
//!
//! [`vbe_enter`] follows Intel's procedure for the switch to real mode (SDM vol. 3, 9.9.2) and
//! back: it enters the blob at the run's physical address with paging still on (the caller installs
//! the low identity window, [`crate::mem::paging::install_low_identity`]); the blob loads the
//! transition GDT and jumps into its 16-bit code segment, loads the 16-bit data segment (64 KiB
//! limits, B=0) into SS, DS, ES, FS and GS, turns paging off, loads the real-mode IDT (the BIOS's
//! vector table), clears PE and far-jumps to reload CS. There it issues the VBE calls (`int 10h`:
//! `AX=4F00h`, then either `AX=4F01h` for every listed mode or `AX=4F02h` when armed) and returns:
//! PE on, a far jump into its 32-bit code segment, the kernel's GDT, paging on, the kernel's data
//! segments and stack, a far return into the kernel image, the kernel's IDT.
//!
//! An NMI while neither IDT is usable — from the transition GDT's load to real mode, and from PE's
//! return to the kernel IDT's — would shut the machine down. Both windows are a dozen instructions
//! with no memory traffic but the save area's; F2K arms no NMI source (no watchdog), so only a
//! hardware error (parity, a channel check) raises one, and that is fatal anyway.

use core::mem::offset_of;
use core::sync::atomic::Ordering;

use super::{
    Bios,
    Entry,
    Framebuffer,
    Geometry,
    ModeError,
    ModeRequest,
    ModeSet,
    PixelMemory,
    MAX_MODES,
    MODE_INFO_BYTES,
    VBE_HEADER_BYTES,
    VBE_INFO_BYTES,
    VBE_INFO_MODE_LIST,
};
use crate::mem::bootmem::{TRAMPOLINE_FIRST_FRAME, TRAMPOLINE_FRAMES};
use crate::mem::paging::KERNEL_BASE;
use crate::sync::InitOnce;

/// The run's physical address: fixed, because the real-mode segment is derived from it.
const RUN: u32 = TRAMPOLINE_FIRST_FRAME * 0x1000;
/// The real-mode segment whose base is the run: 0x9000 (real mode takes base = segment << 4).
const RUN_SEGMENT: u16 = (RUN >> 4) as u16;

// The run's layout, by offset (also the real-mode offsets: every segment is the run's).
const VBE_INFO: u32 = 0x1000;
const SAVE: u32 = 0x1200;
const STACK_TOP: u32 = 0x3000;
const MODE_BUFFER: u32 = 0x3000;
const MODE_BUFFER_END: u32 = MODE_BUFFER + MAX_MODES as u32 * MODE_INFO_BYTES as u32;

const _: () = {
    assert!(VBE_INFO + VBE_INFO_BYTES as u32 <= SAVE);
    assert!(SAVE + core::mem::size_of::<SaveArea>() as u32 <= 0x2000);
    assert!(
        MODE_BUFFER_END <= TRAMPOLINE_FRAMES * 0x1000,
        "the run holds the buffer"
    );
    assert!(MODE_BUFFER_END <= 0x1_0000, "one real-mode segment");
};

// The transition GDT's selectors.
const CODE16: u16 = 0x08;
const DATA16: u16 = 0x10;
const CODE32: u16 = 0x18;

/// A segment descriptor: `base`, a byte-granular 16-bit `limit`, the access byte, and the flags
/// nibble (bit 2: D/B, a 32-bit segment).
const fn descriptor(base: u32, limit: u16, access: u8, flags: u8) -> u64 {
    limit as u64
        | ((base as u64 & 0x00FF_FFFF) << 16)
        | ((access as u64) << 40)
        | (((flags & 0xF) as u64) << 52)
        | (((base >> 24) as u64) << 56)
}

/// The transition GDT, every segment based at the run with 64 KiB limits: a 16-bit code segment,
/// the 16-bit data segment Intel's procedure loads before real mode (writable, B=0), and the 32-bit
/// code segment the way back enters.
const TRANSITION_GDT: [u64; 4] = [
    0,
    descriptor(RUN, 0xFFFF, 0x9A, 0),
    descriptor(RUN, 0xFFFF, 0x92, 0),
    descriptor(RUN, 0xFFFF, 0x9A, 0x4),
];

const _: () = assert!(TRANSITION_GDT[1] == 0x0000_9A09_0000_FFFF);

/// A descriptor-table register's image, as LGDT and LIDT read it and SGDT and SIDT write it: the
/// limit, then the 32-bit base (as two halves, which keeps the record 2-aligned, as the
/// instructions lay it out).
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct TableRegister {
    limit: u16,
    base: [u16; 2],
}

impl TableRegister {
    const fn new(base: u32, limit: u16) -> Self {
        TableRegister {
            limit,
            base: [base as u16, (base >> 16) as u16],
        }
    }
}

/// A 16-bit far pointer, as a far JMP through memory reads it in 16-bit code: offset, selector.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FarPointer16 {
    offset: u16,
    selector: u16,
}

/// The save area in the run: what the kernel hands the blob, what the blob keeps across the BIOS
/// calls, and what it answers.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SaveArea {
    /// The transition GDT ([`TRANSITION_GDT`]) and its register image.
    gdt: [u64; 4],
    gdtr: TableRegister,
    /// The real-mode IDT: the BIOS's vector table at 0, 256 vectors.
    real_mode_idtr: TableRegister,
    /// The kernel's GDT and IDT registers, as `vbe_enter` saved them.
    kernel_gdtr: TableRegister,
    kernel_idtr: TableRegister,
    /// The kernel stack `vbe_enter` returns on.
    kernel_esp: u32,
    /// The 16-bit code's entry offset, for the 32-bit far return into it.
    rm_entry: u32,
    /// The far jumps that reload CS in real mode, and that enter the 32-bit code on the way back.
    to_real_mode: FarPointer16,
    to_protected_mode: FarPointer16,
    /// Whether this run sets the mode, and the `AX=4F02h` call's BX.
    set_mode: u16,
    mode_bx: u16,
    /// The `AX=4F00h` call's AX, and the `AX=4F02h` call's (4Fh when this run does not set it).
    info_result: u16,
    set_result: u16,
    /// The scan: the mode list's far pointer, the next index, the next block's offset, and how
    /// many blocks were fetched.
    mode_list: u32,
    scan_index: u16,
    scan_offset: u16,
    scan_count: u16,
}

/// A save-area field's physical address: `vbe_enter` and `pm_entry` reach it through the identity
/// window and the kernel window.
const fn save(field: usize) -> u32 {
    RUN + SAVE + field as u32
}

/// A save-area field's offset in the run: the real-mode and 16-bit code reach it through DS.
const fn save_off(field: usize) -> u32 {
    SAVE + field as u32
}

extern "C" {
    fn vbe_blob();
    fn vbe_blob_end();
    fn rm_entry();
    fn rm_real();
    fn pm_entry();
    /// Run the blob copied into the run, through real mode and back (its arguments are in the save
    /// area). Called with the low identity window installed; returns with paging on, the window
    /// still installed, and the caller's interrupt flag.
    fn vbe_enter();
}

/// `label`'s offset in the blob (computed where function pointers may be cast to integers, at run
/// time: the assembler takes no label differences as immediates, so the blob reads them from the
/// save area).
fn blob_offset(label: unsafe extern "C" fn()) -> u16 {
    (label as *const () as usize - vbe_blob as *const () as usize) as u16
}

core::arch::global_asm!(
    ".section .text.vbe_trampoline, \"ax\"",
    ".code32",
    ".global vbe_blob",
    ".global vbe_blob_end",
    ".global rm_entry",
    ".global rm_real",
    ".global pm_entry",
    "vbe_blob:",
    // 32-bit protected mode, paging on, the kernel's segments and stack, at the run's physical
    // address (the identity window maps it). The transition GDT, then its 16-bit code segment.
    "    lgdt [{gdtr}]",
    "    push {code16}",
    "    push dword ptr [{rm_entry_ptr}]",
    "    retf",
    ".code16",
    "rm_entry:", // 16-bit protected mode, paging on, CS the run
    // Intel's procedure: the 16-bit data segment into every data register (64 KiB limits, B=0),
    // so real mode inherits neither flat limits nor a 32-bit stack; then paging off (this code is
    // identity-mapped; the change of CR0.PG flushes the TLB), the real-mode IDT, PE off.
    "    mov ax, {data16}",
    "    mov ds, ax",
    "    mov es, ax",
    "    mov fs, ax",
    "    mov gs, ax",
    "    mov ss, ax",
    "    mov esp, {stack_top}", // the 32-bit form: ESP's upper half 0
    "    mov eax, cr0",
    "    and eax, 0x7FFFFFFF",
    "    mov cr0, eax", // paging off
    "    lidt [{real_mode_idtr}]", // the BIOS's vector table, read through DS (the run)
    "    and eax, 0xFFFFFFFE",
    "    mov cr0, eax", // PE off: real mode
    "    ljmp [{to_real_mode}]", // CS reloaded as RUN_SEGMENT: an iret reloads it from the selector
    "rm_real:", // real mode, every segment the run
    "    mov ax, {run_segment}",
    "    mov ds, ax",
    "    mov es, ax",
    "    mov fs, ax",
    "    mov gs, ax",
    "    mov ss, ax",
    "    mov sp, {stack_top}",
    "    sti", // the BIOS handlers may wait on interrupts; the caller masked every line
    // AX=4F00h: the VBE information block to es:di.
    "    mov ax, 0x4F00",
    "    mov di, {vbe_info}",
    "    int 0x10",
    "    mov [{info_result}], ax",
    "    cmp word ptr [{set_mode}], 0",
    "    jne vbe_rm_set",
    // The scan: every listed mode's information block into the buffer, so the kernel reads them all
    // without a BIOS round trip per mode.
    "    mov ax, [{vbe_info_list}]",
    "    mov [{mode_list}], ax",
    "    mov ax, [{vbe_info_list} + 2]",
    "    mov [{mode_list} + 2], ax",
    "    mov word ptr [{scan_index}], 0",
    "    mov word ptr [{scan_offset}], {mode_buffer}",
    "vbe_scan_loop:",
    "    cmp word ptr [{scan_index}], {max_modes}",
    "    jae vbe_scan_done",
    "    mov bx, [{scan_index}]",
    "    shl bx, 1",
    "    les si, [{mode_list}]",
    "    mov cx, es:[si + bx]",
    "    cmp cx, 0xFFFF",
    "    je vbe_scan_done",
    "    mov ax, {run_segment}",
    "    mov es, ax",
    "    mov di, [{scan_offset}]",
    "    mov ax, 0x4F01",
    "    int 0x10",
    "    add word ptr [{scan_offset}], {mode_info_bytes}",
    "    inc word ptr [{scan_index}]",
    "    jmp vbe_scan_loop",
    "vbe_scan_done:",
    "    mov ax, [{scan_index}]",
    "    mov [{scan_count}], ax",
    "    mov word ptr [{set_result}], 0x004F",
    "    jmp vbe_rm_back",
    // AX=4F02h, when the caller armed it.
    "vbe_rm_set:",
    "    mov ax, 0x4F02",
    "    mov bx, [{mode_bx}]",
    "    int 0x10",
    "    mov [{set_result}], ax",
    "vbe_rm_back:",
    "    cli",
    "    mov ax, {run_segment}",
    "    mov ds, ax",
    // Back to protected mode, then a far jump through memory into the 32-bit code segment.
    "    mov eax, cr0",
    "    or eax, 1",
    "    mov cr0, eax", // PE on; CS still the real-mode segment
    "    ljmp [{to_protected_mode}]",
    ".code32",
    "pm_entry:", // 32-bit protected mode, paging off, CS the run; DS keeps real mode's base, the run
    "    lgdt [{kernel_gdtr_off}]", // the kernel's GDT, its base the kernel window's
    "    mov eax, cr0",
    "    or eax, 0x80000000",
    "    mov cr0, eax", // paging on: the identity window maps this fetch, the kernel window the GDT
    "    mov ax, {kernel_data}",
    "    mov ds, ax",
    "    mov es, ax",
    "    mov ss, ax",
    "    mov esp, [{kernel_esp_va}]",
    "    lea eax, [vbe_pm_virtual]",
    "    push {kernel_code}",
    "    push eax",
    "    retf", // to the kernel image's own copy of what follows
    "vbe_blob_end:",
    "vbe_pm_virtual:", // the kernel image, the kernel's code segment
    "    lidt [{kernel_idtr_va}]",
    "    pop gs",
    "    pop fs",
    "    popad",
    "    popfd", // the caller's interrupt flag, as vbe_enter found it
    "    ret",
    // The entry, from the kernel window: the state to come back to into the save area (through the
    // kernel window, which maps the run in every address space), then a jump to the blob's physical
    // address, paging still on.
    ".global vbe_enter",
    "vbe_enter:",
    "    pushfd",
    "    cli",
    "    pushad",
    "    push fs",
    "    push gs",
    "    in al, 0x92", // the fast A20 gate
    "    test al, 0x02",
    "    jnz vbe_enter_a20",
    "    or al, 0x02",
    "    and al, 0xFE",
    "    out 0x92, al",
    "vbe_enter_a20:",
    "    mov [{kernel_esp_va}], esp",
    "    sgdt [{kernel_gdtr_va}]",
    "    sidt [{kernel_idtr_va}]",
    "    mov eax, {run}",
    "    jmp eax",
    run = const RUN,
    run_segment = const RUN_SEGMENT,
    code16 = const CODE16,
    data16 = const DATA16,
    kernel_code = const crate::cpu::gdt::KERNEL_CODE_SELECTOR,
    kernel_data = const crate::cpu::gdt::KERNEL_DATA_SELECTOR,
    stack_top = const STACK_TOP,
    vbe_info = const VBE_INFO,
    vbe_info_list = const VBE_INFO + VBE_INFO_MODE_LIST as u32,
    mode_buffer = const MODE_BUFFER,
    max_modes = const MAX_MODES,
    mode_info_bytes = const MODE_INFO_BYTES,
    gdtr = const save(offset_of!(SaveArea, gdtr)),
    rm_entry_ptr = const save(offset_of!(SaveArea, rm_entry)),
    real_mode_idtr = const save_off(offset_of!(SaveArea, real_mode_idtr)),
    to_real_mode = const save_off(offset_of!(SaveArea, to_real_mode)),
    to_protected_mode = const save_off(offset_of!(SaveArea, to_protected_mode)),
    set_mode = const save_off(offset_of!(SaveArea, set_mode)),
    mode_bx = const save_off(offset_of!(SaveArea, mode_bx)),
    info_result = const save_off(offset_of!(SaveArea, info_result)),
    set_result = const save_off(offset_of!(SaveArea, set_result)),
    mode_list = const save_off(offset_of!(SaveArea, mode_list)),
    scan_index = const save_off(offset_of!(SaveArea, scan_index)),
    scan_offset = const save_off(offset_of!(SaveArea, scan_offset)),
    scan_count = const save_off(offset_of!(SaveArea, scan_count)),
    kernel_gdtr_off = const save_off(offset_of!(SaveArea, kernel_gdtr)),
    kernel_gdtr_va = const KERNEL_BASE + save(offset_of!(SaveArea, kernel_gdtr)),
    kernel_idtr_va = const KERNEL_BASE + save(offset_of!(SaveArea, kernel_idtr)),
    kernel_esp_va = const KERNEL_BASE + save(offset_of!(SaveArea, kernel_esp)),
);

/// The run's save area, through the kernel window (which maps conventional memory in every
/// address space).
fn save_area() -> *mut SaveArea {
    (KERNEL_BASE + RUN + SAVE) as *mut SaveArea
}

/// The BIOS over the trampoline: each run of the blob leaves the BIOS's answers in the run, which
/// is the trampoline's alone, and they are read from there through the kernel window.
pub struct TrampolineBios {
    info_ran: bool,
}

impl TrampolineBios {
    /// The trampoline's BIOS, if its run was reserved at boot; none without it.
    pub fn new() -> Option<Self> {
        crate::mem::bootmem::TRAMPOLINE_RESERVED
            .load(Ordering::Relaxed)
            .then_some(TrampolineBios { info_ran: false })
    }

    /// Run the blob: copy it into the run, fill the save area (`set_mode` arms the `AX=4F02h` call
    /// with that BX), and drop into real mode and back in the boot directory with the low identity
    /// window installed.
    fn run(&mut self, set_mode: Option<u16>) {
        let size = vbe_blob_end as *const () as usize - vbe_blob as *const () as usize;
        assert!(size <= VBE_INFO as usize, "the trampoline fits its page");
        let area = SaveArea {
            gdt: TRANSITION_GDT,
            gdtr: TableRegister::new(save(offset_of!(SaveArea, gdt)), 4 * 8 - 1),
            real_mode_idtr: TableRegister::new(0, 0x3FF),
            rm_entry: blob_offset(rm_entry) as u32,
            to_real_mode: FarPointer16 {
                offset: blob_offset(rm_real),
                selector: RUN_SEGMENT,
            },
            to_protected_mode: FarPointer16 {
                offset: blob_offset(pm_entry),
                selector: CODE32,
            },
            set_mode: set_mode.is_some() as u16,
            mode_bx: set_mode.unwrap_or(0),
            ..SaveArea::default()
        };
        // SAFETY: the run is reserved at boot for the trampoline alone (`new` checked) and mapped
        // in the kernel window for the kernel's lifetime; the mode set runs once at a time
        // (`ModeSet`), so nothing else reads or writes it. The blob is `size` bytes of the kernel
        // image, copied into the run's first page. `vbe_enter` writes only the run and returns
        // with paging on, the identity window still installed, and the caller's interrupt flag.
        unsafe {
            let page = (KERNEL_BASE + RUN) as *mut u8;
            core::ptr::copy_nonoverlapping(vbe_blob as *const u8, page, size);
            save_area().write_volatile(area);
            // Run in the boot directory, whose low entries are free: the identity window must not
            // clobber the calling process's user mappings. The framebuffer region's tables are
            // shared, so the LFB mapping lands in every address space anyway.
            let caller_dir = crate::mem::paging::current_directory_phys();
            crate::mem::paging::activate_address_space(crate::mem::paging::boot_directory_phys());
            crate::mem::paging::install_low_identity();
            crate::interrupt::with_lines_masked(|| vbe_enter());
            crate::mem::paging::remove_low_identity();
            crate::mem::paging::activate_address_space(caller_dir);
        }
    }

    /// The save area as the last run left it.
    fn answers(&self) -> SaveArea {
        // SAFETY: the run's save area, the trampoline's alone (see `run`), read through the
        // kernel window.
        unsafe { save_area().read_volatile() }
    }

    /// Run the blob once for the information calls.
    fn ensure_info(&mut self) {
        if !self.info_ran {
            self.run(None);
            self.info_ran = true;
        }
    }
}

impl Bios for TrampolineBios {
    fn vbe_info(&mut self, header: &mut [u8; VBE_HEADER_BYTES]) -> bool {
        self.ensure_info();
        // SAFETY: the information block is in the run, the trampoline's alone (see `run`), read
        // through the kernel window.
        unsafe {
            core::ptr::copy_nonoverlapping(
                (KERNEL_BASE + RUN + VBE_INFO) as *const u8,
                header.as_mut_ptr(),
                VBE_HEADER_BYTES,
            );
        }
        self.answers().info_result & 0xFF == 0x4F
    }

    fn mode(&mut self, index: usize) -> Option<u16> {
        self.ensure_info();
        if index >= MAX_MODES {
            return None;
        }
        // The list the information block's far pointer names: in the BIOS's memory or in the block
        // itself, below 1 MiB either way.
        let far = self.answers().mode_list;
        let phys = ((far >> 16) << 4) + (far & 0xFFFF);
        // SAFETY: the list is in conventional memory or the BIOS's, below 1 MiB, which the kernel
        // window maps; it is 0xFFFF-terminated, and the scan read it up to `index` already when
        // `index` is below the scan's count (and to its end otherwise).
        let mode = unsafe {
            ((KERNEL_BASE + phys) as *const u16)
                .add(index)
                .read_volatile()
        };
        (mode != 0xFFFF).then_some(mode)
    }

    fn mode_info(&mut self, mode: u16, bytes: &mut [u8; MODE_INFO_BYTES]) -> bool {
        self.ensure_info();
        // The scan fetched the information block of each of the list's first `scan_count` modes
        // into the buffer, in list order: read `mode`'s from there, no BIOS round trip per mode.
        let count = self.answers().scan_count as usize;
        let Some(index) = (0..count).find(|&index| self.mode(index) == Some(mode)) else {
            return false;
        };
        // SAFETY: the buffer is in the run, the trampoline's alone (see `run`), read through the
        // kernel window; `index` is below the scan's count, so its block is inside the buffer.
        unsafe {
            core::ptr::copy_nonoverlapping(
                (KERNEL_BASE + RUN + MODE_BUFFER + (index * MODE_INFO_BYTES) as u32) as *const u8,
                bytes.as_mut_ptr(),
                MODE_INFO_BYTES,
            );
        }
        true
    }

    fn set_mode(&mut self, mode: u16) -> bool {
        self.run(Some(mode));
        self.answers().set_result & 0xFF == 0x4F
    }
}

/// The framebuffer's pixel memory on target: the kernel's uncached mapping of the LFB, at `base`
/// (the LFB's own virtual address).
pub struct LfbMemory {
    base: u32,
}

impl PixelMemory for LfbMemory {
    fn store(&mut self, offset: usize, value: u32) {
        // SAFETY: the LFB is mapped for the kernel's lifetime once the mode is set, and the
        // framebuffer's clipping keeps the offset inside the mode's size. The store is device
        // memory: volatile.
        unsafe {
            ((self.base + offset as u32) as *mut u32).write_volatile(value);
        }
    }
}

/// The graphics mode's state: set once, by the first caller to find it unset.
static STATE: ModeSet = ModeSet::new();
/// The mode's geometry and the LFB's virtual address, set by the caller that set the mode before
/// [`STATE`] says set.
static MODE: InitOnce<(Geometry, u32)> = InitOnce::new();

/// Whether the graphics mode is set.
pub fn graphics_mode_set() -> bool {
    STATE.is_set()
}

/// The work of the mode set: the trampoline's BIOS, the LFB mapped into the framebuffer region,
/// the screen cleared to the desktop color.
fn do_set(request: &ModeRequest) -> Result<(Geometry, u32), ModeError> {
    let mut bios = TrampolineBios::new().ok_or(ModeError::Unsupported)?;
    let (geometry, lfb_va) = super::set_graphics_mode(&mut bios, request, &mut |base, bytes| {
        crate::mem::paging::map_framebuffer(base, bytes)
    })?;
    Framebuffer::new(LfbMemory { base: lfb_va }, geometry).clear(super::DESKTOP_RGB);
    Ok((geometry, lfb_va))
}

/// The mode that was set, if it answers `request`: the mode is set once, and no other is offered
/// after it.
fn set_mode_for(request: &ModeRequest) -> Result<Geometry, ModeError> {
    let geometry = MODE.get().0;
    if request.matches(&geometry) {
        Ok(geometry)
    } else {
        Err(ModeError::Unsupported)
    }
}

/// Set the graphics mode `request` asks for (once; later calls are answered the mode that was
/// set, when it answers them): the VBE mode set through the trampoline, the LFB mapped, the screen
/// cleared to the desktop color. A call while another caller sets it is answered
/// [`ModeError::Busy`] at once, never made to wait.
pub fn enter_graphics_mode(request: &ModeRequest) -> Result<Geometry, ModeError> {
    match STATE.enter() {
        Entry::Set => set_mode_for(request),
        Entry::Busy => Err(ModeError::Busy),
        Entry::Proceed => {
            let result = do_set(request);
            if let Ok(mode) = result {
                MODE.set(mode);
            }
            STATE.finish(result.is_ok());
            result.map(|(geometry, _)| geometry)
        }
    }
}

/// The mode [`enter_graphics_mode`] would set for `request`, nothing set: the BIOS's list is read
/// through the trampoline, the display left as it is.
pub fn test_graphics_mode(request: &ModeRequest) -> Result<Geometry, ModeError> {
    match STATE.enter() {
        Entry::Set => set_mode_for(request),
        Entry::Busy => Err(ModeError::Busy),
        Entry::Proceed => {
            let result = TrampolineBios::new()
                .ok_or(ModeError::Unsupported)
                .and_then(|mut bios| super::choose_mode(&mut bios, request));
            STATE.finish(false);
            result.map(|(_, geometry)| geometry)
        }
    }
}

/// Run `f` against the framebuffer, when the graphics mode is set; none before it. (For the DC
/// and rasterizer, its first consumers.)
#[allow(dead_code)]
pub fn with_framebuffer<R>(f: impl FnOnce(&mut Framebuffer<LfbMemory>) -> R) -> Option<R> {
    if !STATE.is_set() {
        return None;
    }
    let &(geometry, base) = MODE.get();
    Some(f(&mut Framebuffer::new(LfbMemory { base }, geometry)))
}
