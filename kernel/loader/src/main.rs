//! F2K's boot loader: the Multiboot 1 image the loaders boot (QEMU's `-kernel`, Limine's
//! `multiboot1` protocol, GRUB), carrying the kernel's image, ntoskrnl.exe.
//!
//! It plays the part Windows 2000's loader plays for its kernel: it maps the image, relocates it,
//! and enters it. The Multiboot loader places the loader at physical 1 MiB and the image's file at
//! physical 4 MiB, where it runs (the linker script, `scripts/loader.x86`, gives both their places,
//! and reserves the image's memory past its file, so the Multiboot loader keeps its own structures
//! clear of it). Entered with paging off, the loader turns the file into the mapped image where it
//! lies and applies its base relocations when the image is not at its base
//! ([`f2k_loader::Image`]), maps the kernel image window, `[0x80000000, 0x81000000)`, over physical
//! `[0, 16 MiB)` with the low 16 MiB identity-mapped beside it, turns paging on, and jumps to the
//! image's entry point with the Multiboot loader's EAX and EBX as it left them. The kernel takes
//! over its own tables once its frame database exists; it keeps the loader's frames until then.
//!
//! The Multiboot loader's modules (the test boots' disk image) stay where it put them: the loader
//! refuses a module in the memory it writes, its own or the image's, before it writes any.
//!
//! An image the loader refuses is reported on COM1, and the machine halts.

#![no_std]
#![no_main]

use core::cell::UnsafeCell;

use f2k_loader::Image;

/// The kernel image window's start: physical memory from 0 appears here, 16 MiB of it.
const KERNEL_BASE: u32 = 0x8000_0000;
/// The window's page tables: one per 4 MiB.
const WINDOW_TABLES: usize = 4;
/// The window's size.
const WINDOW_SIZE: u32 = WINDOW_TABLES as u32 * 0x40_0000;
/// Page-table entry bits: present, writable.
const PRESENT_WRITABLE: u32 = 0x3;

// The image's place, from the linker script: the address it runs at, the physical address of its
// file (where the Multiboot loader put it), and its file's size. Only their addresses are taken.
unsafe extern "C" {
    static __loader_start: u8;
    static _loader_end: u8;
    static __image_va: u8;
    static __image_phys: u8;
    static __image_file_size: u8;
}

/// The page directory and the window's page tables, page-aligned, in the loader's own memory.
#[repr(C, align(4096))]
struct Tables(UnsafeCell<[[u32; 1024]; 1 + WINDOW_TABLES]>);

// SAFETY: the loader runs alone (one processor, interrupts off), and writes the tables once, before
// it turns paging on.
unsafe impl Sync for Tables {}

static TABLES: Tables = Tables(UnsafeCell::new([[0; 1024]; 1 + WINDOW_TABLES]));

core::arch::global_asm!(
    // The Multiboot 1 header: 4-byte aligned, within the file's first 8 KiB (the linker script
    // puts it first). Flags: modules page-aligned, the memory information provided.
    ".section .multiboot, \"a\"",
    ".align 4",
    ".long 0x1BADB002",
    ".long 0x00000003",
    ".long -(0x1BADB002 + 0x00000003)",
    // The loader's stack.
    ".section .bss.loader_stack, \"aw\", @nobits",
    ".align 16",
    ".skip 16384",
    "loader_stack_top:",
    // The entry: paging off, EAX the Multiboot magic, EBX the information structure's physical
    // address, no stack. `loader_main(magic, info)`, which never returns.
    ".section .text.entry, \"ax\"",
    ".global _start",
    "_start:",
    "    cld",
    "    mov esp, offset loader_stack_top",
    "    push ebx",
    "    push eax",
    "    call loader_main",
    "2:  cli",
    "    hlt",
    "    jmp 2b",
    // `loader_enter(directory, entry, magic, info)`: load the directory, turn paging on (CR0.PG,
    // with CR0.WP so read-only mappings bind the kernel too), and jump to the entry with the
    // Multiboot loader's EAX and EBX. The loader's code is identity-mapped, so the instruction
    // after the switch is fetched from the same place.
    ".section .text.loader_enter, \"ax\"",
    ".global loader_enter",
    "loader_enter:",
    "    mov ecx, [esp + 4]",
    "    mov edx, [esp + 8]",
    "    mov eax, [esp + 12]",
    "    mov ebx, [esp + 16]",
    "    mov cr3, ecx",
    "    mov ecx, cr0",
    "    or ecx, 0x80010000",
    "    mov cr0, ecx",
    "    jmp edx",
    // The C library's memory routines the compiler lowers copies and fills to: the string
    // instructions, one `rep` each, the direction flag clear (the entry clears it, and memmove
    // clears it again after a backward move).
    ".section .text.memcpy, \"ax\"",
    ".global memcpy",
    "memcpy:",
    "    push esi",
    "    push edi",
    "    mov edi, [esp + 12]",
    "    mov esi, [esp + 16]",
    "    mov ecx, [esp + 20]",
    "    rep movsb",
    "    mov eax, [esp + 12]",
    "    pop edi",
    "    pop esi",
    "    ret",
    // memmove: forwards unless the destination starts inside the source, then backwards from the
    // last byte with the direction flag set, and cleared again.
    ".section .text.memmove, \"ax\"",
    ".global memmove",
    "memmove:",
    "    push esi",
    "    push edi",
    "    mov edi, [esp + 12]",
    "    mov esi, [esp + 16]",
    "    mov ecx, [esp + 20]",
    "    mov eax, edi",
    "    sub eax, esi",
    "    cmp eax, ecx",
    "    jb 2f",
    "    rep movsb",
    "    jmp 3f",
    "2:",
    "    lea esi, [esi + ecx - 1]",
    "    lea edi, [edi + ecx - 1]",
    "    std",
    "    rep movsb",
    "    cld",
    "3:",
    "    mov eax, [esp + 12]",
    "    pop edi",
    "    pop esi",
    "    ret",
    ".section .text.memset, \"ax\"",
    ".global memset",
    "memset:",
    "    push edi",
    "    mov edi, [esp + 8]",
    "    mov eax, [esp + 12]",
    "    mov ecx, [esp + 16]",
    "    rep stosb",
    "    mov eax, [esp + 8]",
    "    pop edi",
    "    ret",
    // memcmp: `repe cmpsb` to the first differing byte; the result is its bytes' difference,
    // unsigned. A zero length compares nothing.
    ".section .text.memcmp, \"ax\"",
    ".global memcmp",
    "memcmp:",
    "    push esi",
    "    push edi",
    "    mov esi, [esp + 12]",
    "    mov edi, [esp + 16]",
    "    mov ecx, [esp + 20]",
    "    xor eax, eax",
    "    test ecx, ecx",
    "    jz 2f",
    "    repe cmpsb",
    "    je 2f",
    "    movzx eax, byte ptr [esi - 1]",
    "    movzx ecx, byte ptr [edi - 1]",
    "    sub eax, ecx",
    "2:",
    "    pop edi",
    "    pop esi",
    "    ret",
);

unsafe extern "C" {
    fn loader_enter(directory: u32, entry: u32, magic: u32, info: u32) -> !;
}

/// Map the kernel's image, relocate it when it is not at its base, map the window, and enter it.
#[unsafe(no_mangle)]
extern "C" fn loader_main(magic: u32, info: u32) -> ! {
    let load = &raw const __image_va as u32;
    let physical = &raw const __image_phys as u32;
    let file_len = &raw const __image_file_size as usize;
    if load.wrapping_sub(KERNEL_BASE) != physical {
        fail("the kernel image's address is not where the kernel image window maps its memory");
    }
    // SAFETY: the Multiboot loader put the image's file at `physical`, `file_len` bytes (the
    // linker script's placement), and nothing writes it while this borrow lasts.
    let file = unsafe { core::slice::from_raw_parts(physical as *const u8, file_len) };
    let image = Image::parse(file).unwrap_or_else(|refusal| fail(refusal.text()));
    let size = image.size_of_image();
    if physical as u64 + size as u64 > WINDOW_SIZE as u64 {
        fail(f2k_loader::Refusal::TooLarge.text());
    }
    check_modules(info, physical..physical + size as u32);
    // SAFETY: paging is off, so physical memory reads at its own address; `[physical, physical +
    // size)` is the image's memory (its file, then the reservation the linker script gives it,
    // which the Multiboot loader keeps clear of its own structures), inside the window, and the
    // loader alone touches it. The file's borrow above has ended.
    let memory = unsafe { core::slice::from_raw_parts_mut(physical as *mut u8, size) };
    image
        .map_in_place(memory, file_len)
        .unwrap_or_else(|refusal| fail(refusal.text()));
    // An image at its base needs no fixups, as Windows' loaders skip them.
    let delta = load.wrapping_sub(image.image_base());
    if delta != 0 {
        image
            .relocate(memory, delta)
            .unwrap_or_else(|refusal| fail(refusal.text()));
    }
    let directory = map_window();
    // SAFETY: the directory maps the window and the identity the loader runs in; the image is
    // mapped and relocated for `load`, and its entry point lies in it.
    unsafe { loader_enter(directory, load.wrapping_add(image.entry()), magic, info) }
}

/// Refuse a Multiboot module (`info`'s module list) lying in memory the loader writes: its own
/// (its stack and tables), or the image's, `image`. The kernel reads the modules where they lie.
fn check_modules(info: u32, image: core::ops::Range<u32>) {
    // SAFETY: paging is off, so physical memory reads at its own address; the Multiboot loader put
    // its information structure at `info`, its fields through `mods_addr` included, and nothing
    // writes it while the loader runs.
    let fields =
        unsafe { core::slice::from_raw_parts(info as *const u8, f2k_loader::MULTIBOOT_INFO_LEN) };
    let Some((list, count)) = f2k_loader::module_list(fields) else {
        return;
    };
    // SAFETY: as above, for the module list the structure names (its records, at most
    // MODULE_LIMIT of them).
    let list = unsafe {
        core::slice::from_raw_parts(list as *const u8, count * f2k_loader::MODULE_RECORD)
    };
    let loader = &raw const __loader_start as u32..&raw const _loader_end as u32;
    if f2k_loader::module_overlapping(list, &[loader, image]).is_some() {
        fail(f2k_loader::Refusal::ModuleInTheWay.text());
    }
}

/// Build the boot directory: the kernel image window's entries and the low identity window's (the
/// loader's own code, the Multiboot structures) pointing at the same tables, which map physical
/// `[0, 16 MiB)` 4 MiB apiece. Its physical address (paging is off: the loader's addresses are
/// physical).
fn map_window() -> u32 {
    // SAFETY: the loader runs alone and writes the tables once, here, before paging is on and so
    // before the processor walks them.
    let tables = unsafe { &mut *TABLES.0.get() };
    let (directory, window) = tables.split_at_mut(1);
    let directory = &mut directory[0];
    directory.fill(0);
    let first = (KERNEL_BASE >> 22) as usize;
    for (index, table) in window.iter_mut().enumerate() {
        for (page, entry) in table.iter_mut().enumerate() {
            *entry = ((index * 1024 + page) as u32) << 12 | PRESENT_WRITABLE;
        }
        let table = table.as_ptr() as u32 | PRESENT_WRITABLE;
        directory[index] = table;
        directory[first + index] = table;
    }
    directory.as_ptr() as u32
}

/// Report `why` on COM1 and halt.
fn fail(why: &str) -> ! {
    com1::init();
    com1::write(b"F2K loader: ");
    com1::write(why.as_bytes());
    com1::write(b"\r\n");
    halt()
}

/// Halt with interrupts off.
fn halt() -> ! {
    loop {
        // SAFETY: ring 0; `cli` and `hlt` touch no memory, and the loop halts again after a
        // non-maskable interrupt.
        unsafe { core::arch::asm!("cli", "hlt", options(nomem, nostack)) };
    }
}

/// COM1, for the loader's one report: polled, at the kernel's line settings.
mod com1 {
    const BASE: u16 = 0x3F8;

    fn out(offset: u16, byte: u8) {
        // SAFETY: ring 0; the UART's registers, which nothing else drives while the loader runs.
        unsafe {
            core::arch::asm!("out dx, al", in("dx") BASE + offset, in("al") byte,
                options(nomem, nostack, preserves_flags))
        };
    }

    fn input(offset: u16) -> u8 {
        let byte: u8;
        // SAFETY: as `out`; reading the line status changes nothing.
        unsafe {
            core::arch::asm!("in al, dx", in("dx") BASE + offset, out("al") byte,
                options(nomem, nostack, preserves_flags))
        };
        byte
    }

    /// Program the line: 38400 baud, 8N1, FIFOs on, interrupts off.
    pub fn init() {
        out(1, 0x00); // interrupts off
        out(3, 0x80); // DLAB
        out(0, 3); // divisor 3: 38400 baud
        out(1, 0);
        out(3, 0x03); // 8N1
        out(2, 0xC7); // FIFOs on, cleared
        out(4, 0x0B); // DTR, RTS, OUT2
    }

    /// Send `bytes`, each once the transmitter has room.
    pub fn write(bytes: &[u8]) {
        for &byte in bytes {
            while input(5) & 0x20 == 0 {
                core::hint::spin_loop();
            }
            out(0, byte);
        }
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    fail("the loader panicked")
}
