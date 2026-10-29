//! The process and thread environment blocks as NT 5.0 lays them out on x86, one definition for
//! every side: the PEB ([`Peb`]), the TEB's fields F2K reads ([`Teb`]), the PEB's TLS bitmaps'
//! header ([`RtlBitmap`]) and the loader's lists' head and entries ([`PebLdrData`],
//! [`LdrDataTableEntry`]).
//!
//! Their pointer-sized fields are generic, as [`crate::nt`]'s structures' are: `u32` for a 32-bit
//! process's addresses read from anywhere (the kernel, which writes a new process's blocks on any
//! host), `usize` in the DLLs' own code (the same layout on their target, host addresses in the
//! host tests' stand-in process). The layout asserts hold for the `u32` form.
//!
//! The blocks are shared by the process's threads and DLLs, and the kernel and ntdll write some of
//! their fields after the process starts (the process heap, the loader's lists, the PEB's lock
//! pointers, a thread's own TEB fields): their users read and write them field by field, in place,
//! never through a reference to the whole block.

use core::mem::{offset_of, size_of};

use crate::nt::UnicodeString;

/// The PEB, NT 5.0's: what every process's threads find through FS (TEB+0x30). The kernel fills
/// the fields of the process's creation (its image's base, its parameters, the heap list's room,
/// the system's version, the image's subsystem); ntdll's process initialization fills the rest
/// (the process heap, the loader's lists, and the pointers to ntdll's own locks and bitmap
/// headers).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Peb<P> {
    pub inherited_address_space: u8,
    pub read_image_file_exec_options: u8,
    pub being_debugged: u8,
    pub spare_bool: u8,
    pub mutant: P,
    /// The process image's base, what GetModuleHandle(NULL) returns.
    pub image_base_address: P,
    /// The loader's PEB_LDR_DATA, the heads of the module lists ([`PebLdrData`]).
    pub ldr: P,
    /// The RTL_USER_PROCESS_PARAMETERS block ([`crate::params::ProcessParameters`]).
    pub process_parameters: P,
    pub sub_system_data: P,
    /// What GetProcessHeap returns.
    pub process_heap: P,
    /// The PEB lock: the critical section RtlAcquirePebLock takes, and the routines that take and
    /// release it (ntdll's RtlEnterCriticalSection and RtlLeaveCriticalSection).
    pub fast_peb_lock: P,
    pub fast_peb_lock_routine: P,
    pub fast_peb_unlock_routine: P,
    pub environment_update_count: u32,
    pub kernel_callback_table: P,
    pub system_reserved: [u32; 2],
    pub free_list: P,
    pub tls_expansion_counter: u32,
    /// The RTL_BITMAP over [`Peb::tls_bitmap_bits`]: the TLS indexes 0..64.
    pub tls_bitmap: P,
    pub tls_bitmap_bits: [u32; 2],
    pub read_only_shared_memory_base: P,
    pub read_only_shared_memory_heap: P,
    pub read_only_static_server_data: P,
    pub ansi_code_page_data: P,
    pub oem_code_page_data: P,
    pub unicode_case_table_data: P,
    pub number_of_processors: u32,
    pub nt_global_flag: u32,
    pub spare: u32,
    pub critical_section_timeout: i64,
    pub heap_segment_reserve: u32,
    pub heap_segment_commit: u32,
    pub heap_decommit_total_free_threshold: u32,
    pub heap_decommit_free_block_threshold: u32,
    /// The process's heaps: how many, the array's room, and the array of their handles (the
    /// process heap first; [`crate::heap::HeapList`] over the three).
    pub number_of_heaps: u32,
    pub maximum_number_of_heaps: u32,
    pub process_heaps: P,
    pub gdi_shared_handle_table: P,
    pub process_starter_helper: P,
    pub gdi_dc_attribute_list: u32,
    /// The loader lock: the critical section the loader holds while it reads or changes the module
    /// lists.
    pub loader_lock: P,
    /// The system's version: OSMajorVersion, OSMinorVersion, OSBuildNumber, OSCSDVersion (the
    /// service pack, its major number in the high byte) and OSPlatformId.
    pub os_major_version: u32,
    pub os_minor_version: u32,
    pub os_build_number: u16,
    pub os_csd_version: u16,
    pub os_platform_id: u32,
    /// The image's subsystem and the subsystem version it was linked for.
    pub image_subsystem: u32,
    pub image_subsystem_major_version: u32,
    pub image_subsystem_minor_version: u32,
    pub image_process_affinity_mask: u32,
    pub gdi_handle_buffer: [u32; 34],
    pub post_process_init_routine: P,
    /// The RTL_BITMAP over [`Peb::tls_expansion_bitmap_bits`]: the TLS indexes 64..1088.
    pub tls_expansion_bitmap: P,
    pub tls_expansion_bitmap_bits: [u32; 32],
    pub session_id: u32,
    pub app_compat_info: P,
    /// The service pack's name (GetVersionEx's szCSDVersion).
    pub csd_version: UnicodeString<P>,
    pub padding: u32,
}

impl<P: Default + Copy> Default for Peb<P> {
    fn default() -> Self {
        Self {
            inherited_address_space: 0,
            read_image_file_exec_options: 0,
            being_debugged: 0,
            spare_bool: 0,
            mutant: P::default(),
            image_base_address: P::default(),
            ldr: P::default(),
            process_parameters: P::default(),
            sub_system_data: P::default(),
            process_heap: P::default(),
            fast_peb_lock: P::default(),
            fast_peb_lock_routine: P::default(),
            fast_peb_unlock_routine: P::default(),
            environment_update_count: 0,
            kernel_callback_table: P::default(),
            system_reserved: [0; 2],
            free_list: P::default(),
            tls_expansion_counter: 0,
            tls_bitmap: P::default(),
            tls_bitmap_bits: [0; 2],
            read_only_shared_memory_base: P::default(),
            read_only_shared_memory_heap: P::default(),
            read_only_static_server_data: P::default(),
            ansi_code_page_data: P::default(),
            oem_code_page_data: P::default(),
            unicode_case_table_data: P::default(),
            number_of_processors: 0,
            nt_global_flag: 0,
            spare: 0,
            critical_section_timeout: 0,
            heap_segment_reserve: 0,
            heap_segment_commit: 0,
            heap_decommit_total_free_threshold: 0,
            heap_decommit_free_block_threshold: 0,
            number_of_heaps: 0,
            maximum_number_of_heaps: 0,
            process_heaps: P::default(),
            gdi_shared_handle_table: P::default(),
            process_starter_helper: P::default(),
            gdi_dc_attribute_list: 0,
            loader_lock: P::default(),
            os_major_version: 0,
            os_minor_version: 0,
            os_build_number: 0,
            os_csd_version: 0,
            os_platform_id: 0,
            image_subsystem: 0,
            image_subsystem_major_version: 0,
            image_subsystem_minor_version: 0,
            image_process_affinity_mask: 0,
            gdi_handle_buffer: [0; 34],
            post_process_init_routine: P::default(),
            tls_expansion_bitmap: P::default(),
            tls_expansion_bitmap_bits: [0; 32],
            session_id: 0,
            app_compat_info: P::default(),
            csd_version: UnicodeString {
                length: 0,
                maximum_length: 0,
                buffer: P::default(),
            },
            padding: 0,
        }
    }
}

const _: () = {
    // NT 5.0's layout, with 32-bit pointers on any host.
    type Layout = Peb<u32>;
    assert!(size_of::<Layout>() == 0x1E8);
    assert!(offset_of!(Layout, image_base_address) == 0x08);
    assert!(offset_of!(Layout, ldr) == 0x0C);
    assert!(offset_of!(Layout, process_parameters) == 0x10);
    assert!(offset_of!(Layout, process_heap) == 0x18);
    assert!(offset_of!(Layout, fast_peb_lock) == 0x1C);
    assert!(offset_of!(Layout, fast_peb_lock_routine) == 0x20);
    assert!(offset_of!(Layout, fast_peb_unlock_routine) == 0x24);
    assert!(offset_of!(Layout, tls_bitmap) == 0x40);
    assert!(offset_of!(Layout, tls_bitmap_bits) == 0x44);
    assert!(offset_of!(Layout, number_of_processors) == 0x64);
    assert!(offset_of!(Layout, critical_section_timeout) == 0x70);
    assert!(offset_of!(Layout, number_of_heaps) == 0x88);
    assert!(offset_of!(Layout, maximum_number_of_heaps) == 0x8C);
    assert!(offset_of!(Layout, process_heaps) == 0x90);
    assert!(offset_of!(Layout, loader_lock) == 0xA0);
    assert!(offset_of!(Layout, os_major_version) == 0xA4);
    assert!(offset_of!(Layout, os_minor_version) == 0xA8);
    assert!(offset_of!(Layout, os_build_number) == 0xAC);
    assert!(offset_of!(Layout, os_csd_version) == 0xAE);
    assert!(offset_of!(Layout, os_platform_id) == 0xB0);
    assert!(offset_of!(Layout, image_subsystem) == 0xB4);
    assert!(offset_of!(Layout, image_subsystem_major_version) == 0xB8);
    assert!(offset_of!(Layout, image_subsystem_minor_version) == 0xBC);
    assert!(offset_of!(Layout, tls_expansion_bitmap) == 0x150);
    assert!(offset_of!(Layout, tls_expansion_bitmap_bits) == 0x154);
    assert!(offset_of!(Layout, csd_version) == 0x1DC);
    // The heap list's three fields, in a row as `heap::HeapList` lays them out.
    assert!(offset_of!(Layout, maximum_number_of_heaps) == offset_of!(Layout, number_of_heaps) + 4);
    assert!(offset_of!(Layout, process_heaps) == offset_of!(Layout, number_of_heaps) + 8);
};

/// The TEB's fields F2K reads and writes (NT 5.0's offsets; the fields between them are kept as
/// reserved dwords). A thread's own fields are reached through FS on the target.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Teb<P> {
    /// NT_TIB: the head of the thread's SEH frame chain, its stack's bounds (StackBase one past
    /// the top, StackLimit the lowest committed address), and the TEB's own linear address.
    pub exception_list: P,
    pub stack_base: P,
    pub stack_limit: P,
    pub sub_system_tib: P,
    pub fiber_data: P,
    pub arbitrary_user_pointer: P,
    pub self_: P,
    pub environment_pointer: P,
    /// ClientId: the process's id and the thread's.
    pub unique_process: P,
    pub unique_thread: P,
    pub active_rpc_handle: P,
    /// ThreadLocalStoragePointer: the implicit-TLS block array.
    pub thread_local_storage_pointer: P,
    /// The process's PEB.
    pub process_environment_block: P,
    /// What GetLastError reads and SetLastError writes.
    pub last_error_value: u32,
    pub reserved_1: [u32; (0xC4 - 0x38) / 4],
    /// The thread's locale (GetThreadLocale, SetThreadLocale).
    pub current_locale: u32,
    pub reserved_2: [u32; (0xBF4 - 0xC8) / 4],
    /// The last failed status RtlNtStatusToDosError mapped.
    pub last_status_value: u32,
    pub reserved_3: [u32; (0xE0C - 0xBF8) / 4],
    /// The base of the thread's stack reservation, its lowest address.
    pub deallocation_stack: P,
    /// The first 64 TLS slots.
    pub tls_slots: [P; 64],
    pub reserved_4: [u32; (0xF94 - 0xF10) / 4],
    /// The block holding the other 1024 TLS slots (null until TlsSetValue makes it).
    pub tls_expansion_slots: P,
}

impl<P: Default + Copy> Default for Teb<P> {
    fn default() -> Self {
        Self {
            exception_list: P::default(),
            stack_base: P::default(),
            stack_limit: P::default(),
            sub_system_tib: P::default(),
            fiber_data: P::default(),
            arbitrary_user_pointer: P::default(),
            self_: P::default(),
            environment_pointer: P::default(),
            unique_process: P::default(),
            unique_thread: P::default(),
            active_rpc_handle: P::default(),
            thread_local_storage_pointer: P::default(),
            process_environment_block: P::default(),
            last_error_value: 0,
            reserved_1: [0; (0xC4 - 0x38) / 4],
            current_locale: 0,
            reserved_2: [0; (0xBF4 - 0xC8) / 4],
            last_status_value: 0,
            reserved_3: [0; (0xE0C - 0xBF8) / 4],
            deallocation_stack: P::default(),
            tls_slots: [P::default(); 64],
            reserved_4: [0; (0xF94 - 0xF10) / 4],
            tls_expansion_slots: P::default(),
        }
    }
}

const _: () = {
    // NT 5.0's offsets, with 32-bit pointers on any host.
    type Layout = Teb<u32>;
    assert!(offset_of!(Layout, exception_list) == 0x00);
    assert!(offset_of!(Layout, stack_base) == 0x04);
    assert!(offset_of!(Layout, stack_limit) == 0x08);
    assert!(offset_of!(Layout, self_) == 0x18);
    assert!(offset_of!(Layout, unique_process) == 0x20);
    assert!(offset_of!(Layout, unique_thread) == 0x24);
    assert!(offset_of!(Layout, thread_local_storage_pointer) == 0x2C);
    assert!(offset_of!(Layout, process_environment_block) == 0x30);
    assert!(offset_of!(Layout, last_error_value) == 0x34);
    assert!(offset_of!(Layout, current_locale) == 0xC4);
    assert!(offset_of!(Layout, last_status_value) == 0xBF4);
    assert!(offset_of!(Layout, deallocation_stack) == 0xE0C);
    assert!(offset_of!(Layout, tls_slots) == 0xE10);
    assert!(offset_of!(Layout, tls_expansion_slots) == 0xF94);
};

/// An RTL_BITMAP: its size in bits and its buffer (the PEB's TLS bitmaps' headers are ntdll's own
/// data, the bits the PEB's).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RtlBitmap<P> {
    pub size_of_bit_map: u32,
    pub buffer: P,
}

const _: () = {
    assert!(size_of::<RtlBitmap<u32>>() == 8);
    assert!(offset_of!(RtlBitmap<u32>, buffer) == 4);
};

/// A LIST_ENTRY: the next entry and the previous one (the list's head when there is none).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ListEntry<P> {
    pub flink: P,
    pub blink: P,
}

/// PEB_LDR_DATA: the heads of the three module lists (`crate::modules`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PebLdrData<P> {
    pub length: u32,
    pub initialized: u32,
    pub ss_handle: P,
    pub in_load_order_module_list: ListEntry<P>,
    pub in_memory_order_module_list: ListEntry<P>,
    pub in_initialization_order_module_list: ListEntry<P>,
}

/// LDR_DATA_TABLE_ENTRY: a module's entry in the lists (`crate::modules::entry` names its fields'
/// offsets).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LdrDataTableEntry<P> {
    pub in_load_order_links: ListEntry<P>,
    pub in_memory_order_links: ListEntry<P>,
    pub in_initialization_order_links: ListEntry<P>,
    pub dll_base: P,
    pub entry_point: P,
    pub size_of_image: u32,
    pub full_dll_name: UnicodeString<P>,
    pub base_dll_name: UnicodeString<P>,
    pub flags: u32,
    pub load_count: u16,
    pub tls_index: u16,
    pub hash_links: ListEntry<P>,
    pub time_date_stamp: u32,
}

const _: () = {
    use crate::modules::{data, entry};
    type Data = PebLdrData<u32>;
    assert!(size_of::<Data>() == data::SIZE as usize);
    assert!(
        offset_of!(Data, in_load_order_module_list) == data::IN_LOAD_ORDER_MODULE_LIST as usize
    );
    assert!(
        offset_of!(Data, in_initialization_order_module_list)
            == data::IN_INITIALIZATION_ORDER_MODULE_LIST as usize
    );
    type Entry = LdrDataTableEntry<u32>;
    assert!(size_of::<Entry>() == entry::SIZE as usize);
    assert!(offset_of!(Entry, dll_base) == entry::DLL_BASE as usize);
    assert!(offset_of!(Entry, full_dll_name) == entry::FULL_DLL_NAME as usize);
    assert!(offset_of!(Entry, base_dll_name) == entry::BASE_DLL_NAME as usize);
    assert!(offset_of!(Entry, flags) == entry::FLAGS as usize);
    assert!(offset_of!(Entry, load_count) == entry::LOAD_COUNT as usize);
    assert!(offset_of!(Entry, hash_links) == entry::HASH_LINKS as usize);
    assert!(offset_of!(Entry, time_date_stamp) == entry::TIME_DATE_STAMP as usize);
};
