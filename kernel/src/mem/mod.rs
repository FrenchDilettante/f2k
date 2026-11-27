//! Memory management: the physical frame database, paging, kernel stacks, the nonpaged pool,
//! virtual memory, and the block heap the registry's arena runs on.

pub mod backing;
pub mod demand;
pub mod dma;
pub mod fault;
pub mod faultstats;
pub mod frame;
pub mod heap;
pub mod kstacks;
pub mod ktables;
pub mod layout;
pub mod multiboot;
pub mod pageout;
pub mod paging;
pub mod pagingfile;
pub mod phys;
pub mod pool;
pub mod pte;
pub mod quota;
pub mod vm;
pub mod ws;
pub mod wstrim;

/// Boot-time frame database, built from the Multiboot memory map. Host builds run the modules' unit
/// tests instead; there is no boot loader to ask for memory there.
#[cfg(target_arch = "x86")]
pub mod bootmem;

#[cfg(target_arch = "x86")]
use frame::FrameDb;
#[cfg(target_arch = "x86")]
use kstacks::KernelStacks;
#[cfg(target_arch = "x86")]
use ktables::DirectoryList;
#[cfg(target_arch = "x86")]
use paging::ScratchWindow;
#[cfg(target_arch = "x86")]
use pool::PoolPages;

#[cfg(target_arch = "x86")]
use crate::level::{self, High, LevelCell};

/// The memory manager's database: the frame database, the kernel stacks, the nonpaged pool's pages,
/// the live directories (with the kernel tables made on demand) and the scratch window.
///
/// They are one database because their operations nest. A kernel stack's creation takes a slot,
/// allocates the stack's frames, zeroes each through the scratch window and maps it, as one step;
/// its release unmaps the frames and gives them back. A pool block's is the same, over the pool's
/// pages. Windows 2000 does the same under one lock,
/// the PFN lock, which covers the frame database and is held while a kernel stack is made. A step
/// borrows the whole database once ([`with_database`]) and lends its parts ([`Database::parts`])
/// to the code it calls, which never reaches the database again from inside the borrow.
#[cfg(target_arch = "x86")]
struct Database {
    /// The frame database, from the boot's [`bootmem::boot_init`] on.
    frames: Option<FrameDb>,
    /// The kernel stacks' slot ledger and parked stack.
    stacks: KernelStacks,
    /// Which pages of the nonpaged pool blocks hold.
    pool: PoolPages,
    /// The live process directories, which a kernel table made on demand is installed in.
    directories: DirectoryList,
    /// The system's one scratch window.
    scratch: ScratchWindow,
}

/// The database's parts, borrowed apart.
#[cfg(target_arch = "x86")]
struct Parts<'a> {
    frames: &'a mut FrameDb,
    stacks: &'a mut KernelStacks,
    pool: &'a mut PoolPages,
    directories: &'a mut DirectoryList,
    scratch: &'a mut ScratchWindow,
}

#[cfg(target_arch = "x86")]
impl Database {
    /// The database before the boot builds the frame database: every stack slot free, nothing
    /// parked.
    const fn new() -> Self {
        Database {
            frames: None,
            stacks: KernelStacks::empty(),
            pool: PoolPages::empty(),
            directories: DirectoryList::empty(),
            scratch: ScratchWindow::new(),
        }
    }

    /// The frame database.
    ///
    /// # Panics
    ///
    /// The boot has not built it yet.
    fn frames(&mut self) -> &mut FrameDb {
        self.frames
            .as_mut()
            .expect("frame database not initialized")
    }

    /// Every part at once, for a step that needs more than one.
    ///
    /// # Panics
    ///
    /// The boot has not built the frame database yet.
    fn parts(&mut self) -> Parts<'_> {
        Parts {
            frames: self
                .frames
                .as_mut()
                .expect("frame database not initialized"),
            stacks: &mut self.stacks,
            pool: &mut self.pool,
            directories: &mut self.directories,
            scratch: &mut self.scratch,
        }
    }
}

/// The memory manager's database.
// Note: Windows 2000 keeps this at DISPATCH_LEVEL, under the PFN lock, and it moves there once its
// callers hold tokens. Until then the bridge reaches it at the high level, masking interrupts for
// each step (as the system services and the idle thread's reap, its main callers, run already),
// and refuses a step that reaches it again from inside its own borrow.
#[cfg(target_arch = "x86")]
static DATABASE: LevelCell<High, Database> = LevelCell::new(Database::new());

/// Run `step` on the memory manager's database, through the bridge to the high level.
///
/// # Panics
///
/// The processor is already at the high level: `step`, or code it calls, reaching the database
/// again from inside its own borrow.
#[cfg(target_arch = "x86")]
fn with_database<R>(step: impl FnOnce(&mut Database) -> R) -> R {
    level::raised::<High, _>(|high| step(DATABASE.get(high)))
}

/// The system's commit limit and the total charged against it, in pages
/// (the target has no 64-bit atomics, so the counters are 32-bit page
/// counts). The limit is physical memory until the boot path adds the
/// paging file's size ([`set_system_commit_limit`]); the per-process quotas
/// take it at process creation (quota), the allocate path notes every
/// charge here, and the system-information services report both. Owned by
/// the base branch; integration slices call these, they do not redefine
/// them.
static SYSTEM_COMMIT_LIMIT_PAGES: AtomicU32 = AtomicU32::new(0);
static TOTAL_COMMITTED_PAGES: AtomicU32 = AtomicU32::new(0);

use core::sync::atomic::{AtomicU32, Ordering};

/// The system's commit limit in bytes: the value the boot set, or physical
/// memory (the boot's physical pages) while it is unset.
#[cfg(target_arch = "x86")]
pub fn system_commit_limit() -> u64 {
    let set = SYSTEM_COMMIT_LIMIT_PAGES.load(Ordering::Relaxed);
    if set != 0 {
        return set as u64 * 4096;
    }
    bootmem::physical_pages() as u64 * 4096
}

/// The system's commit limit in bytes, host builds (unit tests) only.
#[cfg(not(target_arch = "x86"))]
pub fn system_commit_limit() -> u64 {
    let set = SYSTEM_COMMIT_LIMIT_PAGES.load(Ordering::Relaxed);
    if set != 0 {
        set as u64 * 4096
    } else {
        u64::MAX
    }
}

/// Set the system's commit limit, once, at boot.
pub fn set_system_commit_limit(bytes: u64) {
    SYSTEM_COMMIT_LIMIT_PAGES.store(
        (bytes / 4096).min(u32::MAX as u64) as u32,
        Ordering::Relaxed,
    );
}

/// Note a charge (`delta` > 0) or discharge (`delta` < 0) of pages against
/// the system's total committed pages.
pub fn note_commit_charge_pages(delta: i32) {
    let _ = TOTAL_COMMITTED_PAGES.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |cur| {
        Some(cur.wrapping_add(delta as u32))
    });
}

/// The total committed bytes across every process.
pub fn total_committed() -> u64 {
    TOTAL_COMMITTED_PAGES.load(Ordering::Relaxed) as u64 * 4096
}
