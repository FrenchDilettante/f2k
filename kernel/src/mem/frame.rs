//! Physical frame allocator.
//!
//! The frame database owns one [`FrameEntry`] per physical frame. Frames
//! not in use are linked onto one of six lists, keyed by state: Zeroed,
//! Free, Standby, Modified, ModifiedNoWrite and Bad. The first three
//! count as available (allocatable in some form); the available counter
//! is always exactly the sum of those three list lengths.
//!
//! Zeroed and Free frames are additionally threaded onto per-color
//! chains (color = frame number modulo the color count) so allocation
//! can honor a color preference in constant time. The head of a list is
//! always the head of its own color chain, and every color chain is
//! exactly the subsequence of the list's frames with that color.
//!
//! Policy:
//! - Releasing a frame appends at the tail, so reuse is FIFO.
//! - Allocating a zeroed frame prefers Zeroed, then Free, then Standby,
//!   requesting zeroing for frames that were not already zeroed.
//! - Allocating an arbitrary frame prefers Free, then Zeroed, then
//!   Standby, and never requests zeroing.
//! - Taking a specific Free/Zeroed frame and unlinking frames from the
//!   other lists are separate operations with separate contracts.
//!
//! This module is pure bookkeeping over an in-memory table: no unsafe
//! code and no hardware access. The kernel wires it to real memory by
//! providing the frame table and (later) real workers via
//! [`FrameHooks`].

/// Physical frame number. Frame 0 is reserved and never allocated.
pub type FrameId = u32;

/// Primary cache color of a frame. This platform has a single primary
/// color; the per-frame field stays zero.
pub const PRIMARY_COLOR: u32 = 0;

/// Lower bound on the configured color count.
pub const MIN_COLOR_COUNT: usize = 2;
/// Upper bound on the configured color count. The count must be a
/// power of two in `[MIN_COLOR_COUNT, MAX_COLOR_COUNT]`.
pub const MAX_COLOR_COUNT: usize = 1024;

/// Default color count used by the kernel and tests.
pub const DEFAULT_COLOR_COUNT: usize = 4;

/// Frame table capacity: 256 MiB of 4 KiB frames, matching the
/// development machine memory (the Makefile's QEMU flags). The boot
/// frame table is sized by this; usable memory beyond it is ignored.
pub const MAX_FRAMES: usize = 65_536;

/// Lifecycle state of a frame. Frames are on one of the six list states
/// or off-list ([`FrameState::Active`] or [`FrameState::Transition`]).
///
/// The grouping below is load-bearing policy, not documentation:
/// - "available" states can satisfy allocations (zeroed/free/standby),
/// - "colored" states keep a per-color chain (zeroed/free),
/// - "transition" states count towards the transition tallies
///   (standby/modified/modified-no-write).
///
/// `Active` is discriminant 0 on purpose: a fresh [`FrameEntry`] is
/// then all-zero, so zeroed memory is a valid fresh entry and large
/// frame tables live in BSS instead of bloating the image's data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameState {
    /// In use; not on any list. Discriminant 0 (see above).
    Active,
    /// Ready for use, contents already zeroed.
    Zeroed,
    /// Ready for use, contents undefined.
    Free,
    /// Removed from a working set, contents intact on backing store.
    Standby,
    /// Dirty, waiting to be written out.
    Modified,
    /// Dirty, but write-back is suppressed.
    ModifiedNoWrite,
    /// Failed hardware; never allocated.
    Bad,
    /// Between working set and standby; not on any list.
    Transition,
}

impl FrameState {
    /// Frames in these states satisfy allocations and count as
    /// available.
    pub const fn counts_as_available(self) -> bool {
        matches!(
            self,
            FrameState::Zeroed | FrameState::Free | FrameState::Standby
        )
    }

    /// Frames in these states are threaded onto per-color chains.
    pub const fn has_color_chain(self) -> bool {
        matches!(self, FrameState::Zeroed | FrameState::Free)
    }

    /// Frames in these states count towards the transition tallies.
    pub const fn is_transition(self) -> bool {
        matches!(
            self,
            FrameState::Standby | FrameState::Modified | FrameState::ModifiedNoWrite
        )
    }

    /// Frames in these states currently sit on a list.
    pub const fn is_list_state(self) -> bool {
        !matches!(self, FrameState::Active | FrameState::Transition)
    }
}

/// Per-frame flags. Cleared by allocation paths that pop a list head;
/// left untouched when a specific frame is taken, so the caller can
/// finish its own state transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FrameFlags(u16);

impl FrameFlags {
    /// Page contents were modified while in use.
    pub const MODIFIED: Self = Self(1 << 0);
    /// A read is in flight for this frame.
    pub const READ_IN_PROGRESS: Self = Self(1 << 1);
    /// A write is in flight for this frame.
    pub const WRITE_IN_PROGRESS: Self = Self(1 << 2);
    /// The frame backs a prototype PTE (shared transition accounting).
    pub const PROTOTYPE_PTE: Self = Self(1 << 3);
    /// The frame contents are invalid after an I/O error.
    pub const IN_PAGE_ERROR: Self = Self(1 << 4);
    /// The frame is scheduled for removal: divert it to the Bad list
    /// instead of any available list on release.
    pub const REMOVAL_REQUESTED: Self = Self(1 << 5);

    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }

    pub fn remove(&mut self, other: Self) {
        self.0 &= !other.0;
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// Per-frame bookkeeping entry. Owned by the [`FrameDb`]; the link
/// fields are only meaningful while the frame is on a list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameEntry {
    next: Option<FrameId>,
    prev: Option<FrameId>,
    next_color: Option<FrameId>,
    /// Current lifecycle state of the frame.
    pub state: FrameState,
    /// Primary cache color (always [`PRIMARY_COLOR`] on this platform).
    pub color: u32,
    /// State flags; see [`FrameFlags`].
    pub flags: FrameFlags,
    /// Outstanding references (I/O or mapping).
    pub refcount: u16,
    /// Mapping share count; meaningful while refcount > 0.
    pub share_count: u32,
}

impl FrameEntry {
    /// A fresh frame: off-list, no flags, no references.
    pub const fn new() -> Self {
        FrameEntry {
            next: None,
            prev: None,
            next_color: None,
            state: FrameState::Active,
            color: PRIMARY_COLOR,
            flags: FrameFlags::empty(),
            refcount: 0,
            share_count: 0,
        }
    }
}

impl Default for FrameEntry {
    fn default() -> Self {
        Self::new()
    }
}

/// Head of one frame list: length plus first/last frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct FrameList {
    total: u32,
    head: Option<FrameId>,
    tail: Option<FrameId>,
}

/// Head and tail of one per-color chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct ColorBucket {
    head: Option<FrameId>,
    tail: Option<FrameId>,
}

/// The per-color chain heads for the two colored states. Kept outside
/// [`FrameDb`] so the database itself stays small: boot code holds it
/// by value without a multi-kilobyte stack frame.
#[derive(Debug)]
pub struct ColorTables {
    inner: [[ColorBucket; MAX_COLOR_COUNT]; 2],
}

impl ColorTables {
    /// Empty tables (const, so large instances live in BSS).
    pub const fn new() -> Self {
        ColorTables {
            inner: [[ColorBucket {
                head: None,
                tail: None,
            }; MAX_COLOR_COUNT]; 2],
        }
    }
}

/// Result of [`FrameDb::unlink`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlinkOutcome {
    /// The frame was removed from its list.
    Unlinked,
    /// The frame has references with no mappings: an I/O transfer is
    /// in flight, so the frame was left untouched. Retry later.
    Busy,
}

/// Side effects of the frame allocator, wired to real workers by the
/// kernel and to recording doubles by tests. All methods have default
/// no-op implementations.
pub trait FrameHooks {
    /// The frame's contents must be zeroed before it is handed out as
    /// a zeroed frame. Fired by [`FrameDb::allocate_zeroed`] when the
    /// frame did not come from the Zeroed list.
    fn zero_frame(&mut self, _frame: FrameId) {}

    /// The frame's contents just became zeroed: either released into
    /// the Zeroed list, or zeroed on demand during allocation.
    fn stamp_zeroed(&mut self, _frame: FrameId) {}

    /// The frame was released from Standby: its transition mapping slot
    /// must be restored. Fired on standby head-removal and on the
    /// removal-requested diversion path.
    fn restore_transition(&mut self, _frame: FrameId) {}

    /// Available frames dropped below the configured minimum. The
    /// listener should free more frames. Fired on every removal path
    /// that crosses the threshold.
    fn reclaim_frames(&mut self) {}

    /// Available frames reached the low water mark. Fired on the
    /// release path whenever the count becomes exactly the low mark.
    fn available_low(&mut self) {}

    /// Available frames reached the high water mark. Fired on the
    /// release path whenever the count becomes exactly the high mark.
    fn available_high(&mut self) {}

    /// The Free list reached the configured zeroing threshold and no
    /// zeroing pass is running. The listener should drain free frames
    /// into the Zeroed list, then call [`FrameDb::zeroing_done`].
    fn zeroing_needed(&mut self) {}
}

/// Hooks that do nothing; the default type parameter of [`FrameDb`].
pub struct NoHooks;

impl FrameHooks for NoHooks {}

/// Ways the frame database can be internally inconsistent; reported by
/// [`FrameDb::audit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditError {
    /// A list link points outside the valid frame range.
    FrameOutOfRange { frame: FrameId },
    /// A list chain does not terminate (cycle or broken link).
    ChainDoesNotTerminate { state: FrameState },
    /// The list total disagrees with its chain length.
    TotalMismatch { state: FrameState },
    /// The list head/tail links disagree with the chain ends.
    HeadTailMismatch { state: FrameState },
    /// A chain's backward links disagree with its forward links.
    PrevLinkMismatch { state: FrameState },
    /// A listed frame's state does not name the list it is on.
    StateMismatch { frame: FrameId },
    /// The available counter is not the sum of the available lists.
    AvailableMismatch,
    /// The transition tallies are not the sum of the transition lists.
    TallyMismatch,
    /// A list head is not the head of its own color chain.
    BucketHeadMismatch { state: FrameState },
    /// A color chain is not the color-matching subsequence of its list.
    ColorChainMismatch { state: FrameState },
}

/// The physical frame database: frame table, per-state FIFO lists,
/// per-color chains, accounting counters, and hooks.
///
/// The frame table is borrowed for the database's lifetime; the kernel
/// supplies a table sized from the boot memory map, tests leak a boxed
/// slice. Index 0 is reserved; valid frames are 1..table_len.
pub struct FrameDb<H: FrameHooks = NoHooks> {
    frames: &'static mut [FrameEntry],
    buckets: &'static mut ColorTables,
    hooks: H,

    zeroed: FrameList,
    free: FrameList,
    standby: FrameList,
    modified: FrameList,
    modified_no_write: FrameList,
    bad: FrameList,

    colors: usize,
    color_mask: u32,

    /// Sum of the zeroed, free and standby list lengths.
    available: u32,

    /// Below this available count, [`FrameHooks::reclaim_frames`] fires.
    min_free: u32,
    /// When the Free list reaches this length, zeroing is requested.
    zero_threshold: u32,
    /// True while a zeroing pass is running (suppresses re-requests).
    zeroing_armed: bool,
    /// Available-page water marks; hooks fire when the count passes
    /// exactly through them on release.
    low_water: u32,
    high_water: u32,

    /// Transition frame tallies, by share type.
    transition_private: u32,
    transition_shared: u32,
}

impl<H: FrameHooks> FrameDb<H> {
    /// Build a database over `frames` (index 0 reserved) and the color
    /// chain heads in `buckets`, with `colors` colors and the given
    /// hooks. Water marks default to 2 (low) and 19 (high); the
    /// free-page minimum and zeroing threshold default to "never".
    pub fn new(
        frames: &'static mut [FrameEntry],
        buckets: &'static mut ColorTables,
        colors: usize,
        hooks: H,
    ) -> Self {
        assert!(
            colors.is_power_of_two() && (MIN_COLOR_COUNT..=MAX_COLOR_COUNT).contains(&colors),
            "color count must be a power of two in [2, 1024]"
        );
        FrameDb {
            frames,
            buckets,
            hooks,
            zeroed: FrameList::default(),
            free: FrameList::default(),
            standby: FrameList::default(),
            modified: FrameList::default(),
            modified_no_write: FrameList::default(),
            bad: FrameList::default(),
            colors,
            color_mask: (colors - 1) as u32,
            available: 0,
            min_free: 0,
            zero_threshold: u32::MAX,
            zeroing_armed: false,
            low_water: 2,
            high_water: 19,
            transition_private: 0,
            transition_shared: 0,
        }
    }

    /// Configure the available-page floor that triggers
    /// [`FrameHooks::reclaim_frames`]. Zero (the default) means never.
    pub fn set_min_free_pages(&mut self, min_free: u32) {
        self.min_free = min_free;
    }

    /// Configure the Free-list length that requests a zeroing pass.
    /// `u32::MAX` (the default) means never.
    pub fn set_zeroing_threshold(&mut self, threshold: u32) {
        self.zero_threshold = threshold;
    }

    /// Clear the zeroing-pass latch once the pass completes, allowing
    /// [`FrameHooks::zeroing_needed`] to fire again.
    pub fn zeroing_done(&mut self) {
        self.zeroing_armed = false;
    }

    /// Total frames that can satisfy allocations (zeroed + free +
    /// standby).
    pub fn available(&self) -> u32 {
        self.available
    }

    /// Number of frames on the given list.
    pub fn list_total(&self, state: FrameState) -> u32 {
        self.list(state).total
    }

    /// Read-only access to a frame's entry.
    pub fn entry(&self, frame: FrameId) -> &FrameEntry {
        assert!(frame != 0 && (frame as usize) < self.frames.len(), "invalid frame id {}", frame);
        &self.frames[frame as usize]
    }

    // -----------------------------------------------------------------
    // Internal accessors

    fn entry_mut(&mut self, frame: FrameId) -> &mut FrameEntry {
        assert!(frame != 0 && (frame as usize) < self.frames.len(), "invalid frame id {}", frame);
        &mut self.frames[frame as usize]
    }

    fn list(&self, state: FrameState) -> &FrameList {
        match state {
            FrameState::Zeroed => &self.zeroed,
            FrameState::Free => &self.free,
            FrameState::Standby => &self.standby,
            FrameState::Modified => &self.modified,
            FrameState::ModifiedNoWrite => &self.modified_no_write,
            FrameState::Bad => &self.bad,
            state => panic!("state {:?} has no frame list", state),
        }
    }

    fn list_mut(&mut self, state: FrameState) -> &mut FrameList {
        match state {
            FrameState::Zeroed => &mut self.zeroed,
            FrameState::Free => &mut self.free,
            FrameState::Standby => &mut self.standby,
            FrameState::Modified => &mut self.modified,
            FrameState::ModifiedNoWrite => &mut self.modified_no_write,
            FrameState::Bad => &mut self.bad,
            state => panic!("state {:?} has no frame list", state),
        }
    }

    /// Color chain table index for a colored state.
    fn color_table(state: FrameState) -> usize {
        match state {
            FrameState::Zeroed => 0,
            FrameState::Free => 1,
            state => panic!("state {:?} has no color chains", state),
        }
    }

    /// Color of a frame: its position in the color chains, derived
    /// from the frame number.
    fn color_of(&self, frame: FrameId) -> usize {
        (frame & self.color_mask) as usize
    }

    /// Transition tally bookkeeping; keeps the share/private split in
    /// lockstep with the transition list lengths.
    fn tally_add(&mut self, frame: FrameId) {
        if self.entry(frame).flags.contains(FrameFlags::PROTOTYPE_PTE) {
            self.transition_shared += 1;
        } else {
            self.transition_private += 1;
        }
        self.assert_tallies();
    }

    fn tally_remove(&mut self, frame: FrameId) {
        if self.entry(frame).flags.contains(FrameFlags::PROTOTYPE_PTE) {
            self.transition_shared -= 1;
        } else {
            self.transition_private -= 1;
        }
        self.assert_tallies();
    }

    fn assert_tallies(&self) {
        let transition_total =
            self.standby.total + self.modified.total + self.modified_no_write.total;
        assert!(
            self.transition_private + self.transition_shared == transition_total,
            "transition tallies disagree with the transition lists"
        );
    }

    /// Common tail-append of `frame` onto `state`'s list.
    fn append_to_list(&mut self, frame: FrameId, state: FrameState) {
        let old_tail = {
            let list = self.list_mut(state);
            list.total += 1;
            let old = list.tail;
            list.tail = Some(frame);
            if old.is_none() {
                list.head = Some(frame);
            }
            old
        };
        if let Some(tail) = old_tail {
            self.entry_mut(tail).next = Some(frame);
        }
        let entry = self.entry_mut(frame);
        entry.prev = old_tail;
        entry.next = None;
    }

    /// Common tail-append of `frame` onto its color chain.
    fn append_to_color_chain(&mut self, frame: FrameId, state: FrameState) {
        let color = self.color_of(frame);
        let old_tail = {
            let bucket = &mut self.buckets.inner[Self::color_table(state)][color];
            let old = bucket.tail;
            bucket.tail = Some(frame);
            if old.is_none() {
                bucket.head = Some(frame);
            }
            old
        };
        if let Some(tail) = old_tail {
            self.entry_mut(tail).next_color = Some(frame);
        }
        self.entry_mut(frame).next_color = None;
    }

    /// Stitch the main chain around `frame` (already known to be on
    /// `state`'s list), decrement the total, and clear its links.
    fn stitch_around(&mut self, frame: FrameId, state: FrameState) {
        let next = self.entry(frame).next;
        let prev = self.entry(frame).prev;
        if let Some(n) = next {
            self.entry_mut(n).prev = prev;
        } else {
            self.list_mut(state).tail = prev;
        }
        if let Some(p) = prev {
            self.entry_mut(p).next = next;
        } else {
            self.list_mut(state).head = next;
        }
        self.list_mut(state).total -= 1;
        let entry = self.entry_mut(frame);
        entry.next = None;
        entry.prev = None;
    }

    /// Removal-side accounting shared by every removal path: available
    /// count, transition tallies (reading flags while they are still
    /// intact), the standby restore hook, and the low-frames hook.
    fn removal_accounting(&mut self, state: FrameState, frame: FrameId, restore_on_standby: bool) {
        if state.counts_as_available() {
            self.available -= 1;
            if state == FrameState::Standby {
                self.tally_remove(frame);
                if restore_on_standby {
                    self.hooks.restore_transition(frame);
                }
            }
            if self.available < self.min_free {
                self.hooks.reclaim_frames();
            }
        } else if state.is_transition() {
            self.tally_remove(frame);
        }
    }

    // -----------------------------------------------------------------
    // Release (list insertion)

    /// Release `frame` onto the list for `state`, appending at the tail.
    ///
    /// The frame must be off-list with no references. If the frame is
    /// flagged [`FrameFlags::REMOVAL_REQUESTED`] and the target is an
    /// available state, the frame is diverted to the Bad list instead.
    pub fn release(&mut self, frame: FrameId, state: FrameState) {
        {
            let entry = self.entry(frame);
            assert_eq!(
                entry.refcount, 0,
                "releasing a frame with outstanding references"
            );
            assert!(!entry.state.is_list_state(), "frame is already on a list");
        }

        let mut target = state;
        if state.counts_as_available()
            && self
                .entry(frame)
                .flags
                .contains(FrameFlags::REMOVAL_REQUESTED)
        {
            if state == FrameState::Standby {
                self.hooks.restore_transition(frame);
            }
            target = FrameState::Bad;
        }

        self.append_to_list(frame, target);
        self.entry_mut(frame).state = target;

        if target.counts_as_available() {
            self.available += 1;
            if self.available == self.low_water {
                self.hooks.available_low();
            } else if self.available == self.high_water {
                self.hooks.available_high();
            }

            if target.has_color_chain() {
                {
                    let entry = self.entry(frame);
                    assert!(
                        !entry.flags.contains(FrameFlags::IN_PAGE_ERROR),
                        "an in-page-error frame cannot join a colored list"
                    );
                    assert_eq!(
                        entry.color, PRIMARY_COLOR,
                        "frames have a single primary color"
                    );
                }
                self.append_to_color_chain(frame, target);
                if target == FrameState::Zeroed {
                    self.hooks.stamp_zeroed(frame);
                }
            } else {
                // Standby: transition tally.
                self.tally_add(frame);
            }

            if target == FrameState::Free
                && !self.zeroing_armed
                && self.free.total >= self.zero_threshold
            {
                self.zeroing_armed = true;
                self.hooks.zeroing_needed();
            }
        } else if target.is_transition() {
            // Modified / modified-no-write: transition tally.
            self.tally_add(frame);
        }
    }

    // -----------------------------------------------------------------
    // Removal

    /// Remove and return the head frame of the list for `state`.
    ///
    /// Not valid for the Modified list, which is drained by its writer
    /// (that path owns the ordering). The frame's flags are cleared;
    /// its color stays. Panics if the list is empty.
    pub fn pop(&mut self, state: FrameState) -> FrameId {
        assert!(
            state != FrameState::Modified,
            "the modified list is drained by its writer, not by allocation"
        );
        assert!(self.list(state).total != 0, "pop from an empty list");
        let frame = self.list(state).head.expect("nonempty list has a head");
        assert!(
            !self
                .entry(frame)
                .flags
                .contains(FrameFlags::REMOVAL_REQUESTED),
            "allocating a frame flagged for removal"
        );

        // Advance the color chain: the list head is its chain's head.
        if state.has_color_chain() {
            let color = self.color_of(frame);
            let next_color = self.entry(frame).next_color;
            let bucket = &mut self.buckets.inner[Self::color_table(state)][color];
            assert_eq!(
                bucket.head,
                Some(frame),
                "list head must be the head of its color chain"
            );
            bucket.head = next_color;
            if next_color.is_none() {
                bucket.tail = None;
            }
        }

        let next = self.entry(frame).next;
        {
            let list = self.list_mut(state);
            list.total -= 1;
            list.head = next;
            if next.is_none() {
                list.tail = None;
            }
        }
        if let Some(n) = next {
            self.entry_mut(n).prev = None;
        }

        // Accounting first (it reads the flags), then clear the frame.
        self.removal_accounting(state, frame, true);
        let entry = self.entry_mut(frame);
        entry.state = FrameState::Active;
        entry.flags = FrameFlags::empty();
        entry.next_color = None;
        frame
    }

    /// Unlink a specific frame from a non-colored list (Standby,
    /// Modified, ModifiedNoWrite or Bad).
    ///
    /// If the frame has references and no mappings, an I/O transfer is
    /// in flight: the call returns [`UnlinkOutcome::Busy`] and the list
    /// is untouched. The frame's flags are left as they are.
    pub fn unlink(&mut self, frame: FrameId) -> UnlinkOutcome {
        let state = {
            let entry = self.entry(frame);
            if entry.refcount > 0 {
                if entry.share_count == 0 {
                    return UnlinkOutcome::Busy;
                }
                panic!("unlinking a mapped frame with references corrupts the list");
            }
            let state = entry.state;
            assert!(
                !state.has_color_chain(),
                "free/zeroed frames must be taken with take() to keep color chains consistent"
            );
            assert!(
                !entry
                    .flags
                    .contains(FrameFlags::WRITE_IN_PROGRESS)
                    && !entry.flags.contains(FrameFlags::READ_IN_PROGRESS),
                "cannot unlink a frame with I/O in progress"
            );
            assert!(self.list(state).total != 0, "unlinking from an empty list");
            state
        };

        self.stitch_around(frame, state);
        self.removal_accounting(state, frame, false);
        self.entry_mut(frame).state = FrameState::Active;
        UnlinkOutcome::Unlinked
    }

    /// Take a specific frame off the Zeroed or Free list, for callers
    /// that need exactly this frame.
    ///
    /// The frame's flags are left as they are; the caller owns the rest
    /// of the transition. Panics if the frame is not on a colored list
    /// or not on its color chain.
    pub fn take(&mut self, frame: FrameId) {
        let state = {
            let entry = self.entry(frame);
            let state = entry.state;
            assert!(
                state.has_color_chain(),
                "take() only accepts zeroed or free frames"
            );
            assert!(
                !entry
                    .flags
                    .contains(FrameFlags::WRITE_IN_PROGRESS)
                    && !entry.flags.contains(FrameFlags::READ_IN_PROGRESS),
                "cannot take a frame with I/O in progress"
            );
            assert!(self.list(state).total != 0, "taking from an empty list");
            state
        };

        self.stitch_around(frame, state);

        // Color chain removal. The head case is O(1); otherwise walk
        // the chain to find the parent (bounded by the table length).
        let color = self.color_of(frame);
        let next_color = self.entry(frame).next_color;
        let bucket_head = self.buckets.inner[Self::color_table(state)][color].head;
        if bucket_head == Some(frame) {
            let bucket = &mut self.buckets.inner[Self::color_table(state)][color];
            bucket.head = next_color;
            if next_color.is_none() {
                bucket.tail = None;
            }
        } else {
            let mut parent = match bucket_head {
                Some(p) => p,
                None => panic!("frame is not on its color chain"),
            };
            let mut steps = 0usize;
            loop {
                let child = self.entry(parent).next_color;
                if child == Some(frame) {
                    self.entry_mut(parent).next_color = next_color;
                    if next_color.is_none() {
                        self.buckets.inner[Self::color_table(state)][color].tail = Some(parent);
                    }
                    break;
                }
                parent = match child {
                    Some(c) => c,
                    None => panic!("frame is not on its color chain"),
                };
                steps += 1;
                if steps > self.frames.len() {
                    panic!("color chain does not terminate");
                }
            }
        }

        self.entry_mut(frame).next_color = None;
        self.entry_mut(frame).state = FrameState::Active;
        self.removal_accounting(state, frame, false);
    }

    /// Allocation-path removal of a colored frame known to be the head
    /// of its color chain. Clears flags and applies removal accounting.
    fn pop_colored(&mut self, frame: FrameId) {
        let state = self.entry(frame).state;
        assert!(
            !self
                .entry(frame)
                .flags
                .contains(FrameFlags::REMOVAL_REQUESTED),
            "allocating a frame flagged for removal"
        );

        let color = self.color_of(frame);
        let next_color = self.entry(frame).next_color;
        {
            let bucket = &mut self.buckets.inner[Self::color_table(state)][color];
            assert_eq!(
                bucket.head,
                Some(frame),
                "color chain head must be the frame being allocated"
            );
            bucket.head = next_color;
            if next_color.is_none() {
                bucket.tail = None;
            }
        }

        self.stitch_around(frame, state);
        self.removal_accounting(state, frame, false);
        let entry = self.entry_mut(frame);
        entry.state = FrameState::Active;
        entry.flags = FrameFlags::empty();
        entry.next_color = None;
    }

    // -----------------------------------------------------------------
    // Allocation

    /// Allocate a zeroed frame, preferring color `color`.
    ///
    /// Preference order: the Zeroed list (requested color, then any),
    /// the Free list (requested color, then any, zeroing on demand),
    /// then Standby (zeroing on demand). Panics if nothing is
    /// available.
    pub fn allocate_zeroed(&mut self, color: u32) -> FrameId {
        assert!(self.available != 0, "no frames are available");
        assert!((color as usize) < self.colors, "color out of range");
        let color = color as usize;

        // Zeroed, matching color.
        if let Some(frame) = self.buckets.inner[Self::color_table(FrameState::Zeroed)][color].head {
            self.pop_colored(frame);
            return frame;
        }
        // Zeroed, any color (the list head is its own chain head).
        if let Some(frame) = self.zeroed.head {
            self.pop_colored(frame);
            return frame;
        }
        // Free, matching color, then any: zero on demand.
        if let Some(frame) = self.buckets.inner[Self::color_table(FrameState::Free)][color].head {
            self.pop_colored(frame);
            self.zero_and_stamp(frame);
            return frame;
        }
        if let Some(frame) = self.free.head {
            self.pop_colored(frame);
            self.zero_and_stamp(frame);
            return frame;
        }

        // Both colored lists are empty by chain; their totals must agree.
        assert_eq!(self.zeroed.total, 0, "zeroed chain is empty but the list is not");
        assert_eq!(self.free.total, 0, "free chain is empty but the list is not");
        assert!(self.standby.total != 0, "no frames are available");

        let frame = self.pop(FrameState::Standby);
        self.zero_and_stamp(frame);
        frame
    }

    /// Allocate any frame, preferring color `color` and non-zeroed
    /// content (no zeroing is ever requested).
    ///
    /// Preference order: the Free list (requested color, then any), the
    /// Zeroed list (requested color, then any), then Standby. Panics if
    /// nothing is available.
    pub fn allocate(&mut self, color: u32) -> FrameId {
        assert!(self.available != 0, "no frames are available");
        assert!((color as usize) < self.colors, "color out of range");
        let color = color as usize;

        // Free, matching color.
        if let Some(frame) = self.buckets.inner[Self::color_table(FrameState::Free)][color].head {
            self.pop_colored(frame);
            return frame;
        }
        // Zeroed, matching color.
        if let Some(frame) = self.buckets.inner[Self::color_table(FrameState::Zeroed)][color].head {
            self.pop_colored(frame);
            return frame;
        }
        // Free, then zeroed, any color.
        if let Some(frame) = self.free.head {
            self.pop_colored(frame);
            return frame;
        }
        if let Some(frame) = self.zeroed.head {
            self.pop_colored(frame);
            return frame;
        }

        // Both colored lists are empty by chain; their totals must agree.
        assert_eq!(self.free.total, 0, "free chain is empty but the list is not");
        assert_eq!(self.zeroed.total, 0, "zeroed chain is empty but the list is not");
        assert!(self.standby.total != 0, "no frames are available");

        self.pop(FrameState::Standby)
    }

    /// Zero a frame on demand and mark it freshly zeroed.
    fn zero_and_stamp(&mut self, frame: FrameId) {
        self.hooks.zero_frame(frame);
        self.hooks.stamp_zeroed(frame);
    }

    // -----------------------------------------------------------------
    // Consistency audit

    /// Check every invariant the database maintains silently. Returns
    /// `Ok(())` when they all hold, or the first violation found.
    ///
    /// Per list: the chain terminates without cycles or out-of-range
    /// frames, the total equals the chain length, head and tail links
    /// match the chain ends, backward links mirror forward links, and
    /// every listed frame's state names its list. Globally: the
    /// available counter equals the sum of the available lists, the
    /// transition tallies equal the sum of the transition lists, each
    /// list head is its color-chain head, and every color chain is the
    /// color-matching subsequence of its list.
    ///
    /// Allocation-free: walks chains with bounded steps instead of
    /// collecting them.
    pub fn audit(&self) -> Result<(), AuditError> {
        let states = [
            FrameState::Zeroed,
            FrameState::Free,
            FrameState::Standby,
            FrameState::Modified,
            FrameState::ModifiedNoWrite,
            FrameState::Bad,
        ];

        for &state in &states {
            let list = self.list(state);

            // Forward walk: range, termination, per-frame state, and
            // backward-link agreement.
            let mut count = 0u32;
            let mut first: Option<FrameId> = None;
            let mut last: Option<FrameId> = None;
            let mut cur = list.head;
            while let Some(f) = cur {
                if f == 0 || (f as usize) >= self.frames.len() {
                    return Err(AuditError::FrameOutOfRange { frame: f });
                }
                if self.entry(f).state != state {
                    return Err(AuditError::StateMismatch { frame: f });
                }
                count += 1;
                if count > self.frames.len() as u32 {
                    return Err(AuditError::ChainDoesNotTerminate { state });
                }
                if let Some(n) = self.entry(f).next {
                    if self.entry(n).prev != Some(f) {
                        return Err(AuditError::PrevLinkMismatch { state });
                    }
                }
                first.get_or_insert(f);
                last = Some(f);
                cur = self.entry(f).next;
            }
            if count != list.total {
                return Err(AuditError::TotalMismatch { state });
            }
            if list.head.is_some() != list.tail.is_some() || list.tail != last {
                return Err(AuditError::HeadTailMismatch { state });
            }
            if let (Some(first), Some(last)) = (first, last) {
                if self.entry(first).prev.is_some() || self.entry(last).next.is_some() {
                    return Err(AuditError::HeadTailMismatch { state });
                }
            }

            // Backward walk must mirror the forward walk.
            let mut backward = 0u32;
            let mut cur = list.tail;
            while let Some(f) = cur {
                backward += 1;
                if backward > self.frames.len() as u32 {
                    return Err(AuditError::ChainDoesNotTerminate { state });
                }
                cur = self.entry(f).prev;
            }
            if backward != count {
                return Err(AuditError::PrevLinkMismatch { state });
            }
        }

        // Global counters.
        if self.available != self.zeroed.total + self.free.total + self.standby.total {
            return Err(AuditError::AvailableMismatch);
        }
        self.assert_tallies();

        // Color chains: each must be the color-matching subsequence of
        // its list, and the list head must be its own chain head.
        for state in [FrameState::Zeroed, FrameState::Free] {
            let head = self.list(state).head;
            if let Some(h) = head {
                let head_color = self.color_of(h);
                if self.buckets.inner[Self::color_table(state)][head_color].head != Some(h) {
                    return Err(AuditError::BucketHeadMismatch { state });
                }
            }
            for color in 0..self.colors {
                let bucket = &self.buckets.inner[Self::color_table(state)][color];
                let chain_budget = 2 * self.frames.len() as u32 + 2;

                // Walk the color-filtered list and the color chain in
                // lockstep.
                let mut list_cur = self.list(state).head;
                let mut bucket_cur = bucket.head;
                let mut last_matched: Option<FrameId> = None;
                let mut steps = 0u32;
                loop {
                    // Advance the list cursor to the next frame of
                    // this color.
                    while let Some(f) = list_cur {
                        if self.color_of(f) == color {
                            break;
                        }
                        steps += 1;
                        if steps > chain_budget {
                            return Err(AuditError::ChainDoesNotTerminate { state });
                        }
                        list_cur = self.entry(f).next;
                    }
                    match (list_cur, bucket_cur) {
                        (None, None) => break,
                        (Some(list_frame), Some(bucket_frame)) => {
                            if list_frame != bucket_frame {
                                return Err(AuditError::ColorChainMismatch { state });
                            }
                            last_matched = Some(list_frame);
                            steps += 1;
                            if steps > chain_budget {
                                return Err(AuditError::ChainDoesNotTerminate { state });
                            }
                            list_cur = self.entry(list_frame).next;
                            bucket_cur = self.entry(bucket_frame).next_color;
                        }
                        (Some(_), None) | (None, Some(_)) => {
                            return Err(AuditError::ColorChainMismatch { state });
                        }
                    }
                }
                if bucket.tail != last_matched {
                    return Err(AuditError::ColorChainMismatch { state });
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use FrameState::*;

    const TABLE: usize = 64;

    /// Records every hook firing so tests can assert on side effects.
    #[derive(Default)]
    struct RecordingHooks {
        zeroed: Vec<FrameId>,
        stamped: Vec<FrameId>,
        restored: Vec<FrameId>,
        reclaim: u32,
        low: u32,
        high: u32,
        zeroing: u32,
    }

    impl FrameHooks for RecordingHooks {
        fn zero_frame(&mut self, frame: FrameId) {
            self.zeroed.push(frame);
        }
        fn stamp_zeroed(&mut self, frame: FrameId) {
            self.stamped.push(frame);
        }
        fn restore_transition(&mut self, frame: FrameId) {
            self.restored.push(frame);
        }
        fn reclaim_frames(&mut self) {
            self.reclaim += 1;
        }
        fn available_low(&mut self) {
            self.low += 1;
        }
        fn available_high(&mut self) {
            self.high += 1;
        }
        fn zeroing_needed(&mut self) {
            self.zeroing += 1;
        }
    }

    fn new_db() -> FrameDb<RecordingHooks> {
        let table: &'static mut [FrameEntry] =
            Box::leak(vec![FrameEntry::new(); TABLE].into_boxed_slice());
        let buckets: &'static mut ColorTables = Box::leak(Box::new(ColorTables::new()));
        FrameDb::new(table, buckets, DEFAULT_COLOR_COUNT, RecordingHooks::default())
    }

    fn release_all(db: &mut FrameDb<RecordingHooks>, state: FrameState, frames: &[FrameId]) {
        for &f in frames {
            db.release(f, state);
        }
    }

    #[test]
    fn fresh_database_is_empty_and_consistent() {
        let db = new_db();
        assert_eq!(db.available(), 0);
        for state in [Zeroed, Free, Standby, Modified, ModifiedNoWrite, Bad] {
            assert_eq!(db.list_total(state), 0);
        }
        assert_eq!(db.audit(), Ok(()));
    }

    #[test]
    fn available_counts_only_allocatable_lists() {
        let mut db = new_db();
        release_all(&mut db, Zeroed, &[1]);
        release_all(&mut db, Free, &[2, 3]);
        release_all(&mut db, Standby, &[4, 5, 6]);
        assert_eq!(db.available(), 6);
        release_all(&mut db, Modified, &[7]);
        release_all(&mut db, ModifiedNoWrite, &[8]);
        release_all(&mut db, Bad, &[9]);
        assert_eq!(db.available(), 6);
        assert_eq!(db.audit(), Ok(()));
    }

    #[test]
    fn release_appends_in_fifo_order() {
        let mut db = new_db();
        release_all(&mut db, Free, &[3, 9, 5]);
        assert_eq!(db.free.head, Some(3));
        assert_eq!(db.free.tail, Some(5));
        assert_eq!(db.entry(3).prev, None);
        assert_eq!(db.entry(9).prev, Some(3));
        assert_eq!(db.entry(9).next, Some(5));
        assert_eq!(db.entry(5).next, None);
        assert_eq!(db.pop(Free), 3);
        assert_eq!(db.pop(Free), 9);
        assert_eq!(db.pop(Free), 5);
        assert_eq!(db.list_total(Free), 0);
        assert_eq!(db.audit(), Ok(()));
    }

    #[test]
    fn release_into_zeroed_stamps() {
        let mut db = new_db();
        db.release(7, Zeroed);
        assert_eq!(db.hooks.stamped, vec![7]);
        db.release(8, Free);
        assert_eq!(db.hooks.stamped, vec![7]);
        assert!(db.hooks.zeroed.is_empty());
    }

    #[test]
    fn release_into_bad_has_no_side_effects() {
        let mut db = new_db();
        db.release(10, Bad);
        assert_eq!(db.available(), 0);
        assert_eq!(db.entry(10).state, Bad);
        assert_eq!(db.list_total(Bad), 1);
        assert_eq!(db.buckets.inner[0][10 & 3].head, None);
        assert_eq!(db.buckets.inner[1][10 & 3].head, None);
        assert_eq!(db.audit(), Ok(()));
    }

    #[test]
    fn removal_requested_frames_divert_to_bad() {
        let mut db = new_db();
        db.entry_mut(4).flags.insert(FrameFlags::REMOVAL_REQUESTED);
        db.release(4, Free);
        assert_eq!(db.entry(4).state, Bad);
        assert_eq!(db.list_total(Free), 0);
        assert_eq!(db.list_total(Bad), 1);
        assert_eq!(db.available(), 0);

        db.entry_mut(5).flags.insert(FrameFlags::REMOVAL_REQUESTED);
        db.release(5, Standby);
        assert_eq!(db.entry(5).state, Bad);
        assert_eq!(db.list_total(Bad), 2);
        assert_eq!(db.available(), 0);
        assert_eq!(db.hooks.restored, vec![5]);
        assert_eq!(db.audit(), Ok(()));
    }

    #[test]
    #[should_panic(expected = "already on a list")]
    fn double_release_panics() {
        let mut db = new_db();
        db.release(4, Free);
        db.release(4, Free);
    }

    #[test]
    #[should_panic(expected = "outstanding references")]
    fn release_with_references_panics() {
        let mut db = new_db();
        db.entry_mut(4).refcount = 1;
        db.release(4, Free);
    }

    #[test]
    fn pop_clears_flags_and_keeps_bookkeeping() {
        let mut db = new_db();
        release_all(&mut db, Free, &[3, 9, 5]);
        db.entry_mut(3).flags.insert(FrameFlags::MODIFIED);
        assert_eq!(db.pop(Free), 3);
        assert_eq!(db.entry(3).state, Active);
        assert!(db.entry(3).flags.is_empty());
        assert_eq!(db.entry(3).color, PRIMARY_COLOR);
        assert_eq!(db.list_total(Free), 2);
        assert_eq!(db.free.head, Some(9));
        assert_eq!(db.entry(9).prev, None);
        assert_eq!(db.available(), 2);
        // Frame 3 is color 3 (sole); 9 and 5 are color 1.
        assert_eq!(db.buckets.inner[1][3].head, None);
        assert_eq!(db.buckets.inner[1][3].tail, None);
        assert_eq!(db.buckets.inner[1][1].head, Some(9));
        assert_eq!(db.buckets.inner[1][1].tail, Some(5));
        assert_eq!(db.audit(), Ok(()));
    }

    #[test]
    #[should_panic(expected = "pop from an empty list")]
    fn pop_from_empty_list_panics() {
        let mut db = new_db();
        db.pop(Free);
    }

    #[test]
    #[should_panic(expected = "modified list")]
    fn pop_from_modified_list_panics() {
        let mut db = new_db();
        db.release(4, Modified);
        db.pop(Modified);
    }

    #[test]
    fn unlink_middle_stitches_neighbors() {
        let mut db = new_db();
        release_all(&mut db, Standby, &[10, 14, 18]);
        assert_eq!(db.unlink(14), UnlinkOutcome::Unlinked);
        assert_eq!(db.list_total(Standby), 2);
        assert_eq!(db.entry(10).next, Some(18));
        assert_eq!(db.entry(18).prev, Some(10));
        assert_eq!(db.entry(14).next, None);
        assert_eq!(db.entry(14).prev, None);
        assert_eq!(db.entry(14).state, Active);
        assert_eq!(db.available(), 2);
        assert_eq!(db.audit(), Ok(()));
    }

    #[test]
    fn unlink_head_tail_and_sole_frames() {
        let mut db = new_db();
        release_all(&mut db, Standby, &[10, 14, 18]);
        db.unlink(10);
        assert_eq!(db.standby.head, Some(14));
        assert_eq!(db.entry(14).prev, None);
        db.unlink(18);
        assert_eq!(db.standby.tail, Some(14));
        assert_eq!(db.entry(14).next, None);
        db.unlink(14);
        assert_eq!(db.standby.head, None);
        assert_eq!(db.standby.tail, None);
        assert_eq!(db.list_total(Standby), 0);
        assert_eq!(db.available(), 0);
        assert_eq!(db.audit(), Ok(()));
    }

    #[test]
    fn unlink_busy_frame_is_left_in_place() {
        let mut db = new_db();
        db.release(10, Standby);
        db.entry_mut(10).refcount = 1;
        assert_eq!(db.unlink(10), UnlinkOutcome::Busy);
        assert_eq!(db.list_total(Standby), 1);
        assert_eq!(db.entry(10).state, Standby);
    }

    #[test]
    #[should_panic(expected = "corrupts the list")]
    fn unlink_referenced_mapped_frame_panics() {
        let mut db = new_db();
        db.release(10, Standby);
        db.entry_mut(10).refcount = 1;
        db.entry_mut(10).share_count = 1;
        db.unlink(10);
    }

    #[test]
    #[should_panic(expected = "take()")]
    fn unlink_free_frame_requires_take() {
        let mut db = new_db();
        db.release(4, Free);
        db.unlink(4);
    }

    #[test]
    fn take_specific_colored_frame_keeps_chains_consistent() {
        let mut db = new_db();
        // Colors (mask 3): 4 and 8 are color 0; 5, 9, 13, 17 are color 1.
        release_all(&mut db, Free, &[4, 5, 9, 8, 13, 17]);
        db.entry_mut(9).flags.insert(FrameFlags::MODIFIED);

        db.take(9);
        assert_eq!(db.entry(5).next, Some(8));
        assert_eq!(db.entry(8).prev, Some(5));
        assert_eq!(db.entry(9).state, Active);
        // Flags survive take: the caller owns the rest of the transition.
        assert!(db.entry(9).flags.contains(FrameFlags::MODIFIED));
        assert_eq!(db.entry(5).next_color, Some(13));
        assert_eq!(db.buckets.inner[1][1].tail, Some(17));
        assert_eq!(db.list_total(Free), 5);
        assert_eq!(db.available(), 5);
        assert_eq!(db.audit(), Ok(()));

        // Tail of a color chain keeps the bucket tail correct.
        db.take(17);
        assert_eq!(db.buckets.inner[1][1].tail, Some(13));
        assert_eq!(db.entry(13).next_color, None);
        // Head of a color chain.
        db.take(5);
        assert_eq!(db.buckets.inner[1][1].head, Some(13));
        // A chain with more than one frame left.
        db.take(4);
        assert_eq!(db.buckets.inner[1][0].head, Some(8));
        // Sole frame of a color chain empties the bucket.
        db.take(8);
        assert_eq!(db.buckets.inner[1][0].head, None);
        assert_eq!(db.buckets.inner[1][0].tail, None);
        assert_eq!(db.audit(), Ok(()));
    }

    #[test]
    #[should_panic(expected = "take() only accepts")]
    fn take_requires_a_colored_state() {
        let mut db = new_db();
        db.release(10, Standby);
        db.take(10);
    }

    #[test]
    fn allocate_zeroed_prefers_matching_color_without_zeroing() {
        let mut db = new_db();
        release_all(&mut db, Zeroed, &[6, 5]);
        let stamps_before = db.hooks.stamped.len();
        assert_eq!(db.allocate_zeroed(1), 5);
        assert!(db.hooks.zeroed.is_empty());
        assert_eq!(db.hooks.stamped.len(), stamps_before);
        // Any-color fallback stays zeroed too.
        assert_eq!(db.allocate_zeroed(0), 6);
        assert!(db.hooks.zeroed.is_empty());
    }

    #[test]
    fn allocate_zeroed_zeroes_free_and_standby_in_fallback() {
        let mut db = new_db();
        release_all(&mut db, Free, &[5]);
        release_all(&mut db, Standby, &[12]);
        let stamps_before = db.hooks.stamped.len();
        assert_eq!(db.allocate_zeroed(1), 5);
        assert_eq!(db.hooks.zeroed, vec![5]);
        assert_eq!(db.hooks.stamped.len(), stamps_before + 1);
        assert_eq!(db.allocate_zeroed(1), 12);
        assert_eq!(db.hooks.restored, vec![12]);
        assert_eq!(db.hooks.zeroed, vec![5, 12]);
        assert_eq!(db.audit(), Ok(()));
    }

    #[test]
    fn allocate_prefers_free_and_never_zeroes() {
        let mut db = new_db();
        release_all(&mut db, Free, &[5]);
        release_all(&mut db, Zeroed, &[9]);
        assert_eq!(db.allocate(1), 5);
        assert!(db.hooks.zeroed.is_empty());
        assert_eq!(db.allocate(1), 9);
        assert!(db.hooks.zeroed.is_empty());

        // The zeroed allocation makes the opposite choice on the same
        // state: zeroed over free.
        {
            let mut db = new_db();
            release_all(&mut db, Free, &[5]);
            release_all(&mut db, Zeroed, &[9]);
            assert_eq!(db.allocate_zeroed(1), 9);
        }
    }

    #[test]
    #[should_panic(expected = "no frames are available")]
    fn allocate_zeroed_on_empty_database_panics() {
        let mut db = new_db();
        db.allocate_zeroed(0);
    }

    #[test]
    #[should_panic(expected = "no frames are available")]
    fn allocate_on_empty_database_panics() {
        let mut db = new_db();
        db.allocate(0);
    }

    #[test]
    fn zeroing_is_requested_once_per_pass_and_only_for_free() {
        let mut db = new_db();
        db.set_zeroing_threshold(3);
        release_all(&mut db, Free, &[1, 2, 3]);
        assert_eq!(db.hooks.zeroing, 1);
        db.release(4, Free); // Pass already armed: no second request.
        assert_eq!(db.hooks.zeroing, 1);
        db.zeroing_done();
        db.release(5, Free); // Armed again at the next release.
        assert_eq!(db.hooks.zeroing, 2);

        // Releasing into the zeroed list never requests a pass.
        {
            let mut db = new_db();
            db.set_zeroing_threshold(3);
            release_all(&mut db, Zeroed, &[1, 2, 3]);
            assert_eq!(db.hooks.zeroing, 0);
        }
    }

    #[test]
    fn available_water_marks_fire_on_release_only() {
        let mut db = new_db();
        release_all(&mut db, Free, &[1, 2]);
        assert_eq!(db.hooks.low, 1);
        db.take(1); // Removal path: no event.
        assert_eq!(db.hooks.low, 1);
        db.release(3, Free); // Back at the low mark: fires again.
        assert_eq!(db.hooks.low, 2);
        for f in 4..=20u32 {
            db.release(f, Free);
        }
        assert_eq!(db.available(), 19);
        assert_eq!(db.hooks.high, 1);
        assert_eq!(db.audit(), Ok(()));
    }

    #[test]
    fn reclaim_hook_fires_below_the_minimum_on_all_removal_paths() {
        let mut db = new_db();
        db.set_min_free_pages(2);
        release_all(&mut db, Free, &[1, 2, 3]);
        assert_eq!(db.hooks.reclaim, 0); // The release path never fires it.
        assert_eq!(db.allocate(1), 1); // Colored removal: not below yet.
        assert_eq!(db.hooks.reclaim, 0);
        assert_eq!(db.allocate(1), 2); // Below the minimum.
        assert_eq!(db.hooks.reclaim, 1);
        db.release(10, Standby); // Release path stays silent.
        assert_eq!(db.hooks.reclaim, 1);
        db.unlink(10); // Unlink path.
        assert_eq!(db.hooks.reclaim, 2);
        db.release(12, Standby);
        assert_eq!(db.allocate_zeroed(1), 3); // Free head, zeroed on demand.
        assert_eq!(db.hooks.reclaim, 3);
        assert_eq!(db.audit(), Ok(()));
    }

    #[test]
    fn audit_detects_corruption() {
        let mut db = new_db();
        release_all(&mut db, Free, &[5, 9]);
        db.available += 1;
        assert_eq!(db.audit(), Err(AuditError::AvailableMismatch));
        db.available -= 1;
        db.free.total = 5;
        assert_eq!(db.audit(), Err(AuditError::TotalMismatch { state: Free }));
        db.free.total = 2;
        db.entry_mut(9).state = Zeroed;
        assert_eq!(db.audit(), Err(AuditError::StateMismatch { frame: 9 }));
        db.entry_mut(9).state = Free;
        assert_eq!(db.audit(), Ok(()));
    }

    #[test]
    fn audit_passes_after_mixed_operations() {
        let mut db = new_db();
        release_all(&mut db, Zeroed, &[6]);
        release_all(&mut db, Free, &[5, 9, 13]);
        release_all(&mut db, Standby, &[10, 14]);
        release_all(&mut db, Modified, &[18]);
        release_all(&mut db, ModifiedNoWrite, &[22]);
        release_all(&mut db, Bad, &[26]);
        assert_eq!(db.allocate_zeroed(1), 6);
        assert_eq!(db.allocate(1), 5);
        assert_eq!(db.allocate_zeroed(1), 9);
        db.take(13);
        db.unlink(14);
        assert_eq!(db.allocate_zeroed(0), 10);
        assert_eq!(db.hooks.zeroed, vec![9, 10]);
        assert_eq!(db.hooks.restored, vec![10]);
        assert_eq!(db.available(), 0);
        assert_eq!(db.list_total(Modified), 1);
        assert_eq!(db.list_total(Bad), 1);
        assert_eq!(db.audit(), Ok(()));
    }

    #[test]
    #[should_panic(expected = "invalid frame id")]
    fn frame_zero_is_rejected() {
        let mut db = new_db();
        db.release(0, Free);
    }

    #[test]
    #[should_panic(expected = "invalid frame id")]
    fn frame_out_of_range_is_rejected() {
        let mut db = new_db();
        db.release(TABLE as FrameId, Free);
    }

    #[test]
    #[should_panic(expected = "in-page-error")]
    fn release_rejects_in_page_error_frames_on_colored_lists() {
        let mut db = new_db();
        db.entry_mut(4).flags.insert(FrameFlags::IN_PAGE_ERROR);
        db.release(4, Free);
    }
}
