//! The working-set trim policy: when free frames run low, how many pages one relieve evicts
//! from a process's working set, and the orchestration that evicts them.
//!
//! [`TrimPolicy`] holds the threshold and the batch cap: [`TrimPolicy::pressure`] says whether a
//! free-frame count is low enough to trim (at or below the threshold), and
//! [`TrimPolicy::victim_count`] how many victims one relieve selects from a set's size and its
//! limits — past the maximum the set comes home to it, within its limits it gives up a batch
//! down towards its minimum, never below the minimum and never more than the cap.
//!
//! [`relieve_pressure`] runs one relieve: it trims the set LRU-oldest first through
//! [`WorkingSet::trim_to`] and evicts each victim — the caller's `resolve` maps the page's
//! address to its frame and backing state, a clean frame goes to standby through
//! [`pageout::to_standby`], and a dirty page is handed to the caller's `evict_dirty` callback
//! with its frame and slot, because the page-out I/O lives in the page-out slice. The fault
//! path calls it when a demand-zero map finds no frame; this module is the policy and the
//! orchestration, and reaches no page tables itself.

use super::frame::{FrameDb, FrameHooks, FrameId};
use super::pageout::{self, SlotId};
use super::paging::PAGE_SIZE;
use super::ws::WorkingSet;

/// One victim page, as the caller resolves it from the page's entry and the frame database: the
/// frame the entry names, whether the frame is dirty, and the backing-store slot the page
/// already holds.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Victim {
    /// The page's frame, as a frame number (its physical address over the page size).
    pub frame: FrameId,
    /// Whether the frame is dirty — written since it was mapped: a dirty page needs page-out
    /// I/O before its frame can be reused, a clean one does not.
    pub dirty: bool,
    /// The backing-store slot the page already holds, or [`pageout::INVALID_SLOT`] when it holds
    /// none (a page never written out).
    pub slot: SlotId,
}

/// The trim policy: the free-frame threshold that triggers a relieve, and the batch cap on how
/// many victims one relieve selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrimPolicy {
    /// The free-frame threshold: pressure at or below this many free frames.
    pub free_threshold: u32,
    /// The most victims one relieve selects.
    pub batch_max: usize,
}

impl TrimPolicy {
    /// The policy a relieve runs with on this target: pressure at or below 64 free frames — the
    /// page writer's free goal ([`super::pageout::WriterPolicy::TYPICAL`]) — relieving in
    /// batches of up to 64 pages.
    pub const DEFAULT: TrimPolicy = TrimPolicy {
        free_threshold: 64,
        batch_max: 64,
    };

    /// Thresholds `free_threshold`/`batch_max`; a zero batch is refused.
    pub const fn new(free_threshold: u32, batch_max: usize) -> Self {
        assert!(batch_max >= 1, "a relieve always selects at least one candidate");
        TrimPolicy {
            free_threshold,
            batch_max,
        }
    }

    /// Whether `free_frames` is low enough to trim: at or below the threshold.
    pub fn pressure(&self, free_frames: u32) -> bool {
        free_frames <= self.free_threshold
    }

    /// How many victims one relieve selects from a set of `len` entries limited to `min`/`max`:
    /// past the maximum the set comes home to it, within its limits it gives up a batch down
    /// towards the minimum — never below the minimum, never more than [`Self::batch_max`].
    pub fn victim_count(&self, len: usize, min: usize, max: usize) -> usize {
        let down_to = if len > max { max } else { min };
        len.saturating_sub(down_to).min(self.batch_max)
    }
}

/// What one [`relieve_pressure`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TrimReport {
    /// Whether pressure was found: the free-frame count was at or below the threshold.
    pub pressured: bool,
    /// How many victims the policy selected. Locked entries mean fewer actual evictions.
    pub selected: usize,
    /// How many clean victims went to standby.
    pub clean: usize,
    /// How many dirty victims were handed to the eviction callback.
    pub dirty: usize,
    /// How many victims the resolver could not map to a frame; their entries left the set all
    /// the same, their frames stayed where they were.
    pub skipped: usize,
}

/// The victims one relieve selects, in chunks, so the selection buffer stays small next to the
/// caller's stack.
const CHUNK: usize = 64;

/// Relieve pressure on the free frames by trimming `ws`: when `free_frames` is at or below the
/// policy's threshold, select [`TrimPolicy::victim_count`] victims — LRU-oldest first, through
/// [`WorkingSet::trim_to`] — and evict each one. `resolve` maps a victim's page address to its
/// frame and backing state; a clean frame goes to standby through [`pageout::to_standby`] in
/// `db`, and a dirty page is handed to `evict_dirty` with its frame and slot, the page-out I/O
/// being the caller's. Returns what the relieve did; with no pressure the set is untouched.
pub fn relieve_pressure<H: FrameHooks>(
    policy: &TrimPolicy,
    ws: &mut WorkingSet,
    db: &mut FrameDb<H>,
    free_frames: u32,
    mut resolve: impl FnMut(u32) -> Option<Victim>,
    mut evict_dirty: impl FnMut(FrameId, SlotId),
) -> TrimReport {
    let mut report = TrimReport {
        pressured: policy.pressure(free_frames),
        ..TrimReport::default()
    };
    if !report.pressured {
        return report;
    }
    let mut remaining = policy.victim_count(ws.len(), ws.min(), ws.max());
    report.selected = remaining;
    let mut batch = [0u32; CHUNK];
    while remaining > 0 {
        let want = remaining.min(CHUNK);
        let target = ws.len().saturating_sub(want);
        let evicted = ws.trim_to(target, &mut batch);
        if evicted == 0 {
            break;
        }
        for &va in &batch[..evicted] {
            match resolve(va) {
                Some(victim) => {
                    if victim.dirty {
                        evict_dirty(victim.frame, victim.slot);
                        report.dirty += 1;
                    } else {
                        pageout::to_standby(db, victim.frame);
                        report.clean += 1;
                    }
                }
                None => report.skipped += 1,
            }
        }
        remaining -= evicted;
    }
    report
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::mem::frame::{ColorTables, FrameEntry, FrameState, NoHooks, DEFAULT_COLOR_COUNT};
    use crate::mem::pageout;

    /// Page `n`'s base address.
    fn page(n: u32) -> u32 {
        n * PAGE_SIZE
    }

    /// The virtual addresses of the set, least recently used first.
    fn order(ws: &WorkingSet) -> Vec<u32> {
        ws.iter().map(|e| e.va).collect()
    }

    /// The fake frame database: a table of in-use frames, as the host builds it.
    const TABLE: usize = 256;

    fn new_db() -> FrameDb<NoHooks> {
        let table: &'static mut [FrameEntry] =
            Box::leak(vec![FrameEntry::new(); TABLE].into_boxed_slice());
        let buckets: &'static mut ColorTables = Box::leak(Box::new(ColorTables::new()));
        FrameDb::new(table, buckets, DEFAULT_COLOR_COUNT, NoHooks)
    }

    /// The fake resolution: page `n` maps frame `n`, dirty when `n` is in `dirty`, holding slot
    /// `100 + n` when dirty and no slot otherwise.
    fn victims(dirty: &[u32]) -> HashMap<u32, Victim> {
        let mut map = HashMap::new();
        for n in 1..TABLE as u32 {
            let is_dirty = dirty.contains(&n);
            map.insert(
                page(n),
                Victim {
                    frame: n,
                    dirty: is_dirty,
                    slot: if is_dirty {
                        100 + n
                    } else {
                        pageout::INVALID_SLOT
                    },
                },
            );
        }
        map
    }

    /// Pressure trips at or below the threshold: at it and below it trims, above it does not.
    #[test]
    fn pressure_trips_at_or_below_the_threshold() {
        let policy = TrimPolicy::new(64, 64);
        assert!(policy.pressure(64), "at the threshold");
        assert!(policy.pressure(63), "below it");
        assert!(policy.pressure(0));
        assert!(!policy.pressure(65), "above it");
        assert!(!policy.pressure(u32::MAX));
        assert_eq!(TrimPolicy::DEFAULT.free_threshold, 64);
        assert!(TrimPolicy::DEFAULT.batch_max >= 1);
    }

    /// A policy with an empty batch is refused: a relieve always selects at least one candidate.
    #[test]
    #[should_panic(expected = "at least one")]
    fn the_policy_refuses_an_empty_batch() {
        TrimPolicy::new(1, 0);
    }

    /// The victim count: past the maximum the set comes home to it, within its limits it gives
    /// up a batch down towards the minimum — never below the minimum, never past the batch cap.
    #[test]
    fn the_victim_count_follows_the_limits_and_the_batch_cap() {
        let policy = TrimPolicy::new(10, 4);
        // Past the maximum: home to it (10 - 6 = 4, within the cap of 4).
        assert_eq!(policy.victim_count(10, 2, 6), 4);
        assert_eq!(policy.victim_count(8, 2, 6), 2);
        // At or within the limits: a batch towards the minimum, capped at 4.
        assert_eq!(policy.victim_count(6, 2, 6), 4);
        assert_eq!(policy.victim_count(5, 2, 6), 3);
        assert_eq!(policy.victim_count(3, 2, 6), 1);
        // At or below the minimum: nothing.
        assert_eq!(policy.victim_count(2, 2, 6), 0);
        assert_eq!(policy.victim_count(1, 2, 6), 0);
        // The batch cap binds past the maximum too.
        assert_eq!(policy.victim_count(20, 0, 2), 4);
        let wide = TrimPolicy::new(10, 100);
        assert_eq!(wide.victim_count(50, 10, 20), 30, "50 - 20, past the max");
        assert_eq!(wide.victim_count(15, 10, 20), 5, "towards the min");
        assert_eq!(wide.victim_count(20, 10, 20), 10, "at the max, down to the min");
    }

    /// Above the threshold a relieve does nothing: the set, the database and the callback are
    /// untouched, and the report says there was no pressure.
    #[test]
    fn a_relieve_above_the_threshold_does_nothing() {
        let mut ws = WorkingSet::with_limits(0, 100).unwrap();
        for n in 1..=8 {
            ws.insert(page(n));
        }
        let mut db = new_db();
        let policy = TrimPolicy::new(10, 64);
        let map = victims(&[2, 5]);
        let mut dirty_calls: Vec<(FrameId, SlotId)> = Vec::new();
        let report = relieve_pressure(
            &policy,
            &mut ws,
            &mut db,
            11,
            |va| map.get(&va).copied(),
            |frame, slot| dirty_calls.push((frame, slot)),
        );
        assert_eq!(
            report,
            TrimReport {
                pressured: false,
                selected: 0,
                clean: 0,
                dirty: 0,
                skipped: 0
            }
        );
        assert_eq!(ws.len(), 8, "the set is untouched");
        assert_eq!(order(&ws), (1..=8).map(page).collect::<Vec<_>>());
        assert_eq!(db.list_total(FrameState::Standby), 0);
        assert!(dirty_calls.is_empty());
    }

    /// A relieve under pressure trims LRU-oldest first: each victim resolves to its frame, a
    /// clean frame goes to standby in the database, a dirty page goes to the callback with its
    /// frame and slot — both in the trim's order.
    #[test]
    fn a_relieve_trims_lru_oldest_first_and_splits_clean_from_dirty() {
        let mut ws = WorkingSet::with_limits(0, 100).unwrap();
        for n in 1..=8 {
            ws.insert(page(n));
        }
        ws.touch(page(2));
        ws.touch(page(5));
        assert_eq!(
            order(&ws),
            [page(1), page(3), page(4), page(6), page(7), page(8), page(2), page(5)]
        );

        let mut db = new_db();
        let policy = TrimPolicy::new(10, 64);
        let map = victims(&[2, 5]);
        let mut dirty_calls: Vec<(FrameId, SlotId)> = Vec::new();
        let report = relieve_pressure(
            &policy,
            &mut ws,
            &mut db,
            10, // at the threshold: pressure
            |va| map.get(&va).copied(),
            |frame, slot| dirty_calls.push((frame, slot)),
        );
        assert_eq!(
            report,
            TrimReport {
                pressured: true,
                selected: 8,
                clean: 6,
                dirty: 2,
                skipped: 0
            }
        );
        assert!(ws.is_empty(), "the whole set was within the batch");
        for n in [1u32, 3, 4, 6, 7, 8] {
            assert_eq!(
                db.entry(n).state,
                FrameState::Standby,
                "clean page {n} went to standby"
            );
        }
        assert_eq!(
            dirty_calls,
            vec![(2, 102), (5, 105)],
            "the dirty victims, LRU order, with their slots"
        );
        for n in [2u32, 5] {
            assert_eq!(
                db.entry(n).state,
                FrameState::Active,
                "dirty page {n} is the callback's to evict"
            );
        }
        assert_eq!(db.available(), 6, "the standby frames are available again");
        assert_eq!(db.audit(), Ok(()));
    }

    /// A set past its maximum comes home to it on a relieve: the victims are the oldest past the
    /// maximum, and the set is back within its limits.
    #[test]
    fn a_relieve_brings_a_set_past_its_maximum_home() {
        let mut ws = WorkingSet::with_limits(2, 4).unwrap();
        for n in 1..=6 {
            ws.insert(page(n));
        }
        assert!(ws.over_max());
        let mut db = new_db();
        let policy = TrimPolicy::new(0, 64);
        let map = victims(&[]);
        let report = relieve_pressure(&policy, &mut ws, &mut db, 0, |va| map.get(&va).copied(), |_, _| {
            panic!("no dirty pages in this set")
        });
        assert_eq!(
            report,
            TrimReport {
                pressured: true,
                selected: 2,
                clean: 2,
                dirty: 0,
                skipped: 0
            }
        );
        assert_eq!(order(&ws), [page(3), page(4), page(5), page(6)]);
        assert!(!ws.over_max());
    }

    /// A relieve never evicts below the set's minimum, and locked entries are never selected: the
    /// trim takes the unlocked ones past them and stops where the minimum binds.
    #[test]
    fn a_relieve_never_goes_below_the_minimum_and_skips_locked_entries() {
        let mut ws = WorkingSet::with_limits(3, 10).unwrap();
        for n in 1..=5 {
            ws.insert(page(n));
        }
        assert!(ws.lock(page(1)));
        let mut db = new_db();
        let policy = TrimPolicy::new(0, 64);
        let map = victims(&[]);
        let report = relieve_pressure(&policy, &mut ws, &mut db, 0, |va| map.get(&va).copied(), |_, _| {});
        assert_eq!(
            report,
            TrimReport {
                pressured: true,
                selected: 2,
                clean: 2,
                dirty: 0,
                skipped: 0
            }
        );
        assert_eq!(order(&ws), [page(1), page(4), page(5)], "locked page 1 stayed");
        assert_eq!(ws.len(), 3, "down to the minimum");
        assert_eq!(db.entry(1).state, FrameState::Active);
        assert_eq!(db.entry(2).state, FrameState::Standby);
        assert_eq!(db.entry(3).state, FrameState::Standby);

        // A fully locked set evicts nothing at all.
        let mut locked = WorkingSet::with_limits(0, 10).unwrap();
        for n in 1..=3 {
            locked.insert(page(n));
            assert!(locked.lock(page(n)));
        }
        let mut db = new_db();
        let report = relieve_pressure(&policy, &mut locked, &mut db, 0, |va| map.get(&va).copied(), |_, _| {});
        assert_eq!(report.selected, 3);
        assert_eq!(report.clean, 0, "nothing evictable");
        assert_eq!(locked.len(), 3);
    }

    /// The batch cap binds: a relieve selects at most `batch_max` victims however big the set,
    /// still LRU-oldest first.
    #[test]
    fn a_relieve_selects_at_most_the_batch() {
        let mut ws = WorkingSet::new();
        for n in 1..=10 {
            ws.insert(page(n));
        }
        let mut db = new_db();
        let policy = TrimPolicy::new(5, 3);
        let map = victims(&[]);
        let mut seen: Vec<u32> = Vec::new();
        let report = relieve_pressure(
            &policy,
            &mut ws,
            &mut db,
            5,
            |va| {
                seen.push(va);
                map.get(&va).copied()
            },
            |_, _| {},
        );
        assert_eq!(report.selected, 3);
        assert_eq!(report.clean, 3);
        assert_eq!(seen, vec![page(1), page(2), page(3)]);
        assert_eq!(ws.len(), 7);
        assert_eq!(db.list_total(FrameState::Standby), 3);
    }

    /// A victim the resolver cannot resolve is skipped: its entry left the set all the same, but
    /// no frame moved and the callback heard nothing.
    #[test]
    fn a_relieve_skips_a_victim_it_cannot_resolve() {
        let mut ws = WorkingSet::with_limits(0, 100).unwrap();
        for n in 1..=4 {
            ws.insert(page(n));
        }
        let mut db = new_db();
        let policy = TrimPolicy::new(0, 64);
        let map = victims(&[]);
        let mut dirty_calls: Vec<(FrameId, SlotId)> = Vec::new();
        let report = relieve_pressure(
            &policy,
            &mut ws,
            &mut db,
            0,
            |va| {
                if va == page(2) {
                    None
                } else {
                    map.get(&va).copied()
                }
            },
            |frame, slot| dirty_calls.push((frame, slot)),
        );
        assert_eq!(
            report,
            TrimReport {
                pressured: true,
                selected: 4,
                clean: 3,
                dirty: 0,
                skipped: 1
            }
        );
        assert!(ws.is_empty());
        assert_eq!(db.entry(2).state, FrameState::Active, "page 2's frame stayed put");
        assert_eq!(db.list_total(FrameState::Standby), 3);
        assert!(dirty_calls.is_empty());
    }

    /// A relieve larger than the selection chunk still takes its victims LRU-oldest first, in
    /// one pass over the set.
    #[test]
    fn a_relieve_larger_than_the_chunk_keeps_the_lru_order() {
        let mut ws = WorkingSet::new();
        for n in 1..=150 {
            ws.insert(page(n));
        }
        let mut db = new_db();
        let policy = TrimPolicy::new(0, 200); // more than one chunk
        let map = victims(&[]);
        let mut seen: Vec<u32> = Vec::new();
        let report = relieve_pressure(
            &policy,
            &mut ws,
            &mut db,
            0,
            |va| {
                seen.push(va);
                map.get(&va).copied()
            },
            |_, _| {},
        );
        assert_eq!(report.selected, 150);
        assert_eq!(report.clean, 150);
        assert_eq!(seen, (1..=150).map(page).collect::<Vec<_>>());
        assert!(ws.is_empty());
        assert_eq!(db.list_total(FrameState::Standby), 150);
        assert_eq!(db.audit(), Ok(()));
    }

    /// A relieve on an empty set under pressure selects nothing and touches nothing.
    #[test]
    fn a_relieve_on_an_empty_set_selects_nothing() {
        let mut ws = WorkingSet::new();
        let mut db = new_db();
        let policy = TrimPolicy::new(4, 8);
        let report = relieve_pressure(&policy, &mut ws, &mut db, 0, |_| None, |_, _| {
            panic!("no victims to evict")
        });
        assert_eq!(
            report,
            TrimReport {
                pressured: true,
                selected: 0,
                clean: 0,
                dirty: 0,
                skipped: 0
            }
        );
        assert!(ws.is_empty());
        assert_eq!(db.list_total(FrameState::Standby), 0);
    }
}
