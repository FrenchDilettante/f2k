//! The mount state: where a validated volume keeps its FAT, its data region, and its clusters.
//! All LBAs are volume-relative (sector 0 is the boot sector).

/// A mounted volume's geometry, computed from its boot sector.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Layout {
    pub sectors_per_cluster: u32,
    /// The first FAT's first sector: right after the reserved sectors.
    pub fat_start: u64,
    pub sectors_per_fat: u32,
    /// Cluster 2's first sector: after the reserved sectors and every FAT copy.
    pub data_start: u64,
    /// Data clusters on the volume; they are numbered 2 onward.
    pub cluster_count: u32,
    /// The root directory's first cluster.
    pub root_cluster: u32,
}

impl Layout {
    /// The highest valid cluster number.
    pub fn max_cluster(&self) -> u32 {
        self.cluster_count + 1
    }

    /// Whether `cluster` names a data cluster of this volume (2..=max).
    pub fn is_data_cluster(&self, cluster: u32) -> bool {
        (2..=self.max_cluster()).contains(&cluster)
    }

    /// The first sector of `cluster`, which must be a data cluster of this volume.
    pub fn cluster_lba(&self, cluster: u32) -> u64 {
        assert!(
            self.is_data_cluster(cluster),
            "cluster {} is not a data cluster of the volume",
            cluster
        );
        self.data_start + (cluster - 2) as u64 * self.sectors_per_cluster as u64
    }
}

#[cfg(test)]
mod tests {
    use super::super::fixtures::built_layout as built;
    use super::*;

    /// Cluster 2 is the data region's first sector; cluster 3 the next; the last valid cluster is
    /// the cluster count plus one.
    #[test]
    fn the_cluster_math() {
        let layout = built();
        assert_eq!(layout.cluster_lba(2), 2018);
        assert_eq!(layout.cluster_lba(3), 2019);
        assert_eq!(layout.max_cluster(), 127_007);
        assert_eq!(layout.cluster_lba(127_007), 2018 + 127_005);
        assert!(!layout.is_data_cluster(0));
        assert!(!layout.is_data_cluster(1));
        assert!(!layout.is_data_cluster(127_008));

        // Larger clusters scale the offset.
        let wide = Layout {
            sectors_per_cluster: 8,
            ..layout
        };
        assert_eq!(wide.cluster_lba(3), 2018 + 8);
    }

    #[test]
    #[should_panic(expected = "not a data cluster")]
    fn cluster_one_has_no_sectors() {
        built().cluster_lba(1);
    }

    #[test]
    #[should_panic(expected = "not a data cluster")]
    fn a_cluster_past_the_volume_has_no_sectors() {
        built().cluster_lba(127_008);
    }
}
