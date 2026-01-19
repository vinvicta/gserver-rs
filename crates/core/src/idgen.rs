//! ID generation with segmented ranges

use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::atomic::{self, AtomicU64};
use std::sync::Arc;

/// Thread-safe ID generator with segmented ranges
pub struct IdGenerator<T: Copy + Into<u64> + TryFrom<u64> + Eq + std::hash::Hash> {
    segments: Mutex<HashMap<T, Vec<T>>>,
    next_id: Arc<AtomicU64>,
    phantom: std::marker::PhantomData<T>,
}

impl<T: Copy + Into<u64> + TryFrom<u64> + Eq + std::hash::Hash> IdGenerator<T> {
    pub fn new() -> Self {
        Self {
            segments: Mutex::new(HashMap::new()),
            next_id: Arc::new(AtomicU64::new(0)),
            phantom: std::marker::PhantomData,
        }
    }

    /// Create a new segment for ID allocation
    pub fn create_segment(&self, range: std::ops::Range<T>) {
        let mut segments = self.segments.lock();
        let ids: Vec<T> = (range.start.into()..range.end.into())
            .map(|v| T::try_from(v).ok())
            .filter_map(|v| v)
            .collect();
        segments.insert(range.start, ids);
    }

    /// Get the next available ID
    pub fn get_available_id(&self) -> T {
        loop {
            let id = self.next_id.fetch_add(1, atomic::Ordering::Relaxed);
            if let Ok(id) = T::try_from(id) {
                return id;
            }
        }
    }
}

impl<T: Copy + Into<u64> + TryFrom<u64> + Eq + std::hash::Hash> Default for IdGenerator<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_id_generation() {
        let gen = IdGenerator::<u16>::new();
        let id1 = gen.get_available_id();
        let id2 = gen.get_available_id();
        assert_ne!(id1, id2);
    }
}
