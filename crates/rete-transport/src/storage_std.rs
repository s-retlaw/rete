//! Heap-allocated storage backend for hosted targets.
//!
//! Uses `hashbrown::HashMap`/`HashSet` (no_std + alloc compatible) and
//! `alloc::collections::VecDeque`.

extern crate alloc;

use alloc::collections::VecDeque;
use hashbrown::HashMap;

use crate::announce::PendingAnnounce;
use crate::link::Link;
use crate::path::Path;
use crate::receipt::PacketReceipt;
use crate::storage::{
    StorageDeque, StorageMap, TransportStorage,
};
use crate::transport::{AnnounceRateEntry, ChannelReceipt, LinkTableEntry, ReverseEntry};
use rete_core::{DestHash, LinkId, TRUNCATED_HASH_LEN};

// ---------------------------------------------------------------------------
// BoundedVecDeque — VecDeque with a capacity limit (for dedup windows)
// ---------------------------------------------------------------------------

/// A `VecDeque` that reports `is_full()` when it reaches a fixed capacity.
///
/// Matches Python RNS's `Transport.HASHLIST_MAXSIZE = 4096`.
/// Without this, the hosted dedup window never evicts entries, causing
/// identical keepalive hashes to be permanently flagged as duplicates.
#[derive(Debug)]
pub struct BoundedVecDeque<V> {
    inner: VecDeque<V>,
    capacity: usize,
}

impl<V> Default for BoundedVecDeque<V> {
    fn default() -> Self {
        Self {
            inner: VecDeque::with_capacity(4096),
            capacity: 4096,
        }
    }
}

impl<V> StorageDeque<V> for BoundedVecDeque<V> {
    fn push_back(&mut self, value: V) -> Result<(), V> {
        self.inner.push_back(value);
        Ok(())
    }
    fn pop_front(&mut self) -> Option<V> {
        self.inner.pop_front()
    }
    fn len(&self) -> usize {
        self.inner.len()
    }
    fn is_full(&self) -> bool {
        self.inner.len() >= self.capacity
    }
    fn iter<'a>(&'a self) -> impl Iterator<Item = &'a V>
    where
        V: 'a,
    {
        self.inner.iter()
    }
    fn iter_mut<'a>(&'a mut self) -> impl Iterator<Item = &'a mut V>
    where
        V: 'a,
    {
        self.inner.iter_mut()
    }
    fn clear(&mut self) {
        self.inner.clear()
    }
}

// ---------------------------------------------------------------------------
// StdStorage — heap-allocated, growable
// ---------------------------------------------------------------------------

/// Heap-allocated storage using `hashbrown::HashMap` / `VecDeque`.
///
/// All collections grow dynamically — `insert` never returns `Err`,
/// `is_full` always returns `false`.
#[derive(Debug, Default)]
pub struct StdStorage;

impl TransportStorage for StdStorage {
    type PathMap = HashMap<DestHash, Path>;
    type IdentityMap = HashMap<DestHash, [u8; 64]>;
    type AnnounceRateMap = HashMap<DestHash, AnnounceRateEntry>;
    type PathRequestTimeMap = HashMap<DestHash, u64>;

    type ReverseMap = HashMap<[u8; TRUNCATED_HASH_LEN], ReverseEntry>;
    type ReceiptMap = HashMap<[u8; TRUNCATED_HASH_LEN], PacketReceipt>;

    type LinkMap = HashMap<LinkId, Link>;
    type ChannelReceiptMap = HashMap<[u8; TRUNCATED_HASH_LEN], ChannelReceipt>;
    type LinkTableMap = HashMap<LinkId, LinkTableEntry>;

    type AnnounceDeque = VecDeque<PendingAnnounce>;
    type DedupDeque = BoundedVecDeque<[u8; 32]>;
}

// ---------------------------------------------------------------------------
// StorageMap impl for HashMap
// ---------------------------------------------------------------------------

impl<K, V> StorageMap<K, V> for HashMap<K, V>
where
    K: Eq + core::hash::Hash,
{
    fn get(&self, key: &K) -> Option<&V> {
        HashMap::get(self, key)
    }
    fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        HashMap::get_mut(self, key)
    }
    fn insert(&mut self, key: K, value: V) -> Result<Option<V>, (K, V)> {
        Ok(HashMap::insert(self, key, value))
    }
    fn remove(&mut self, key: &K) -> Option<V> {
        HashMap::remove(self, key)
    }
    fn contains_key(&self, key: &K) -> bool {
        HashMap::contains_key(self, key)
    }
    fn len(&self) -> usize {
        HashMap::len(self)
    }
    fn iter<'a>(&'a self) -> impl Iterator<Item = (&'a K, &'a V)>
    where
        K: 'a,
        V: 'a,
    {
        HashMap::iter(self)
    }
    fn iter_mut<'a>(&'a mut self) -> impl Iterator<Item = (&'a K, &'a mut V)>
    where
        K: 'a,
        V: 'a,
    {
        HashMap::iter_mut(self)
    }
    fn keys<'a>(&'a self) -> impl Iterator<Item = &'a K>
    where
        K: 'a,
    {
        HashMap::keys(self)
    }
    fn retain(&mut self, f: impl FnMut(&K, &mut V) -> bool) {
        HashMap::retain(self, f)
    }
}

// ---------------------------------------------------------------------------
// StorageDeque impl for VecDeque
// ---------------------------------------------------------------------------

impl<V> StorageDeque<V> for VecDeque<V> {
    fn push_back(&mut self, value: V) -> Result<(), V> {
        VecDeque::push_back(self, value);
        Ok(())
    }
    fn pop_front(&mut self) -> Option<V> {
        VecDeque::pop_front(self)
    }
    fn len(&self) -> usize {
        VecDeque::len(self)
    }
    fn is_full(&self) -> bool {
        false
    }
    fn iter<'a>(&'a self) -> impl Iterator<Item = &'a V>
    where
        V: 'a,
    {
        VecDeque::iter(self)
    }
    fn iter_mut<'a>(&'a mut self) -> impl Iterator<Item = &'a mut V>
    where
        V: 'a,
    {
        VecDeque::iter_mut(self)
    }
    fn clear(&mut self) {
        VecDeque::clear(self)
    }
}

