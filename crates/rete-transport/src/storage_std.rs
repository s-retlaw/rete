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
use rete_core::TRUNCATED_HASH_LEN;

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
    type PathMap = HashMap<[u8; TRUNCATED_HASH_LEN], Path>;
    type IdentityMap = HashMap<[u8; TRUNCATED_HASH_LEN], [u8; 64]>;
    type ReverseMap = HashMap<[u8; TRUNCATED_HASH_LEN], ReverseEntry>;
    type ReceiptMap = HashMap<[u8; TRUNCATED_HASH_LEN], PacketReceipt>;
    type AnnounceRateMap = HashMap<[u8; TRUNCATED_HASH_LEN], AnnounceRateEntry>;
    type PathRequestTimeMap = HashMap<[u8; TRUNCATED_HASH_LEN], u64>;

    type LinkMap = HashMap<[u8; TRUNCATED_HASH_LEN], Link>;
    type ChannelReceiptMap = HashMap<[u8; TRUNCATED_HASH_LEN], ChannelReceipt>;
    type LinkTableMap = HashMap<[u8; TRUNCATED_HASH_LEN], LinkTableEntry>;

    type AnnounceDeque = VecDeque<PendingAnnounce>;
    type DedupDeque = VecDeque<[u8; 32]>;
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

