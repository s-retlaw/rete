//! Storage abstraction — pluggable map, deque, and set backends.
//!
//! `Transport` is generic over [`TransportStorage`], which bundles the
//! associated collection types.  Two implementations ship:
//!
//! - [`HeaplessStorage`] — const-generic fixed-size (for embedded / no_std)
//! - [`StdStorage`] — heap-allocated growable (for hosted, behind `hosted` feature)

use crate::announce::PendingAnnounce;
use crate::link::Link;
use crate::receipt::PacketReceipt;
use crate::transport::{AnnounceRateEntry, ChannelReceipt, LinkTableEntry, ReverseEntry};
use crate::path::Path;
use rete_core::{DestHash, LinkId, TRUNCATED_HASH_LEN};

// ---------------------------------------------------------------------------
// Collection traits
// ---------------------------------------------------------------------------

/// A key-value map (like `HashMap` or `FnvIndexMap`).
pub trait StorageMap<K, V>: Default {
    fn get(&self, key: &K) -> Option<&V>;
    fn get_mut(&mut self, key: &K) -> Option<&mut V>;
    /// Insert a key-value pair.
    ///
    /// Returns `Ok(Some(old))` if the key existed, `Ok(None)` if new,
    /// `Err((k, v))` if the map is full (bounded maps only).
    fn insert(&mut self, key: K, value: V) -> Result<Option<V>, (K, V)>;
    fn remove(&mut self, key: &K) -> Option<V>;
    fn contains_key(&self, key: &K) -> bool;
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn iter<'a>(&'a self) -> impl Iterator<Item = (&'a K, &'a V)>
    where
        K: 'a,
        V: 'a;
    fn iter_mut<'a>(&'a mut self) -> impl Iterator<Item = (&'a K, &'a mut V)>
    where
        K: 'a,
        V: 'a;
    fn keys<'a>(&'a self) -> impl Iterator<Item = &'a K>
    where
        K: 'a;
    fn retain(&mut self, f: impl FnMut(&K, &mut V) -> bool);
}

/// A double-ended queue (like `VecDeque` or `heapless::Deque`).
pub trait StorageDeque<V>: Default {
    /// Push to the back. Returns `Err(v)` if full.
    fn push_back(&mut self, value: V) -> Result<(), V>;
    fn pop_front(&mut self) -> Option<V>;
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Returns `true` if the deque is at capacity (always `false` for growable).
    fn is_full(&self) -> bool;
    fn iter<'a>(&'a self) -> impl Iterator<Item = &'a V>
    where
        V: 'a;
    fn iter_mut<'a>(&'a mut self) -> impl Iterator<Item = &'a mut V>
    where
        V: 'a;
    fn clear(&mut self);
}


// ---------------------------------------------------------------------------
// TransportStorage — bundles all associated types
// ---------------------------------------------------------------------------

/// Provides concrete collection types for [`Transport`](crate::transport::Transport).
///
/// Each associated type corresponds to a logical table in the transport layer.
/// Grouped by capacity role: PATH (high cap), LINK (medium), deques, and sets.
pub trait TransportStorage: Default {
    // --- PATH-capacity maps (keyed by DestHash) ---
    type PathMap: StorageMap<DestHash, Path>;
    type IdentityMap: StorageMap<DestHash, [u8; 64]>;
    type AnnounceRateMap: StorageMap<DestHash, AnnounceRateEntry>;
    type PathRequestTimeMap: StorageMap<DestHash, u64>;

    // --- PATH-capacity maps (keyed by truncated packet hash) ---
    type ReverseMap: StorageMap<[u8; TRUNCATED_HASH_LEN], ReverseEntry>;
    type ReceiptMap: StorageMap<[u8; TRUNCATED_HASH_LEN], PacketReceipt>;

    // --- LINK-capacity maps ---
    type LinkMap: StorageMap<LinkId, Link>;
    type ChannelReceiptMap: StorageMap<[u8; TRUNCATED_HASH_LEN], ChannelReceipt>;
    type LinkTableMap: StorageMap<LinkId, LinkTableEntry>;

    // --- Deques ---
    type AnnounceDeque: StorageDeque<PendingAnnounce>;
    type DedupDeque: StorageDeque<[u8; 32]>;
}

// ---------------------------------------------------------------------------
// HeaplessStorage — const-generic fixed-size (embedded)
// ---------------------------------------------------------------------------

use heapless::FnvIndexMap;

/// Fixed-size storage backed by [`heapless`] collections.
///
/// Const generics mirror the original `Transport<P, A, D, L>` parameters:
/// - `P` = max paths (also identities, reverse entries, receipts, rate entries)
/// - `A` = max pending announces
/// - `D` = dedup window size
/// - `L` = max links (also channel receipts, link table entries)
#[derive(Debug)]
pub struct HeaplessStorage<
    const P: usize,
    const A: usize,
    const D: usize,
    const L: usize,
>;

impl<const P: usize, const A: usize, const D: usize, const L: usize> Default
    for HeaplessStorage<P, A, D, L>
{
    fn default() -> Self {
        HeaplessStorage
    }
}

impl<const P: usize, const A: usize, const D: usize, const L: usize> TransportStorage
    for HeaplessStorage<P, A, D, L>
{
    type PathMap = FnvIndexMap<DestHash, Path, P>;
    type IdentityMap = FnvIndexMap<DestHash, [u8; 64], P>;
    type AnnounceRateMap = FnvIndexMap<DestHash, AnnounceRateEntry, P>;
    type PathRequestTimeMap = FnvIndexMap<DestHash, u64, P>;

    type ReverseMap = FnvIndexMap<[u8; TRUNCATED_HASH_LEN], ReverseEntry, P>;
    type ReceiptMap = FnvIndexMap<[u8; TRUNCATED_HASH_LEN], PacketReceipt, P>;

    type LinkMap = FnvIndexMap<LinkId, Link, L>;
    type ChannelReceiptMap = FnvIndexMap<[u8; TRUNCATED_HASH_LEN], ChannelReceipt, L>;
    type LinkTableMap = FnvIndexMap<LinkId, LinkTableEntry, L>;

    type AnnounceDeque = heapless::Deque<PendingAnnounce, A>;
    type DedupDeque = heapless::Deque<[u8; 32], D>;
}

// ---------------------------------------------------------------------------
// StorageMap impl for FnvIndexMap
// ---------------------------------------------------------------------------

impl<K, V, const N: usize> StorageMap<K, V> for FnvIndexMap<K, V, N>
where
    K: Eq + core::hash::Hash,
{
    fn get(&self, key: &K) -> Option<&V> {
        FnvIndexMap::get(self, key)
    }
    fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        FnvIndexMap::get_mut(self, key)
    }
    fn insert(&mut self, key: K, value: V) -> Result<Option<V>, (K, V)> {
        FnvIndexMap::insert(self, key, value)
    }
    fn remove(&mut self, key: &K) -> Option<V> {
        FnvIndexMap::remove(self, key)
    }
    fn contains_key(&self, key: &K) -> bool {
        FnvIndexMap::contains_key(self, key)
    }
    fn len(&self) -> usize {
        FnvIndexMap::len(self)
    }
    fn iter<'a>(&'a self) -> impl Iterator<Item = (&'a K, &'a V)>
    where
        K: 'a,
        V: 'a,
    {
        FnvIndexMap::iter(self)
    }
    fn iter_mut<'a>(&'a mut self) -> impl Iterator<Item = (&'a K, &'a mut V)>
    where
        K: 'a,
        V: 'a,
    {
        FnvIndexMap::iter_mut(self)
    }
    fn keys<'a>(&'a self) -> impl Iterator<Item = &'a K>
    where
        K: 'a,
    {
        FnvIndexMap::keys(self)
    }
    fn retain(&mut self, f: impl FnMut(&K, &mut V) -> bool) {
        FnvIndexMap::retain(self, f)
    }
}

// ---------------------------------------------------------------------------
// StorageDeque impl for heapless::Deque
// ---------------------------------------------------------------------------

impl<V, const N: usize> StorageDeque<V> for heapless::Deque<V, N> {
    fn push_back(&mut self, value: V) -> Result<(), V> {
        heapless::Deque::push_back(self, value)
    }
    fn pop_front(&mut self) -> Option<V> {
        heapless::Deque::pop_front(self)
    }
    fn len(&self) -> usize {
        heapless::Deque::len(self)
    }
    fn is_full(&self) -> bool {
        heapless::Deque::is_full(self)
    }
    fn iter<'a>(&'a self) -> impl Iterator<Item = &'a V>
    where
        V: 'a,
    {
        heapless::Deque::iter(self)
    }
    fn iter_mut<'a>(&'a mut self) -> impl Iterator<Item = &'a mut V>
    where
        V: 'a,
    {
        heapless::Deque::iter_mut(self)
    }
    fn clear(&mut self) {
        heapless::Deque::clear(self)
    }
}

