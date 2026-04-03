//! Strongly-typed newtypes for the various 16-byte truncated hashes used
//! throughout the Reticulum protocol.
//!
//! All five types wrap `[u8; TRUNCATED_HASH_LEN]` (16 bytes) but are
//! distinct at the type level so the compiler prevents mixing them up.

use crate::TRUNCATED_HASH_LEN;
use zeroize::Zeroize;

macro_rules! define_hash_newtype {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        #[cfg_attr(feature = "serde", serde(transparent))]
        #[repr(transparent)]
        pub struct $name([u8; TRUNCATED_HASH_LEN]);

        impl Zeroize for $name {
            fn zeroize(&mut self) {
                self.0.zeroize();
            }
        }

        impl $name {
            /// Create from a raw byte array.
            pub const fn new(bytes: [u8; TRUNCATED_HASH_LEN]) -> Self {
                Self(bytes)
            }

            /// View the underlying bytes.
            pub const fn as_bytes(&self) -> &[u8; TRUNCATED_HASH_LEN] {
                &self.0
            }

            /// The all-zeros value.
            pub const ZERO: Self = Self([0u8; TRUNCATED_HASH_LEN]);

            /// Create from a byte slice (must be exactly 16 bytes).
            ///
            /// # Panics
            /// Panics if `slice.len() != 16`.
            pub fn from_slice(slice: &[u8]) -> Self {
                let mut arr = [0u8; TRUNCATED_HASH_LEN];
                arr.copy_from_slice(slice);
                Self(arr)
            }
        }

        impl From<[u8; TRUNCATED_HASH_LEN]> for $name {
            fn from(bytes: [u8; TRUNCATED_HASH_LEN]) -> Self {
                Self(bytes)
            }
        }

        impl From<$name> for [u8; TRUNCATED_HASH_LEN] {
            fn from(h: $name) -> [u8; TRUNCATED_HASH_LEN] {
                h.0
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(
                    f,
                    "{}({:02x}{:02x}{:02x}{:02x}..)",
                    stringify!($name),
                    self.0[0], self.0[1], self.0[2], self.0[3],
                )
            }
        }
    };
}

define_hash_newtype!(
    /// Destination address — `SHA-256(name_hash [|| identity_hash])[0:16]`.
    DestHash
);

define_hash_newtype!(
    /// Identity fingerprint — `SHA-256(pub_key)[0:16]`.
    IdentityHash
);

define_hash_newtype!(
    /// Link session identifier — `SHA-256(hashable_part)[0:16]`.
    LinkId
);

define_hash_newtype!(
    /// RPC path identifier — `SHA-256(path.as_bytes())[0:16]`.
    PathHash
);

define_hash_newtype!(
    /// Request correlation identifier — `SHA-256(packed_request)[0:16]`.
    RequestId
);

#[cfg(test)]
mod tests {
    extern crate std;
    use std::collections::HashMap;
    use std::format;

    use super::*;

    const SAMPLE: [u8; 16] = [
        0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22,
        0x33, 0x44,
    ];

    // -- Conversion round-trips --

    #[test]
    fn dest_hash_from_into_roundtrip() {
        let dh = DestHash::from(SAMPLE);
        let back: [u8; 16] = dh.into();
        assert_eq!(back, SAMPLE);
    }

    #[test]
    fn identity_hash_from_into_roundtrip() {
        let ih = IdentityHash::from(SAMPLE);
        let back: [u8; 16] = ih.into();
        assert_eq!(back, SAMPLE);
    }

    #[test]
    fn link_id_from_into_roundtrip() {
        let lid = LinkId::from(SAMPLE);
        let back: [u8; 16] = lid.into();
        assert_eq!(back, SAMPLE);
    }

    #[test]
    fn path_hash_from_into_roundtrip() {
        let ph = PathHash::from(SAMPLE);
        let back: [u8; 16] = ph.into();
        assert_eq!(back, SAMPLE);
    }

    #[test]
    fn request_id_from_into_roundtrip() {
        let rid = RequestId::from(SAMPLE);
        let back: [u8; 16] = rid.into();
        assert_eq!(back, SAMPLE);
    }

    // -- from_slice --

    #[test]
    fn from_slice_roundtrip() {
        let dh = DestHash::from_slice(&SAMPLE);
        assert_eq!(*dh.as_bytes(), SAMPLE);
    }

    #[test]
    #[should_panic]
    fn from_slice_wrong_length_panics() {
        let _ = DestHash::from_slice(&[0u8; 8]);
    }

    // -- AsRef<[u8]> --

    #[test]
    fn as_ref_returns_16_byte_slice() {
        let dh = DestHash::from(SAMPLE);
        let slice: &[u8] = dh.as_ref();
        assert_eq!(slice, &SAMPLE);
    }

    // -- as_bytes --

    #[test]
    fn as_bytes_matches_original() {
        let dh = DestHash::from(SAMPLE);
        assert_eq!(dh.as_bytes(), &SAMPLE);
    }

    // -- ZERO constant --

    #[test]
    fn zero_is_all_zeros() {
        assert_eq!(DestHash::ZERO.as_bytes(), &[0u8; 16]);
        assert_eq!(IdentityHash::ZERO.as_bytes(), &[0u8; 16]);
        assert_eq!(LinkId::ZERO.as_bytes(), &[0u8; 16]);
        assert_eq!(PathHash::ZERO.as_bytes(), &[0u8; 16]);
        assert_eq!(RequestId::ZERO.as_bytes(), &[0u8; 16]);
    }

    // -- Debug formatting --

    #[test]
    fn debug_shows_type_name_and_hex_prefix() {
        let dh = DestHash::from(SAMPLE);
        let dbg = format!("{:?}", dh);
        assert_eq!(dbg, "DestHash(abcdef01..)");
    }

    #[test]
    fn debug_differs_per_type() {
        let lid = LinkId::from(SAMPLE);
        let dbg = format!("{:?}", lid);
        assert!(dbg.starts_with("LinkId("));
    }

    // -- HashMap key --

    #[test]
    fn dest_hash_works_as_hashmap_key() {
        let mut map = HashMap::new();
        let dh = DestHash::from(SAMPLE);
        map.insert(dh, "value");
        assert_eq!(map.get(&dh), Some(&"value"));
    }

    #[test]
    fn link_id_works_as_hashmap_key() {
        let mut map = HashMap::new();
        let lid = LinkId::from(SAMPLE);
        map.insert(lid, 42u32);
        assert_eq!(map.get(&lid), Some(&42));
    }

    // -- Type distinctness (compile-time safety) --

    #[test]
    fn types_are_distinct() {
        fn accepts_dest_hash(_: DestHash) {}
        fn accepts_link_id(_: LinkId) {}
        fn accepts_identity_hash(_: IdentityHash) {}
        fn accepts_path_hash(_: PathHash) {}
        fn accepts_request_id(_: RequestId) {}

        // Each type can only be passed to its own function.
        // Passing the wrong type would be a compile error.
        accepts_dest_hash(DestHash::from(SAMPLE));
        accepts_link_id(LinkId::from(SAMPLE));
        accepts_identity_hash(IdentityHash::from(SAMPLE));
        accepts_path_hash(PathHash::from(SAMPLE));
        accepts_request_id(RequestId::from(SAMPLE));
    }

    // -- Copy semantics --

    #[test]
    fn copy_works() {
        let dh = DestHash::from(SAMPLE);
        let dh2 = dh; // Copy
        assert_eq!(dh, dh2); // both still usable
    }

    // -- Eq / Ord --

    #[test]
    fn equality_by_value() {
        let a = DestHash::from(SAMPLE);
        let b = DestHash::from(SAMPLE);
        assert_eq!(a, b);

        let c = DestHash::from([0u8; 16]);
        assert_ne!(a, c);
    }

    #[test]
    fn ordering_is_lexicographic() {
        let lo = DestHash::from([0x00; 16]);
        let hi = DestHash::from([0xFF; 16]);
        assert!(lo < hi);
    }
}
