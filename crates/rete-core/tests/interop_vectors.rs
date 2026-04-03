//! Validate all rete-core identity/crypto functions against the Python-generated
//! test vectors in tests/interop/vectors.json.

use rete_core::{destination_hash, destination_hashes, expand_name, Identity, IdentityHash};
use serde_json::Value;

/// Load the test vectors JSON.
fn vectors() -> Value {
    let raw = include_str!("../../../tests/interop/vectors.json");
    serde_json::from_str(raw).expect("Failed to parse vectors.json")
}

/// Decode a lowercase hex string to bytes.
fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_else(|e| panic!("bad hex '{s}': {e}"))
}

// =========================================================================
// Identity vectors — key derivation and identity hash
// =========================================================================

#[test]
fn identity_key_derivation() {
    let v = vectors();
    for iv in v["identity_vectors"].as_array().unwrap() {
        let label = iv["seed_label"].as_str().unwrap();
        let prv_hex = iv["private_key_hex"].as_str().unwrap();
        let pub_hex = iv["public_key_hex"].as_str().unwrap();
        let x_pub_hex = iv["x25519_pub_hex"].as_str().unwrap();
        let ed_pub_hex = iv["ed25519_pub_hex"].as_str().unwrap();
        let hash_hex = iv["identity_hash_hex"].as_str().unwrap();

        let prv = unhex(prv_hex);
        let id = Identity::from_private_key(&prv)
            .unwrap_or_else(|e| panic!("from_private_key failed for '{label}': {e}"));

        // Public key must match
        assert_eq!(
            hex::encode(id.public_key()),
            pub_hex,
            "public_key mismatch for '{label}'"
        );

        // Individual sub-keys
        let pub_key = id.public_key();
        assert_eq!(
            hex::encode(&pub_key[..32]),
            x_pub_hex,
            "x25519_pub mismatch for '{label}'"
        );
        assert_eq!(
            hex::encode(&pub_key[32..]),
            ed_pub_hex,
            "ed25519_pub mismatch for '{label}'"
        );

        // Identity hash
        assert_eq!(
            hex::encode(id.hash()),
            hash_hex,
            "identity_hash mismatch for '{label}'"
        );
    }
}

// =========================================================================
// Destination hash vectors
// =========================================================================

#[test]
fn destination_hash_vectors() {
    let v = vectors();
    for dv in v["destination_hash_vectors"].as_array().unwrap() {
        let app_name = dv["app_name"].as_str().unwrap();
        let aspects: Vec<&str> = dv["aspects"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a.as_str().unwrap())
            .collect();
        let expanded_exp = dv["expanded_name"].as_str().unwrap();
        let name_hash_hex = dv["name_hash_hex"].as_str().unwrap();
        let dest_hash_hex = dv["dest_hash_hex"].as_str().unwrap();

        // Test expand_name
        let mut buf = [0u8; 128];
        let expanded = expand_name(app_name, &aspects, &mut buf).unwrap();
        assert_eq!(
            expanded, expanded_exp,
            "expand_name mismatch for {app_name}"
        );

        // Test name_hash intermediate
        use sha2::Digest;
        let name_digest = sha2::Sha256::digest(expanded.as_bytes());
        assert_eq!(
            hex::encode(&name_digest[..10]),
            name_hash_hex,
            "name_hash mismatch for {expanded_exp}"
        );

        // Test destination_hash
        let id_hash = match dv["identity_hash_hex"].as_str() {
            Some(h) => {
                let bytes = unhex(h);
                let arr: [u8; 16] = bytes.try_into().unwrap();
                Some(IdentityHash::new(arr))
            }
            None => None,
        };

        let dh = destination_hash(expanded, id_hash.as_ref());
        assert_eq!(
            hex::encode(dh),
            dest_hash_hex,
            "dest_hash mismatch for {expanded_exp}"
        );

        // Verify destination_hashes() returns both correctly
        let (dh2, nh2) = destination_hashes(expanded, id_hash.as_ref());
        assert_eq!(
            hex::encode(dh2),
            dest_hash_hex,
            "destination_hashes dest_hash mismatch for {expanded_exp}"
        );
        assert_eq!(
            hex::encode(nh2),
            name_hash_hex,
            "destination_hashes name_hash mismatch for {expanded_exp}"
        );
    }
}

// =========================================================================
// Signing vectors — Ed25519 sign and verify
// =========================================================================

#[test]
fn signing_vectors() {
    let v = vectors();
    for sv in v["signing_vectors"].as_array().unwrap() {
        let desc = sv["_description"].as_str().unwrap();
        let verify_ok = sv["verify_result"].as_bool().unwrap();

        if verify_ok {
            // Sign test: verify our signature matches
            let ed_prv_hex = sv["ed25519_prv_hex"].as_str().unwrap();
            let msg_hex = sv["message_hex"].as_str().unwrap();
            let sig_hex = sv["signature_hex"].as_str().unwrap();

            // Build identity with just the Ed25519 keys (X25519 doesn't matter)
            let ed_prv = unhex(ed_prv_hex);

            // We need a full 64-byte private key. Use dummy X25519 bytes.
            let mut prv_key = [0u8; 64];
            prv_key[32..].copy_from_slice(&ed_prv);
            let id = Identity::from_private_key(&prv_key).unwrap();

            let msg = unhex(msg_hex);
            let expected = unhex(sig_hex);

            // Sign
            let sig = id.sign(&msg).unwrap();
            assert_eq!(hex::encode(sig), sig_hex, "sign mismatch: {desc}");

            // Verify should pass
            id.verify(&msg, &expected)
                .unwrap_or_else(|e| panic!("verify should pass: {desc}: {e}"));
        } else {
            // Tampered message test: verify should fail
            let ed_pub_hex = sv["ed25519_pub_hex"].as_str().unwrap();
            let tampered_hex = sv["tampered_message_hex"].as_str().unwrap();
            let sig_hex = sv["signature_hex"].as_str().unwrap();

            let ed_pub = unhex(ed_pub_hex);
            let tampered = unhex(tampered_hex);
            let sig = unhex(sig_hex);

            // Build verify-only identity from public key
            let mut pub_key = [0u8; 64];
            pub_key[32..].copy_from_slice(&ed_pub);
            let id = Identity::from_public_key(&pub_key).unwrap();

            assert!(
                id.verify(&tampered, &sig).is_err(),
                "verify should fail for tampered message: {desc}"
            );
        }
    }
}

// =========================================================================
// Encryption vectors — decrypt test (encrypt is non-deterministic)
// =========================================================================

#[test]
fn encryption_decrypt_vectors() {
    let v = vectors();
    for ev in v["encryption_vectors"].as_array().unwrap() {
        let desc = ev["_description"].as_str().unwrap();
        let pt_hex = ev["plaintext_hex"].as_str().unwrap();
        let ct_hex = ev["ciphertext_hex"].as_str().unwrap();

        // Build full identity (decrypt uses self.hash() as HKDF salt)
        let alice_iv = &v["identity_vectors"][0];
        let full_prv = unhex(alice_iv["private_key_hex"].as_str().unwrap());
        let id = Identity::from_private_key(&full_prv).unwrap();

        let ct = unhex(ct_hex);
        let expected_pt = unhex(pt_hex);

        let mut out = vec![0u8; ct.len()];
        let pt_len = id
            .decrypt(&ct, &mut out)
            .unwrap_or_else(|e| panic!("decrypt failed: {desc}: {e}"));

        assert_eq!(
            &out[..pt_len],
            expected_pt.as_slice(),
            "decrypt mismatch: {desc}"
        );
    }
}

// =========================================================================
// Encryption round-trip — encrypt then decrypt
// =========================================================================

#[test]
fn encryption_round_trip() {
    use rand_core::{CryptoRng, RngCore};

    // Simple deterministic RNG for testing
    struct TestRng(u64);
    impl RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }
        fn next_u64(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            let mut i = 0;
            while i < dest.len() {
                let v = self.next_u64().to_le_bytes();
                let n = core::cmp::min(8, dest.len() - i);
                dest[i..i + n].copy_from_slice(&v[..n]);
                i += n;
            }
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }
    impl CryptoRng for TestRng {}

    let v = vectors();
    let alice_prv = unhex(
        v["identity_vectors"][0]["private_key_hex"]
            .as_str()
            .unwrap(),
    );
    let id = Identity::from_private_key(&alice_prv).unwrap();

    let mut rng = TestRng(42);

    for plaintext in &[
        b"hello".as_slice(),
        b"",
        &[0u8; 32],
        &[0xFFu8; 100],
        b"van: temp=68 bat=87 heater=off",
    ] {
        let mut ct = vec![0u8; 32 + 48 + plaintext.len() + 16]; // generous
        let ct_len = id.encrypt(plaintext, &mut rng, &mut ct).unwrap();

        let mut pt = vec![0u8; ct_len];
        let pt_len = id.decrypt(&ct[..ct_len], &mut pt).unwrap();

        assert_eq!(
            &pt[..pt_len],
            *plaintext,
            "round-trip failed for {} byte plaintext",
            plaintext.len()
        );
    }
}

// =========================================================================
// Announce signature verification
// =========================================================================

#[test]
fn announce_signature_vectors() {
    let v = vectors();
    for av in v["announce_packet_vectors"].as_array().unwrap() {
        let desc = av["_description"].as_str().unwrap();

        // Only test vectors that have private keys (for signing)
        if let Some(prv_hex) = av.get("private_key_hex").and_then(|v| v.as_str()) {
            let sig_hex = av["signature_hex"].as_str().unwrap();
            let signed_hex = av["signed_data_hex"].as_str().unwrap();
            let pub_hex = av["public_key_hex"].as_str().unwrap();

            let prv = unhex(prv_hex);
            let id = Identity::from_private_key(&prv).unwrap();
            let signed = unhex(signed_hex);
            let sig_exp = unhex(sig_hex);

            // Verify public key matches
            assert_eq!(
                hex::encode(id.public_key()),
                pub_hex,
                "pubkey mismatch: {desc}"
            );

            // Sign and compare
            let sig = id.sign(&signed).unwrap();
            assert_eq!(hex::encode(sig), sig_hex, "announce sig mismatch: {desc}");

            // Verify should pass
            id.verify(&signed, &sig_exp)
                .unwrap_or_else(|e| panic!("announce verify failed: {desc}: {e}"));
        }

        // All vectors have signatures we can verify with public key
        if let Some(sig_hex) = av.get("signature_hex").and_then(|v| v.as_str()) {
            let signed_hex = av["signed_data_hex"].as_str().unwrap();
            let pub_hex = av["public_key_hex"].as_str().unwrap();

            let pub_key = unhex(pub_hex);
            let signed = unhex(signed_hex);
            let sig = unhex(sig_hex);

            // Create verify-only identity from public key
            let id = Identity::from_public_key(&pub_key).unwrap();

            id.verify(&signed, &sig)
                .unwrap_or_else(|e| panic!("announce pubkey verify failed: {desc}: {e}"));
        }
    }
}
