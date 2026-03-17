//! LXMF message vector tests — validate pack/unpack against Python reference.

use rete_core::Identity;
use rete_lxmf::LXMessage;
use serde_json::Value;
use std::collections::BTreeMap;

/// Load test vectors from the shared vectors.json file.
fn load_vectors() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/interop/vectors.json"
    );
    let data = std::fs::read_to_string(path).expect("vectors.json not found");
    serde_json::from_str(&data).expect("invalid vectors.json")
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn hex_to_16(hex: &str) -> [u8; 16] {
    let bytes = hex_to_bytes(hex);
    bytes.as_slice().try_into().unwrap()
}

/// Get a deterministic test identity matching the Python generator.
///
/// Python: `seed = hashlib.sha512(label.encode()).digest()` (64 bytes)
fn get_identity(label: &str) -> Identity {
    use sha2::{Digest, Sha512};

    let seed = Sha512::digest(label.as_bytes());
    let mut prv = [0u8; 64];
    prv.copy_from_slice(&seed[..64]);

    Identity::from_private_key(&prv).expect("invalid test identity")
}

#[test]
fn test_lxmf_vector_pack_matches_python() {
    let doc = load_vectors();
    let vectors = doc["lxmf_message_vectors"]
        .as_array()
        .expect("lxmf_message_vectors should be an array");

    // Skip placeholder vectors (when msgpack wasn't available during generation)
    let real_vectors: Vec<_> = vectors
        .iter()
        .filter(|v| v.get("packed_hex").is_some())
        .collect();

    assert!(
        !real_vectors.is_empty(),
        "No real LXMF vectors found (regenerate with msgpack installed)"
    );

    for (i, v) in real_vectors.iter().enumerate() {
        let desc = v["_description"].as_str().unwrap_or("?");
        println!("Vector {i}: {desc}");

        let source_label = v["source_label"].as_str().unwrap();
        let source = get_identity(source_label);
        let source_hash = hex_to_16(v["source_hash_hex"].as_str().unwrap());
        let dest_hash = hex_to_16(v["dest_hash_hex"].as_str().unwrap());
        let timestamp = v["timestamp"].as_f64().unwrap();
        let title_bytes = hex_to_bytes(v["title_bytes_hex"].as_str().unwrap());
        let content_bytes = hex_to_bytes(v["content_bytes_hex"].as_str().unwrap());
        let expected_packed = hex_to_bytes(v["packed_hex"].as_str().unwrap());
        let expected_signature = hex_to_bytes(v["signature_hex"].as_str().unwrap());
        let expected_msgpack = hex_to_bytes(v["msgpack_payload_hex"].as_str().unwrap());

        // Parse fields
        let fields_obj = v["fields"].as_object().unwrap();
        let mut fields = BTreeMap::new();
        for (k, val) in fields_obj {
            let key: u8 = k.parse().unwrap();
            let hex_val = val.as_str().unwrap();
            fields.insert(key, hex_to_bytes(hex_val));
        }

        // Verify source_hash matches identity
        assert_eq!(
            source.hash(),
            source_hash,
            "source_hash mismatch for {desc}"
        );

        // Create message
        let msg = LXMessage::new(
            dest_hash,
            source_hash,
            &source,
            &title_bytes,
            &content_bytes,
            fields,
            timestamp,
        )
        .unwrap_or_else(|e| panic!("LXMessage::new failed for {desc}: {e}"));

        // Verify msgpack payload
        let packed = msg.pack();
        let actual_msgpack = &packed[96..];
        assert_eq!(
            actual_msgpack,
            &expected_msgpack,
            "msgpack payload mismatch for {desc}\n  actual:   {}\n  expected: {}",
            hex::encode(actual_msgpack),
            hex::encode(&expected_msgpack),
        );

        // Verify signature
        assert_eq!(
            msg.signature.as_slice(),
            expected_signature.as_slice(),
            "signature mismatch for {desc}"
        );

        // Verify full packed output
        assert_eq!(
            packed,
            expected_packed,
            "packed output mismatch for {desc}\n  actual len:   {}\n  expected len: {}",
            packed.len(),
            expected_packed.len(),
        );

        // Verify unpack round-trip
        let unpacked = LXMessage::unpack(&packed, Some(&source))
            .unwrap_or_else(|e| panic!("unpack failed for {desc}: {e}"));
        assert_eq!(unpacked.destination_hash, dest_hash);
        assert_eq!(unpacked.source_hash, source_hash);
        assert_eq!(unpacked.title, title_bytes);
        assert_eq!(unpacked.content, content_bytes);
        assert!((unpacked.timestamp - timestamp).abs() < 0.001);
    }
}

#[test]
fn test_lxmf_vector_unpack_python_packed() {
    let doc = load_vectors();
    let vectors = doc["lxmf_message_vectors"]
        .as_array()
        .expect("lxmf_message_vectors should be an array");

    for v in vectors {
        if v.get("packed_hex").is_none() {
            continue;
        }

        let desc = v["_description"].as_str().unwrap_or("?");
        let packed = hex_to_bytes(v["packed_hex"].as_str().unwrap());
        let source_label = v["source_label"].as_str().unwrap();
        let source = get_identity(source_label);

        // Unpack with verification
        let msg = LXMessage::unpack(&packed, Some(&source))
            .unwrap_or_else(|e| panic!("unpack failed for {desc}: {e}"));

        // Verify fields
        let title = v["title"].as_str().unwrap();
        let content = v["content"].as_str().unwrap();
        assert_eq!(
            std::str::from_utf8(&msg.title).unwrap_or("?"),
            title,
            "title mismatch for {desc}"
        );
        assert_eq!(
            std::str::from_utf8(&msg.content).unwrap_or("?"),
            content,
            "content mismatch for {desc}"
        );
    }
}
