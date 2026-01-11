use proptest::prelude::*;
use std::io::Cursor;

use crate::{
    orchard::{self, Action},
    serialization::{ZcashDeserializeInto, ZcashSerialize},
};

proptest! {
    /// Make sure only valid flags deserialize
    #[test]
    fn flag_roundtrip_bytes(flags in any::<u8>()) {

        let mut serialized = Cursor::new(Vec::new());
        flags.zcash_serialize(&mut serialized)?;

        serialized.set_position(0);
        let maybe_deserialized = (&mut serialized).zcash_deserialize_into();

        let invalid_bits_mask = !orchard::Flags::all().bits();
        match orchard::Flags::from_bits(flags) {
            Some(valid_flags) => {
                prop_assert_eq!(maybe_deserialized.ok(), Some(valid_flags));
                prop_assert_eq!(flags & invalid_bits_mask, 0);
            }
            None => {
                prop_assert_eq!(
                    maybe_deserialized.err().unwrap().to_string(),
                    "parse error: invalid reserved orchard flags"
                );
                prop_assert_ne!(flags & invalid_bits_mask, 0);
            }
        }
    }

    /// Verify V5 action serialization roundtrip (no tag field).
    /// This test ensures backward compatibility - V5 format must remain unchanged.
    #[test]
    fn action_v5_roundtrip(action in any::<Action>()) {
        let mut serialized = Vec::new();
        action.zcash_serialize_v5(&mut serialized)?;

        // V5 action size: 32 (cv) + 32 (nullifier) + 32 (rk) + 32 (cmx) + 32 (epk) + 580 (enc) + 80 (out) = 820 bytes
        prop_assert_eq!(serialized.len(), 820, "V5 action should be exactly 820 bytes");

        let deserialized = Action::zcash_deserialize_v5(&serialized[..])?;

        prop_assert_eq!(action.cv, deserialized.cv);
        prop_assert_eq!(action.nullifier, deserialized.nullifier);
        prop_assert_eq!(action.rk, deserialized.rk);
        prop_assert_eq!(action.cm_x, deserialized.cm_x);
        prop_assert_eq!(action.ephemeral_key, deserialized.ephemeral_key);
        prop_assert_eq!(action.enc_ciphertext, deserialized.enc_ciphertext);
        prop_assert_eq!(action.out_ciphertext, deserialized.out_ciphertext);

        // Verify re-serialization produces identical bytes
        let mut reserialized = Vec::new();
        deserialized.zcash_serialize_v5(&mut reserialized)?;
        prop_assert_eq!(serialized, reserialized, "V5 roundtrip must produce identical bytes");
    }

    /// Verify V6 action serialization roundtrip (with 16-byte tag field).
    /// This test ensures the new tag field is correctly serialized and preserved.
    /// Uses action_with_tag_strategy() to generate non-zero tags for thorough testing.
    #[cfg(all(zcash_unstable = "nu7", feature = "tx_v6"))]
    #[test]
    fn action_v6_roundtrip(action in crate::orchard::arbitrary::action_with_tag_strategy()) {
        let mut serialized = Vec::new();
        action.zcash_serialize_v6(&mut serialized)?;

        // V6 action size: 820 (V5 fields) + 16 (tag) = 836 bytes
        prop_assert_eq!(serialized.len(), 836, "V6 action should be exactly 836 bytes (820 + 16 tag)");

        let deserialized = Action::zcash_deserialize_v6(&serialized[..])?;

        // Verify all fields including the tag
        prop_assert_eq!(action.cv, deserialized.cv);
        prop_assert_eq!(action.nullifier, deserialized.nullifier);
        prop_assert_eq!(action.rk, deserialized.rk);
        prop_assert_eq!(action.cm_x, deserialized.cm_x);
        prop_assert_eq!(action.ephemeral_key, deserialized.ephemeral_key);
        prop_assert_eq!(action.enc_ciphertext, deserialized.enc_ciphertext);
        prop_assert_eq!(action.out_ciphertext, deserialized.out_ciphertext);
        prop_assert_eq!(action.tag, deserialized.tag, "Tag must be preserved in V6 roundtrip");

        // Verify re-serialization produces identical bytes
        let mut reserialized = Vec::new();
        deserialized.zcash_serialize_v6(&mut reserialized)?;
        prop_assert_eq!(serialized, reserialized, "V6 roundtrip must produce identical bytes");
    }
}
