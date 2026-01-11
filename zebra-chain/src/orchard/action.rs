use std::io;

use halo2::pasta::pallas;
use reddsa::orchard::SpendAuth;

use crate::serialization::{
    serde_helpers, ReadZcashExt, SerializationError, ZcashDeserialize, ZcashSerialize,
};

use super::{
    commitment::{self, ValueCommitment},
    keys,
    note::{self, Nullifier},
};

/// An Action description, as described in the [Zcash specification §7.3][actiondesc].
///
/// Action transfers can optionally perform a spend, and optionally perform an
/// output.  Action descriptions are data included in a transaction that
/// describe Action transfers.
///
/// [actiondesc]: https://zips.z.cash/protocol/nu5.pdf#actiondesc
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Action {
    /// A value commitment to net value of the input note minus the output note
    pub cv: commitment::ValueCommitment,
    /// The nullifier of the input note being spent.
    pub nullifier: note::Nullifier,
    /// The randomized validating key for spendAuthSig,
    pub rk: reddsa::VerificationKeyBytes<SpendAuth>,
    /// The x-coordinate of the note commitment for the output note.
    #[serde(with = "serde_helpers::Base")]
    pub cm_x: pallas::Base,
    /// An encoding of an ephemeral Pallas public key corresponding to the
    /// encrypted private key in `out_ciphertext`.
    pub ephemeral_key: keys::EphemeralPublicKey,
    /// A ciphertext component for the encrypted output note.
    pub enc_ciphertext: note::EncryptedNote,
    /// A ciphertext component that allows the holder of a full viewing key to
    /// recover the recipient diversified transmission key and the ephemeral
    /// private key (and therefore the entire note plaintext).
    pub out_ciphertext: note::WrappedNoteKey,
    /// Detection tag for PIR-based transaction scanning (V6/NU7+ only).
    ///
    /// This 16-byte tag allows light wallets to filter relevant transactions
    /// without trial decryption, reducing bandwidth and battery usage.
    /// For V5 transactions, this field contains zeros.
    #[cfg(all(zcash_unstable = "nu7", feature = "tx_v6"))]
    pub tag: [u8; 16],
}

impl Action {
    /// Serialize in V5 format (no tag) - used by Transaction::V5.
    pub fn zcash_serialize_v5<W: io::Write>(&self, mut writer: W) -> Result<(), io::Error> {
        self.cv.zcash_serialize(&mut writer)?;
        writer.write_all(&<[u8; 32]>::from(self.nullifier)[..])?;
        writer.write_all(&<[u8; 32]>::from(self.rk)[..])?;
        writer.write_all(&<[u8; 32]>::from(self.cm_x)[..])?;
        self.ephemeral_key.zcash_serialize(&mut writer)?;
        self.enc_ciphertext.zcash_serialize(&mut writer)?;
        self.out_ciphertext.zcash_serialize(&mut writer)?;
        // NO tag for V5
        Ok(())
    }

    /// Serialize in V6 format (with tag) - used by Transaction::V6.
    #[cfg(all(zcash_unstable = "nu7", feature = "tx_v6"))]
    pub fn zcash_serialize_v6<W: io::Write>(&self, mut writer: W) -> Result<(), io::Error> {
        self.zcash_serialize_v5(&mut writer)?;
        writer.write_all(&self.tag)?;
        Ok(())
    }

    /// Deserialize from V5 format (no tag).
    pub fn zcash_deserialize_v5<R: io::Read>(mut reader: R) -> Result<Self, SerializationError> {
        Ok(Action {
            cv: ValueCommitment::zcash_deserialize(&mut reader)?,
            nullifier: Nullifier::try_from(reader.read_32_bytes()?)?,
            rk: reader.read_32_bytes()?.into(),
            cm_x: pallas::Base::zcash_deserialize(&mut reader)?,
            ephemeral_key: keys::EphemeralPublicKey::zcash_deserialize(&mut reader)?,
            enc_ciphertext: note::EncryptedNote::zcash_deserialize(&mut reader)?,
            out_ciphertext: note::WrappedNoteKey::zcash_deserialize(&mut reader)?,
            #[cfg(all(zcash_unstable = "nu7", feature = "tx_v6"))]
            tag: [0u8; 16], // Zeros for V5 transactions
        })
    }

    /// Deserialize from V6 format (with tag).
    #[cfg(all(zcash_unstable = "nu7", feature = "tx_v6"))]
    pub fn zcash_deserialize_v6<R: io::Read>(mut reader: R) -> Result<Self, SerializationError> {
        Ok(Action {
            cv: ValueCommitment::zcash_deserialize(&mut reader)?,
            nullifier: Nullifier::try_from(reader.read_32_bytes()?)?,
            rk: reader.read_32_bytes()?.into(),
            cm_x: pallas::Base::zcash_deserialize(&mut reader)?,
            ephemeral_key: keys::EphemeralPublicKey::zcash_deserialize(&mut reader)?,
            enc_ciphertext: note::EncryptedNote::zcash_deserialize(&mut reader)?,
            out_ciphertext: note::WrappedNoteKey::zcash_deserialize(&mut reader)?,
            tag: {
                let mut tag = [0u8; 16];
                reader.read_exact(&mut tag)?;
                tag
            },
        })
    }
}

// Keep the ZcashSerialize trait impl for backwards compatibility with V5
impl ZcashSerialize for Action {
    fn zcash_serialize<W: io::Write>(&self, writer: W) -> Result<(), io::Error> {
        self.zcash_serialize_v5(writer)
    }
}

// Keep the ZcashDeserialize trait impl for backwards compatibility with V5
impl ZcashDeserialize for Action {
    fn zcash_deserialize<R: io::Read>(reader: R) -> Result<Self, SerializationError> {
        // # Consensus
        //
        // > Elements of an Action description MUST be canonical encodings of the types given above.
        //
        // https://zips.z.cash/protocol/protocol.pdf#actiondesc
        //
        // > LEOS2IP_{256}(cmx) MUST be less than 𝑞_ℙ.
        //
        // https://zips.z.cash/protocol/protocol.pdf#actionencodingandconsensus
        //
        // See [`Action::zcash_deserialize_v5`] for per-field consensus rules.
        Action::zcash_deserialize_v5(reader)
    }
}
