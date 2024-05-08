//! SimplPedPoP data structures.

#![allow(clippy::too_many_arguments)]

use alloc::vec::Vec;
use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint, Scalar};
use zeroize::ZeroizeOnDrop;
use crate::{context::SigningTranscript, PublicKey, Signature, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
use super::{
    errors::{DKGError, DKGResult},
    GroupPublicKey, VerifyingKey, MINIMUM_THRESHOLD,
};
use aead::{generic_array::GenericArray, KeyInit, KeySizeUser};
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, Nonce};

pub(super) const COMPRESSED_RISTRETTO_LENGTH: usize = 32;
pub(super) const U16_LENGTH: usize = 2;
pub(super) const ENCRYPTION_NONCE_LENGTH: usize = 12;
pub(super) const RECIPIENTS_HASH_LENGTH: usize = 16;
pub(super) const CHACHA20POLY1305_LENGTH: usize = 64;

/// The parameters of a given execution of the SimplPedPoP protocol.
#[derive(Clone, PartialEq, Eq)]
pub struct Parameters {
    pub(super) participants: u16,
    pub(super) threshold: u16,
}

impl Parameters {
    /// Create new parameters.
    pub fn generate(participants: u16, threshold: u16) -> Parameters {
        Parameters { participants, threshold }
    }

    pub(super) fn validate(&self) -> Result<(), DKGError> {
        if self.threshold < MINIMUM_THRESHOLD {
            return Err(DKGError::InsufficientThreshold);
        }

        if self.participants < MINIMUM_THRESHOLD {
            return Err(DKGError::InvalidNumberOfParticipants);
        }

        if self.threshold > self.participants {
            return Err(DKGError::ExcessiveThreshold);
        }

        Ok(())
    }

    pub(super) fn commit<T: SigningTranscript>(&self, t: &mut T) {
        t.commit_bytes(b"threshold", &self.threshold.to_le_bytes());
        t.commit_bytes(b"participants", &self.participants.to_le_bytes());
    }
}

#[derive(ZeroizeOnDrop)]
pub(super) struct SecretShare(pub(super) Scalar);

impl SecretShare {
    pub(super) fn encrypt<T: SigningTranscript>(
        &self,
        ephemeral_key: &Scalar,
        mut transcript: T,
        recipient: &PublicKey,
        nonce: &[u8; ENCRYPTION_NONCE_LENGTH],
        i: usize,
    ) -> DKGResult<EncryptedSecretShare> {
        transcript.commit_bytes(b"i", &i.to_le_bytes());
        transcript.commit_point(b"recipient", recipient.as_compressed());
        transcript
            .commit_point(b"key exchange", &(ephemeral_key * recipient.as_point()).compress());

        let mut key: GenericArray<
            u8,
            <chacha20poly1305::ChaCha20Poly1305 as KeySizeUser>::KeySize,
        > = Default::default();

        transcript.challenge_bytes(b"", key.as_mut_slice());

        let cipher = ChaCha20Poly1305::new(&key);

        let nonce = Nonce::from_slice(&nonce[..]);

        let ciphertext: Vec<u8> = cipher
            .encrypt(nonce, &self.0.to_bytes()[..])
            .map_err(DKGError::EncryptionError)?;

        Ok(EncryptedSecretShare(ciphertext))
    }
}

#[derive(Clone)]
pub struct EncryptedSecretShare(pub(super) Vec<u8>);

impl EncryptedSecretShare {
    pub(super) fn decrypt<T: SigningTranscript>(
        &self,
        mut transcript: T,
        recipient: &PublicKey,
        key_exchange: &RistrettoPoint,
        nonce: &[u8; ENCRYPTION_NONCE_LENGTH],
        i: usize,
    ) -> DKGResult<SecretShare> {
        transcript.commit_bytes(b"i", &i.to_le_bytes());
        transcript.commit_point(b"recipient", recipient.as_compressed());
        transcript.commit_point(b"key exchange", &key_exchange.compress());

        let mut key: GenericArray<
            u8,
            <chacha20poly1305::ChaCha20Poly1305 as KeySizeUser>::KeySize,
        > = Default::default();

        transcript.challenge_bytes(b"", key.as_mut_slice());

        let cipher = ChaCha20Poly1305::new(&key);

        let nonce = Nonce::from_slice(&nonce[..]);

        let plaintext = cipher.decrypt(nonce, &self.0[..]).map_err(DKGError::DecryptionError)?;

        let mut bytes = [0; 32];
        bytes.copy_from_slice(&plaintext);

        Ok(SecretShare(Scalar::from_bytes_mod_order(bytes)))
    }
}

/// AllMessage packs together messages for all participants.
///
/// We'd save bandwidth by having separate messages for each
/// participant, but typical thresholds lie between 1/2 and 2/3,
/// so this doubles or tripples bandwidth usage.
pub struct AllMessage {
    pub(super) content: MessageContent,
    pub(super) signature: Signature,
}

impl AllMessage {
    /// Creates a new message.
    pub fn new(content: MessageContent, signature: Signature) -> Self {
        Self { content, signature }
    }
    /// Serialize AllMessage
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend(self.content.to_bytes());
        bytes.extend(self.signature.to_bytes());

        bytes
    }

    /// Deserialize AllMessage from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<AllMessage, DKGError> {
        let mut cursor = 0;

        let content = MessageContent::from_bytes(&bytes[cursor..])?;
        cursor += content.to_bytes().len();

        let signature = Signature::from_bytes(&bytes[cursor..cursor + SIGNATURE_LENGTH])
            .map_err(DKGError::InvalidSignature)?;

        Ok(AllMessage { content, signature })
    }
}

/// The contents of the message destined to all participants.
pub struct MessageContent {
    pub(super) sender: PublicKey,
    pub(super) encryption_nonce: [u8; ENCRYPTION_NONCE_LENGTH],
    pub(super) parameters: Parameters,
    pub(super) recipients_hash: [u8; RECIPIENTS_HASH_LENGTH],
    pub(super) point_polynomial: Vec<RistrettoPoint>,
    pub(super) encrypted_secret_shares: Vec<EncryptedSecretShare>,
    pub(super) ephemeral_key: PublicKey,
    pub(super) proof_of_possession: Signature,
}

impl MessageContent {
    /// Creates the content of the message.
    pub fn new(
        sender: PublicKey,
        encryption_nonce: [u8; ENCRYPTION_NONCE_LENGTH],
        parameters: Parameters,
        recipients_hash: [u8; RECIPIENTS_HASH_LENGTH],
        point_polynomial: Vec<RistrettoPoint>,
        ciphertexts: Vec<EncryptedSecretShare>,
        ephemeral_key: PublicKey,
        proof_of_possession: Signature,
    ) -> Self {
        Self {
            sender,
            encryption_nonce,
            parameters,
            recipients_hash,
            point_polynomial,
            encrypted_secret_shares: ciphertexts,
            ephemeral_key,
            proof_of_possession,
        }
    }
    /// Serialize MessageContent
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend(self.sender.to_bytes());
        bytes.extend(&self.encryption_nonce);
        bytes.extend(self.parameters.participants.to_le_bytes());
        bytes.extend(self.parameters.threshold.to_le_bytes());
        bytes.extend(&self.recipients_hash);

        for point in &self.point_polynomial {
            bytes.extend(point.compress().to_bytes());
        }

        for ciphertext in &self.encrypted_secret_shares {
            bytes.extend(ciphertext.0.clone());
        }

        bytes.extend(&self.ephemeral_key.to_bytes());
        bytes.extend(&self.proof_of_possession.to_bytes());

        bytes
    }

    /// Deserialize MessageContent from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<MessageContent, DKGError> {
        let mut cursor = 0;

        let sender = PublicKey::from_bytes(&bytes[cursor..cursor + PUBLIC_KEY_LENGTH])
            .map_err(DKGError::InvalidPublicKey)?;
        cursor += PUBLIC_KEY_LENGTH;

        let encryption_nonce: [u8; ENCRYPTION_NONCE_LENGTH] = bytes
            [cursor..cursor + ENCRYPTION_NONCE_LENGTH]
            .try_into()
            .map_err(DKGError::DeserializationError)?;
        cursor += ENCRYPTION_NONCE_LENGTH;

        let participants = u16::from_le_bytes(
            bytes[cursor..cursor + U16_LENGTH]
                .try_into()
                .map_err(DKGError::DeserializationError)?,
        );
        cursor += U16_LENGTH;
        let threshold = u16::from_le_bytes(
            bytes[cursor..cursor + U16_LENGTH]
                .try_into()
                .map_err(DKGError::DeserializationError)?,
        );
        cursor += U16_LENGTH;

        let recipients_hash: [u8; RECIPIENTS_HASH_LENGTH] = bytes
            [cursor..cursor + RECIPIENTS_HASH_LENGTH]
            .try_into()
            .map_err(DKGError::DeserializationError)?;
        cursor += RECIPIENTS_HASH_LENGTH;

        let mut point_polynomial = Vec::with_capacity(participants as usize);
        for _ in 0..participants {
            let point = CompressedRistretto::from_slice(
                &bytes[cursor..cursor + COMPRESSED_RISTRETTO_LENGTH],
            )
            .map_err(DKGError::DeserializationError)?;
            point_polynomial.push(point.decompress().ok_or(DKGError::InvalidRistrettoPoint)?);
            cursor += COMPRESSED_RISTRETTO_LENGTH;
        }

        let mut encrypted_secret_shares = Vec::new();

        for _ in 0..participants {
            let ciphertext = bytes[cursor..cursor + CHACHA20POLY1305_LENGTH].to_vec();
            encrypted_secret_shares.push(EncryptedSecretShare(ciphertext));
            cursor += CHACHA20POLY1305_LENGTH;
        }

        let ephemeral_key = PublicKey::from_bytes(&bytes[cursor..cursor + PUBLIC_KEY_LENGTH])
            .map_err(DKGError::InvalidPublicKey)?;
        cursor += PUBLIC_KEY_LENGTH;

        let proof_of_possession = Signature::from_bytes(&bytes[cursor..cursor + SIGNATURE_LENGTH])
            .map_err(DKGError::InvalidSignature)?;

        Ok(MessageContent {
            sender,
            encryption_nonce,
            parameters: Parameters { participants, threshold },
            recipients_hash,
            point_polynomial,
            encrypted_secret_shares,
            ephemeral_key,
            proof_of_possession,
        })
    }
}

/// The signed output of the SimplPedPoP protocol.
pub struct DKGOutput {
    pub(super) sender: PublicKey,
    pub(super) content: DKGOutputContent,
    pub(super) signature: Signature,
}

impl DKGOutput {
    /// Creates a signed SimplPedPoP output.
    pub fn new(sender: PublicKey, content: DKGOutputContent, signature: Signature) -> Self {
        Self { sender, content, signature }
    }

    /// Serializes the DKGOutput into bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        let pk_bytes = self.sender.to_bytes();
        bytes.extend(pk_bytes);

        let content_bytes = self.content.to_bytes();
        bytes.extend(content_bytes);

        let signature_bytes = self.signature.to_bytes();
        bytes.extend(signature_bytes);

        bytes
    }

    /// Deserializes the DKGOutput from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DKGError> {
        let mut cursor = 0;

        let pk_bytes = &bytes[..PUBLIC_KEY_LENGTH];
        let sender = PublicKey::from_bytes(pk_bytes).map_err(DKGError::InvalidPublicKey)?;
        cursor += PUBLIC_KEY_LENGTH;

        let content_bytes = &bytes[cursor..bytes.len() - SIGNATURE_LENGTH];
        let content = DKGOutputContent::from_bytes(content_bytes)?;

        cursor = bytes.len() - SIGNATURE_LENGTH;
        let signature = Signature::from_bytes(&bytes[cursor..cursor + SIGNATURE_LENGTH])
            .map_err(DKGError::InvalidSignature)?;

        Ok(DKGOutput { sender, content, signature })
    }
}

/// The content of the signed output of the SimplPedPoP protocol.
pub struct DKGOutputContent {
    pub(super) group_public_key: GroupPublicKey,
    pub(super) verifying_keys: Vec<VerifyingKey>,
}

impl DKGOutputContent {
    /// Creates the content of the SimplPedPoP output.
    pub fn new(group_public_key: GroupPublicKey, verifying_keys: Vec<VerifyingKey>) -> Self {
        Self { group_public_key, verifying_keys }
    }
    /// Serializes the DKGOutputContent into bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        let compressed_public_key = self.group_public_key.0.as_compressed(); // Assuming PublicKey can be compressed directly
        bytes.extend(compressed_public_key.to_bytes().iter());

        let key_count = self.verifying_keys.len() as u16;
        bytes.extend(key_count.to_le_bytes());

        for key in &self.verifying_keys {
            bytes.extend(key.0.to_bytes());
        }

        bytes
    }
}

impl DKGOutputContent {
    /// Deserializes the DKGOutputContent from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<DKGOutputContent, DKGError> {
        let mut cursor = 0;

        let public_key_bytes = &bytes[cursor..cursor + PUBLIC_KEY_LENGTH]; // Ristretto points are 32 bytes when compressed
        cursor += PUBLIC_KEY_LENGTH;
        let compressed_public_key = CompressedRistretto::from_slice(public_key_bytes)
            .map_err(DKGError::DeserializationError)?;
        let group_public_key =
            compressed_public_key.decompress().ok_or(DKGError::InvalidRistrettoPoint)?;

        let key_count_bytes = &bytes[cursor..cursor + U16_LENGTH];
        cursor += U16_LENGTH;
        let key_count =
            u16::from_le_bytes(key_count_bytes.try_into().map_err(DKGError::DeserializationError)?);

        let mut verifying_keys = Vec::with_capacity(key_count as usize);
        for _ in 0..key_count {
            let key_bytes = &bytes[cursor..cursor + PUBLIC_KEY_LENGTH];
            cursor += PUBLIC_KEY_LENGTH;
            let key = PublicKey::from_bytes(key_bytes).map_err(DKGError::InvalidPublicKey)?;
            verifying_keys.push(VerifyingKey(key));
        }

        Ok(DKGOutputContent {
            group_public_key: GroupPublicKey(PublicKey::from_point(group_public_key)),
            verifying_keys,
        })
    }
}

#[cfg(test)]
mod tests {
    use merlin::Transcript;
    use rand_core::OsRng;
    use crate::Keypair;
    use super::*;

    #[test]
    fn test_serialize_deserialize_all_message() {
        let sender = Keypair::generate();
        let encryption_nonce = [1u8; ENCRYPTION_NONCE_LENGTH];
        let parameters = Parameters { participants: 2, threshold: 1 };
        let recipients_hash = [2u8; RECIPIENTS_HASH_LENGTH];
        let point_polynomial =
            vec![RistrettoPoint::random(&mut OsRng), RistrettoPoint::random(&mut OsRng)];
        let encrypted_secret_shares = vec![
            EncryptedSecretShare(vec![1; CHACHA20POLY1305_LENGTH]),
            EncryptedSecretShare(vec![1; CHACHA20POLY1305_LENGTH]),
        ];
        let proof_of_possession = sender.sign(Transcript::new(b"pop"));
        let signature = sender.sign(Transcript::new(b"sig"));
        let ephemeral_key = PublicKey::from_point(RistrettoPoint::random(&mut OsRng));

        let message_content = MessageContent::new(
            sender.public,
            encryption_nonce,
            parameters,
            recipients_hash,
            point_polynomial,
            encrypted_secret_shares,
            ephemeral_key,
            proof_of_possession,
        );

        let message = AllMessage::new(message_content, signature);

        let bytes = message.to_bytes();

        let deserialized_message = AllMessage::from_bytes(&bytes).expect("Failed to deserialize");

        assert_eq!(message.content.sender, deserialized_message.content.sender);

        assert_eq!(message.content.encryption_nonce, deserialized_message.content.encryption_nonce);

        assert_eq!(
            message.content.parameters.participants,
            deserialized_message.content.parameters.participants
        );

        assert_eq!(
            message.content.parameters.threshold,
            deserialized_message.content.parameters.threshold
        );

        assert_eq!(message.content.recipients_hash, deserialized_message.content.recipients_hash);

        assert!(message
            .content
            .point_polynomial
            .iter()
            .zip(deserialized_message.content.point_polynomial.iter())
            .all(|(a, b)| a.compress() == b.compress()));

        assert!(message
            .content
            .encrypted_secret_shares
            .iter()
            .zip(deserialized_message.content.encrypted_secret_shares.iter())
            .all(|(a, b)| a.0 == b.0));

        assert_eq!(
            message.content.proof_of_possession,
            deserialized_message.content.proof_of_possession
        );

        assert_eq!(message.signature, deserialized_message.signature);
    }

    #[test]
    fn test_dkg_output_serialization() {
        let mut rng = OsRng;
        let group_public_key = RistrettoPoint::random(&mut rng);
        let verifying_keys = vec![
            VerifyingKey(PublicKey::from_point(RistrettoPoint::random(&mut rng))),
            VerifyingKey(PublicKey::from_point(RistrettoPoint::random(&mut rng))),
            VerifyingKey(PublicKey::from_point(RistrettoPoint::random(&mut rng))),
        ];

        let dkg_output_content = DKGOutputContent {
            group_public_key: GroupPublicKey(PublicKey::from_point(group_public_key)),
            verifying_keys,
        };

        let keypair = Keypair::generate();
        let signature = keypair.sign(Transcript::new(b"test"));

        let dkg_output =
            DKGOutput { sender: keypair.public, content: dkg_output_content, signature };

        // Serialize the DKGOutput
        let bytes = dkg_output.to_bytes();

        // Deserialize the DKGOutput
        let deserialized_dkg_output =
            DKGOutput::from_bytes(&bytes).expect("Deserialization failed");

        // Check if the deserialized content matches the original
        assert_eq!(
            deserialized_dkg_output.content.group_public_key.0.as_compressed(),
            dkg_output.content.group_public_key.0.as_compressed(),
            "Group public keys do not match"
        );

        assert_eq!(
            deserialized_dkg_output.content.verifying_keys.len(),
            dkg_output.content.verifying_keys.len(),
            "Verifying keys counts do not match"
        );

        assert!(
            deserialized_dkg_output
                .content
                .verifying_keys
                .iter()
                .zip(dkg_output.content.verifying_keys.iter())
                .all(|(a, b)| a.0 == b.0),
            "Verifying keys do not match"
        );

        assert_eq!(
            deserialized_dkg_output.signature.s, dkg_output.signature.s,
            "Signatures do not match"
        );
    }

    #[test]
    fn test_encryption_decryption() {
        let mut rng = OsRng;
        let ephemeral_key = Keypair::generate();
        let recipient = Keypair::generate();
        let encryption_nonce = [1; ENCRYPTION_NONCE_LENGTH];
        let t = Transcript::new(b"label");
        let key_exchange = ephemeral_key.secret.key * recipient.public.as_point();
        let secret_share = SecretShare(Scalar::random(&mut rng));

        let encrypted_share = secret_share
            .encrypt(&ephemeral_key.secret.key, t.clone(), &recipient.public, &encryption_nonce, 0)
            .unwrap();

        encrypted_share
            .decrypt(t, &recipient.public, &key_exchange, &encryption_nonce, 0)
            .unwrap();
    }
}
