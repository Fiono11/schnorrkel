use alloc::vec::Vec;
use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint, Scalar};
use crate::{context::SigningTranscript, PublicKey, Signature};
use super::{errors::DKGError, MINIMUM_THRESHOLD};

/// The parameters of a given execution of the SimplPedPoP protocol.
#[derive(Clone, PartialEq, Eq)]
pub struct Parameters {
    pub(crate) participants: u16,
    pub(crate) threshold: u16,
}

impl Parameters {
    /// Create new parameters.
    pub fn generate(participants: u16, threshold: u16) -> Parameters {
        Parameters { participants, threshold }
    }

    pub(crate) fn validate(&self) -> Result<(), DKGError> {
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

    pub(crate) fn commit<T: SigningTranscript>(&self, t: &mut T) {
        t.commit_bytes(b"threshold", &self.threshold.to_le_bytes());
        t.commit_bytes(b"participants", &self.participants.to_le_bytes());
    }
}

/// The contents of the message destined to all participants.
pub struct MessageContent {
    pub(crate) sender: PublicKey,
    pub(crate) encryption_nonce: [u8; 16],
    pub(crate) parameters: Parameters,
    pub(crate) recipients_hash: [u8; 16],
    pub(crate) point_polynomial: Vec<RistrettoPoint>,
    pub(crate) ciphertexts: Vec<Scalar>,
}

impl MessageContent {
    pub fn new(
        sender: PublicKey,
        encryption_nonce: [u8; 16],
        parameters: Parameters,
        recipients_hash: [u8; 16],
        point_polynomial: Vec<RistrettoPoint>,
        ciphertexts: Vec<Scalar>,
    ) -> Self {
        Self {
            sender,
            encryption_nonce,
            parameters,
            recipients_hash,
            point_polynomial,
            ciphertexts,
        }
    }
    /// Serialize MessageContent
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Serialize PublicKey
        bytes.extend(self.sender.to_bytes());

        // Serialize encryption_nonce
        bytes.extend(&self.encryption_nonce);

        // Serialize Parameters
        bytes.extend(self.parameters.participants.to_le_bytes());
        bytes.extend(self.parameters.threshold.to_le_bytes());

        // Serialize recipients_hash
        bytes.extend(&self.recipients_hash);

        // Serialize point_polynomial (list of RistrettoPoints)
        for point in &self.point_polynomial {
            bytes.extend(point.compress().to_bytes());
        }

        // Serialize ciphertexts (list of Scalars)
        for ciphertext in &self.ciphertexts {
            bytes.extend(ciphertext.to_bytes());
        }

        bytes
    }

    /// Deserialize MessageContent from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<MessageContent, DKGError> {
        let mut cursor = 0;

        // Deserialize PublicKey
        let sender = PublicKey::from_bytes(&bytes[cursor..cursor + 32])
            .map_err(DKGError::InvalidPublicKey)?;
        cursor += 32;

        // Deserialize encryption_nonce
        let encryption_nonce: [u8; 16] =
            bytes[cursor..cursor + 16].try_into().map_err(DKGError::DeserializationError)?;
        cursor += 16;

        // Deserialize Parameters
        let participants = u16::from_le_bytes(
            bytes[cursor..cursor + 2].try_into().map_err(DKGError::DeserializationError)?,
        );
        cursor += 2;
        let threshold = u16::from_le_bytes(
            bytes[cursor..cursor + 2].try_into().map_err(DKGError::DeserializationError)?,
        );
        cursor += 2;

        // Deserialize recipients_hash
        let recipients_hash: [u8; 16] =
            bytes[cursor..cursor + 16].try_into().map_err(DKGError::DeserializationError)?;
        cursor += 16;

        // Deserialize point_polynomial
        let mut point_polynomial = Vec::with_capacity(participants as usize);
        for _ in 0..participants {
            let point = CompressedRistretto::from_slice(&bytes[cursor..cursor + 32])
                .map_err(DKGError::DeserializationError)?;
            point_polynomial.push(point.decompress().ok_or(DKGError::InvalidRistrettoPoint)?);
            cursor += 32;
        }

        // Deserialize ciphertexts
        let mut ciphertexts = Vec::new();
        for _ in 0..participants {
            let ciphertext = Scalar::from_canonical_bytes(
                bytes[cursor..cursor + 32].try_into().map_err(DKGError::DeserializationError)?,
            );
            if ciphertext.is_some().unwrap_u8() == 1 {
                ciphertexts.push(ciphertext.unwrap());
            } else {
                return Err(DKGError::InvalidScalar);
            }
            cursor += 32;
        }

        Ok(MessageContent {
            sender,
            encryption_nonce,
            parameters: Parameters { participants, threshold },
            recipients_hash,
            point_polynomial,
            ciphertexts,
        })
    }
}

pub struct DKGOutput {
    pub(crate) sender: PublicKey,
    pub(crate) content: DKGOutputContent,
    pub(crate) signature: Signature,
}

impl DKGOutput {
    pub fn new(sender: PublicKey, content: DKGOutputContent, signature: Signature) -> Self {
        Self { sender, content, signature }
    }
    /// Serializes the DKGOutput into bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        let pk_bytes = self.sender.to_bytes();
        bytes.extend(pk_bytes);

        // Serialize the content
        let content_bytes = self.content.to_bytes();
        bytes.extend(content_bytes);

        // Serialize the signature
        let signature_bytes = self.signature.to_bytes();
        bytes.extend(signature_bytes);

        bytes
    }

    /// Deserializes the DKGOutput from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DKGError> {
        let mut cursor = 0;

        // TODO: constants
        let pk_bytes = &bytes[..32];
        let sender = PublicKey::from_bytes(pk_bytes).map_err(DKGError::InvalidPublicKey)?;
        cursor += 32;

        let content_bytes = &bytes[cursor..bytes.len() - 64];
        let content = DKGOutputContent::from_bytes(content_bytes)?;

        cursor = bytes.len() - 64;
        // Deserialize signature (Signature)
        let signature = Signature::from_bytes(&bytes[cursor..cursor + 64])
            .map_err(DKGError::InvalidSignature)?;

        Ok(DKGOutput { sender, content, signature })
    }
}

#[derive(Debug)]
pub struct DKGOutputContent {
    pub(crate) group_public_key: PublicKey,
    pub(crate) verifying_keys: Vec<RistrettoPoint>,
}

impl DKGOutputContent {
    pub fn new(group_public_key: PublicKey, verifying_keys: Vec<RistrettoPoint>) -> Self {
        Self { group_public_key, verifying_keys }
    }
    /// Serializes the DKGOutputContent into bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Serialize the group public key
        let compressed_public_key = self.group_public_key.as_compressed(); // Assuming PublicKey can be compressed directly
        bytes.extend(compressed_public_key.to_bytes().iter());

        // Serialize the number of verifying keys
        let key_count = self.verifying_keys.len() as u16;
        bytes.extend(key_count.to_le_bytes());

        // Serialize each verifying key
        for key in &self.verifying_keys {
            let compressed_key = key.compress();
            bytes.extend(compressed_key.to_bytes());
        }

        bytes
    }
}

impl DKGOutputContent {
    /// Deserializes the DKGOutputContent from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<DKGOutputContent, DKGError> {
        let mut cursor = 0;

        // Deserialize the group public key
        let public_key_bytes = &bytes[cursor..cursor + 32]; // Ristretto points are 32 bytes when compressed
        cursor += 32;
        let compressed_public_key = CompressedRistretto::from_slice(public_key_bytes)
            .map_err(DKGError::DeserializationError)?;
        let group_public_key =
            compressed_public_key.decompress().ok_or(DKGError::InvalidRistrettoPoint)?;

        // Deserialize the number of verifying keys
        let key_count_bytes = &bytes[cursor..cursor + 2];
        cursor += 2;
        let key_count =
            u16::from_le_bytes(key_count_bytes.try_into().map_err(DKGError::DeserializationError)?);

        // Deserialize each verifying key
        let mut verifying_keys = Vec::with_capacity(key_count as usize);
        for _ in 0..key_count {
            let key_bytes = &bytes[cursor..cursor + 32];
            cursor += 32;
            let compressed_key = CompressedRistretto::from_slice(key_bytes)
                .map_err(DKGError::DeserializationError)?;
            let key = compressed_key.decompress().ok_or(DKGError::InvalidRistrettoPoint)?;
            verifying_keys.push(key);
        }

        Ok(DKGOutputContent {
            group_public_key: PublicKey::from_point(group_public_key),
            verifying_keys,
        })
    }
}

/// AllMessage packs together messages for all participants.
///
/// We'd save bandwidth by having separate messages for each
/// participant, but typical thresholds lie between 1/2 and 2/3,
/// so this doubles or tripples bandwidth usage.
pub struct AllMessage {
    pub(crate) content: MessageContent,
    pub(crate) proof_of_possession: Signature,
    pub(crate) signature: Signature,
}

impl AllMessage {
    pub fn new(
        content: MessageContent,
        proof_of_possession: Signature,
        signature: Signature,
    ) -> Self {
        Self { content, proof_of_possession, signature }
    }
    /// Serialize AllMessage
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Serialize MessageContent
        bytes.extend(self.content.to_bytes());

        // Serialize proof_of_possession (Signature)
        bytes.extend(self.proof_of_possession.to_bytes());

        // Serialize signature (Signature)
        bytes.extend(self.signature.to_bytes());

        bytes
    }

    /// Deserialize AllMessage from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<AllMessage, DKGError> {
        let mut cursor = 0;

        // Deserialize MessageContent
        let content = MessageContent::from_bytes(&bytes[cursor..])?;
        cursor += content.to_bytes().len();

        // Deserialize proof_of_possession (Signature)
        let proof_of_possession = Signature::from_bytes(&bytes[cursor..cursor + 64])
            .map_err(DKGError::InvalidSignature)?;
        cursor += 64;

        // Deserialize signature (Signature)
        let signature = Signature::from_bytes(&bytes[cursor..cursor + 64])
            .map_err(DKGError::InvalidSignature)?;

        Ok(AllMessage { content, proof_of_possession, signature })
    }
}
