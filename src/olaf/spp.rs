//!

// It's irrelevant if we're in the recipients or not ???

use core::iter;
use alloc::vec::Vec;
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::CompressedRistretto, RistrettoPoint, Scalar,
};
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use crate::{context::SigningTranscript, Keypair, PublicKey, SecretKey, Signature};
use super::errors::{DKGError, DKGResult};

/// The parameters of a given execution of the SimplPedPoP protocol.
#[derive(Clone)]
pub struct Parameters {
    participants: u16,
    threshold: u16,
}

impl Parameters {
    /// Create new parameters.
    pub fn new(participants: u16, threshold: u16) -> Parameters {
        Parameters { participants, threshold }
    }

    fn validate(&self) -> Result<(), DKGError> {
        if self.threshold < 2 {
            return Err(DKGError::InsufficientThreshold);
        }

        if self.participants < 2 {
            return Err(DKGError::InvalidNumberOfParticipants);
        }

        if self.threshold > self.participants {
            return Err(DKGError::ExcessiveThreshold);
        }

        Ok(())
    }

    fn commit<T: SigningTranscript>(&self, t: &mut T) {
        t.commit_bytes(b"threshold", &self.threshold.to_le_bytes());
        t.commit_bytes(b"participants", &self.participants.to_le_bytes());
    }
}

/// Compute identifier aka evaluation position scalar from recipiants_hash
/// and recipiant index.
pub fn identifier(recipients_hash: &[u8; 16], index: u16) -> Scalar {
    let mut pos = merlin::Transcript::new(b"Identifier");
    pos.append_message(b"RecipientsHash", recipients_hash);
    pos.append_message(b"i", &index.to_le_bytes()[..]);
    pos.challenge_scalar(b"evaluation position")
}

impl Keypair {
    /// First round of the SimplPedPoP protocol.
    pub fn simplpedpop_contribute_all(
        &self,
        threshold: u16,
        recipients: Vec<PublicKey>,
    ) -> DKGResult<AllMessage> {
        let parameters = Parameters { threshold, participants: recipients.len() as u16 };
        parameters.validate()?;

        let mut rng = crate::getrandom_or_panic();

        // We do not  recipiants.sort() because the protocol is simpler
        // if we require that all contributions provide the list in
        // exactly the same order.
        //
        // Instead we create a kind of session id by hashing the list
        // provided, but we provide only hash to recipiants, not the
        // full recipiants list.
        let mut t = merlin::Transcript::new(b"RecipientsHash");
        parameters.commit(&mut t);
        for r in recipients.iter() {
            t.commit_point(b"recipient", r.as_compressed());
        }
        let mut recipients_hash = [0u8; 16];
        t.challenge_bytes(b"finalize", &mut recipients_hash);

        // uses identifier(recipients_hash, i)
        let coefficients = generate_coefficients(parameters.threshold as usize - 1, &mut rng);
        let mut scalar_evaluations = Vec::new();

        for i in 0..parameters.participants {
            let identifier = identifier(&recipients_hash, i);
            let scalar_evaluation = evaluate_polynomial(&identifier, &coefficients);
            scalar_evaluations.push(scalar_evaluation);
        }

        // Create the vector of commitments
        let point_polynomial: Vec<RistrettoPoint> =
            coefficients.iter().map(|c| RISTRETTO_BASEPOINT_POINT * *c).collect();

        // All this custom encryption mess saves 32 bytes per recipiant
        // over chacha20poly1305, so maybe not worth the trouble.

        let mut enc0 = merlin::Transcript::new(b"Encryption");
        parameters.commit(&mut enc0);
        enc0.commit_point(b"contributor", self.public.as_compressed());

        let mut encryption_nonce = [0u8; 16];
        rand_core::RngCore::fill_bytes(&mut rng, &mut encryption_nonce);
        enc0.append_message(b"nonce", &encryption_nonce);

        let mut ciphertexts = scalar_evaluations;
        for i in 0..parameters.participants {
            let mut e = enc0.clone();
            // We tweak by i too since encryption_nonce is not truly a nonce.
            e.append_message(b"i", &i.to_le_bytes());

            e.commit_point(b"recipient", recipients[i as usize].as_compressed());
            self.secret.commit_raw_key_exchange(&mut e, b"kex", &recipients[i as usize]);

            // Afaik redundant for merlin, but attacks get better.
            e.append_message(b"nonce", &encryption_nonce);

            // As this is encryption, we require similar security properties
            // as from witness_bytes here, but without randomness, and
            // challenge_scalar is imeplemented close enough.
            ciphertexts[i as usize] += e.challenge_scalar(b"encryption scalar");
        }

        let message_content = MessageContent {
            sender: self.public,
            encryption_nonce,
            parameters,
            recipients_hash,
            point_polynomial,
            ciphertexts,
        };

        let mut m = Transcript::new(b"signature");
        m.append_message(b"message", &message_content.to_bytes());

        let signature = self.sign(m.clone());
        let secret_key = derive_secret_key_from_secret(
            coefficients
                .first()
                .expect("This never fails because the minimum threshold is 2"),
            &mut rng,
        );
        let proof_of_possession =
            secret_key.sign(m, &PublicKey::from_point(secret_key.key * RISTRETTO_BASEPOINT_POINT));

        Ok(AllMessage { content: message_content, signature, proof_of_possession })
    }
}

/// The contents of the message destined to all participants.
#[derive(Clone)]
pub struct MessageContent {
    sender: PublicKey,
    encryption_nonce: [u8; 16],
    parameters: Parameters,
    recipients_hash: [u8; 16],
    point_polynomial: Vec<RistrettoPoint>,
    ciphertexts: Vec<Scalar>,
}

impl MessageContent {
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

/// AllMessage packs together messages for all participants.
///
/// We'd save bandwidth by having separate messages for each
/// participant, but typical thresholds lie between 1/2 and 2/3,
/// so this doubles or tripples bandwidth usage.
#[derive(Clone)]
pub struct AllMessage {
    content: MessageContent,
    proof_of_possession: Signature,
    signature: Signature,
}

impl AllMessage {
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

impl Keypair {
    /// Second round of the SimplPedPoP protocol.
    pub fn simplpedpop_recipient_all(&self, messages: &[AllMessage]) {}
}

/// Evaluate the polynomial with the given coefficients (constant term first)
/// at the point x=identifier using Horner's method.
fn evaluate_polynomial(identifier: &Scalar, coefficients: &[Scalar]) -> Scalar {
    let mut value = Scalar::ZERO;

    let ell_scalar = identifier;
    for coeff in coefficients.iter().skip(1).rev() {
        value = value + *coeff;
        value *= ell_scalar;
    }
    value = value + *coefficients.first().expect("coefficients must have at least one element");
    value
}

/// Return a vector of randomly generated polynomial coefficients ([`Scalar`]s).
pub(crate) fn generate_coefficients<R: RngCore + CryptoRng>(
    size: usize,
    rng: &mut R,
) -> Vec<Scalar> {
    let mut coefficients = Vec::with_capacity(size);

    // Ensure the first coefficient is not zero
    let mut first = Scalar::random(rng);
    while first == Scalar::ZERO {
        first = Scalar::random(rng);
    }
    coefficients.push(first);

    // Generate the remaining coefficients
    coefficients.extend(iter::repeat_with(|| Scalar::random(rng)).take(size - 1));

    coefficients
}

fn derive_secret_key_from_secret<R: RngCore + CryptoRng>(secret: &Scalar, mut rng: R) -> SecretKey {
    let mut bytes = [0u8; 64];
    let mut nonce: [u8; 32] = [0u8; 32];

    rng.fill_bytes(&mut nonce);
    let secret_bytes = secret.to_bytes();

    bytes[..32].copy_from_slice(&secret_bytes[..]);
    bytes[32..].copy_from_slice(&nonce[..]);

    SecretKey::from_bytes(&bytes[..])
        .expect("This never fails because bytes has length 64 and the key is a scalar")
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::scalar::Scalar;
    use rand::rngs::OsRng;

    // Helper function to create a test PublicKey
    fn test_public_key() -> PublicKey {
        let point = RistrettoPoint::random(&mut OsRng);
        PublicKey::from_point(point)
    }

    // Helper function to create a test Signature
    fn test_signature() -> Signature {
        let point = RistrettoPoint::random(&mut OsRng);
        let scalar = Scalar::random(&mut OsRng);
        Signature { R: point.compress(), s: scalar }
    }

    #[test]
    fn test_serialize_deserialize() {
        let sender = test_public_key();
        let encryption_nonce = [1u8; 16];
        let parameters = Parameters { participants: 2, threshold: 1 };
        let recipients_hash = [2u8; 16];
        let point_polynomial =
            vec![RistrettoPoint::random(&mut OsRng), RistrettoPoint::random(&mut OsRng)];
        let ciphertexts = vec![Scalar::random(&mut OsRng), Scalar::random(&mut OsRng)];
        let proof_of_possession = test_signature();
        let signature = test_signature();

        let message_content = MessageContent {
            sender,
            encryption_nonce,
            parameters,
            recipients_hash,
            point_polynomial,
            ciphertexts,
        };

        let message = AllMessage { content: message_content, proof_of_possession, signature };

        // Serialize the message
        let bytes = message.clone().to_bytes();

        // Deserialize the message
        let deserialized_message = AllMessage::from_bytes(&bytes).expect("Failed to deserialize");

        // Assertions to ensure that the deserialized message matches the original message
        assert_eq!(
            message.content.sender.to_bytes(),
            deserialized_message.content.sender.to_bytes()
        );
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
        assert_eq!(
            message.content.point_polynomial.len(),
            deserialized_message.content.point_polynomial.len()
        );
        assert!(message
            .content
            .point_polynomial
            .iter()
            .zip(deserialized_message.content.point_polynomial.iter())
            .all(|(a, b)| a.compress() == b.compress()));
        assert_eq!(
            message.content.ciphertexts.len(),
            deserialized_message.content.ciphertexts.len()
        );
        assert!(message
            .content
            .ciphertexts
            .iter()
            .zip(deserialized_message.content.ciphertexts.iter())
            .all(|(a, b)| a == b));
        assert_eq!(message.proof_of_possession.R, deserialized_message.proof_of_possession.R);
        assert_eq!(message.proof_of_possession.s, deserialized_message.proof_of_possession.s);
        assert_eq!(message.signature.R, deserialized_message.signature.R);
        assert_eq!(message.signature.s, deserialized_message.signature.s);
    }
}
