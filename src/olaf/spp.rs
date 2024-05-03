//!

// It's irrelevant if we're in the recipients or not ???

use core::iter;
use alloc::vec::Vec;
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::CompressedRistretto, traits::Identity,
    RistrettoPoint, Scalar,
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
    /// Encrypt a single scalar evaluation for a single recipient.
    pub fn encrypt_secret_share(
        &self,
        recipient: &PublicKey,
        scalar_evaluation: &Scalar,
        nonce: &[u8; 16],
        i: usize,
    ) -> Scalar {
        // Initialize the transcript for encryption
        let mut transcript = Transcript::new(b"SingleScalarEncryption");
        // We tweak by i too since encrypton_nonce is not truly a nonce.
        transcript.append_message(b"i", &i.to_le_bytes());
        transcript.commit_point(b"contributor", &self.public.as_compressed());
        transcript.commit_point(b"recipient", recipient.as_compressed());

        transcript.append_message(b"nonce", nonce);

        self.secret.commit_raw_key_exchange(&mut transcript, b"kex", &recipient);

        // Derive a scalar from the transcript to use as the encryption key
        let encryption_scalar = transcript.challenge_scalar(b"encryption scalar");
        let encrypted_scalar = scalar_evaluation + encryption_scalar;

        encrypted_scalar
    }

    /// Decrypt a single scalar evaluation for a single sender.
    pub fn decrypt_secret_share(
        &self,
        sender: &PublicKey,
        encrypted_scalar: &Scalar,
        nonce: &[u8; 16],
        i: usize,
    ) -> Scalar {
        // Initialize the transcript for decryption using the same setup as encryption
        let mut transcript = Transcript::new(b"SingleScalarEncryption");
        transcript.append_message(b"i", &i.to_le_bytes());
        transcript.commit_point(b"contributor", sender.as_compressed());
        transcript.commit_point(b"recipient", &self.public.as_compressed());

        // Append the same nonce used during encryption
        transcript.append_message(b"nonce", nonce);

        self.secret.commit_raw_key_exchange(&mut transcript, b"kex", &sender);

        // Derive the same scalar from the transcript used as the encryption key
        let decryption_scalar = transcript.challenge_scalar(b"encryption scalar");

        // Decrypt the scalar by reversing the addition
        let original_scalar = encrypted_scalar - decryption_scalar;

        original_scalar
    }

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

        // All this custom encryption mess saves 32 bytes per recipient
        // over chacha20poly1305, so maybe not worth the trouble.

        let mut enc0 = merlin::Transcript::new(b"Encryption");
        parameters.commit(&mut enc0);
        enc0.commit_point(b"contributor", self.public.as_compressed());

        let mut encryption_nonce = [0u8; 16];
        rng.fill_bytes(&mut encryption_nonce);
        enc0.append_message(b"nonce", &encryption_nonce);

        let mut ciphertexts = Vec::new();
        for i in 0..parameters.participants {
            let ciphertext = self.encrypt_secret_share(
                &recipients[i as usize],
                &scalar_evaluations[i as usize],
                &encryption_nonce,
                i as usize,
            );

            ciphertexts.push(ciphertext);
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

    /// Second round of the SimplPedPoP protocol.
    pub fn simplpedpop_recipient_all(
        &self,
        messages: &[AllMessage],
    ) -> DKGResult<(DKGOutput, Scalar)> {
        let mut secret_shares = Vec::new();
        let mut verifying_keys = [RistrettoPoint::identity(); 2];
        let mut transcript = Transcript::new(b"dkg output");
        let mut identified = false;

        assert!(messages.len() == 2);

        for message in messages {
            // Recreate the encryption environment
            let mut enc = merlin::Transcript::new(b"Encryption");
            message.content.parameters.commit(&mut enc);
            enc.commit_point(b"contributor", message.content.sender.as_compressed());
            let recipients_hash = message.content.recipients_hash;
            let point_polynomial = &message.content.point_polynomial;
            let sender = message.content.sender;

            let encryption_nonce = message.content.encryption_nonce;
            enc.append_message(b"nonce", &encryption_nonce);

            assert!(message.content.ciphertexts.len() == 2);

            for (i, ciphertext) in message.content.ciphertexts.iter().enumerate() {
                let original_scalar =
                    self.decrypt_secret_share(&sender, ciphertext, &encryption_nonce, i as usize);

                let evaluation = evaluate_secret_share(
                    identifier(&recipients_hash, i as u16),
                    &point_polynomial,
                );

                verifying_keys[i] += evaluation;

                if evaluation == original_scalar * RISTRETTO_BASEPOINT_POINT {
                    if !identified {
                        // This is to distinguish different output messages in the case that recipients != participants
                        transcript.append_u64(b"id", i as u64);
                        identified = true;
                    }
                    secret_shares.push(original_scalar);
                }
            }
        }

        for verifying_key in &verifying_keys {
            assert!(*verifying_key != RistrettoPoint::identity());
        }

        assert!(verifying_keys.len() == messages[0].content.parameters.participants as usize);

        if secret_shares.len() != messages[0].content.parameters.participants as usize {
            return Err(DKGError::IncorrectNumberOfSecretShares {
                expected: messages[0].content.parameters.participants as usize,
                actual: secret_shares.len(),
            });
        }

        let mut total_secret_share = Scalar::ZERO;

        for secret_share in secret_shares {
            total_secret_share += secret_share;
        }

        let mut group_point = RistrettoPoint::identity();

        for message in messages {
            group_point += message
                .content
                .point_polynomial
                .first()
                .expect("This never fails because the minimum threshold is 2");
        }

        let dkg_output_content = DKGOutputContent {
            group_public_key: PublicKey::from_point(group_point),
            verifying_keys: verifying_keys.to_vec(),
        };

        let signature = self.sign(transcript);

        let dkg_output = DKGOutput { sender: self.public, content: dkg_output_content, signature };

        Ok((dkg_output, total_secret_share))
    }
}

/// The contents of the message destined to all participants.
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

pub struct DKGOutput {
    sender: PublicKey,
    content: DKGOutputContent,
    signature: Signature,
}

impl DKGOutput {
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
    group_public_key: PublicKey,
    verifying_keys: Vec<RistrettoPoint>,
}

impl DKGOutputContent {
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

fn evaluate_secret_share(identifier: Scalar, commitment: &Vec<RistrettoPoint>) -> RistrettoPoint {
    let i = identifier;

    let (_, result) = commitment
        .iter()
        .fold((Scalar::ONE, RistrettoPoint::identity()), |(i_to_the_k, sum_so_far), comm_k| {
            (i * i_to_the_k, sum_so_far + comm_k * i_to_the_k)
        });
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::scalar::Scalar;
    use rand::rngs::OsRng;

    #[test]
    fn test_serialize_deserialize() {
        let sender = Keypair::generate();
        let encryption_nonce = [1u8; 16];
        let parameters = Parameters { participants: 2, threshold: 1 };
        let recipients_hash = [2u8; 16];
        let point_polynomial =
            vec![RistrettoPoint::random(&mut OsRng), RistrettoPoint::random(&mut OsRng)];
        let ciphertexts = vec![Scalar::random(&mut OsRng), Scalar::random(&mut OsRng)];
        let proof_of_possession = sender.sign(Transcript::new(b"pop"));
        let signature = sender.sign(Transcript::new(b"sig"));

        let message_content = MessageContent {
            sender: sender.public,
            encryption_nonce,
            parameters,
            recipients_hash,
            point_polynomial,
            ciphertexts,
        };

        let message = AllMessage { content: message_content, proof_of_possession, signature };

        // Serialize the message
        let bytes = message.to_bytes();

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

    #[test]
    fn test_simplpedpop_protocol() {
        // Create participants
        let threshold = 2;
        let participants = 2;
        let keypairs: Vec<Keypair> = (0..participants).map(|_| Keypair::generate()).collect();
        let public_keys: Vec<PublicKey> = keypairs.iter().map(|kp| kp.public.clone()).collect();

        // Each participant creates an AllMessage
        let mut all_messages = Vec::new();
        for i in 0..participants {
            let message: AllMessage =
                keypairs[i].simplpedpop_contribute_all(threshold, public_keys.clone()).unwrap();
            all_messages.push(message);
        }

        let mut dkg_outputs = Vec::new();

        for kp in keypairs.iter() {
            let dkg_output = kp.simplpedpop_recipient_all(&all_messages).unwrap();
            dkg_outputs.push(dkg_output);
        }

        // Assert that all DKG outputs are equal for group_public_key and verifying_keys
        assert!(
            dkg_outputs.windows(2).all(|w| w[0].0.content.group_public_key
                == w[1].0.content.group_public_key
                && w[0].0.content.verifying_keys.len() == w[1].0.content.verifying_keys.len()
                && w[0]
                    .0
                    .content
                    .verifying_keys
                    .iter()
                    .zip(w[1].0.content.verifying_keys.iter())
                    .all(|(a, b)| a == b)),
            "All DKG outputs should have identical group public keys and verifying keys."
        );

        for i in 0..participants {
            for j in 0..participants {
                assert_eq!(
                    dkg_outputs[i].0.content.verifying_keys[j].compress(),
                    (dkg_outputs[j].1 * RISTRETTO_BASEPOINT_POINT).compress(),
                    "Verification of total secret shares failed!"
                );
            }
        }
    }

    #[test]
    fn test_encrypt_decrypt_scalar() {
        // Create a sender and a recipient Keypair
        let sender = Keypair::generate();
        let recipient = Keypair::generate();

        // Generate a scalar to encrypt
        let original_scalar = Scalar::random(&mut OsRng);

        let nonce = [0; 16];

        // Encrypt the scalar using sender's keypair and recipient's public key
        let encrypted_scalar =
            sender.encrypt_secret_share(&recipient.public, &original_scalar, &nonce, 0);

        // Decrypt the scalar using recipient's keypair
        let decrypted_scalar =
            recipient.decrypt_secret_share(&sender.public, &encrypted_scalar, &nonce, 0);

        // Check that the decrypted scalar matches the original scalar
        assert_eq!(
            decrypted_scalar, original_scalar,
            "Decrypted scalar should match the original scalar."
        );
    }

    #[test]
    fn test_dkg_output_serialization() {
        let mut rng = OsRng;
        let group_public_key = RistrettoPoint::random(&mut rng);
        let verifying_keys = vec![
            RistrettoPoint::random(&mut rng),
            RistrettoPoint::random(&mut rng),
            RistrettoPoint::random(&mut rng),
        ];

        let dkg_output_content = DKGOutputContent {
            group_public_key: PublicKey::from_point(group_public_key),
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
            deserialized_dkg_output.content.group_public_key.as_compressed(),
            dkg_output.content.group_public_key.as_compressed(),
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
                .all(|(a, b)| a == b),
            "Verifying keys do not match"
        );

        assert_eq!(
            deserialized_dkg_output.signature.s, dkg_output.signature.s,
            "Signatures do not match"
        );
    }
}
