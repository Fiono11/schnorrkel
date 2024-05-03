//! Implementation of the SimplPedPoP protocol (<https://eprint.iacr.org/2023/899>), a DKG based on PedPoP, which in turn is based
//! on Pedersen's DKG. All of them have as the fundamental building block the Shamir's Secret Sharing scheme.

use alloc::vec::Vec;
use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, traits::Identity, RistrettoPoint, Scalar};
use merlin::Transcript;
use rand_core::RngCore;
use crate::{context::SigningTranscript, olaf::data_structures::Identifier, Keypair, PublicKey};
use super::{
    data_structures::{AllMessage, DKGOutput, DKGOutputContent, MessageContent, Parameters},
    errors::{DKGError, DKGResult},
    utils::{
        derive_secret_key_from_secret, evaluate_polynomial, evaluate_secret_share,
        generate_coefficients,
    },
};

impl Keypair {
    /// Encrypt a single scalar evaluation for a single recipient.
    pub fn encrypt_secret_share<T: SigningTranscript>(
        &self,
        mut transcript: T,
        recipient: &PublicKey,
        scalar_evaluation: &Scalar,
        nonce: &[u8; 16],
        i: usize,
    ) -> Scalar {
        transcript.commit_bytes(b"i", &i.to_le_bytes());
        transcript.commit_point(b"contributor", &self.public.as_compressed());
        transcript.commit_point(b"recipient", recipient.as_compressed());

        transcript.commit_bytes(b"nonce", nonce);

        self.secret.commit_raw_key_exchange(&mut transcript, b"kex", &recipient);

        // Derive a scalar from the transcript to use as the encryption key
        let encryption_scalar = transcript.challenge_scalar(b"encryption scalar");
        let encrypted_scalar = scalar_evaluation + encryption_scalar;

        encrypted_scalar
    }

    /// Decrypt a single scalar evaluation for a single sender.
    pub fn decrypt_secret_share<T: SigningTranscript>(
        &self,
        mut transcript: T,
        sender: &PublicKey,
        encrypted_scalar: &Scalar,
        nonce: &[u8; 16],
        i: usize,
    ) -> Scalar {
        transcript.commit_bytes(b"i", &i.to_le_bytes());
        transcript.commit_point(b"contributor", sender.as_compressed());
        transcript.commit_point(b"recipient", &self.public.as_compressed());

        // Append the same nonce used during encryption
        transcript.commit_bytes(b"nonce", nonce);

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
        let parameters = Parameters::generate(threshold, recipients.len() as u16);
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
            let identifier = Identifier::generate(&recipients_hash, i);
            let scalar_evaluation = evaluate_polynomial(&identifier.0, &coefficients);
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
                enc0.clone(),
                &recipients[i as usize],
                &scalar_evaluations[i as usize],
                &encryption_nonce,
                i as usize,
            );

            ciphertexts.push(ciphertext);
        }

        let pk = &PublicKey::from_point(
            *point_polynomial
                .first()
                .expect("This never fails because the minimum threshold is 2"),
        );

        let message_content = MessageContent::new(
            self.public,
            encryption_nonce,
            parameters,
            recipients_hash,
            point_polynomial,
            ciphertexts,
        );

        let mut m = Transcript::new(b"signature");
        m.append_message(b"message", &message_content.to_bytes());

        let signature = self.sign(m.clone());
        let secret_key = derive_secret_key_from_secret(
            coefficients
                .first()
                .expect("This never fails because the minimum threshold is 2"),
            &mut rng,
        );
        let proof_of_possession = secret_key.sign(m, pk);

        Ok(AllMessage::new(message_content, proof_of_possession, signature))
    }

    /// Second round of the SimplPedPoP protocol.
    pub fn simplpedpop_recipient_all(
        &self,
        messages: &[AllMessage],
    ) -> DKGResult<(DKGOutput, Scalar)> {
        // It's irrelevant if we're in the recipiants or not ???

        let mut secret_shares = Vec::new();
        let mut transcript = Transcript::new(b"dkg output");
        let mut identified = false;

        if messages.len() < 2 {
            return Err(DKGError::InvalidNumberOfMessages);
        }

        let first_params = &messages[0].content.parameters;
        let recipients_hash = &messages[0].content.recipients_hash;

        for message in messages {
            if &message.content.parameters != first_params {
                return Err(DKGError::DifferentParameters);
            }
            if &message.content.recipients_hash != recipients_hash {
                return Err(DKGError::DifferentRecipientsHash);
            }
        }

        messages[0].content.parameters.validate()?;

        let participants = messages[0].content.parameters.participants as usize;
        if messages.len() != participants {
            return Err(DKGError::IncorrectNumberOfMessages);
        }

        let mut verifying_keys = Vec::new();
        for _ in 0..participants {
            verifying_keys.push(RistrettoPoint::identity());
        }

        for message in messages {
            // Recreate the encryption environment
            let mut enc = merlin::Transcript::new(b"Encryption");
            message.content.parameters.commit(&mut enc);
            enc.commit_point(b"contributor", message.content.sender.as_compressed());

            let point_polynomial = &message.content.point_polynomial;
            let sender = message.content.sender;
            let ciphertexts = &message.content.ciphertexts;

            if point_polynomial.len() != participants - 1 {
                return Err(DKGError::IncorrectNumberOfCommitments);
            }

            if ciphertexts.len() != participants {
                return Err(DKGError::IncorrectNumberOfEncryptedShares);
            }

            let encryption_nonce = message.content.encryption_nonce;
            enc.append_message(b"nonce", &encryption_nonce);

            let mut m = Transcript::new(b"signature");
            m.append_message(b"message", &message.content.to_bytes());

            let pk = PublicKey::from_point(
                *message
                    .content
                    .point_polynomial
                    .first()
                    .expect("This never fails because the minimum threshold is 2"),
            );

            // TODO: Verify batch
            pk.verify(m.clone(), &message.proof_of_possession)
                .map_err(DKGError::InvalidProofOfPossession)?;

            sender.verify(m, &message.signature).map_err(DKGError::InvalidSignature)?;

            for (i, ciphertext) in ciphertexts.iter().enumerate() {
                let original_scalar = self.decrypt_secret_share(
                    enc.clone(),
                    &sender,
                    ciphertext,
                    &encryption_nonce,
                    i as usize,
                );

                let evaluation = evaluate_secret_share(
                    Identifier::generate(&recipients_hash, i as u16).0,
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
            if verifying_key == &RistrettoPoint::identity() {
                return Err(DKGError::InvalidVerifyingKey);
            }
        }

        if secret_shares.len() != messages[0].content.parameters.participants as usize {
            return Err(DKGError::IncorrectNumberOfValidSecretShares {
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

        let dkg_output_content =
            DKGOutputContent::new(PublicKey::from_point(group_point), verifying_keys.to_vec());

        let signature = self.sign(transcript);

        let dkg_output = DKGOutput::new(self.public, dkg_output_content, signature);

        Ok((dkg_output, total_secret_share))
    }
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

        let message_content = MessageContent::new(
            sender.public,
            encryption_nonce,
            parameters,
            recipients_hash,
            point_polynomial,
            ciphertexts,
        );

        let message = AllMessage::new(message_content, proof_of_possession, signature);

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

        // Verify that all DKG outputs are equal for group_public_key and verifying_keys
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

        // Verify that all verifying_keys are valid
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
        let encrypted_scalar = sender.encrypt_secret_share(
            Transcript::new(b"enc"),
            &recipient.public,
            &original_scalar,
            &nonce,
            0,
        );

        // Decrypt the scalar using recipient's keypair
        let decrypted_scalar = recipient.decrypt_secret_share(
            Transcript::new(b"enc"),
            &sender.public,
            &encrypted_scalar,
            &nonce,
            0,
        );

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
