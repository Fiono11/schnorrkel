//! Implementation of the SimplPedPoP protocol (<https://eprint.iacr.org/2023/899>), a DKG based on PedPoP, which in turn is based
//! on Pedersen's DKG. All of them have as the fundamental building block the Shamir's Secret Sharing scheme.

use alloc::vec::Vec;
use curve25519_dalek::{traits::Identity, RistrettoPoint, Scalar};
use merlin::Transcript;
use rand_core::RngCore;
use crate::{context::SigningTranscript, verify_batch, Keypair, PublicKey};
use super::{
    data_structures::{
        AllMessage, DKGOutput, DKGOutputContent, MessageContent, Parameters,
        ENCRYPTION_NONCE_LENGTH, RECIPIENTS_HASH_LENGTH,
    },
    errors::{DKGError, DKGResult},
    utils::{
        decrypt, derive_secret_key_from_secret, encrypt, evaluate_polynomial,
        evaluate_polynomial_commitment, generate_coefficients, generate_identifier,
        sum_commitments,
    },
    GENERATOR, MINIMUM_THRESHOLD,
};

impl Keypair {
    /// Encrypt a single scalar evaluation for a single recipient.
    pub fn encrypt_secret_share<T: SigningTranscript>(
        &self,
        mut transcript: T,
        recipient: &PublicKey,
        scalar_evaluation: &Scalar,
        nonce: &[u8; ENCRYPTION_NONCE_LENGTH],
        i: usize,
    ) -> Scalar {
        transcript.commit_bytes(b"i", &i.to_le_bytes());
        transcript.commit_point(b"contributor", self.public.as_compressed());
        transcript.commit_point(b"recipient", recipient.as_compressed());

        transcript.commit_bytes(b"nonce", nonce);

        self.secret.commit_raw_key_exchange(&mut transcript, b"kex", recipient);

        // Derive a scalar from the transcript to use as the encryption key
        let encryption_scalar = transcript.challenge_scalar(b"encryption scalar");
        scalar_evaluation + encryption_scalar
    }

    /// Decrypt a single scalar evaluation for a single sender.
    pub fn decrypt_secret_share<T: SigningTranscript>(
        &self,
        mut transcript: T,
        sender: &PublicKey,
        encrypted_scalar: &Scalar,
        nonce: &[u8; ENCRYPTION_NONCE_LENGTH],
        i: usize,
    ) -> Scalar {
        transcript.commit_bytes(b"i", &i.to_le_bytes());
        transcript.commit_point(b"contributor", sender.as_compressed());
        transcript.commit_point(b"recipient", self.public.as_compressed());

        // Append the same nonce used during encryption
        transcript.commit_bytes(b"nonce", nonce);

        self.secret.commit_raw_key_exchange(&mut transcript, b"kex", sender);

        // Derive the same scalar from the transcript used as the encryption key
        let decryption_scalar = transcript.challenge_scalar(b"encryption scalar");

        // Decrypt the scalar by reversing the addition
        encrypted_scalar - decryption_scalar
    }

    /// First round of the SimplPedPoP protocol.
    pub fn simplpedpop_contribute_all(
        &self,
        threshold: u16,
        recipients: Vec<PublicKey>,
    ) -> DKGResult<AllMessage> {
        let parameters = Parameters::generate(recipients.len() as u16, threshold);
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
        let mut recipients_hash = [0u8; RECIPIENTS_HASH_LENGTH];
        t.challenge_bytes(b"finalize", &mut recipients_hash);

        // uses identifier(recipients_hash, i)
        let coefficients = generate_coefficients(parameters.threshold as usize - 1, &mut rng);
        let mut scalar_evaluations = Vec::new();

        for i in 0..parameters.participants {
            let identifier = generate_identifier(&recipients_hash, i);
            let scalar_evaluation = evaluate_polynomial(&identifier, &coefficients);
            scalar_evaluations.push(scalar_evaluation);
        }

        // Create the vector of commitments
        let point_polynomial: Vec<RistrettoPoint> =
            coefficients.iter().map(|c| GENERATOR * *c).collect();

        // All this custom encryption mess saves 32 bytes per recipient
        // over chacha20poly1305, so maybe not worth the trouble.

        let mut enc0 = merlin::Transcript::new(b"Encryption");
        parameters.commit(&mut enc0);
        enc0.commit_point(b"contributor", self.public.as_compressed());

        let mut encryption_nonce = [0u8; ENCRYPTION_NONCE_LENGTH];
        rng.fill_bytes(&mut encryption_nonce);
        enc0.append_message(b"nonce", &encryption_nonce);

        let mut ciphertexts = Vec::new();
        for i in 0..parameters.participants {
            /*let ciphertext = self.encrypt_secret_share(
            enc0.clone(),
            &recipients[i as usize],
            &scalar_evaluations[i as usize],
            &encryption_nonce,
            i as usize,
            );*/

            let ciphertext = encrypt(
                &scalar_evaluations[i as usize],
                &self.secret.key,
                &recipients[i as usize].into_point(),
                b"secret share",
            )?;

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

        let message_bytes = message_content.to_bytes();

        let mut t_sig = Transcript::new(b"signature");
        t_sig.append_message(b"message", &message_bytes);
        let signature = self.sign(t_sig);

        let secret_key = derive_secret_key_from_secret(
            coefficients
                .first()
                .expect("This never fails because the minimum threshold is 2"),
            &mut rng,
        );

        let mut t_pop = Transcript::new(b"pop");
        t_pop.append_message(b"message", &message_bytes.clone());
        let proof_of_possession = secret_key.sign(t_pop, pk);

        Ok(AllMessage::new(message_content, proof_of_possession, signature))
    }

    /// Second round of the SimplPedPoP protocol.
    pub fn simplpedpop_recipient_all(
        &self,
        messages: &[AllMessage],
    ) -> DKGResult<(DKGOutput, Scalar)> {
        if messages.len() < MINIMUM_THRESHOLD as usize {
            return Err(DKGError::InvalidNumberOfMessages);
        }

        let participants = messages[0].content.parameters.participants as usize;
        let threshold = messages[0].content.parameters.threshold as usize;

        if messages.len() != participants {
            return Err(DKGError::IncorrectNumberOfMessages);
        }

        messages[0].content.parameters.validate()?;

        let first_params = &messages[0].content.parameters;
        let recipients_hash = &messages[0].content.recipients_hash;

        let mut secret_shares = Vec::new();

        let mut verifying_keys = Vec::new();

        let mut public_keys = Vec::with_capacity(participants);
        let mut proofs_of_possession = Vec::with_capacity(participants);

        let mut senders = Vec::with_capacity(participants);
        let mut signatures = Vec::with_capacity(participants);

        let mut t_sigs = Vec::with_capacity(participants);
        let mut t_pops = Vec::with_capacity(participants);

        let mut group_point = RistrettoPoint::identity();
        let mut total_secret_share = Scalar::ZERO;
        let mut total_polynomial_commitment: Vec<RistrettoPoint> = Vec::new();

        for (j, message) in messages.iter().enumerate() {
            if &message.content.parameters != first_params {
                return Err(DKGError::DifferentParameters);
            }
            if &message.content.recipients_hash != recipients_hash {
                return Err(DKGError::DifferentRecipientsHash);
            }
            // The public keys are the secret commitments of the participants
            let public_key =
                PublicKey::from_point(
                    *message.content.point_polynomial.first().expect(
                        "This never fails because the minimum threshold of the protocol is 2",
                    ),
                );

            public_keys.push(public_key);
            proofs_of_possession.push(message.proof_of_possession);

            senders.push(message.content.sender);
            signatures.push(message.signature);

            // Recreate the encryption environment
            let mut enc = merlin::Transcript::new(b"Encryption");
            message.content.parameters.commit(&mut enc);
            enc.commit_point(b"contributor", message.content.sender.as_compressed());

            let point_polynomial = &message.content.point_polynomial;
            let sender = message.content.sender;
            let ciphertexts = &message.content.ciphertexts;

            if point_polynomial.len() != threshold - 1 {
                return Err(DKGError::IncorrectNumberOfCommitments);
            }

            if ciphertexts.len() != participants {
                return Err(DKGError::IncorrectNumberOfEncryptedShares);
            }

            let encryption_nonce = message.content.encryption_nonce;
            enc.append_message(b"nonce", &encryption_nonce);

            let message_bytes = &message.content.to_bytes();

            let mut t_sig = Transcript::new(b"signature");
            t_sig.append_message(b"message", message_bytes);

            let mut t_pop = Transcript::new(b"pop");
            t_pop.append_message(b"message", &message_bytes.clone());

            t_sigs.push(t_sig);
            t_pops.push(t_pop);

            if total_polynomial_commitment.is_empty() {
                total_polynomial_commitment = point_polynomial.clone();
            } else {
                total_polynomial_commitment =
                    sum_commitments(&[&total_polynomial_commitment, point_polynomial])?;
            }

            for (i, ciphertext) in ciphertexts.iter().enumerate() {
                /*let evaluation = evaluate_polynomial_commitment(
                &generate_identifier(recipients_hash, i as u16),
                point_polynomial,
                );*/

                /*let original_scalar = self.decrypt_secret_share(
                enc.clone(),
                &sender,
                ciphertext,
                &encryption_nonce,
                i,
                );*/

                let original_scalar =
                    decrypt(ciphertext, &self.secret.key, &sender.into_point(), b"secret share");

                if original_scalar.is_ok() {
                    secret_shares.push(original_scalar.unwrap());
                    break;
                }

                //if evaluation == original_scalar * GENERATOR {
                //secret_shares.push(original_scalar);
                //break;
                //}
            }

            total_secret_share += secret_shares[j];

            group_point += message
                .content
                .point_polynomial
                .first()
                .expect("This never fails because the minimum threshold is 2");
        }

        for i in 0..participants {
            let identifier = generate_identifier(recipients_hash, i as u16);
            verifying_keys
                .push(evaluate_polynomial_commitment(&identifier, &total_polynomial_commitment));
        }

        if secret_shares.len() != messages[0].content.parameters.participants as usize {
            return Err(DKGError::IncorrectNumberOfValidSecretShares {
                expected: messages[0].content.parameters.participants as usize,
                actual: secret_shares.len(),
            });
        }

        verify_batch(t_pops, &proofs_of_possession[..], &public_keys[..], false)
            .map_err(DKGError::InvalidProofOfPossession)?;

        verify_batch(t_sigs, &signatures[..], &senders[..], false)
            .map_err(DKGError::InvalidProofOfPossession)?;

        let dkg_output_content =
            DKGOutputContent::new(PublicKey::from_point(group_point), verifying_keys);

        let mut transcript = Transcript::new(b"dkg output");
        transcript.append_message(b"content", &dkg_output_content.to_bytes());

        let signature = self.sign(transcript);

        let dkg_output = DKGOutput::new(self.public, dkg_output_content, signature);

        Ok((dkg_output, total_secret_share))
    }
}
