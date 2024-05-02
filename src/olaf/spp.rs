//!

// It's irrelevant if we're in the recipiants or not ???

use core::iter;
use alloc::vec::Vec;
use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, RistrettoPoint, Scalar};
use rand_core::{CryptoRng, RngCore};
use crate::{context::SigningTranscript, Keypair, PublicKey, SecretKey, Signature};
use super::errors::{DKGError, DKGResult};

/// The parameters of a given execution of the SimplPedPoP protocol.
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
    pos.append_message(b"RecipiantsHash", recipients_hash);
    pos.append_message(b"i", &index.to_le_bytes()[..]);
    pos.challenge_scalar(b"evaluation position")
}

impl Keypair {
    /// First round of the SimplPedPoP protocol.
    pub fn simplpedpop_contribute_all(
        &self,
        threshold: u16,
        mut recipients: Vec<PublicKey>,
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

        for i in [0..parameters.participants] {
            let mut p = t.clone();
        }

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

        let signature = self.sign(t.clone());
        let secret_key = derive_secret_key_from_secret(
            coefficients
                .first()
                .expect("This never fails because the minimum threshold is 2"),
            &mut rng,
        );
        let proof_of_possession =
            secret_key.sign(t, &PublicKey::from_point(secret_key.key * RISTRETTO_BASEPOINT_POINT));

        let sender = self.public;
        Ok(AllMessage {
            sender,
            encryption_nonce,
            parameters,
            recipients_hash,
            point_polynomial,
            ciphertexts,
            signature,
            proof_of_possession,
        })
    }
}

/// AllMessage packs together messages for all participants.
///
/// We'd save bandwidth by having separate messages for each
/// participant, but typical thresholds lie between 1/2 and 2/3,
/// so this doubles or tripples bandwidth usage.
pub struct AllMessage {
    sender: PublicKey,
    encryption_nonce: [u8; 16],
    parameters: Parameters,
    recipients_hash: [u8; 16],
    point_polynomial: Vec<RistrettoPoint>,
    ciphertexts: Vec<Scalar>,
    proof_of_possession: Signature,
    signature: Signature,
}

impl AllMessage {
    /// Serialize AllMessage
    pub fn to_bytes(self) -> Vec<u8> {
        Vec::new()
    }
    /*pub fn from_bytes(bytes: &[u8]) -> DKGResult<AllMessage> {
    Ok(AllMessage)
    }*/
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
