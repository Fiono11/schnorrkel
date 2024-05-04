use core::iter;
use alloc::vec::Vec;
use aead::{generic_array::GenericArray, KeyInit, KeySizeUser};
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, Nonce};
use curve25519_dalek::{traits::Identity, RistrettoPoint, Scalar};
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use crate::{context::SigningTranscript, SecretKey};
use super::errors::{DKGError, DKGResult};

pub(crate) fn generate_identifier(recipients_hash: &[u8; 16], index: u16) -> Scalar {
    let mut pos = merlin::Transcript::new(b"Identifier");
    pos.append_message(b"RecipientsHash", recipients_hash);
    pos.append_message(b"i", &index.to_le_bytes()[..]);
    pos.challenge_scalar(b"evaluation position")
}

/// Evaluate the polynomial with the given coefficients (constant term first)
/// at the point x=identifier using Horner's method.
pub(crate) fn evaluate_polynomial(identifier: &Scalar, coefficients: &[Scalar]) -> Scalar {
    let mut value = Scalar::ZERO;

    let ell_scalar = identifier;
    for coeff in coefficients.iter().skip(1).rev() {
        value += *coeff;
        value *= ell_scalar;
    }
    value += *coefficients.first().expect("coefficients must have at least one element");
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

pub(crate) fn derive_secret_key_from_secret<R: RngCore + CryptoRng>(
    secret: &Scalar,
    mut rng: R,
) -> SecretKey {
    let mut bytes = [0u8; 64];
    let mut nonce: [u8; 32] = [0u8; 32];

    rng.fill_bytes(&mut nonce);
    let secret_bytes = secret.to_bytes();

    bytes[..32].copy_from_slice(&secret_bytes[..]);
    bytes[32..].copy_from_slice(&nonce[..]);

    SecretKey::from_bytes(&bytes[..])
        .expect("This never fails because bytes has length 64 and the key is a scalar")
}

pub(crate) fn evaluate_polynomial_commitment(
    identifier: &Scalar,
    commitment: &[RistrettoPoint],
) -> RistrettoPoint {
    let i = identifier;

    let (_, result) = commitment
        .iter()
        .fold((Scalar::ONE, RistrettoPoint::identity()), |(i_to_the_k, sum_so_far), comm_k| {
            (i * i_to_the_k, sum_so_far + comm_k * i_to_the_k)
        });
    result
}

pub(crate) fn sum_commitments(
    commitments: &[&Vec<RistrettoPoint>],
) -> Result<Vec<RistrettoPoint>, DKGError> {
    let mut group_commitment =
        vec![
            RistrettoPoint::identity();
            commitments.first().ok_or(DKGError::IncorrectNumberOfCommitments)?.len()
        ];
    for commitment in commitments {
        for (i, c) in group_commitment.iter_mut().enumerate() {
            *c += commitment.get(i).ok_or(DKGError::IncorrectNumberOfCommitments)?;
        }
    }
    Ok(group_commitment)
}

pub(crate) fn encrypt(
    scalar: &Scalar,
    decryption_key: &Scalar,
    encryption_key: &RistrettoPoint,
    context: &[u8],
) -> DKGResult<Vec<u8>> {
    let shared_secret = decryption_key * encryption_key;

    let mut transcript = Transcript::new(b"encryption");
    transcript.commit_point(b"shared secret", &shared_secret.compress());
    transcript.append_message(b"context", context);

    let mut bytes = [0; 12];
    transcript.challenge_bytes(b"nonce", &mut bytes);

    let nonce = Nonce::from_slice(&bytes[..]);

    let mut key: GenericArray<u8, <chacha20poly1305::ChaCha20Poly1305 as KeySizeUser>::KeySize> =
        Default::default();

    transcript.challenge_bytes(b"", key.as_mut_slice());

    let cipher = ChaCha20Poly1305::new(&key);

    let ciphertext: Vec<u8> = cipher
        .encrypt(nonce, &scalar.as_bytes()[..])
        .map_err(DKGError::EncryptionError)?;

    Ok(ciphertext)
}

pub(crate) fn decrypt(
    ciphertext: &[u8],
    decryption_key: &Scalar,
    encryption_key: &RistrettoPoint,
    context: &[u8],
) -> DKGResult<Scalar> {
    let shared_secret = decryption_key * encryption_key;

    let mut transcript = Transcript::new(b"encryption");
    transcript.commit_point(b"shared secret", &shared_secret.compress());
    transcript.append_message(b"context", context);

    let mut bytes = [0; 12];
    transcript.challenge_bytes(b"nonce", &mut bytes);

    let nonce = Nonce::from_slice(&bytes);

    let mut key: GenericArray<u8, <chacha20poly1305::ChaCha20Poly1305 as KeySizeUser>::KeySize> =
        Default::default();

    transcript.challenge_bytes(b"", key.as_mut_slice());

    let cipher = ChaCha20Poly1305::new(&key);

    let plaintext = cipher.decrypt(nonce, &ciphertext[..]).map_err(DKGError::DecryptionError)?;

    let mut bytes = [0; 32];
    bytes.copy_from_slice(&plaintext);

    Ok(Scalar::from_bytes_mod_order(bytes))
}
