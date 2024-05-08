//! Implementation of the Olaf protocol (<https://eprint.iacr.org/2023/899>), which is composed of the Distributed
//! Key Generation (DKG) protocol SimplPedPoP and the Threshold Signing protocol FROST.

use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, RistrettoPoint, Scalar};
use crate::{PublicKey, SecretKey};
use rand_core::{RngCore, CryptoRng};
use crate::context::SigningTranscript;

pub mod errors;
pub mod simplpedpop;
mod tests;
mod types;

const MINIMUM_THRESHOLD: u16 = 2;
const GENERATOR: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;

/// The group public key generated by the SimplPedPoP protocol.
pub struct GroupPublicKey(PublicKey);
/// The verifying share of a participant in the SimplPedPoP protocol, used to verify its signature share.
pub struct VerifyingShare(PublicKey);
/// The signing share of a participant in the SimplPedPoP protocol, used to produce its signature share.
pub struct SigningShare(SecretKey);

pub(super) fn generate_identifier(recipients_hash: &[u8; 16], index: u16) -> Scalar {
    let mut pos = merlin::Transcript::new(b"Identifier");
    pos.append_message(b"RecipientsHash", recipients_hash);
    pos.append_message(b"i", &index.to_le_bytes()[..]);
    pos.challenge_scalar(b"evaluation position")
}

pub(super) fn derive_secret_key_from_scalar<R: RngCore + CryptoRng>(
    scalar: &Scalar,
    mut rng: R,
) -> SecretKey {
    let mut bytes = [0u8; 64];
    let mut nonce: [u8; 32] = [0u8; 32];

    rng.fill_bytes(&mut nonce);
    let secret_bytes = scalar.to_bytes();

    bytes[..32].copy_from_slice(&secret_bytes[..]);
    bytes[32..].copy_from_slice(&nonce[..]);

    SecretKey::from_bytes(&bytes[..])
        .expect("This never fails because bytes has length 64 and the key is a scalar")
}
