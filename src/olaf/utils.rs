use core::iter;

use alloc::vec::Vec;
use curve25519_dalek::{traits::Identity, RistrettoPoint, Scalar};
use rand_core::{CryptoRng, RngCore};

use crate::SecretKey;

/// Evaluate the polynomial with the given coefficients (constant term first)
/// at the point x=identifier using Horner's method.
pub(crate) fn evaluate_polynomial(identifier: &Scalar, coefficients: &[Scalar]) -> Scalar {
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

pub(crate) fn evaluate_secret_share(
    identifier: Scalar,
    commitment: &Vec<RistrettoPoint>,
) -> RistrettoPoint {
    let i = identifier;

    let (_, result) = commitment
        .iter()
        .fold((Scalar::ONE, RistrettoPoint::identity()), |(i_to_the_k, sum_so_far), comm_k| {
            (i * i_to_the_k, sum_so_far + comm_k * i_to_the_k)
        });
    result
}
