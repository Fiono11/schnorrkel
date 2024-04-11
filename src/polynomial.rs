//! Implementation of a polynomial and related operations.

use alloc::vec;
use alloc::vec::Vec;
use curve25519_dalek::{traits::Identity, RistrettoPoint, Scalar};
use rand_core::{CryptoRng, RngCore};
use zeroize::ZeroizeOnDrop;

use crate::{points::Element, simplpedpop::GENERATOR};

pub(crate) type Coefficient = Scalar;
pub(crate) type Value = Scalar;
pub(crate) type ValueCommitment = Element;
pub(crate) type CoefficientCommitment = Element;

/// A polynomial.
#[derive(Debug, Clone, ZeroizeOnDrop)]
pub struct Polynomial {
    pub(crate) constant_coefficient: Coefficient,
    pub(crate) non_constant_coefficients: Vec<Coefficient>,
}

impl Polynomial {
    pub(crate) fn generate<R: RngCore + CryptoRng>(rng: &mut R, degree: u16) -> Self {
        let constant_coefficient = Scalar::random(rng);

        let mut non_constant_coefficients = Vec::new();
        for _ in 0..degree as usize - 2 {
            non_constant_coefficients.push(Scalar::random(rng));
        }

        Self {
            constant_coefficient,
            non_constant_coefficients,
        }
    }

    pub(crate) fn evaluate(&self, value: &Value) -> Value {
        let ell_scalar = value;
        let mut result = Scalar::ZERO;

        for coefficient in self.non_constant_coefficients.iter().rev() {
            result = (result + coefficient) * ell_scalar;
        }

        result += self.constant_coefficient;

        result
    }
}

/// A polynomial commitment.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PolynomialCommitment {
    pub(crate) constant_coefficient_commitment: CoefficientCommitment,
    pub(crate) non_constant_coefficients_commitments: Vec<CoefficientCommitment>,
}

impl PolynomialCommitment {
    pub(crate) fn commit(polynomial: &Polynomial) -> Self {
        let commitment = GENERATOR * polynomial.constant_coefficient;

        let non_constant_coefficients_commitments = polynomial
            .non_constant_coefficients
            .iter()
            .map(|coefficient| Element((GENERATOR * coefficient).compress()))
            .collect();

        Self {
            constant_coefficient_commitment: Element(commitment.compress()),
            non_constant_coefficients_commitments,
        }
    }

    pub(crate) fn evaluate(&self, identifier: &Value) -> ValueCommitment {
        let mut sum = RistrettoPoint::identity();
        let mut i_to_the_k = Scalar::ONE;

        sum += self.constant_coefficient_commitment.0.decompress().unwrap() * i_to_the_k;

        for coefficient_commitment in &self.non_constant_coefficients_commitments {
            i_to_the_k *= identifier;
            sum += coefficient_commitment.0.decompress().unwrap() * i_to_the_k;
        }

        Element(sum.compress())
    }

    pub(crate) fn sum_polynomial_commitments(
        polynomials_commitments: &[&PolynomialCommitment],
    ) -> PolynomialCommitment {
        let max_length = polynomials_commitments
            .iter()
            .map(|c| c.non_constant_coefficients_commitments.len())
            .max()
            .unwrap_or(0);

        let mut total_commitment = vec![RistrettoPoint::default(); max_length + 1];

        for polynomial_commitment in polynomials_commitments {
            total_commitment[0] += polynomial_commitment
                .constant_coefficient_commitment
                .0
                .decompress()
                .unwrap();
            for (i, coeff_commitment) in polynomial_commitment
                .non_constant_coefficients_commitments
                .iter()
                .enumerate()
            {
                if i < total_commitment.len() - 1 {
                    total_commitment[i + 1] += coeff_commitment.0.decompress().unwrap();
                }
            }
        }

        PolynomialCommitment {
            constant_coefficient_commitment: Element(total_commitment[0].compress()),
            non_constant_coefficients_commitments: total_commitment[1..]
                .iter()
                .map(|x| Element(x.compress()))
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        points::Element,
        polynomial::{Coefficient, Polynomial, PolynomialCommitment},
        simplpedpop::GENERATOR,
    };

    use alloc::vec::Vec;
    use curve25519_dalek::Scalar;
    use rand::rngs::OsRng;

    #[test]
    fn test_generate_polynomial_commitment_valid() {
        let min_signers = 3;

        let polynomial = Polynomial::generate(&mut OsRng, min_signers);

        let polynomial_commitment = PolynomialCommitment::commit(&polynomial);

        assert_eq!(
            polynomial.non_constant_coefficients.len() + 1,
            (min_signers - 1) as usize
        );

        assert_eq!(
            polynomial_commitment
                .non_constant_coefficients_commitments
                .len()
                + 1,
            (min_signers - 1) as usize
        );
    }

    #[test]
    fn test_evaluate_polynomial() {
        let coefficients: Vec<Coefficient> =
            vec![Scalar::from(3u64), Scalar::from(2u64), Scalar::from(1u64)]; // Polynomial x^2 + 2x + 3

        let polynomial = Polynomial {
            constant_coefficient: coefficients[0],
            non_constant_coefficients: coefficients[1..].to_vec(),
        };

        let value = Scalar::from(5u64); // x = 5

        let result = polynomial.evaluate(&value);

        assert_eq!(result, Scalar::from(38u64)); // 5^2 + 2*5 + 3
    }

    #[test]
    fn test_sum_secret_polynomial_commitments() {
        let polynomial_commitment1 = PolynomialCommitment {
            constant_coefficient_commitment: Element((GENERATOR * Scalar::from(1u64)).compress()),
            non_constant_coefficients_commitments: vec![
                Element((GENERATOR * Scalar::from(2u64)).compress()),
                Element((GENERATOR * Scalar::from(3u64)).compress()),
            ],
        };

        let polynomial_commitment2 = PolynomialCommitment {
            constant_coefficient_commitment: Element((GENERATOR * Scalar::from(4u64)).compress()),
            non_constant_coefficients_commitments: vec![
                Element((GENERATOR * Scalar::from(5u64)).compress()),
                Element((GENERATOR * Scalar::from(6u64)).compress()),
            ],
        };

        let summed_polynomial_commitments = PolynomialCommitment::sum_polynomial_commitments(&[
            &polynomial_commitment1,
            &polynomial_commitment2,
        ]);

        let expected_constant_coefficient_commitment = GENERATOR * Scalar::from(5u64); // 1 + 4
        let expected_non_constant_coefficients_commitments = vec![
            GENERATOR * Scalar::from(7u64), // 2 + 5
            GENERATOR * Scalar::from(9u64), // 3 + 6
        ];

        assert_eq!(
            summed_polynomial_commitments
                .constant_coefficient_commitment
                .0,
            expected_constant_coefficient_commitment.compress(),
            "Constant coefficients commitments do not match"
        );

        assert_eq!(
            summed_polynomial_commitments
                .non_constant_coefficients_commitments
                .len(),
            expected_non_constant_coefficients_commitments.len(),
            "Non-constant coefficient commitment lengths do not match"
        );

        for (actual, expected) in summed_polynomial_commitments
            .non_constant_coefficients_commitments
            .iter()
            .zip(expected_non_constant_coefficients_commitments.iter())
        {
            assert_eq!(
                actual.0,
                expected.compress(),
                "Non-constant coefficient commitments do not match"
            );
        }
    }

    #[test]
    fn test_evaluate_polynomial_commitment() {
        // f(x) = 3 + 2x + x^2
        let constant_commitment = (Scalar::from(3u64) * GENERATOR).compress();
        let linear_commitment = (Scalar::from(2u64) * GENERATOR).compress();
        let quadratic_commitment = (Scalar::from(1u64) * GENERATOR).compress();

        let polynomial_commitment = PolynomialCommitment {
            constant_coefficient_commitment: Element(constant_commitment),
            non_constant_coefficients_commitments: vec![
                Element(linear_commitment),
                Element(quadratic_commitment),
            ],
        };

        let value = Scalar::from(2u64);

        // f(2) = 11
        let expected = Scalar::from(11u64) * GENERATOR;

        let result = polynomial_commitment.evaluate(&value);

        assert_eq!(
            result.0,
            expected.compress(),
            "The evaluated commitment does not match the expected result"
        );
    }
}
