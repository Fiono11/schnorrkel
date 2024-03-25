//! Implementation of SimplPedPoP (<https://eprint.iacr.org/2023/899>), a DKG based on PedPoP, which in turn is based
//! on Pedersen's DKG.
//! All of them have as the fundamental building block the Shamir's Secret Sharing scheme.
//!
//! The protocol is divided into three rounds. In each round some data and some messages are produced and verified
//! (if received from a previous round). Messages can be private, which means that they can be relayed through a
//! coordinator to its recipients, or private, which means they need to be sent directly to its recipients (unless
//! encrypted).

use crate::{
    errors::DKGError,
    identifier::Identifier,
    polynomial::{Coefficient, CoefficientCommitment, Polynomial, PolynomialCommitment, Value},
    PublicKey, SecretKey, Signature,
};
use alloc::collections::BTreeSet;
use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, RistrettoPoint, Scalar};
use derive_getters::Getters;
use rand_core::{CryptoRng, RngCore};
use zeroize::ZeroizeOnDrop;

pub(crate) const GENERATOR: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;

pub(crate) type SecretPolynomialCommitment = PolynomialCommitment;
pub(crate) type SecretPolynomial = Polynomial;
pub(crate) type SharedPublicKey = PublicKey;
pub(crate) type TotalSecretShare = SecretShare;
pub(crate) type TotalSecretShareCommitment = CoefficientCommitment;
pub(crate) type SecretCommitment = CoefficientCommitment;
pub(crate) type Certificate = Signature;
pub(crate) type ProofOfPossession = Signature;
pub(crate) type Secret = Coefficient;

/// A secret share, which corresponds to an evaluation of a value that identifies a participant in a secret polynomial.
#[derive(Debug, Clone, ZeroizeOnDrop)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SecretShare(pub(crate) Value);

/// The parameters of a given execution of the SimplPedPoP protocol.
#[derive(Debug, Clone, Getters)]
pub struct Parameters {
    participants: u16,
    threshold: u16,
    own_identifier: Identifier,
    others_identifiers: BTreeSet<Identifier>,
}

impl Parameters {
    /// Create new parameters.
    pub fn new(
        participants: u16,
        threshold: u16,
        own_identifier: Identifier,
        others_identifiers: BTreeSet<Identifier>,
    ) -> Parameters {
        Parameters {
            participants,
            threshold,
            own_identifier,
            others_identifiers,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), DKGError> {
        if self.own_identifier.0 == Scalar::ZERO {
            return Err(DKGError::InvalidIdentifier);
        }

        for other_identifier in &self.others_identifiers {
            if other_identifier.0 == Scalar::ZERO {
                return Err(DKGError::InvalidIdentifier);
            }
        }

        if self.threshold < 2 {
            return Err(DKGError::InsufficientThreshold);
        }

        if self.participants < 2 {
            return Err(DKGError::InvalidNumberOfParticipants);
        }

        if self.threshold > self.participants {
            return Err(DKGError::ExcessiveThreshold);
        }

        if self.others_identifiers.len() != self.participants as usize - 1 {
            return Err(DKGError::IncorrectNumberOfIdentifiers {
                expected: self.participants as usize,
                actual: self.others_identifiers.len() + 1,
            });
        }

        Ok(())
    }
}

fn derive_secret_key_from_secret<R: RngCore + CryptoRng>(secret: Secret, mut rng: R) -> SecretKey {
    let mut bytes = [0u8; 64];
    let mut nonce: [u8; 32] = [0u8; 32];

    rng.fill_bytes(&mut nonce);
    let secret_bytes = secret.to_bytes();

    bytes[..32].copy_from_slice(&secret_bytes[..]);
    bytes[32..].copy_from_slice(&nonce[..]);

    SecretKey::from_bytes(&bytes[..]).unwrap() // This never fails because bytes has length 64 and the key is a scalar
}

/// SimplPedPoP round 1.
///
/// The participant commits to a secret polynomial f(x) of degree t-1, where t is the threshold of the DKG and n
/// is the total number of participants.
///
/// From the secret polynomial it derives a secret key from the secret and the secret shares f(i)...f(n) and it
/// generates a Proof of Possession of the secret f(0) by signing a message with the secret key.
///
/// It stores the secret key and its own secret share in its private data, sends each secret share directly to its
/// corresponding recipient and the polynomial commitment to all the other participants (or to the coordinator).
pub mod round1 {
    use crate::polynomial::PolynomialCommitment;
    use crate::{errors::DKGResult, polynomial::Polynomial};
    use crate::{PublicKey, SecretKey};
    use alloc::collections::BTreeMap;
    use curve25519_dalek::Scalar;
    use derive_getters::Getters;
    use merlin::Transcript;
    use rand_core::{CryptoRng, RngCore};
    use zeroize::ZeroizeOnDrop;

    use super::{
        derive_secret_key_from_secret, Identifier, Parameters, ProofOfPossession, SecretPolynomial,
        SecretPolynomialCommitment, SecretShare,
    };

    /// The private data generated by the participant in round 1.
    #[derive(Debug, Clone, Getters)]
    pub struct PrivateData {
        pub(crate) secret_key: SecretKey,
        pub(crate) secret_share: SecretShare,
    }

    /// The public data generated by the participant in round 1.
    #[derive(Debug, Clone, Getters)]
    pub struct PublicData {
        pub(crate) secret_polynomial_commitment: SecretPolynomialCommitment,
        pub(crate) proof_of_possession: ProofOfPossession,
    }

    /// The messages to be sent by the participant in round 1.
    #[derive(Debug, Clone, Getters)]
    pub struct Messages {
        private_messages: BTreeMap<Identifier, PrivateMessage>,
        public_message: PublicMessage,
    }

    /// Public message to be sent by the participant to all the other participants or to the coordinator in round 1.
    #[derive(Debug, Clone, Getters)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct PublicMessage {
        secret_polynomial_commitment: SecretPolynomialCommitment,
        proof_of_possession: ProofOfPossession,
    }

    impl PublicMessage {
        /// Creates a new public message.
        pub fn new(
            secret_polynomial_commitment: SecretPolynomialCommitment,
            proof_of_possession: ProofOfPossession,
        ) -> PublicMessage {
            PublicMessage {
                secret_polynomial_commitment,
                proof_of_possession,
            }
        }
    }

    /// Private message to sent by a participant to another participant or to the coordinator in encrypted form in round 1.
    #[derive(Debug, Clone, ZeroizeOnDrop, Getters)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct PrivateMessage {
        pub(crate) secret_share: SecretShare,
    }

    impl PrivateMessage {
        /// Creates a new private message.
        pub fn new(secret_share: SecretShare) -> PrivateMessage {
            PrivateMessage { secret_share }
        }
    }

    /// Runs the round 1 of the SimplPedPoP protocol.
    pub fn run<R: RngCore + CryptoRng>(
        parameters: &Parameters,
        mut rng: R,
    ) -> DKGResult<(PrivateData, Messages, PublicData)> {
        parameters.validate()?;

        let (private_data, proof_of_possession, secret_polynomial, public_data) =
            generate_data(parameters, &mut rng);

        let messages = generate_messages(
            parameters,
            &proof_of_possession,
            &secret_polynomial,
            &public_data.secret_polynomial_commitment,
        );

        Ok((private_data, messages, public_data))
    }

    fn generate_data<R: RngCore + CryptoRng>(
        parameters: &Parameters,
        mut rng: R,
    ) -> (PrivateData, ProofOfPossession, SecretPolynomial, PublicData) {
        let secret_polynomial = loop {
            let temp_polynomial = Polynomial::generate(&mut rng, *parameters.threshold());
            // There must be a secret, which is the constant coefficient of the secret polynomial
            if temp_polynomial.constant_coefficient != Scalar::ZERO {
                break temp_polynomial;
            }
        };

        let secret_polynomial_commitment = PolynomialCommitment::generate(&secret_polynomial);

        let secret_share = secret_polynomial.evaluate(&parameters.own_identifier().0);

        // This secret key will be used to sign the proof of possession and the certificate
        let secret_key = derive_secret_key_from_secret(secret_polynomial.constant_coefficient, rng);

        let public_key =
            PublicKey::from_point(secret_polynomial_commitment.constant_coefficient_commitment);

        let proof_of_possession =
            secret_key.sign(Transcript::new(b"Proof of Possession"), &public_key);

        (
            PrivateData {
                secret_key,
                secret_share: SecretShare(secret_share),
            },
            proof_of_possession,
            secret_polynomial,
            PublicData {
                secret_polynomial_commitment,
                proof_of_possession,
            },
        )
    }

    fn generate_messages(
        parameters: &Parameters,
        proof_of_possession: &ProofOfPossession,
        secret_polynomial: &SecretPolynomial,
        secret_polynomial_commitment: &SecretPolynomialCommitment,
    ) -> Messages {
        let mut private_messages = BTreeMap::new();

        for identifier in &parameters.others_identifiers {
            let secret_share = secret_polynomial.evaluate(&identifier.0);
            private_messages.insert(*identifier, PrivateMessage::new(SecretShare(secret_share)));
        }

        let public_message =
            PublicMessage::new(secret_polynomial_commitment.clone(), *proof_of_possession);

        Messages {
            private_messages,
            public_message,
        }
    }
}

/// SimplPedPoP round 2.
///
/// The participant verifies the received messages of the other participants from round 1, the polynomial commitments,
/// the Proofs of Possession and the secret shares.
///
/// It stores its own total secret share privately, which corresponds to the sum of all its secret shares (including its own)
/// It signs a transcript of the protocol execution (certificate) with its secret key, which contains the PoPs and the polynomial
/// commitments from all the participants (including its own), and sends it to all the other participants (or the
/// coordinator).
pub mod round2 {
    use super::{
        round1::{self, PrivateMessage},
        Certificate, Identifier, Parameters, SecretCommitment, SecretShare, TotalSecretShare,
        GENERATOR,
    };
    use crate::{
        context::SigningTranscript,
        errors::{DKGError, DKGResult},
        verify_batch, PublicKey, SecretKey,
    };
    use alloc::{collections::BTreeMap, vec, vec::Vec};
    use curve25519_dalek::Scalar;
    use merlin::Transcript;
    use zeroize::ZeroizeOnDrop;

    /// The public data of round 2.
    #[derive(Debug, Clone)]
    pub struct PublicData<T: SigningTranscript + Clone> {
        pub(crate) transcript: T,
    }

    /// The private data of round 2.
    #[derive(Debug, Clone, ZeroizeOnDrop)]
    pub struct PrivateData {
        pub(crate) total_secret_share: TotalSecretShare,
    }

    /// The public message of round 2.
    #[derive(Debug, Clone)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct PublicMessage {
        pub(crate) certificate: Certificate,
    }

    /// Runs the round 2 of a SimplPedPoP protocol.
    pub fn run<T: SigningTranscript + Clone>(
        parameters: &Parameters,
        round1_private_data: round1::PrivateData,
        round1_public_data: &round1::PublicData,
        round1_public_messages: &BTreeMap<Identifier, round1::PublicMessage>,
        round1_private_messages: BTreeMap<Identifier, round1::PrivateMessage>,
        transcript: T,
    ) -> DKGResult<(PublicData<T>, PrivateData, PublicMessage)> {
        parameters.validate()?;

        if round1_public_messages.len() != *parameters.participants() as usize - 1 {
            return Err(DKGError::IncorrectNumberOfRound1PublicMessages {
                expected: *parameters.participants() as usize - 1,
                actual: round1_public_messages.len(),
            });
        }

        if round1_private_messages.len() != *parameters.participants() as usize - 1 {
            return Err(DKGError::IncorrectNumberOfPrivateMessages {
                expected: *parameters.participants() as usize - 1,
                actual: round1_private_messages.len(),
            });
        }

        verify_round1_messages(parameters, round1_public_messages, &round1_private_messages)?;

        let private_data = generate_private_data(
            parameters,
            &round1_private_messages,
            &round1_private_data.secret_share,
        )?;

        let public_data =
            generate_public_data(round1_public_messages, round1_public_data, transcript)?;

        let secret_commitment = round1_public_data
            .secret_polynomial_commitment()
            .constant_coefficient_commitment;

        let public_message = generate_public_message(
            round1_private_data.secret_key,
            &secret_commitment,
            public_data.transcript.clone(),
        );

        Ok((public_data, private_data, public_message))
    }

    fn generate_private_data(
        parameters: &Parameters,
        private_messages: &BTreeMap<Identifier, PrivateMessage>,
        own_secret_share: &SecretShare,
    ) -> DKGResult<PrivateData> {
        let mut total_secret_share = Scalar::ZERO;

        for id in parameters.others_identifiers() {
            total_secret_share += private_messages
                .get(id)
                .ok_or(DKGError::UnknownIdentifier)?
                .secret_share()
                .0;
        }

        total_secret_share += own_secret_share.0;

        let private_data = PrivateData {
            total_secret_share: SecretShare(total_secret_share),
        };

        Ok(private_data)
    }

    fn generate_public_data<T: SigningTranscript + Clone>(
        round1_public_messages: &BTreeMap<Identifier, round1::PublicMessage>,
        round1_public_data: &round1::PublicData,
        mut transcript: T,
    ) -> DKGResult<PublicData<T>> {
        // Writes the data of all the participants in the transcript ordered by their identifiers
        for identifier in 1..=round1_public_messages.len() + 1 {
            if let Some(round1_public_message) =
                round1_public_messages.get(&(identifier as u16).try_into().unwrap())
            // This never fails because we previously checked for invalid identifiers
            {
                // Writes the data of the other participants in the transcript
                transcript.commit_point(
                    b"SecretCommitment",
                    &round1_public_message
                        .secret_polynomial_commitment()
                        .constant_coefficient_commitment
                        .compress(),
                );

                for coefficient_commitment in &round1_public_message
                    .secret_polynomial_commitment()
                    .non_constant_coefficients_commitments
                {
                    transcript
                        .commit_point(b"CoefficientCommitment", &coefficient_commitment.compress());
                }

                transcript.commit_point(
                    b"ProofOfPossessionR",
                    &round1_public_message.proof_of_possession().R,
                );
            } else {
                // Writes the data of the participant in the transcript
                transcript.commit_point(
                    b"SecretCommitment",
                    &round1_public_data
                        .secret_polynomial_commitment()
                        .constant_coefficient_commitment
                        .compress(),
                );

                for coefficient_commitment in &round1_public_data
                    .secret_polynomial_commitment()
                    .non_constant_coefficients_commitments
                {
                    transcript
                        .commit_point(b"CoefficientCommitment", &coefficient_commitment.compress());
                }

                transcript.commit_point(
                    b"ProofOfPossessionR",
                    &round1_public_data.proof_of_possession().R,
                );
            }
        }

        Ok(PublicData { transcript })
    }

    fn verify_round1_messages(
        parameters: &Parameters,
        round1_public_messages: &BTreeMap<Identifier, round1::PublicMessage>,
        round1_private_messages: &BTreeMap<Identifier, round1::PrivateMessage>,
    ) -> DKGResult<()> {
        for identifier in parameters.others_identifiers() {
            let public_message = round1_public_messages
                .get(identifier)
                .ok_or(DKGError::UnknownIdentifier)?;

            let private_message = round1_private_messages
                .get(identifier)
                .ok_or(DKGError::UnknownIdentifier)?;

            verify_round1_private_message(
                parameters,
                public_message,
                private_message,
                *identifier,
            )?;
        }

        verify_round1_public_messages(parameters, round1_public_messages)
    }

    fn verify_round1_public_messages(
        parameters: &Parameters,
        round1_public_messages: &BTreeMap<Identifier, round1::PublicMessage>,
    ) -> DKGResult<()> {
        let mut public_keys = Vec::new();
        let mut proofs_of_possession = Vec::new();

        // The public keys are the secret commitments of the participants
        for (identifier, public_message) in round1_public_messages {
            if identifier != parameters.own_identifier() {
                let public_key = PublicKey::from_point(
                    public_message
                        .secret_polynomial_commitment()
                        .constant_coefficient_commitment,
                );
                public_keys.push(public_key);
                proofs_of_possession.push(*public_message.proof_of_possession());
            }
        }

        verify_batch(
            vec![Transcript::new(b"Proof of Possession"); parameters.participants as usize - 1],
            &proofs_of_possession[..],
            &public_keys[..],
            false,
        )
        .map_err(DKGError::InvalidProofOfPossession)
    }

    fn verify_round1_private_message(
        params: &Parameters,
        round1_public_message: &round1::PublicMessage,
        round1_private_message: &PrivateMessage,
        identifier: Identifier,
    ) -> DKGResult<()> {
        let expected_evaluation = GENERATOR * round1_private_message.secret_share().0;

        let evaluation = round1_public_message
            .secret_polynomial_commitment()
            .evaluate(params.own_identifier().0);

        if !(evaluation == expected_evaluation) {
            Err(DKGError::InvalidSecretShare(identifier))
        } else {
            Ok(())
        }
    }

    fn generate_public_message<T: SigningTranscript + Clone>(
        secret_key: SecretKey,
        secret_commitment: &SecretCommitment,
        transcript: T,
    ) -> PublicMessage {
        let public_key = PublicKey::from_point(*secret_commitment);

        let certificate = secret_key.sign(transcript, &public_key);

        PublicMessage { certificate }
    }
}

/// SimplPedPoP round 3.
///
/// The participant verifies the certificates from all the other participants and generates the shared public
/// key and the total secret shares commitments of the other partipants.
pub mod round3 {
    use super::{
        round1, round2, Certificate, Identifier, Parameters, SharedPublicKey,
        TotalSecretShareCommitment,
    };
    use crate::{
        context::SigningTranscript,
        errors::{DKGError, DKGResult},
        polynomial::PolynomialCommitment,
        verify_batch, PublicKey,
    };
    use alloc::{collections::BTreeMap, vec, vec::Vec};
    use curve25519_dalek::Scalar;

    /// Runs the round 3 of the SimplPedPoP protocol.
    pub fn run<T: SigningTranscript + Clone>(
        parameters: &Parameters,
        round2_public_messages: &BTreeMap<Identifier, round2::PublicMessage>,
        round2_public_data: &round2::PublicData<T>,
        round1_public_data: &round1::PublicData,
        round1_public_messages: &BTreeMap<Identifier, round1::PublicMessage>,
    ) -> DKGResult<(
        SharedPublicKey,
        BTreeMap<Identifier, TotalSecretShareCommitment>,
    )> {
        parameters.validate()?;

        if round2_public_messages.len() != *parameters.participants() as usize - 1 {
            return Err(DKGError::IncorrectNumberOfRound2PublicMessages {
                expected: *parameters.participants() as usize - 1,
                actual: round2_public_messages.len(),
            });
        }

        if round1_public_messages.len() != *parameters.participants() as usize - 1 {
            return Err(DKGError::IncorrectNumberOfRound1PublicMessages {
                expected: *parameters.participants() as usize - 1,
                actual: round1_public_messages.len(),
            });
        }

        verify_round2_messages(
            parameters,
            round1_public_messages,
            round2_public_messages,
            round2_public_data,
        )?;

        generate_public_data(parameters, round1_public_messages, round1_public_data)
    }

    fn verify_round2_messages<T: SigningTranscript + Clone>(
        parameters: &Parameters,
        round1_public_messages: &BTreeMap<Identifier, round1::PublicMessage>,
        round2_public_messages: &BTreeMap<Identifier, round2::PublicMessage>,
        round2_state: &round2::PublicData<T>,
    ) -> DKGResult<()> {
        let mut public_keys = Vec::new();

        // The public keys are the secret commitments of the participants
        for (id, round1_public_message) in round1_public_messages {
            if id != parameters.own_identifier() {
                let public_key = PublicKey::from_point(
                    round1_public_message
                        .secret_polynomial_commitment()
                        .constant_coefficient_commitment,
                );
                public_keys.push(public_key);
            }
        }

        verify_batch(
            vec![round2_state.transcript.clone(); parameters.participants as usize - 1],
            &round2_public_messages
                .values()
                .map(|x| x.certificate)
                .collect::<Vec<Certificate>>(),
            &public_keys[..],
            false,
        )
        .map_err(DKGError::InvalidCertificate)
    }

    fn generate_public_data(
        parameters: &Parameters,
        round1_public_messages: &BTreeMap<Identifier, round1::PublicMessage>,
        round1_public_data: &round1::PublicData,
    ) -> DKGResult<(
        SharedPublicKey,
        BTreeMap<Identifier, TotalSecretShareCommitment>,
    )> {
        // Sum of the secret polynomial commitments of the other participants
        let others_secret_polynomial_commitment = PolynomialCommitment::sum_polynomial_commitments(
            &round1_public_messages
                .iter()
                .map(|x| x.1.secret_polynomial_commitment())
                .collect::<Vec<&PolynomialCommitment>>(),
        );

        // The total secret polynomial commitment, which includes the secret polynomial commitment of the participant
        let total_secret_polynomial_commitment =
            PolynomialCommitment::sum_polynomial_commitments(&[
                &others_secret_polynomial_commitment,
                &round1_public_data.secret_polynomial_commitment,
            ]);

        // The total secret shares commitments of all the participants
        let mut total_secret_shares_commitments = BTreeMap::new();

        for identifier in parameters.others_identifiers() {
            let total_secret_share_commitment =
                total_secret_polynomial_commitment.evaluate(identifier.0);

            total_secret_shares_commitments.insert(*identifier, total_secret_share_commitment);
        }

        let own_total_secret_share_commitment =
            total_secret_polynomial_commitment.evaluate(parameters.own_identifier.0);

        total_secret_shares_commitments
            .insert(parameters.own_identifier, own_total_secret_share_commitment);

        let shared_public_key = SharedPublicKey::from_point(
            total_secret_polynomial_commitment.constant_coefficient_commitment,
        );

        // The shared public key corresponds to the secret commitment of the total secret polynomial commitment
        if shared_public_key.as_point()
            != &total_secret_polynomial_commitment.evaluate(Scalar::ZERO)
        {
            return Err(DKGError::SharedPublicKeyMismatch);
        }

        Ok((shared_public_key, total_secret_shares_commitments))
    }
}

#[cfg(test)]
mod tests {
    use self::round1::{PrivateData, PublicData};
    use super::*;
    use crate::SignatureError;
    use alloc::borrow::ToOwned;
    #[cfg(feature = "alloc")]
    use alloc::{
        collections::{BTreeMap, BTreeSet},
        vec::Vec,
    };
    use curve25519_dalek::Scalar;
    use merlin::Transcript;
    use rand::rngs::OsRng;
    use tests::round1::{PrivateMessage, PublicMessage};

    fn generate_parameters(max_signers: u16, min_signers: u16) -> Vec<Parameters> {
        (1..=max_signers)
            .map(|i| {
                let own_identifier = i.try_into().expect("should be nonzero");

                let others_identifiers = (1..=max_signers)
                    .filter_map(|j| {
                        if j != i {
                            Some(j.try_into().expect("should be nonzero"))
                        } else {
                            None
                        }
                    })
                    .collect();

                Parameters::new(max_signers, min_signers, own_identifier, others_identifiers)
            })
            .collect()
    }

    fn round1(
        participants: u16,
        threshold: u16,
    ) -> (
        Vec<Parameters>,
        Vec<PrivateData>,
        Vec<PublicData>,
        Vec<BTreeMap<Identifier, PublicMessage>>,
        Vec<BTreeMap<Identifier, PrivateMessage>>,
        BTreeSet<Identifier>,
    ) {
        let parameters_list = generate_parameters(participants, threshold);

        let mut all_public_messages = Vec::new();
        let mut all_private_messages = Vec::new();
        let mut participants_round1_private_data = Vec::new();
        let mut participants_round1_public_data = Vec::new();
        let mut participants_round1_messages = Vec::new();

        for parameters in parameters_list.iter() {
            let (private_data, messages, public_data) =
                round1::run(parameters, OsRng).expect("Round 1 should complete without errors!");

            all_public_messages.push((
                parameters.own_identifier(),
                messages.public_message().clone(),
            ));
            all_private_messages.push((
                parameters.own_identifier(),
                messages.private_messages().clone(),
            ));
            participants_round1_messages.push(messages);
            participants_round1_private_data.push(private_data);
            participants_round1_public_data.push(public_data);
        }

        let mut participants_round1_public_messages: Vec<BTreeMap<Identifier, PublicMessage>> =
            Vec::new();
        let mut participants_round1_private_messages: Vec<BTreeMap<Identifier, PrivateMessage>> =
            Vec::new();

        let mut identifiers: BTreeSet<Identifier> = parameters_list[0]
            .others_identifiers()
            .iter()
            .copied()
            .collect();

        identifiers.insert(*parameters_list[0].own_identifier());

        for identifier in &identifiers {
            let mut all_public_msgs = BTreeMap::new();
            let mut received_private_msgs = BTreeMap::new();

            for i in 0..participants {
                all_public_msgs.insert(
                    *all_public_messages[i as usize].0,
                    all_public_messages[i as usize].1.clone(),
                );
            }

            participants_round1_public_messages.push(all_public_msgs);

            for i in 0..participants {
                if let Some(private_msg) = all_private_messages[i as usize].1.get(identifier) {
                    received_private_msgs
                        .insert(*all_private_messages[i as usize].0, private_msg.clone());
                }
            }

            participants_round1_private_messages.push(received_private_msgs);
        }

        // Remove own public messages
        for i in 0..participants {
            participants_round1_public_messages[i as usize]
                .remove(&parameters_list[i as usize].own_identifier());
        }

        (
            parameters_list,
            participants_round1_private_data,
            participants_round1_public_data,
            participants_round1_public_messages,
            participants_round1_private_messages,
            identifiers,
        )
    }

    fn round2(
        participants: u16,
        parameters_list: Vec<Parameters>,
        participants_round1_private_data: Vec<PrivateData>,
        participants_round1_public_data: Vec<PublicData>,
        participants_round1_public_messages: Vec<BTreeMap<Identifier, PublicMessage>>,
        participants_round1_private_messages: Vec<BTreeMap<Identifier, PrivateMessage>>,
    ) -> (
        Vec<round2::PublicData<Transcript>>,
        Vec<round2::PrivateData>,
        Vec<round2::PublicMessage>,
    ) {
        let mut participants_public_data_round2 = Vec::new();
        let mut participants_private_data_round2 = Vec::new();
        let mut participants_public_msgs_round2 = Vec::new();

        for i in 0..participants {
            let result = round2::run(
                &parameters_list[i as usize],
                participants_round1_private_data[i as usize].clone(),
                &participants_round1_public_data[i as usize].clone(),
                &participants_round1_public_messages[i as usize].clone(),
                participants_round1_private_messages[i as usize].clone(),
                Transcript::new(b"transcript"),
            )
            .expect("Round 2 should complete without errors!");

            participants_public_data_round2.push(result.0);
            participants_private_data_round2.push(result.1);
            participants_public_msgs_round2.push(result.2);
        }

        (
            participants_public_data_round2,
            participants_private_data_round2,
            participants_public_msgs_round2,
        )
    }

    fn round3(
        participants: u16,
        identifiers: BTreeSet<Identifier>,
        parameters_list: &Vec<Parameters>,
        participants_round2_public_messages: Vec<round2::PublicMessage>,
        participants_round2_public_data: Vec<round2::PublicData<Transcript>>,
        participants_round1_public_messages: Vec<BTreeMap<Identifier, round1::PublicMessage>>,
        participants_round1_public_data: Vec<round1::PublicData>,
    ) -> Vec<(
        SharedPublicKey,
        BTreeMap<Identifier, TotalSecretShareCommitment>,
    )> {
        let mut participant_data_round3 = Vec::new();
        let identifiers_vec: Vec<Identifier> = identifiers.clone().iter().copied().collect();

        for i in 0..participants {
            let received_round2_public_messages = participants_round2_public_messages
                .iter()
                .enumerate()
                .filter(|(index, _msg)| {
                    identifiers_vec[*index] != *parameters_list[i as usize].own_identifier()
                })
                .map(|(index, msg)| (identifiers_vec[index], msg.clone()))
                .collect::<BTreeMap<Identifier, round2::PublicMessage>>();

            let result = round3::run(
                &parameters_list[i as usize],
                &received_round2_public_messages,
                &participants_round2_public_data[i as usize],
                &participants_round1_public_data[i as usize],
                &participants_round1_public_messages[i as usize],
            )
            .expect("Round 3 should complete without errors!");

            participant_data_round3.push(result);
        }

        participant_data_round3
    }

    #[test]
    pub fn test_successful_simplpedpop() {
        let participants: u16 = 5;
        let threshold: u16 = 3;

        let (
            parameters_list,
            participants_round1_private_data,
            participants_round1_public_data,
            mut participants_round1_public_messages,
            participants_round1_private_messages,
            identifiers,
        ) = round1(participants, threshold);

        for i in 0..participants {
            participants_round1_public_messages[i as usize]
                .remove(&parameters_list[i as usize].own_identifier());
        }

        let (
            participants_public_data_round2,
            participants_private_data_round2,
            participants_public_msgs_round2,
        ) = round2(
            participants,
            parameters_list.clone(),
            participants_round1_private_data.clone(),
            participants_round1_public_data.clone(),
            participants_round1_public_messages.clone(),
            participants_round1_private_messages.clone(),
        );

        let participant_data_round3 = round3(
            participants,
            identifiers,
            &parameters_list,
            participants_public_msgs_round2,
            participants_public_data_round2,
            participants_round1_public_messages,
            participants_round1_public_data,
        );

        let shared_public_keys: Vec<SharedPublicKey> = participant_data_round3
            .iter()
            .map(|state| state.0)
            .collect();

        assert!(
            shared_public_keys.windows(2).all(|w| w[0] == w[1]),
            "All participants should have the same shared public key!"
        );

        for i in 0..participants {
            assert_eq!(
                participant_data_round3[i as usize]
                    .1
                    .get(parameters_list[i as usize].own_identifier())
                    .unwrap(),
                &(participants_private_data_round2[i as usize]
                    .total_secret_share
                    .0
                    * GENERATOR),
                "Verification of total secret shares failed!"
            );
        }
    }

    #[test]
    fn test_incorrect_number_of_round1_public_messages_in_round2() {
        let participants: u16 = 5;
        let threshold: u16 = 3;

        let (
            parameters_list,
            participants_round1_private_data,
            participants_round1_public_data,
            mut participants_round1_public_messages,
            participants_round1_private_messages,
            _identifiers,
        ) = round1(participants, threshold);

        participants_round1_public_messages[0].remove(&2.try_into().unwrap());

        let result = round2::run(
            &parameters_list[0],
            participants_round1_private_data[0].clone(),
            &participants_round1_public_data[0],
            &participants_round1_public_messages[0],
            participants_round1_private_messages[0].clone(),
            Transcript::new(b"transcript"),
        );

        match result {
            Ok(_) => panic!("Expected an error, but got Ok."),
            Err(e) => assert_eq!(
                e,
                DKGError::IncorrectNumberOfRound1PublicMessages {
                    expected: participants as usize - 1,
                    actual: participants as usize - 2,
                },
                "Expected DKGError::IncorrectNumberOfRound1PublicMessages."
            ),
        }
    }

    #[test]
    fn test_incorrect_number_of_private_messages_in_round2() {
        let participants: u16 = 5;
        let threshold: u16 = 3;

        let (
            parameters_list,
            participants_round1_private_data,
            participants_round1_public_data,
            mut participants_round1_public_messages,
            mut participants_round1_private_messages,
            identifiers,
        ) = round1(participants, threshold);

        for i in 0..participants {
            participants_round1_public_messages[i as usize]
                .remove(&parameters_list[i as usize].own_identifier());
        }

        let identifiers_vec: Vec<Identifier> = identifiers.iter().copied().collect();
        participants_round1_private_messages[0].remove(&identifiers_vec[1]);

        let result = round2::run(
            &parameters_list[0],
            participants_round1_private_data[0].clone(),
            &participants_round1_public_data[0],
            &participants_round1_public_messages[0],
            participants_round1_private_messages[0].clone(),
            Transcript::new(b"transcript"),
        );

        match result {
            Ok(_) => panic!("Expected an error, but got Ok."),
            Err(e) => assert_eq!(
                e,
                DKGError::IncorrectNumberOfPrivateMessages {
                    expected: participants as usize - 1,
                    actual: participants as usize - 2,
                },
                "Expected DKGError::IncorrectNumberOfPrivateMessages."
            ),
        }
    }

    #[test]
    fn test_missing_private_message_in_round2() {
        let participants: u16 = 5;
        let threshold: u16 = 3;

        let (
            parameters_list,
            participants_round1_private_data,
            participants_round1_public_data,
            mut participants_round1_public_messages,
            mut participants_round1_private_messages,
            identifiers,
        ) = round1(participants, threshold);

        for i in 0..participants {
            participants_round1_public_messages[i as usize]
                .remove(&parameters_list[i as usize].own_identifier());
        }

        let identifiers_vec: Vec<Identifier> = identifiers.iter().copied().collect();
        participants_round1_private_messages[0].remove(&identifiers_vec[1]);

        let identifiers_vec: Vec<Identifier> = identifiers.iter().copied().collect();
        let private_message = participants_round1_private_messages[0]
            .get(&identifiers_vec[2])
            .unwrap()
            .clone();
        participants_round1_private_messages[0].remove(&identifiers_vec[1]);
        participants_round1_private_messages[0]
            .insert(Identifier(Scalar::random(&mut OsRng)), private_message);

        let result = round2::run(
            &parameters_list[0],
            participants_round1_private_data[0].clone(),
            &participants_round1_public_data[0],
            &participants_round1_public_messages[0],
            participants_round1_private_messages[0].clone(),
            Transcript::new(b"transcript"),
        );

        match result {
            Ok(_) => panic!("Expected an error, but got Ok."),
            Err(e) => assert_eq!(
                e,
                DKGError::UnknownIdentifier,
                "Expected DKGError::UnknownIdentifier."
            ),
        }
    }

    #[test]
    fn test_missing_public_message_in_round2() {
        let participants: u16 = 5;
        let threshold: u16 = 3;

        let (
            parameters_list,
            participants_round1_private_data,
            participants_round1_public_data,
            mut participants_round1_public_messages,
            participants_round1_private_messages,
            identifiers,
        ) = round1(participants, threshold);

        for i in 0..participants {
            participants_round1_public_messages[i as usize]
                .remove(&parameters_list[i as usize].own_identifier());
        }

        round2(
            participants,
            parameters_list.clone(),
            participants_round1_private_data.clone(),
            participants_round1_public_data.clone(),
            participants_round1_public_messages.clone(),
            participants_round1_private_messages.clone(),
        );

        let identifiers_vec: Vec<Identifier> = identifiers.iter().copied().collect();
        let public_message = participants_round1_public_messages[0]
            .get(&identifiers_vec[1])
            .unwrap()
            .clone();
        participants_round1_public_messages[0].remove(&identifiers_vec[1]);
        participants_round1_public_messages[0]
            .insert(Identifier(Scalar::random(&mut OsRng)), public_message);

        let result = round2::run(
            &parameters_list[0],
            participants_round1_private_data[0].clone(),
            &participants_round1_public_data[0],
            &participants_round1_public_messages[0],
            participants_round1_private_messages[0].clone(),
            Transcript::new(b"transcript"),
        );

        match result {
            Ok(_) => panic!("Expected an error, but got Ok."),
            Err(e) => assert_eq!(
                e,
                DKGError::UnknownIdentifier,
                "Expected DKGError::UnknownIdentifier."
            ),
        }
    }

    #[test]
    fn test_invalid_secret_share_error_in_round2() {
        let participants: u16 = 5;
        let threshold: u16 = 3;

        let (
            parameters_list,
            participants_round1_private_data,
            participants_round1_public_data,
            mut participants_round1_public_messages,
            mut participants_round1_private_messages,
            identifiers,
        ) = round1(participants, threshold);

        for i in 0..participants {
            participants_round1_public_messages[i as usize]
                .remove(&parameters_list[i as usize].own_identifier());
        }

        let identifiers_vec: Vec<Identifier> = identifiers.iter().copied().collect();

        let private_message = participants_round1_private_messages[0]
            .get_mut(&identifiers_vec[1])
            .unwrap();

        private_message.secret_share.0 += Scalar::ONE;

        let result = round2::run(
            &parameters_list[0],
            participants_round1_private_data[0].clone(),
            &participants_round1_public_data[0],
            &participants_round1_public_messages[0],
            participants_round1_private_messages[0].clone(),
            Transcript::new(b"transcript"),
        );

        match result {
            Ok(_) => panic!("Expected an error, but got Ok."),
            Err(e) => assert_eq!(
                e,
                DKGError::InvalidSecretShare(identifiers_vec[1]),
                "Expected DKGError::InvalidSecretShare."
            ),
        }
    }

    #[test]
    fn test_invalid_proof_of_possession_in_round2() {
        let participants: u16 = 5;
        let threshold: u16 = 3;

        let (
            parameters_list,
            participants_round1_private_data,
            participants_round1_public_data,
            mut participants_round1_public_messages,
            participants_round1_private_messages,
            identifiers,
        ) = round1(participants, threshold);

        for i in 0..participants {
            participants_round1_public_messages[i as usize]
                .remove(&parameters_list[i as usize].own_identifier());
        }

        let identifiers_vec: Vec<Identifier> = identifiers.iter().copied().collect();

        let secret_polynomial_commitment = participants_round1_public_messages[0]
            .get(&identifiers_vec[1])
            .unwrap()
            .secret_polynomial_commitment()
            .clone();

        let sk = SecretKey::generate();
        let proof_of_possession = sk.sign(Transcript::new(b"b"), &PublicKey::from(sk.clone()));
        let msg = PublicMessage::new(secret_polynomial_commitment, proof_of_possession);
        participants_round1_public_messages[0].insert(identifiers_vec[1], msg);

        let result = round2::run(
            &parameters_list[0],
            participants_round1_private_data[0].clone(),
            &participants_round1_public_data[0],
            &participants_round1_public_messages[0],
            participants_round1_private_messages[0].clone(),
            Transcript::new(b"transcript"),
        );

        match result {
            Ok(_) => panic!("Expected an error, but got Ok."),
            Err(e) => assert_eq!(
                e,
                DKGError::InvalidProofOfPossession(SignatureError::EquationFalse),
                "Expected DKGError::InvalidProofOfPossession."
            ),
        }
    }

    #[test]
    pub fn test_invalid_certificate_in_round3() {
        let participants: u16 = 5;
        let threshold: u16 = 3;

        let (
            parameters_list,
            participants_round1_private_data,
            participants_round1_public_data,
            mut participants_round1_public_messages,
            participants_round1_private_messages,
            identifiers,
        ) = round1(participants, threshold);

        for i in 0..participants {
            participants_round1_public_messages[i as usize]
                .remove(&parameters_list[i as usize].own_identifier());
        }

        let (
            participants_round2_public_data,
            _participants_round2_private_data,
            participants_round2_public_messages,
        ) = round2(
            participants,
            parameters_list.clone(),
            participants_round1_private_data.clone(),
            participants_round1_public_data.clone(),
            participants_round1_public_messages.clone(),
            participants_round1_private_messages.clone(),
        );

        let identifiers_vec: Vec<Identifier> = identifiers.clone().iter().copied().collect();
        let mut received_round2_public_messages = BTreeMap::new();

        for i in 0..participants {
            received_round2_public_messages = participants_round2_public_messages
                .iter()
                .enumerate()
                .filter(|(index, _msg)| {
                    identifiers_vec[*index] != *parameters_list[i as usize].own_identifier()
                })
                .map(|(index, msg)| (identifiers_vec[index], msg.clone()))
                .collect::<BTreeMap<Identifier, round2::PublicMessage>>();
        }

        let mut public_message = received_round2_public_messages
            .get_mut(&identifiers_vec[1])
            .unwrap()
            .to_owned();

        let sk = SecretKey::generate();

        public_message.certificate =
            sk.sign(Transcript::new(b"label"), &PublicKey::from(sk.clone()));

        received_round2_public_messages.insert(identifiers_vec[1], public_message);

        let result = round3::run(
            &parameters_list[0],
            &received_round2_public_messages,
            &participants_round2_public_data[0],
            &participants_round1_public_data[0],
            &participants_round1_public_messages[0],
        );

        match result {
            Ok(_) => panic!("Expected an error, but got Ok."),
            Err(e) => assert_eq!(
                e,
                DKGError::InvalidCertificate(SignatureError::EquationFalse),
                "Expected DKGError::InvalidCertificate."
            ),
        }
    }

    #[test]
    pub fn test_incorrect_number_of_round2_public_messages_in_round3() {
        let participants: u16 = 5;
        let threshold: u16 = 3;

        let (
            parameters_list,
            participants_round1_private_data,
            participants_round1_public_data,
            mut participants_round1_public_messages,
            participants_round1_private_messages,
            identifiers,
        ) = round1(participants, threshold);

        for i in 0..participants {
            participants_round1_public_messages[i as usize]
                .remove(&parameters_list[i as usize].own_identifier());
        }

        let (
            participants_round2_public_data,
            _participants_round2_private_data,
            participants_round2_public_messages,
        ) = round2(
            participants,
            parameters_list.clone(),
            participants_round1_private_data.clone(),
            participants_round1_public_data.clone(),
            participants_round1_public_messages.clone(),
            participants_round1_private_messages.clone(),
        );

        let identifiers_vec: Vec<Identifier> = identifiers.clone().iter().copied().collect();
        let mut received_round2_public_messages = BTreeMap::new();

        for i in 0..participants {
            received_round2_public_messages = participants_round2_public_messages
                .iter()
                .enumerate()
                .filter(|(index, _msg)| {
                    identifiers_vec[*index] != *parameters_list[i as usize].own_identifier()
                })
                .map(|(index, msg)| (identifiers_vec[index], msg.clone()))
                .collect::<BTreeMap<Identifier, round2::PublicMessage>>();
        }

        received_round2_public_messages.pop_first();

        let result = round3::run(
            &parameters_list[0],
            &received_round2_public_messages,
            &participants_round2_public_data[0],
            &participants_round1_public_data[0],
            &participants_round1_public_messages[0],
        );

        match result {
            Ok(_) => panic!("Expected an error, but got Ok."),
            Err(e) => assert_eq!(
                e,
                DKGError::IncorrectNumberOfRound2PublicMessages {
                    expected: participants as usize - 1,
                    actual: participants as usize - 2
                },
                "Expected DKGError::IncorrectNumberOfRound2PublicMessages."
            ),
        }
    }

    #[test]
    pub fn test_incorrect_number_of_round1_public_messages_in_round3() {
        let participants: u16 = 5;
        let threshold: u16 = 3;

        let (
            parameters_list,
            participants_round1_private_data,
            participants_round1_public_data,
            mut participants_round1_public_messages,
            participants_round1_private_messages,
            identifiers,
        ) = round1(participants, threshold);

        for i in 0..participants {
            participants_round1_public_messages[i as usize]
                .remove(&parameters_list[i as usize].own_identifier());
        }

        let (
            participants_round2_public_data,
            _participants_round2_private_data,
            participants_round2_public_messages,
        ) = round2(
            participants,
            parameters_list.clone(),
            participants_round1_private_data.clone(),
            participants_round1_public_data.clone(),
            participants_round1_public_messages.clone(),
            participants_round1_private_messages.clone(),
        );

        let identifiers_vec: Vec<Identifier> = identifiers.clone().iter().copied().collect();
        let mut received_round2_public_messages = BTreeMap::new();

        for i in 0..participants {
            received_round2_public_messages = participants_round2_public_messages
                .iter()
                .enumerate()
                .filter(|(index, _msg)| {
                    identifiers_vec[*index] != *parameters_list[i as usize].own_identifier()
                })
                .map(|(index, msg)| (identifiers_vec[index], msg.clone()))
                .collect::<BTreeMap<Identifier, round2::PublicMessage>>();
        }

        participants_round1_public_messages[0].pop_first();

        let result = round3::run(
            &parameters_list[0],
            &received_round2_public_messages,
            &participants_round2_public_data[0],
            &participants_round1_public_data[0],
            &participants_round1_public_messages[0],
        );

        match result {
            Ok(_) => panic!("Expected an error, but got Ok."),
            Err(e) => assert_eq!(
                e,
                DKGError::IncorrectNumberOfRound1PublicMessages {
                    expected: participants as usize - 1,
                    actual: participants as usize - 2
                },
                "Expected DKGError::IncorrectNumberOfRound1PublicMessages."
            ),
        }
    }

    #[test]
    fn test_invalid_own_identifier() {
        let own_identifier = Identifier(Scalar::ZERO);
        let parameters = Parameters::new(3, 2, own_identifier, BTreeSet::new());
        assert_eq!(parameters.validate(), Err(DKGError::InvalidIdentifier));
    }

    #[test]
    fn test_invalid_other_identifier() {
        let mut others_identifiers = BTreeSet::new();
        others_identifiers.insert(Identifier(Scalar::ZERO));

        let parameters = Parameters::new(3, 2, Identifier(Scalar::ONE), others_identifiers);
        assert_eq!(parameters.validate(), Err(DKGError::InvalidIdentifier));
    }

    #[test]
    fn test_incorrect_number_of_identifiers() {
        let mut others_identifiers = BTreeSet::new();
        others_identifiers.insert(Identifier(Scalar::ONE));

        let parameters = Parameters::new(3, 2, Identifier(Scalar::ONE), others_identifiers);
        assert_eq!(
            parameters.validate(),
            Err(DKGError::IncorrectNumberOfIdentifiers {
                expected: 3,
                actual: 2
            })
        );
    }

    #[test]
    fn test_invalid_threshold() {
        let parameters = Parameters::new(3, 1, Identifier(Scalar::ONE), BTreeSet::new());
        assert_eq!(parameters.validate(), Err(DKGError::InsufficientThreshold));
    }

    #[test]
    fn test_invalid_participants() {
        let parameters = Parameters::new(1, 2, Identifier(Scalar::ONE), BTreeSet::new());
        assert_eq!(
            parameters.validate(),
            Err(DKGError::InvalidNumberOfParticipants)
        );
    }

    #[test]
    fn test_threshold_greater_than_participants() {
        let parameters = Parameters::new(2, 3, Identifier(Scalar::ONE), BTreeSet::new());
        assert_eq!(parameters.validate(), Err(DKGError::ExcessiveThreshold));
    }
}
