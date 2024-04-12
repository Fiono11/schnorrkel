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
pub(crate) type GroupPublicKey = PublicKey;
pub(crate) type TotalSecretShare = SecretShare;
pub(crate) type GroupPublicKeyShare = CoefficientCommitment;
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
}

impl Parameters {
    /// Create new parameters.
    pub fn new(participants: u16, threshold: u16) -> Parameters {
        Parameters {
            participants,
            threshold,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), DKGError> {
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
}

/// The participants of a given execution of the SimplPedPoP protocol.
#[derive(Debug, Clone, Getters)]
pub struct Participants {
    pub(crate) own_identifier: Identifier,
    pub(crate) others_identifiers: BTreeSet<Identifier>,
}

impl Participants {
    /// Create new participants.
    pub fn new(
        own_identifier: Identifier,
        others_identifiers: BTreeSet<Identifier>,
    ) -> Participants {
        Participants {
            own_identifier,
            others_identifiers,
        }
    }

    pub(crate) fn validate(&self, participants: u16) -> Result<(), DKGError> {
        if self.own_identifier.0 == Scalar::ZERO {
            return Err(DKGError::InvalidIdentifier);
        }

        for other_identifier in &self.others_identifiers {
            if other_identifier.0 == Scalar::ZERO {
                return Err(DKGError::InvalidIdentifier);
            }
        }

        if self.others_identifiers.len() != participants as usize - 1 {
            return Err(DKGError::IncorrectNumberOfIdentifiers {
                expected: participants as usize,
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
    use core::cmp::Ordering;

    use super::{
        derive_secret_key_from_secret, Parameters, ProofOfPossession, SecretPolynomial,
        SecretPolynomialCommitment,
    };
    use crate::polynomial::PolynomialCommitment;
    use crate::{errors::DKGResult, polynomial::Polynomial};
    use crate::{PublicKey, SecretKey};
    use curve25519_dalek::Scalar;
    use derive_getters::Getters;
    use merlin::Transcript;
    use rand_core::{CryptoRng, RngCore};

    /// The private data generated by the participant in round 1.
    #[derive(Debug, Clone, Getters)]
    pub struct PrivateData {
        pub(crate) secret_key: SecretKey,
        pub(crate) secret_polynomial: SecretPolynomial,
        //pub(crate) secret_share: SecretShare,
    }

    /// The public data generated by the participant in round 1.
    #[derive(Debug, Clone, Getters)]
    pub struct PublicData {
        pub(crate) parameters: Parameters,
        pub(crate) secret_polynomial_commitment: SecretPolynomialCommitment,
        pub(crate) proof_of_possession: ProofOfPossession,
    }

    /// Public message to be sent by the participant to all the other participants or to the coordinator in round 1.
    #[derive(Debug, Clone, Getters, PartialEq, Eq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct PublicMessage {
        pub(crate) secret_polynomial_commitment: SecretPolynomialCommitment,
        pub(crate) proof_of_possession: ProofOfPossession,
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

    impl PartialOrd for PublicMessage {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.cmp(other))
        }
    }

    impl Ord for PublicMessage {
        fn cmp(&self, other: &Self) -> Ordering {
            self.secret_polynomial_commitment
                .cmp(&other.secret_polynomial_commitment)
        }
    }

    /// Runs the round 1 of the SimplPedPoP protocol.
    pub fn run<R: RngCore + CryptoRng>(
        parameters: &Parameters,
        mut rng: R,
    ) -> DKGResult<(PrivateData, PublicMessage, PublicData)> {
        parameters.validate()?;

        let (private_data, proof_of_possession, public_data) = generate_data(parameters, &mut rng);

        let messages = generate_message(
            &proof_of_possession,
            &public_data.secret_polynomial_commitment,
        );

        Ok((private_data, messages, public_data))
    }

    fn generate_data<R: RngCore + CryptoRng>(
        parameters: &Parameters,
        mut rng: R,
    ) -> (PrivateData, ProofOfPossession, PublicData) {
        let secret_polynomial = loop {
            let temp_polynomial = Polynomial::generate(&mut rng, *parameters.threshold());
            // There must be a secret, which is the constant coefficient of the secret polynomial
            if temp_polynomial.constant_coefficient != Scalar::ZERO {
                break temp_polynomial;
            }
        };

        let secret_polynomial_commitment = PolynomialCommitment::commit(&secret_polynomial);

        // This secret key will be used to sign the proof of possession and the certificate
        let secret_key = derive_secret_key_from_secret(secret_polynomial.constant_coefficient, rng);

        let public_key = PublicKey::from_point(
            secret_polynomial_commitment
                .constant_coefficient_commitment
                .0
                .decompress()
                .unwrap(),
        );

        let proof_of_possession =
            secret_key.sign(Transcript::new(b"Proof of Possession"), &public_key);

        (
            PrivateData {
                secret_key,
                secret_polynomial,
            },
            proof_of_possession,
            PublicData {
                parameters: parameters.clone(),
                secret_polynomial_commitment,
                proof_of_possession,
            },
        )
    }

    fn generate_message(
        proof_of_possession: &ProofOfPossession,
        secret_polynomial_commitment: &SecretPolynomialCommitment,
    ) -> PublicMessage {
        PublicMessage::new(secret_polynomial_commitment.clone(), *proof_of_possession)
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
        round1, Certificate, Identifier, Parameters, Participants, SecretCommitment,
        SecretPolynomial, SecretShare,
    };
    use crate::{
        context::SigningTranscript,
        errors::{DKGError, DKGResult},
        verify_batch, PublicKey, SecretKey,
    };
    use alloc::{
        collections::{BTreeMap, BTreeSet},
        string::ToString,
        vec::Vec,
    };
    use curve25519_dalek::Scalar;
    use derive_getters::Getters;
    use merlin::Transcript;
    use sha2::{digest::Update, Digest, Sha512};
    use zeroize::ZeroizeOnDrop;

    /// The public data of round 2.
    #[derive(Debug, Clone)]
    pub struct PublicData<T: SigningTranscript + Clone> {
        pub(crate) participants: Participants,
        pub(crate) round1_public_messages: BTreeSet<round1::PublicMessage>,
        pub(crate) transcript: T,
    }

    /// The public message of round 2.
    #[derive(Debug, Clone)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct PublicMessage {
        pub(crate) certificate: Certificate,
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

    /// The messages to be sent by the participant in round 2.
    #[derive(Debug, Clone, Getters)]
    pub struct Messages {
        private_messages: BTreeMap<Identifier, PrivateMessage>,
        public_message: PublicMessage,
    }

    fn validate_messages(
        parameters: &Parameters,
        round1_public_messages: &BTreeSet<round1::PublicMessage>,
    ) -> DKGResult<()> {
        if round1_public_messages.len() != *parameters.participants() as usize - 1 {
            return Err(DKGError::IncorrectNumberOfRound1PublicMessages {
                expected: *parameters.participants() as usize - 1,
                actual: round1_public_messages.len(),
            });
        }

        Ok(())
    }

    /// Runs the round 2 of a SimplPedPoP protocol.
    pub fn run<T: SigningTranscript + Clone>(
        parameters: &Parameters,
        round1_private_data: round1::PrivateData,
        round1_public_data: &round1::PublicData,
        round1_public_messages: &BTreeSet<round1::PublicMessage>,
        transcript: T,
    ) -> DKGResult<(PublicData<T>, Messages)> {
        parameters.validate()?;

        validate_messages(parameters, round1_public_messages)?;

        verify_round1_messages(round1_public_messages)?;

        let public_data =
            generate_public_data(round1_public_messages, round1_public_data, transcript)?;

        let secret_commitment = round1_public_data
            .secret_polynomial_commitment()
            .constant_coefficient_commitment;

        let messages = generate_messages(
            &public_data,
            &round1_private_data.secret_polynomial,
            round1_private_data.secret_key,
            &secret_commitment,
        );

        Ok((public_data, messages))
    }

    fn generate_public_data<T: SigningTranscript + Clone>(
        round1_public_messages: &BTreeSet<round1::PublicMessage>,
        round1_public_data: &round1::PublicData,
        mut transcript: T,
    ) -> DKGResult<PublicData<T>> {
        let mut all_messages = round1_public_messages.clone();
        all_messages.insert(round1::PublicMessage {
            secret_polynomial_commitment: round1_public_data.secret_polynomial_commitment().clone(),
            proof_of_possession: *round1_public_data.proof_of_possession(),
        });
        // Writes the data of all the participants in the transcript ordered by their identifiers
        for message in all_messages {
            // Writes the data of the other participants in the transcript
            transcript.commit_point(
                b"SecretCommitment",
                &message
                    .secret_polynomial_commitment()
                    .constant_coefficient_commitment
                    .0,
            );

            for coefficient_commitment in &message
                .secret_polynomial_commitment()
                .non_constant_coefficients_commitments
            {
                transcript.commit_point(b"CoefficientCommitment", &coefficient_commitment.0);
            }

            transcript.commit_point(b"ProofOfPossessionR", &message.proof_of_possession().R);
        }

        let scalar = transcript.challenge_scalar(b"participants");

        let participants =
            generate_participants(round1_public_data, round1_public_messages, &scalar);

        Ok(PublicData {
            participants,
            round1_public_messages: round1_public_messages.clone(),
            transcript,
        })
    }

    fn generate_participants(
        round1_public_data: &round1::PublicData,
        round1_public_messages: &BTreeSet<round1::PublicMessage>,
        scalar: &Scalar,
    ) -> Participants {
        // Clone the messages to avoid changing the original set
        let mut messages = round1_public_messages.clone();

        // Prepare the message to be inserted
        let new_message = round1::PublicMessage {
            secret_polynomial_commitment: round1_public_data.secret_polynomial_commitment.clone(),
            proof_of_possession: round1_public_data.proof_of_possession,
        };

        // Insert the new message into the set
        messages.insert(new_message.clone());

        // Now find the index of the newly inserted message
        let mut index = 0;
        for message in &messages {
            if *message == new_message {
                // Found the message, index is the position
                break;
            }
            index += 1;
        }

        let mut others_identifiers: BTreeSet<Identifier> = BTreeSet::new();

        for i in 0..messages.len() {
            let input = Sha512::new().chain(scalar.as_bytes()).chain(i.to_string());
            let random_scalar = Scalar::from_hash(input);
            others_identifiers.insert(Identifier(random_scalar));
        }

        let own_identifier = others_identifiers.iter().nth(index).cloned(); // Retrieve the element at `index`
        own_identifier.as_ref().map(|val| {
            others_identifiers.remove(val); // Remove the element by value
            Some(val)
        });

        // Create and return the Participants struct
        Participants::new(own_identifier.unwrap(), others_identifiers)
    }

    fn verify_round1_messages(round1_messages: &BTreeSet<round1::PublicMessage>) -> DKGResult<()> {
        let mut public_keys = Vec::new();
        let mut proofs_of_possession = Vec::new();

        // The public keys are the secret commitments of the participants
        for round1_message in round1_messages {
            let public_key = PublicKey::from_point(
                round1_message
                    .secret_polynomial_commitment()
                    .constant_coefficient_commitment
                    .0
                    .decompress()
                    .unwrap(),
            );
            public_keys.push(public_key);
            proofs_of_possession.push(*round1_message.proof_of_possession());
        }

        verify_batch(
            vec![Transcript::new(b"Proof of Possession"); round1_messages.len()],
            &proofs_of_possession[..],
            &public_keys[..],
            false,
        )
        .map_err(DKGError::InvalidProofOfPossession)
    }

    fn generate_messages<T: SigningTranscript + Clone>(
        round2_public_data: &PublicData<T>,
        secret_polynomial: &SecretPolynomial,
        secret_key: SecretKey,
        secret_commitment: &SecretCommitment,
    ) -> Messages {
        let mut private_messages = BTreeMap::new();

        for identifier in &round2_public_data.participants.others_identifiers {
            let secret_share = secret_polynomial.evaluate(&identifier.0);
            private_messages.insert(*identifier, PrivateMessage::new(SecretShare(secret_share)));
        }

        let public_key = PublicKey::from_point(secret_commitment.0.decompress().unwrap());

        let certificate = secret_key.sign(round2_public_data.transcript.clone(), &public_key);

        let public_message = PublicMessage { certificate };

        Messages {
            private_messages,
            public_message,
        }
    }
}

/// SimplPedPoP round 3.
///
/// The participant verifies the certificates from all the other participants and generates the shared public
/// key and the total secret shares commitments of the other partipants.
pub mod round3 {
    use super::{
        round1, round2, Certificate, GroupPublicKey, GroupPublicKeyShare, Identifier, Parameters,
        Participants, SecretPolynomial, SecretShare, TotalSecretShare, GENERATOR,
    };
    use crate::{
        context::SigningTranscript,
        errors::{DKGError, DKGResult},
        polynomial::PolynomialCommitment,
        verify_batch, PublicKey,
    };
    use alloc::{
        collections::{BTreeMap, BTreeSet},
        vec::Vec,
    };
    use curve25519_dalek::Scalar;
    use zeroize::ZeroizeOnDrop;

    /// The private data of round 3.
    #[derive(Debug, Clone, ZeroizeOnDrop)]
    pub struct PrivateData {
        pub(crate) total_secret_share: TotalSecretShare,
    }

    fn validate_messages(
        parameters: &Parameters,
        round2_public_messages: &BTreeMap<Identifier, round2::PublicMessage>,
        round1_public_messages: &BTreeSet<round1::PublicMessage>,
    ) -> DKGResult<()> {
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

        Ok(())
    }

    /// Runs the round 3 of the SimplPedPoP protocol.
    pub fn run<T: SigningTranscript + Clone>(
        round2_public_messages: &BTreeMap<Identifier, round2::PublicMessage>,
        round2_public_data: &round2::PublicData<T>,
        round1_public_data: &round1::PublicData,
        round1_private_data: round1::PrivateData,
        round2_private_messages: BTreeMap<Identifier, round2::PrivateMessage>,
    ) -> DKGResult<(
        GroupPublicKey,
        BTreeMap<Identifier, GroupPublicKeyShare>,
        PrivateData,
    )> {
        round1_public_data.parameters.validate()?;

        round2_public_data
            .participants
            .validate(round1_public_data.parameters.participants)?;

        validate_messages(
            &round1_public_data.parameters,
            round2_public_messages,
            &round2_public_data.round1_public_messages,
        )?;

        verify_round2_public_messages(
            &round2_public_data.participants,
            &round2_public_data.round1_public_messages,
            round2_public_messages,
            round2_public_data,
        )?;

        verify_round2_private_messages(
            &round2_public_data.participants,
            &round2_public_data.round1_public_messages,
            &round2_private_messages,
        )?;

        let private_data = generate_private_data(
            &round2_public_data.participants,
            &round2_private_messages,
            &round1_private_data.secret_polynomial,
        )?;

        let (group_public_key, group_public_key_shares) = generate_public_data(
            &round2_public_data.participants,
            &round2_public_data.round1_public_messages,
            round1_public_data,
        )?;

        Ok((group_public_key, group_public_key_shares, private_data))
    }

    fn verify_round2_public_messages<T: SigningTranscript + Clone>(
        participants: &Participants,
        round1_public_messages: &BTreeSet<round1::PublicMessage>,
        round2_public_messages: &BTreeMap<Identifier, round2::PublicMessage>,
        round2_public_data: &round2::PublicData<T>,
    ) -> DKGResult<()> {
        let mut public_keys = Vec::new();

        // The public keys are the secret commitments of the participants
        for round1_public_message in round1_public_messages {
            let public_key = PublicKey::from_point(
                round1_public_message
                    .secret_polynomial_commitment()
                    .constant_coefficient_commitment
                    .0
                    .decompress()
                    .unwrap(),
            );
            public_keys.push(public_key);
        }

        verify_batch(
            vec![round2_public_data.transcript.clone(); participants.others_identifiers().len()],
            &round2_public_messages
                .values()
                .map(|x| x.certificate)
                .collect::<Vec<Certificate>>(),
            &public_keys[..],
            false,
        )
        .map_err(DKGError::InvalidCertificate)
    }

    fn verify_round2_private_messages(
        participants: &Participants,
        round1_public_messages: &BTreeSet<round1::PublicMessage>,
        round2_private_messages: &BTreeMap<Identifier, round2::PrivateMessage>,
    ) -> DKGResult<()> {
        let round1_public_messages: Vec<round1::PublicMessage> =
            round1_public_messages.iter().cloned().collect();

        for (i, (identifier, private_message)) in round2_private_messages.iter().enumerate() {
            let expected_evaluation = GENERATOR * private_message.secret_share().0;

            let evaluation = round1_public_messages[i]
                .secret_polynomial_commitment()
                .evaluate(&participants.own_identifier().0)
                .0
                .decompress()
                .unwrap();

            if !(evaluation == expected_evaluation) {
                return Err(DKGError::InvalidSecretShare(*identifier));
            }
        }

        Ok(())
    }

    fn generate_private_data(
        participants: &Participants,
        private_messages: &BTreeMap<Identifier, round2::PrivateMessage>,
        secret_polynomial: &SecretPolynomial,
    ) -> DKGResult<PrivateData> {
        let own_secret_share = secret_polynomial.evaluate(&participants.own_identifier().0);

        let mut total_secret_share = Scalar::ZERO;

        for id in participants.others_identifiers() {
            total_secret_share += private_messages
                .get(id)
                .ok_or(DKGError::UnknownIdentifier)?
                .secret_share()
                .0;
        }

        total_secret_share += own_secret_share;

        let private_data = PrivateData {
            total_secret_share: SecretShare(total_secret_share),
        };

        Ok(private_data)
    }

    fn generate_public_data(
        participants: &Participants,
        round1_public_messages: &BTreeSet<round1::PublicMessage>,
        round1_public_data: &round1::PublicData,
    ) -> DKGResult<(GroupPublicKey, BTreeMap<Identifier, GroupPublicKeyShare>)> {
        // Sum of the secret polynomial commitments of the other participants
        let others_secret_polynomial_commitment = PolynomialCommitment::sum_polynomial_commitments(
            &round1_public_messages
                .iter()
                .map(|msg| msg.secret_polynomial_commitment())
                .collect::<Vec<&PolynomialCommitment>>(),
        );

        // The total secret polynomial commitment, which includes the secret polynomial commitment of the participant
        let total_secret_polynomial_commitment =
            PolynomialCommitment::sum_polynomial_commitments(&[
                &others_secret_polynomial_commitment,
                &round1_public_data.secret_polynomial_commitment,
            ]);

        // The group public key shares of all the participants, which correspond to the total secret shares commitments
        let mut group_public_key_shares = BTreeMap::new();

        for identifier in participants.others_identifiers() {
            let group_public_key_share = total_secret_polynomial_commitment.evaluate(&identifier.0);

            group_public_key_shares.insert(*identifier, group_public_key_share);
        }

        let own_group_public_key_share =
            total_secret_polynomial_commitment.evaluate(&participants.own_identifier.0);

        group_public_key_shares.insert(participants.own_identifier, own_group_public_key_share);

        let shared_public_key = GroupPublicKey::from_point(
            total_secret_polynomial_commitment
                .constant_coefficient_commitment
                .0
                .decompress()
                .unwrap(),
        );

        // The shared public key corresponds to the secret commitment of the total secret polynomial commitment
        if shared_public_key.as_point()
            != &total_secret_polynomial_commitment
                .evaluate(&Scalar::ZERO)
                .0
                .decompress()
                .unwrap()
        {
            return Err(DKGError::SharedPublicKeyMismatch);
        }

        Ok((shared_public_key, group_public_key_shares))
    }
}

#[cfg(test)]
mod tests {
    use self::{
        round1::{PrivateData, PublicData},
        round2::Messages,
    };
    use super::*;
    #[cfg(feature = "alloc")]
    use alloc::{
        collections::{BTreeMap, BTreeSet},
        vec::Vec,
    };
    use merlin::Transcript;
    use rand::rngs::OsRng;
    use tests::round1::PublicMessage;

    fn generate_parameters(max_signers: u16, min_signers: u16) -> Vec<Parameters> {
        (1..=max_signers)
            .map(|_| Parameters::new(max_signers, min_signers))
            .collect()
    }

    fn round1(
        participants: u16,
        threshold: u16,
    ) -> (
        Vec<Parameters>,
        Vec<PrivateData>,
        Vec<PublicData>,
        Vec<BTreeSet<PublicMessage>>,
    ) {
        let parameters_list = generate_parameters(participants, threshold);

        let mut all_public_messages_vec = Vec::new();
        let mut participants_round1_private_data = Vec::new();
        let mut participants_round1_public_data = Vec::new();

        for i in 0..parameters_list.len() {
            let (private_data, public_message, public_data) =
                round1::run(&parameters_list[i as usize], OsRng)
                    .expect("Round 1 should complete without errors!");

            all_public_messages_vec.push(public_message.clone());
            participants_round1_public_data.push(public_data);
            participants_round1_private_data.push(private_data);
        }

        let mut received_round1_public_messages: Vec<BTreeSet<PublicMessage>> = Vec::new();

        let mut all_public_messages = BTreeSet::new();

        for i in 0..participants {
            all_public_messages.insert(all_public_messages_vec[i as usize].clone());
        }

        // Iterate through each participant to create a set of messages excluding their own.
        for i in 0..participants as usize {
            let own_message = PublicMessage::new(
                participants_round1_public_data[i]
                    .secret_polynomial_commitment
                    .clone(),
                participants_round1_public_data[i]
                    .proof_of_possession
                    .clone(),
            );

            let mut messages_for_participant = BTreeSet::new();

            for message in &all_public_messages {
                if &own_message != message {
                    // Exclude the participant's own message.
                    messages_for_participant.insert(message.clone());
                }
            }

            received_round1_public_messages.push(messages_for_participant);
        }

        (
            parameters_list,
            participants_round1_private_data,
            participants_round1_public_data,
            received_round1_public_messages,
        )
    }

    fn round2(
        parameters_list: &Vec<Parameters>,
        participants_round1_private_data: Vec<PrivateData>,
        participants_round1_public_data: &Vec<PublicData>,
        participants_round1_public_messages: &Vec<BTreeSet<PublicMessage>>,
    ) -> (
        Vec<round2::PublicData<Transcript>>,
        Vec<Messages>,
        Vec<Participants>,
        Vec<Identifier>,
    ) {
        let mut participants_round2_public_data = Vec::new();
        let mut participants_round2_public_messages = Vec::new();
        let mut participants_set_of_participants = Vec::new();
        let mut identifiers_vec = Vec::new();

        for i in 0..parameters_list[0].participants {
            let result = round2::run(
                &parameters_list[i as usize],
                participants_round1_private_data[i as usize].clone(),
                &participants_round1_public_data[i as usize].clone(),
                &participants_round1_public_messages[i as usize].clone(),
                Transcript::new(b"transcript"),
            )
            .expect("Round 2 should complete without errors!");

            participants_round2_public_data.push(result.0.clone());
            participants_round2_public_messages.push(result.1);
            participants_set_of_participants.push(result.0.participants.clone());
            identifiers_vec.push(result.0.participants.own_identifier);
        }

        (
            participants_round2_public_data,
            participants_round2_public_messages,
            participants_set_of_participants,
            identifiers_vec,
        )
    }

    fn round3(
        participants_sets_of_participants: &Vec<Participants>,
        participants_round2_public_messages: &Vec<round2::PublicMessage>,
        participants_round2_public_data: &Vec<round2::PublicData<Transcript>>,
        participants_round1_public_data: &Vec<round1::PublicData>,
        participants_round1_private_data: Vec<round1::PrivateData>,
        participants_round2_private_messages: Vec<BTreeMap<Identifier, round2::PrivateMessage>>,
        identifiers_vec: &Vec<Identifier>,
    ) -> Vec<(
        GroupPublicKey,
        BTreeMap<Identifier, GroupPublicKeyShare>,
        round3::PrivateData,
    )> {
        let mut participant_data_round3 = Vec::new();

        for i in 0..participants_sets_of_participants.len() {
            let received_round2_public_messages = participants_round2_public_messages
                .iter()
                .enumerate()
                .filter(|(index, _msg)| {
                    identifiers_vec[*index]
                        != *participants_sets_of_participants[i as usize].own_identifier()
                })
                .map(|(index, msg)| (identifiers_vec[index], msg.clone()))
                .collect::<BTreeMap<Identifier, round2::PublicMessage>>();

            let mut collected_messages: Vec<BTreeMap<Identifier, round2::PrivateMessage>> =
                Vec::new();

            for participants in participants_sets_of_participants.iter() {
                let mut messages_for_participant = BTreeMap::new();

                for (i, round_messages) in participants_round2_private_messages.iter().enumerate() {
                    if let Some(message) = round_messages.get(&participants.own_identifier) {
                        messages_for_participant.insert(identifiers_vec[i], message.clone());
                    }
                }

                if !messages_for_participant.is_empty() {
                    collected_messages.push(messages_for_participant);
                }
            }

            let result = round3::run(
                &received_round2_public_messages,
                &participants_round2_public_data[i as usize],
                &participants_round1_public_data[i as usize],
                participants_round1_private_data[i as usize].clone(),
                collected_messages[i as usize].clone(),
            )
            .expect("Round 3 should complete without errors!");

            participant_data_round3.push(result);
        }

        participant_data_round3
    }

    #[test]
    pub fn test_successful_simplpedpop() {
        let participants: u16 = 3;
        let threshold: u16 = 2;

        let (
            parameters_list,
            participants_round1_private_data,
            participants_round1_public_data,
            participants_round1_public_messages,
        ) = round1(participants, threshold);

        let (
            participants_round2_public_data,
            participants_round2_messages,
            participants_sets_of_participants,
            identifiers_vec,
        ) = round2(
            &parameters_list,
            participants_round1_private_data.clone(),
            &participants_round1_public_data,
            &participants_round1_public_messages,
        );

        let participants_data_round3 = round3(
            &participants_sets_of_participants,
            &participants_round2_messages
                .iter()
                .map(|x| x.public_message().clone())
                .collect(),
            &participants_round2_public_data,
            &participants_round1_public_data,
            participants_round1_private_data,
            participants_round2_messages
                .iter()
                .map(|x| x.private_messages().clone())
                .collect(),
            &identifiers_vec,
        );

        let shared_public_keys: Vec<GroupPublicKey> = participants_data_round3
            .iter()
            .map(|state| state.0)
            .collect();

        assert!(
            shared_public_keys.windows(2).all(|w| w[0] == w[1]),
            "All participants must have the same group public key!"
        );

        for i in 0..participants {
            assert_eq!(
                participants_data_round3[i as usize]
                    .1
                    .get(participants_sets_of_participants[i as usize].own_identifier())
                    .unwrap()
                    .0
                    .decompress()
                    .unwrap(),
                participants_data_round3[i as usize].2.total_secret_share.0 * GENERATOR,
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
        ) = round1(participants, threshold);

        participants_round1_public_messages[0].pop_last();

        let result = round2::run(
            &parameters_list[0],
            participants_round1_private_data[0].clone(),
            &participants_round1_public_data[0],
            &participants_round1_public_messages[0],
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

    /*#[test]
    fn test_missing_public_message_in_round2() {
        let participants: u16 = 5;
        let threshold: u16 = 3;

        let (
            parameters_list,
            participants_round1_private_data,
            participants_round1_public_data,
            mut participants_round1_public_messages,
        ) = round1(participants, threshold);

        let mut public_message = participants_round1_public_messages[0]
            .first()
            .unwrap()
            .clone();
        public_message.secret_polynomial_commitment =
            PolynomialCommitment::commit(&SecretPolynomial::generate(&mut OsRng, threshold));
        participants_round1_public_messages[0].pop_last();
        participants_round1_public_messages[0].insert(public_message.clone());

        let result = round2::run(
            &parameters_list[0],
            participants_round1_private_data[0].clone(),
            &participants_round1_public_data[0],
            &participants_round1_public_messages[0],
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
        }*/
}
