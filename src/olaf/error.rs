//! Errors of the Olaf protocol.

use super::Identifier;
use crate::SignatureError;

/// A result for the SimplPedPoP protocol.
pub type DKGResult<T> = Result<T, DKGError>;

/// An error ocurred during the execution of the SimplPedPoP protocol.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum DKGError {
    /// Invalid Proof of Possession.
    InvalidProofOfPossession(SignatureError),
    /// Invalid certificate.
    InvalidCertificate(SignatureError),
    /// Threshold cannot be greater than the number of participants.
    ExcessiveThreshold,
    /// Threshold must be at least 2.
    InsufficientThreshold,
    /// Number of participants is invalid.
    InvalidNumberOfParticipants,
    /// Secret share verification failed.
    InvalidSecretShare(Identifier),
    /// Invalid secret.
    InvalidSecret,
    /// Unknown identifier in round 2 public messages.
    UnknownIdentifierRound2PublicMessages(Identifier),
    /// Unknown identifier in round 2 private messages.
    UnknownIdentifierRound2PrivateMessages(Identifier),
    /// Shared public key mismatch.
    SharedPublicKeyMismatch,
    /// Identifier cannot be a zero scalar.
    InvalidIdentifier,
    /// Incorrect number of identifiers.
    IncorrectNumberOfIdentifiers {
        /// The expected value.
        expected: usize,
        /// The actual value.
        actual: usize,
    },
    /// Incorrect number of private messages.
    IncorrectNumberOfPrivateMessages {
        /// The expected value.
        expected: usize,
        /// The actual value.
        actual: usize,
    },
    /// Incorrect number of round 1 public messages.
    IncorrectNumberOfRound1PublicMessages {
        /// The expected value.
        expected: usize,
        /// The actual value.
        actual: usize,
    },
    /// Incorrect number of round 2 public messages.
    IncorrectNumberOfRound2PublicMessages {
        /// The expected value.
        expected: usize,
        /// The actual value.
        actual: usize,
    },
    /// Incorrect number of round 2 private messages.
    IncorrectNumberOfRound2PrivateMessages {
        /// The expected value.
        expected: usize,
        /// The actual value.
        actual: usize,
    },
    /// Decryption error when decrypting an encrypted secret share.
    DecryptionError(chacha20poly1305::Error),
    /// Incorrect number of coefficient commitments.
    InvalidSecretPolynomialCommitment {
        /// The expected value.
        expected: usize,
        /// The actual value.
        actual: usize,
    },
}

/// A result for the FROST protocol.
pub type FROSTResult<T> = Result<T, FROSTError>;

/// An error ocurred during the execution of the FROST protocol
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum FROSTError {
    /// Signature share verification failed.
    InvalidSignatureShare {
        /// The identifier of the signer whose share validation failed.
        culprit: Identifier,
    },
    /// Incorrect number of signing commitments.
    IncorrectNumberOfSigningCommitments,
    /// The participant's signing commitment is missing from the Signing Package
    MissingSigningCommitment,
    /// The participant's signing commitment is incorrect
    IncorrectSigningCommitment,
    /// This identifier does not belong to a participant in the signing process.
    UnknownIdentifier,
    /// Commitment equals the identity
    IdentitySigningCommitment,
    /// Incorrect number of identifiers.
    IncorrectNumberOfIdentifiers,
    /// Signature verification failed.
    InvalidSignature,
    /// This identifier is duplicated.
    DuplicatedIdentifier,
}
