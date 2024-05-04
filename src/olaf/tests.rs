#[cfg(test)]
mod tests {
    use crate::olaf::data_structures::{
        AllMessage, DKGOutput, DKGOutputContent, MessageContent, Parameters,
    };
    use crate::{Keypair, PublicKey};
    use alloc::vec::Vec;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::scalar::Scalar;
    use merlin::Transcript;
    use rand::rngs::OsRng;

    #[test]
    fn test_simplpedpop_protocol() {
        // Create participants
        let threshold = 2;
        let participants = 3;
        let keypairs: Vec<Keypair> = (0..participants).map(|_| Keypair::generate()).collect();
        let public_keys: Vec<PublicKey> = keypairs.iter().map(|kp| kp.public).collect();

        // Each participant creates an AllMessage
        let mut all_messages = Vec::new();
        for i in 0..participants {
            let message: AllMessage =
                keypairs[i].simplpedpop_contribute_all(threshold, public_keys.clone()).unwrap();
            all_messages.push(message);
        }

        let mut dkg_outputs = Vec::new();

        let kp = &keypairs[0];

        for _ in keypairs.iter() {
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
    fn test_serialize_deserialize_all_message() {
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
    fn test_encrypt_decrypt_secret_share() {
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
