macro_rules! make_tests {
    () => {
        #[cfg(test)]
        mod common_test {
            use std::ops::Deref as _;

            #[test]
            fn encrypt_decrypt() {
                let mut rng = rand_dev::DevRng::new();
                let key = super::PrivateKey::generate(&mut rng);
                let pubkey = key.public_key();

                let original_message = {
                    let mut bytes = vec![0u8; 1337];
                    rand_core::RngCore::fill_bytes(&mut rng, &mut bytes);
                    bytes
                };

                let mut encrypted_bytes;
                let encrypted_message = {
                    encrypted_bytes = original_message.clone();
                    pubkey
                        .encrypt_in_place(&mut encrypted_bytes, &mut rng)
                        .unwrap()
                };

                let mut decrypted_bytes;
                let decrypted_message = {
                    decrypted_bytes = encrypted_message.message.to_vec();
                    let message = super::EncryptedMessage {
                        ephemeral_key: encrypted_message.ephemeral_key,
                        message: &mut decrypted_bytes,
                        tag: encrypted_message.tag,
                    };
                    key.decrypt_in_place(message).unwrap()
                };

                assert_eq!(original_message, decrypted_message);
            }

            #[test]
            fn message_encode() {
                let mut rng = rand_dev::DevRng::new();

                let ephemeral_key = generic_ec::Point::generator()
                    * generic_ec::NonZero::<generic_ec::Scalar<super::E>>::random(&mut rng);
                let mut message = [0u8; 322];
                rand_core::RngCore::fill_bytes(&mut rng, &mut message);
                let mut tag = cipher::generic_array::GenericArray::<
                    u8,
                    <super::Mac as digest::OutputSizeUser>::OutputSize,
                >::default();
                rand_core::RngCore::fill_bytes(&mut rng, &mut tag);

                let message = super::EncryptedMessage {
                    ephemeral_key,
                    message: &mut message,
                    tag,
                };
                let mut message_bytes = message.to_bytes();
                let restored = super::EncryptedMessage::from_bytes(&mut message_bytes).unwrap();
                assert_eq!(message, restored);
            }

            #[test]
            fn encrypt_decrypt_inplace_ornot() {
                let mut rng = rand_dev::DevRng::new();
                let key = super::PrivateKey::generate(&mut rng);
                let pubkey = key.public_key();

                let mut bytes = vec![0u8; 1337];
                rand_core::RngCore::fill_bytes(&mut rng, &mut bytes);
                let original = bytes.clone();

                let mut encrypted = pubkey.encrypt(&bytes, &mut rng.clone()).unwrap();
                let encrypted_ = pubkey
                    .encrypt_in_place(&mut bytes, &mut rng)
                    .unwrap()
                    .to_bytes();
                assert_eq!(encrypted, encrypted_);

                let encrypted = super::EncryptedMessage::from_bytes(&mut encrypted).unwrap();
                let decrypted = key.decrypt(&encrypted).unwrap();
                let decrypted_ = key.decrypt_in_place(encrypted).unwrap();
                assert_eq!(decrypted_, decrypted);
                assert_eq!(original, decrypted);
            }

            #[test]
            fn key_encode() {
                let mut rng = rand_dev::DevRng::new();

                let key = super::PrivateKey::generate(&mut rng);
                let key_bytes = key.to_bytes();
                let key_ = super::PrivateKey::from_bytes(&key_bytes).unwrap();
                assert_eq!(key.scalar.deref().as_ref(), key_.scalar.deref().as_ref());

                let pubkey = key.public_key();
                let key_bytes = pubkey.to_bytes();
                let pubkey_ = super::PublicKey::from_bytes(&key_bytes).unwrap();
                assert_eq!(pubkey, pubkey_);
            }
        }
    }
}
pub(crate) use make_tests;
