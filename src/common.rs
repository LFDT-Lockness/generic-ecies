#[cfg(feature = "curve-ed25519")]
impl<S> crate::PrivateKey<S>
where
    S: crate::Suite<E = generic_ec::curves::Ed25519>,
{
    /// Since eddsa secret key is not a scalar, and most tools that call
    /// themselves ed25519 are actually eddsa, we need to convert from eddsa key
    /// to a scalar.
    ///
    /// Returns `None` if the bytes hash to zero (this has a vanishing
    /// probability of occuring)
    pub fn from_eddsa_pkey_bytes(bytes: &[u8; 32]) -> Option<Self> {
        use sha2::Digest as _;
        let scalar_bytes = sha2::Sha512::new().chain_update(bytes).finalize();
        let mut scalar_bytes = zeroize::Zeroizing::<[u8; 64]>::new(scalar_bytes.into());
        let scalar_bytes = &mut scalar_bytes[0..32];

        // The lowest three bits of the first octet are cleared
        scalar_bytes[0] &= 0b1111_1000;
        // the highest bit of the last octet is cleared
        scalar_bytes[31] &= 0b0111_1111;
        // and the second highest bit of the last octet is set
        scalar_bytes[31] |= 0b0100_0000;

        let mut scalar = generic_ec::Scalar::<generic_ec::curves::Ed25519>::from_le_bytes_mod_order(
            scalar_bytes,
        );
        let scalar = generic_ec::SecretScalar::new(&mut scalar);
        let scalar =
            generic_ec::NonZero::<generic_ec::SecretScalar<generic_ec::curves::Ed25519>>::try_from(
                scalar,
            )
            .ok()?;
        Some(Self { scalar })
    }
}

macro_rules! make_tests {
    ($specific_tests:tt) => {
        #[cfg(test)]
        mod common_test {
            use std::ops::Deref as _;
            type E = <super::S as crate::Suite>::E;

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

                let mut encrypted_message = pubkey.encrypt(&original_message, &mut rng).unwrap();

                let parsed_message =
                    super::EncryptedMessage::from_bytes(&mut encrypted_message).unwrap();
                let decrypted_message = key.decrypt_in_place(parsed_message).unwrap();

                assert_eq!(original_message, decrypted_message);
            }

            #[test]
            fn message_encode() {
                let mut rng = rand_dev::DevRng::new();

                let ephemeral_key = generic_ec::Point::generator()
                    * generic_ec::NonZero::<generic_ec::Scalar<E>>::random(&mut rng);
                let mut message = [0u8; 322];
                rand_core::RngCore::fill_bytes(&mut rng, &mut message);
                let mut tag =
                    cipher::generic_array::GenericArray::<u8, crate::MacSize<super::S>>::default();
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

            internal_make_specific_tests!($specific_tests);
        }
    };
}
pub(crate) use make_tests;

#[cfg(test)]
macro_rules! internal_make_specific_tests {
    ("stream") => {
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
    };
    ("block") => {
        #[test]
        fn encrypt_decrypt_inplace_ornot() {
            let mut rng = rand_dev::DevRng::new();
            let key = super::PrivateKey::generate(&mut rng);
            let pubkey = key.public_key();

            let mut bytes = vec![0u8; 1337];
            rand_core::RngCore::fill_bytes(&mut rng, &mut bytes);
            let original = bytes.clone();

            let mut encrypted = pubkey.encrypt(&bytes, &mut rng.clone()).unwrap();

            let size_with_pad = bytes.len() + crate::pad_size::<super::S>(bytes.len());
            bytes.resize(size_with_pad, 0);
            let encrypted_ = pubkey
                .encrypt_in_place(&mut bytes, original.len(), &mut rng)
                .unwrap()
                .to_bytes();

            assert_eq!(encrypted, encrypted_);

            let encrypted = super::EncryptedMessage::from_bytes(&mut encrypted).unwrap();
            let decrypted = key.decrypt(&encrypted).unwrap();
            let decrypted_ = key.decrypt_in_place(encrypted).unwrap();
            assert_eq!(decrypted_, decrypted);
            assert_eq!(original, decrypted);
        }
    };
    ($($_:tt)*) => {
        compile_error!("make_tests! macro only supports \"block\" and \"stream\" parameters");
    };
}
