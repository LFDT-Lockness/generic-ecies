pub type E = generic_ec::curves::Ed25519;
pub type Mac = hmac::Hmac<sha2::Sha256>;
pub type Enc = salsa20::XSalsa20;

pub type PrivateKey = crate::PrivateKey<E>;
pub type PublicKey = crate::PublicKey<E>;
pub type EncryptedMessage<'m> = crate::EncryptedMessage<'m, Mac, E>;

impl PublicKey {
    pub fn encrypt_in_place<'m>(
        &self,
        message: &'m mut [u8],
        rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
    ) -> Result<EncryptedMessage<'m>, crate::EncError> {
        self.stream_encrypt_in_place::<Mac, Enc>(message, rng)
    }
}

impl PrivateKey {
    pub fn decrypt_in_place<'m>(
        &self,
        message: EncryptedMessage<'m>,
    ) -> Result<&'m mut [u8], crate::DecError> {
        self.stream_decrypt_in_place::<Mac, Enc>(message)
    }
}

#[cfg(test)]
mod test {
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
                ephemeral_key: encrypted_message.ephemeral_key.clone(),
                message: &mut decrypted_bytes,
                tag: encrypted_message.tag.clone(),
            };
            key.decrypt_in_place(message).unwrap()
        };

        assert_eq!(original_message, decrypted_message);
    }

    #[test]
    fn message_encode() {
        let mut rng = rand_dev::DevRng::new();

        let ephemeral_key =
            generic_ec::Point::<super::E>::generator() * generic_ec::Scalar::random(&mut rng);
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
    fn key_encode() {
        let mut rng = rand_dev::DevRng::new();

        let key = super::PrivateKey::generate(&mut rng);
        let key_bytes = key.to_bytes();
        let key_ = super::PrivateKey::from_bytes(&key_bytes).unwrap();
        assert_eq!(key.scalar.as_ref(), key_.scalar.as_ref());

        let pubkey = key.public_key();
        let key_bytes = pubkey.to_bytes();
        let pubkey_ = super::PublicKey::from_bytes(&key_bytes).unwrap();
        assert_eq!(pubkey, pubkey_);
    }
}
