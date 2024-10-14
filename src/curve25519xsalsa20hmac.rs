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

    pub fn encrypt(
        &self,
        message: &[u8],
        rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
    ) -> Result<Vec<u8>, crate::EncError> {
        self.stream_encrypt::<Mac, Enc>(message, rng)
    }
}

impl PrivateKey {
    pub fn decrypt_in_place<'m>(
        &self,
        message: EncryptedMessage<'m>,
    ) -> Result<&'m mut [u8], crate::DecError> {
        self.stream_decrypt_in_place::<Mac, Enc>(message)
    }

    pub fn decrypt(&self, message: &EncryptedMessage<'_>) -> Result<Vec<u8>, crate::DecError> {
        self.stream_decrypt::<Mac, Enc>(message)
    }

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

        let mut scalar = generic_ec::Scalar::<E>::from_le_bytes_mod_order(scalar_bytes);
        let scalar = generic_ec::SecretScalar::new(&mut scalar);
        let scalar = generic_ec::NonZero::<generic_ec::SecretScalar<E>>::try_from(scalar).ok()?;
        Some(Self { scalar })
    }
}

crate::common::make_tests!();
#[cfg(test)]
mod test {
    #[test]
    fn openssl_key() {
        // This key is obtained from openssl by
        // `openssl genpkey -algorithm ed25519 -out ed25519key.pem`
        // And converted from pem to hex by
        // `openssl pkey -in backup_key.pem -text -noout | grep -E '^priv:$' -A3 | tail -n +2 | tr -d ' :\n'`
        let key_bytes =
            hex::decode("eaec3fecf6d988cd8a51bbfba5d5a310d1887459f8433fa0a17fc09f34ee77a4")
                .unwrap();
        // Public key is obtained by `openssl pkey -in ed25519key.pem -pubout`
        // And then converted to hex in a similar way
        // `openssl pkey -pubin -in ed25519.pub -text -noout | grep -E '^pub:$' -A3 | tail -n +2 | tr -d ' :\n'`
        let pubkey_bytes =
            hex::decode("d24f3652e2100524d31ae794e781c4cd0b4f53e2bb02665b85f9c71d5e80ab69")
                .unwrap();
        // Would be a good idea to generate them on the fly with openssl, but it's
        // not available in all distributions by default, for example on macos

        let pubkey = super::PublicKey::from_bytes(pubkey_bytes).unwrap();
        let key =
            super::PrivateKey::from_eddsa_pkey_bytes(key_bytes[0..32].try_into().unwrap()).unwrap();
        assert_eq!(key.public_key(), pubkey);
    }

    #[test]
    fn compat() {
        // Sadly we already use this in production to encrypt data for long-term
        // storage, and unless something breaking is discovered, we need to be
        // able to still decrypt the data we encrypted at the old revision of
        // this library. (If something is discovered though, we'll have to make
        // a breaking change and use an old compat version for decrypting, which
        // would be extremely inconvenient)

        let key_bytes =
            hex::decode("eaec3fecf6d988cd8a51bbfba5d5a310d1887459f8433fa0a17fc09f34ee77a4")
                .unwrap();
        let key =
            super::PrivateKey::from_eddsa_pkey_bytes(key_bytes[0..32].try_into().unwrap()).unwrap();

        let plaintext = b"Look at this very important data, I hope nothing happens to it.";
        let mut ciphertext = [
            92, 192, 226, 249, 116, 180, 153, 152, 175, 76, 239, 137, 146, 108, 44, 37, 235, 153,
            93, 214, 162, 184, 139, 81, 116, 9, 222, 126, 28, 56, 67, 115, 240, 125, 224, 21, 125,
            74, 130, 14, 122, 74, 148, 102, 17, 64, 196, 16, 37, 118, 97, 118, 106, 77, 244, 187,
            167, 116, 82, 230, 180, 88, 165, 33, 235, 106, 231, 254, 195, 15, 223, 88, 182, 9, 47,
            197, 182, 25, 47, 55, 238, 79, 132, 141, 236, 27, 95, 59, 91, 226, 208, 222, 159, 8,
            53, 105, 82, 6, 253, 206, 83, 2, 191, 72, 8, 194, 112, 92, 18, 54, 131, 20, 34, 228,
            195, 79, 169, 25, 246, 176, 181, 143, 5, 172, 230, 96, 53,
        ];
        let message = super::EncryptedMessage::from_bytes(&mut ciphertext).unwrap();
        let decrypted = key.decrypt_in_place(message).unwrap();
        assert_eq!(plaintext, decrypted);
    }
}
