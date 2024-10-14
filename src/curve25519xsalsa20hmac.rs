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

        let pubkey = super::PublicKey::from_bytes(pubkey_bytes).unwrap();
        let key =
            super::PrivateKey::from_eddsa_pkey_bytes(key_bytes[0..32].try_into().unwrap()).unwrap();
        assert_eq!(key.public_key(), pubkey);
    }
}
