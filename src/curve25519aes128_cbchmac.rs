pub type E = generic_ec::curves::Ed25519;
pub type Mac = hmac::Hmac<sha2::Sha256>;
pub type Enc = cbc::Encryptor<aes::Aes128>;
pub type Dec = cbc::Decryptor<aes::Aes128>;

pub type PrivateKey = crate::PrivateKey<E>;
pub type PublicKey = crate::PublicKey<E>;
pub type EncryptedMessage<'m> = crate::EncryptedMessage<'m, Mac, E>;

impl PublicKey {
    pub fn encrypt_in_place<'m>(
        &self,
        message: &'m mut [u8],
        rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
    ) -> Result<EncryptedMessage<'m>, crate::EncError> {
        self.block_encrypt_in_place::<Mac, Enc>(message, rng)
    }

    pub fn encrypt(
        &self,
        message: &[u8],
        rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
    ) -> Result<Vec<u8>, crate::EncError> {
        self.stream_encrypt::<Mac, Enc>(message, rng)
    }
}

/*
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
}
*/

crate::common::make_tests!();
