#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct S;

impl super::Suite for S {
    type E = generic_ec::curves::Ed25519;
    type Mac = hmac::Hmac<sha2::Sha256>;
    type Enc = cbc::Encryptor<aes::Aes128>;
    type Dec = cbc::Decryptor<aes::Aes128>;
}

pub type PrivateKey = crate::PrivateKey<S>;
pub type PublicKey = crate::PublicKey<S>;
pub type EncryptedMessage<'m> = crate::EncryptedMessage<'m, S>;

impl PublicKey {
    pub fn encrypt_in_place<'m>(
        &self,
        message: &'m mut [u8],
        data_len: usize,
        rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
    ) -> Result<EncryptedMessage<'m>, crate::EncError> {
        self.block_encrypt_in_place(message, data_len, rng)
    }

    pub fn encrypt(
        &self,
        message: &[u8],
        rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
    ) -> Result<Vec<u8>, crate::EncError> {
        self.block_encrypt(message, rng)
    }
}

impl PrivateKey {
    pub fn decrypt_in_place<'m>(
        &self,
        message: EncryptedMessage<'m>,
    ) -> Result<&'m mut [u8], crate::DecError> {
        self.block_decrypt_in_place(message)
    }

    pub fn decrypt(&self, message: &EncryptedMessage<'_>) -> Result<Vec<u8>, crate::DecError> {
        self.block_decrypt(message)
    }
}

crate::common::make_tests!("block");
