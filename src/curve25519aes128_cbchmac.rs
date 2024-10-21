//! Instantiation of ECIES with the following parameters:
//!
//! * Curve25519 as the elliptic curve
//! * AES128 in CBC mode as the symmetric cipher
//! * HMAC-SHA256 as the message authentication code
//!
//! ## Example of usage
//! ```rust
//! # let mut rng = rand_dev::DevRng::new();
//! use generic_ecies::curve25519aes128_cbchmac as ecies;
//! // Use EdDSA key as openssl generates it instead of Curve25519 private scalar
//! let eddsa_private_key_bytes = b"eddsa priv key is any 32 bytes^^";
//! let private_key = ecies::PrivateKey::from_eddsa_pkey_bytes(eddsa_private_key_bytes).unwrap();
//! let public_key = private_key.public_key();
//!
//! // Encrypt
//! let message = b"Lenin was a communist";
//! let mut encrypted_message = public_key.encrypt(message, &mut rng).unwrap();
//!
//! // Decrypt
//! let parsed_message = ecies::EncryptedMessage::from_bytes(&mut encrypted_message).unwrap();
//! let decrypted_message = private_key.decrypt_in_place(parsed_message).unwrap();
//! assert_eq!(decrypted_message, message);
//! ```

/// The ciphersuite for curve25519+aes128_cbc+hmacsha256
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Curve25519Aes128cbcHmacsha256;

type S = Curve25519Aes128cbcHmacsha256;

impl super::Suite for S {
    type E = generic_ec::curves::Ed25519;
    type Mac = hmac::Hmac<sha2::Sha256>;
    type Enc = cbc::Encryptor<aes::Aes128>;
    type Dec = cbc::Decryptor<aes::Aes128>;
}

/// Private key of this suite, a scalar of Curve25519
pub type PrivateKey = crate::PrivateKey<S>;
/// Public key of this suite, a point on Curve25519
pub type PublicKey = crate::PublicKey<S>;
/// Message encrypted with this ciphersuite
pub type EncryptedMessage<'m> = crate::EncryptedMessage<'m, S>;

impl PublicKey {
    /// Encrypt the message bytes in place; specialization for
    /// `curve25519aes128_cbchmac`. Uses PKCS7 padding.
    ///
    /// - `message` - the buffer containing the message to encrypt, plus enough
    ///   space for padding
    /// - `data_len` - length of the message in the buffer
    ///
    /// Given a message `m`, the size of the buffer should be at least `m.len() +
    /// pad_size(m.len())`. If the buffer size is too small, the function will
    /// return [`crate::EncError::PadError`]
    ///
    /// You can interact with the encrypted bytes through the returned
    /// [`EncryptedMessage`], but be careful that changing them will invalidate
    /// the mac.
    ///
    /// Convenient alias for [`PublicKey::block_encrypt_in_place`]
    pub fn encrypt_in_place<'m>(
        &self,
        message: &'m mut [u8],
        data_len: usize,
        rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
    ) -> Result<EncryptedMessage<'m>, crate::EncError> {
        self.block_encrypt_in_place(message, data_len, rng)
    }

    /// Encrypt the message bytes into a new buffer. Uses PKCS7 padding.
    /// Returnes the encoded bytes of [`EncryptedMessage`]. Specialization for
    /// `curve25519aes128_cbchmac`
    ///
    /// Convenient alias for [`PublicKey::block_encrypt`]
    pub fn encrypt(
        &self,
        message: &[u8],
        rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
    ) -> Result<Vec<u8>, crate::EncError> {
        self.block_encrypt(message, rng)
    }
}

impl PrivateKey {
    /// Decrypt the message bytes in place; specialization for
    /// `curve25519aes128_cbchmac`. Uses PKCS7 padding.
    ///
    /// When you have a buffer of bytes to decrypt, you first need to parse it
    /// with `EncryptedMessage::from_bytes`, and then decrypt the structure
    /// using this funciton. It will modify the bytes in the buffer and return a
    /// slice to them.
    ///
    /// Convenient alias for [`PrivateKey::block_decrypt_in_place`]
    pub fn decrypt_in_place<'m>(
        &self,
        message: EncryptedMessage<'m>,
    ) -> Result<&'m mut [u8], crate::DecError> {
        self.block_decrypt_in_place(message)
    }

    /// Decrypt the message bytes into a new buffer; specialization for
    /// `curve25519aes128_cbchmac`. Uses PKCS7 padding.
    ///
    /// When you have a buffer of bytes to decrypt, you first need to parse it
    /// with `EncryptedMessage::from_bytes`, and then decrypt the structure
    /// using this funciton. It will copy the message bytes into a new buffer
    /// and return a [`Vec`] containing them.
    ///
    /// Convenient alias for [`PrivateKey::block_decrypt`]
    pub fn decrypt(&self, message: &EncryptedMessage<'_>) -> Result<Vec<u8>, crate::DecError> {
        self.block_decrypt(message)
    }
}

#[cfg(test)]
crate::common::make_tests!("block");
