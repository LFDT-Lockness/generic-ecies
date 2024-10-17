//! Instantiation of ECIES with the following parameters:
//!
//! * Curve25519 as the elliptic curve
//! * XSalsa20 as the symmetric cipher
//! * HMAC-SHA256 as the message authentication code
//!
//! ## Example of usage
//! ```rust
//! # let mut rng = rand_dev::DevRng::new();
//! use generic_ecies::curve25519xsalsa20hmac as ecies;
//! // Use EdDSA key as openssl generates it instead of Ed25519 private scalar
//! let eddsa_private_key_bytes = b"eddsa priv key is any 32 bytes^^";
//! let private_key = ecies::PrivateKey::from_eddsa_pkey_bytes(eddsa_private_key_bytes).unwrap();
//! let public_key = private_key.public_key();
//!
//! // Encrypt
//! let message = b"Putin is an agent of kremlin";
//! let mut encrypted_message = public_key.encrypt(message, &mut rng).unwrap();
//!
//! // Decrypt
//! let parsed_message = ecies::EncryptedMessage::from_bytes(&mut encrypted_message).unwrap();
//! let decrypted_message = private_key.decrypt_in_place(parsed_message).unwrap();
//! assert_eq!(decrypted_message, message);
//! ```

/// The ciphersuite for curve25519+xsalsa20+hmacsha256
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct S;

impl super::Suite for S {
    type E = generic_ec::curves::Ed25519;
    type Mac = hmac::Hmac<sha2::Sha256>;
    type Enc = salsa20::XSalsa20;
    type Dec = salsa20::XSalsa20;
}

/// Private key of this suite, a scalar of the Ed25519 curve
pub type PrivateKey = crate::PrivateKey<S>;
/// Public key of this suite, a point on the Ed25519 curve
pub type PublicKey = crate::PublicKey<S>;
pub type EncryptedMessage<'m> = crate::EncryptedMessage<'m, S>;

impl PublicKey {
    /// Encrypt the message bytes in place; specialization for
    /// `curve25519xsalsa20hmac`
    ///
    /// You can interact with the encrypted bytes through the returned
    /// [`EncryptedMessage`], but be careful that changing them will invalidate
    /// the mac.
    ///
    /// Convenient alias for [`PublicKey::stream_encrypt_in_place`]
    pub fn encrypt_in_place<'m>(
        &self,
        message: &'m mut [u8],
        rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
    ) -> Result<EncryptedMessage<'m>, crate::EncError> {
        self.stream_encrypt_in_place(message, rng)
    }

    /// Encrypt the message bytes into a new buffer. Returnes the encoded bytes
    /// of [`EncryptedMessage`]. Specialization for `curve25519xsalsa20hmac`
    ///
    /// Convenient alias for [`PublicKey::stream_encrypt`]
    pub fn encrypt(
        &self,
        message: &[u8],
        rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
    ) -> Result<Vec<u8>, crate::EncError> {
        self.stream_encrypt(message, rng)
    }
}

impl PrivateKey {
    /// Decrypt the message bytes in place; specialization for
    /// `curve25519xsalsa20hmac`
    ///
    /// When you have a buffer of bytes to decrypt, you first need to parse it
    /// with `EncryptedMessage::from_bytes`, and then decrypt the structure
    /// using this funciton. It will modify the bytes in the buffer and return a
    /// slice to them.
    ///
    /// Convenient alias to [`PrivateKey::stream_decrypt_in_place`]
    pub fn decrypt_in_place<'m>(
        &self,
        message: EncryptedMessage<'m>,
    ) -> Result<&'m mut [u8], crate::DecError> {
        self.stream_decrypt_in_place(message)
    }

    /// Decrypt the message bytes into a new buffer; specialization for
    /// `curve25519xsalsa20hmac`
    ///
    /// When you have a buffer of bytes to decrypt, you first need to parse it
    /// with `EncryptedMessage::from_bytes`, and then decrypt the structure
    /// using this funciton. It will copy the message bytes into a new buffer
    /// and return a [`Vec`] containing them.
    ///
    /// Convenient alias to [`PrivateKey::decrypt_in_place`]
    pub fn decrypt(&self, message: &EncryptedMessage<'_>) -> Result<Vec<u8>, crate::DecError> {
        self.stream_decrypt(message)
    }
}

crate::common::make_tests!("stream");
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
