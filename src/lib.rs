//! Based on [SECG SEC-1](http://www.secg.org/sec1-v2.pdf)

#[cfg(feature = "curve25519xsalsa20hmac")]
pub mod curve25519xsalsa20hmac;

use cipher::generic_array::GenericArray;
use generic_ec::Curve;
use rand_core::{CryptoRng, RngCore};

#[derive(Debug)]
pub struct PrivateKey<E: Curve> {
    /// `d` in the standard
    pub scalar: generic_ec::SecretScalar<E>,
}

#[derive(Debug)]
pub struct PublicKey<E: Curve> {
    /// `Q` in the standard
    pub point: generic_ec::Point<E>,
}

#[derive(Debug)]
pub struct EncryptedMessage<'m, Mac: digest::OutputSizeUser, E: Curve> {
    pub ephemeral_key: generic_ec::Point<E>,
    pub message: &'m mut [u8],
    pub tag: GenericArray<u8, Mac::OutputSize>,
}

impl<E: Curve> PrivateKey<E> {
    pub fn generate(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let mut scalar = generic_ec::Scalar::random(rng);
        let scalar = generic_ec::SecretScalar::new(&mut scalar);
        Self { scalar }
    }

    pub fn public_key(&self) -> PublicKey<E> {
        let point = generic_ec::Point::generator() * &self.scalar;
        PublicKey { point }
    }
}

impl<E: Curve> PublicKey<E> {
    pub fn stream_encrypt_in_place<'m, Mac, Enc>(
        &self,
        message: &'m mut [u8],
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<EncryptedMessage<'m, Mac, E>, EncError>
    where
        Mac: digest::Mac + cipher::KeyInit,
        Enc: cipher::KeyIvInit + cipher::StreamCipher,
    {
        stream_encrypt_in_place::<_, _, _, Enc>(message, &self.point, rng)
    }
}

impl<E: Curve> PrivateKey<E> {
    pub fn stream_decrypt_in_place<'m, Mac, Enc>(
        &self,
        message: EncryptedMessage<'m, Mac, E>,
    ) -> Result<&'m mut [u8], DecError>
    where
        Mac: digest::Mac + cipher::KeyInit,
        Enc: cipher::KeyIvInit + cipher::StreamCipher,
    {
        stream_decrypt_in_place::<_, _, Enc>(message, &self.scalar)
    }
}

fn stream_encrypt_in_place<'m, E, R, Mac, Enc>(
    m: &'m mut [u8],
    q: &generic_ec::Point<E>,
    rng: &mut R,
) -> Result<EncryptedMessage<'m, Mac, E>, EncError>
where
    E: Curve,
    R: RngCore + CryptoRng,
    Mac: digest::Mac + cipher::KeyInit,
    Enc: cipher::KeyIvInit + cipher::StreamCipher,
{
    // 1. Select ephemeral key pair
    let mut k = generic_ec::Scalar::random(rng);
    let k = generic_ec::SecretScalar::new(&mut k);
    let r = generic_ec::Point::generator() * &k;

    // 2: Use compression unconditionally
    // 3: Use plain DH (no cofactors)
    let z = k * q;
    if z.is_zero() {
        return Err(EncError::ZeroDH);
    }

    // 4: convert z to octet string
    let z_bs = z.to_bytes(true);

    // 5-6. Use KDF to produce keys for encryption and mac
    let kdf = hkdf::Hkdf::<sha2::Sha256>::new(None, &z_bs);
    let mut cipher_key = cipher::Key::<Enc>::default();
    kdf.expand(b"generic-ecies stream encryption key", &mut cipher_key)
        .map_err(EncError::KdfCipher)?;
    // Use zero IV since the key never repeats
    let cipher_iv = cipher::Iv::<Enc>::default();
    let mut cipher: Enc = cipher::KeyIvInit::new(&cipher_key, &cipher_iv);
    let mut mac_key = cipher::Key::<Mac>::default();
    kdf.expand(b"generic-ecies mac key", &mut mac_key)
        .map_err(EncError::KdfMac)?;
    let mac: Mac = digest::Mac::new(&mac_key);

    // 7. Encrypt message
    cipher.try_apply_keystream(m).map_err(EncError::StreamEnd)?;

    // 8. MAC-tag the message
    let d = mac.chain_update(&*m).finalize().into_bytes();

    // 9. Output as structured message. Byte conversion is done separately
    Ok(EncryptedMessage {
        ephemeral_key: r,
        message: m,
        tag: d,
    })
}

fn stream_decrypt_in_place<'m, E, Mac, Enc>(
    message: EncryptedMessage<'m, Mac, E>,
    d: &generic_ec::SecretScalar<E>,
) -> Result<&'m mut [u8], DecError>
where
    E: Curve,
    Mac: digest::Mac + cipher::KeyInit,
    Enc: cipher::KeyIvInit + cipher::StreamCipher,
{
    // Byte conversion of step 1 and 2 is done separately

    let r = message.ephemeral_key;
    let m = message.message;
    let tag = message.tag;

    // 3. Verify the validity of the ephemeral key

    // Followint the steps in 3.2.2.1 of SECG SEC-1. Steps 2-4 are achieved by
    // point construction
    // 1: check for zero
    if r.is_zero() {
        return Err(DecError::DhInvalid("zero"));
    }

    // 4. Use plain DH (no cofactors)
    let z = d * r;
    if z.is_zero() {
        return Err(DecError::ZeroDH);
    }

    // 5: convert z to octet string
    let z_bs = z.to_bytes(true);

    // 6-7. Use KDF to produce keys for encryption and mac
    let kdf = hkdf::Hkdf::<sha2::Sha256>::new(None, &z_bs);
    let mut cipher_key = cipher::Key::<Enc>::default();
    kdf.expand(b"generic-ecies stream encryption key", &mut cipher_key)
        .map_err(DecError::KdfCipher)?;
    // Use zero IV since the key never repeats
    let cipher_iv = cipher::Iv::<Enc>::default();
    let mut cipher: Enc = cipher::KeyIvInit::new(&cipher_key, &cipher_iv);
    let mut mac_key = cipher::Key::<Mac>::default();
    kdf.expand(b"generic-ecies mac key", &mut mac_key)
        .map_err(DecError::KdfMac)?;
    let mac: Mac = digest::Mac::new(&mac_key);

    // 8. Verify MAC
    mac.chain_update(&*m)
        .verify(&tag)
        .map_err(DecError::MacInvalid)?;

    // 9. Decrypt message
    cipher.try_apply_keystream(m).map_err(DecError::StreamEnd)?;

    // 10. Output message
    Ok(m)
}

impl<'m, Mac: digest::OutputSizeUser, E: Curve> EncryptedMessage<'m, Mac, E> {
    pub fn to_bytes(&self) -> Vec<u8> {
        // Followint SECG SEC-1 part 5.1.3, byte representation is a
        // concatenation of component represenatations
        let r = self.ephemeral_key.to_bytes(true);
        let mut bytes = Vec::with_capacity(r.len() + self.message.len() + self.tag.len());
        bytes.extend_from_slice(&r);
        bytes.extend_from_slice(self.message);
        bytes.extend_from_slice(&self.tag);
        bytes
    }

    pub fn from_bytes(bytes: &'m mut [u8]) -> Result<Self, DeserializeError> {
        // No only for convenience, but because borrow checker can't say that
        // `len` doesn't borrow for lifetime of its return value?
        let l = bytes.len();

        // Followint SECG SEC-1 part 5.1.4, byte representation is a
        // concatenation of component represenatations. Care must be taken
        // to parse the point correctly if it's compressed or not.
        let compressed_len = generic_ec::Point::<E>::serialized_len(true);
        let (point_len, ephemeral_key) =
            match generic_ec::Point::<E>::from_bytes(&bytes[..compressed_len]) {
                Ok(point) => (compressed_len, point),
                Err(e1) => {
                    let len = generic_ec::Point::<E>::serialized_len(false);
                    match generic_ec::Point::<E>::from_bytes(&bytes[..len]) {
                        Ok(point) => (len, point),
                        Err(e2) => return Err(DeserializeError::InvalidPoint(e1, e2)),
                    }
                }
            };

        let tag_len = GenericArray::<u8, Mac::OutputSize>::default().len();
        let tag = &bytes[(l - tag_len)..];
        let tag = GenericArray::<u8, Mac::OutputSize>::clone_from_slice(tag);

        let message = &mut bytes[point_len..(l - tag_len)];

        Ok(EncryptedMessage {
            ephemeral_key,
            message,
            tag,
        })
    }
}

impl<'m, Mac: digest::OutputSizeUser, E: Curve> PartialEq for EncryptedMessage<'m, Mac, E> {
    fn eq(&self, other: &Self) -> bool {
        self.ephemeral_key == other.ephemeral_key
            && self.message == other.message
            && self.tag == other.tag
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EncError {
    #[error("DH produced zero")]
    ZeroDH,
    #[error("KDF for MAC key failed: {0}")]
    KdfMac(hkdf::InvalidLength),
    #[error("KDF for MAC key failed: {0}")]
    KdfCipher(hkdf::InvalidLength),
    #[error("Key stream end (too much data supplied): {0}")]
    StreamEnd(cipher::StreamCipherError),
}

#[derive(Debug, thiserror::Error)]
pub enum DecError {
    #[error("Ephemeral DH key is invalid: {0}")]
    DhInvalid(&'static str),
    #[error("MAC verification failed: {0}")]
    MacInvalid(digest::MacError),
    #[error("DH produced zero")]
    ZeroDH,
    #[error("KDF for MAC key failed: {0}")]
    KdfMac(hkdf::InvalidLength),
    #[error("KDF for MAC key failed: {0}")]
    KdfCipher(hkdf::InvalidLength),
    #[error("Key stream end (too much data supplied): {0}")]
    StreamEnd(cipher::StreamCipherError),
}

#[derive(Debug, thiserror::Error)]
pub enum DeserializeError {
    #[error("Ephemeral DH key is invalid: {0}; {1}")]
    InvalidPoint(
        generic_ec::errors::InvalidPoint,
        generic_ec::errors::InvalidPoint,
    ),
}