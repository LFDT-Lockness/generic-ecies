//! Based on [SECG SEC-1](http://www.secg.org/sec1-v2.pdf)

#[macro_use]
mod common;

#[cfg(feature = "curve25519aes128-cbchmac")]
pub mod curve25519aes128_cbchmac;
#[cfg(feature = "curve25519xsalsa20hmac")]
pub mod curve25519xsalsa20hmac;

use cipher::generic_array::GenericArray;
use generic_ec::Curve;
use hmac::Mac as _;
use rand_core::{CryptoRng, RngCore};

pub trait Suite {
    type E: Curve;
    type Mac: digest::OutputSizeUser;
    type Enc;
}

pub(crate) type MacSize<S> = <<S as Suite>::Mac as digest::OutputSizeUser>::OutputSize;

#[derive(Clone, Debug)]
pub struct PrivateKey<S: Suite> {
    /// `d` in the standard
    pub scalar: generic_ec::NonZero<generic_ec::SecretScalar<S::E>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey<S: Suite> {
    /// `Q` in the standard
    pub point: generic_ec::NonZero<generic_ec::Point<S::E>>,
}

#[derive(Debug, PartialEq)]
pub struct EncryptedMessage<'m, S: Suite> {
    pub ephemeral_key: generic_ec::NonZero<generic_ec::Point<S::E>>,
    pub message: &'m mut [u8],
    pub tag: GenericArray<u8, MacSize<S>>,
}

impl<S: Suite> PrivateKey<S> {
    pub fn generate(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let scalar = generic_ec::NonZero::<generic_ec::SecretScalar<S::E>>::random(rng);
        Self { scalar }
    }
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Option<Self> {
        let scalar = generic_ec::SecretScalar::from_be_bytes(bytes.as_ref()).ok()?;
        let scalar = generic_ec::NonZero::try_from(scalar).ok()?;
        Some(Self { scalar })
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let scalar: &generic_ec::Scalar<S::E> = self.scalar.as_ref();
        scalar.to_be_bytes().to_vec()
    }

    pub fn public_key(&self) -> PublicKey<S> {
        let point = generic_ec::Point::generator() * &self.scalar;
        PublicKey { point }
    }
}

impl<S: Suite> PublicKey<S> {
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Option<Self> {
        let point = generic_ec::Point::<S::E>::from_bytes(bytes).ok()?;
        let point = generic_ec::NonZero::<generic_ec::Point<S::E>>::try_from(point).ok()?;
        Some(Self { point })
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        self.point.to_bytes(true).to_vec()
    }

    pub fn stream_encrypt_in_place<'m>(
        &self,
        message: &'m mut [u8],
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<EncryptedMessage<'m, S>, EncError>
    where
        S::Mac: digest::Mac + cipher::KeyInit,
        S::Enc: cipher::KeyIvInit + cipher::StreamCipher,
    {
        stream_encrypt_in_place::<S, _>(message, &self.point, rng)
    }

    pub fn block_encrypt_in_place<'m>(
        &self,
        message: &'m mut [u8],
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<EncryptedMessage<'m, S>, EncError>
    where
        S::Mac: digest::Mac + cipher::KeyInit,
        S::Enc: cipher::KeyIvInit + cipher::BlockEncryptMut,
    {
        block_encrypt_in_place::<S, _>(message, &self.point, rng)
    }

    pub fn stream_encrypt(
        &self,
        message: &[u8],
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Vec<u8>, EncError>
    where
        S::Mac: digest::Mac + cipher::KeyInit,
        S::Enc: cipher::KeyIvInit + cipher::StreamCipher,
    {
        let key_len = generic_ec::Point::<S::E>::serialized_len(true);
        let mac_len = <MacSize<S> as cipher::typenum::Unsigned>::USIZE;
        let mut bytes = vec![0; key_len + message.len() + mac_len];
        let message_slice = &mut bytes[key_len..(key_len + message.len())];
        message_slice.copy_from_slice(message);
        let EncryptedMessage {
            ephemeral_key, tag, ..
        } = self.stream_encrypt_in_place(message_slice, rng)?;
        bytes[..key_len].copy_from_slice(&ephemeral_key.to_bytes(true));
        bytes[(key_len + message.len())..].copy_from_slice(&tag);
        Ok(bytes)
    }
}

impl<S: Suite> PrivateKey<S> {
    pub fn stream_decrypt_in_place<'m>(
        &self,
        message: EncryptedMessage<'m, S>,
    ) -> Result<&'m mut [u8], DecError>
    where
        S::Mac: digest::Mac + cipher::KeyInit,
        S::Enc: cipher::KeyIvInit + cipher::StreamCipher,
    {
        stream_decrypt_in_place(message, &self.scalar)
    }

    pub fn stream_decrypt(&self, message: &EncryptedMessage<'_, S>) -> Result<Vec<u8>, DecError>
    where
        S::Mac: digest::Mac + cipher::KeyInit,
        S::Enc: cipher::KeyIvInit + cipher::StreamCipher,
    {
        let mut msg_bytes = Vec::with_capacity(message.message.len());
        msg_bytes.extend_from_slice(message.message);
        let msg = EncryptedMessage {
            ephemeral_key: message.ephemeral_key,
            tag: message.tag.clone(),
            message: &mut msg_bytes,
        };
        let _ = self.stream_decrypt_in_place(msg)?;
        Ok(msg_bytes)
    }
}

fn stream_encrypt_in_place<'m, S, R>(
    m: &'m mut [u8],
    q: &generic_ec::NonZero<generic_ec::Point<S::E>>,
    rng: &mut R,
) -> Result<EncryptedMessage<'m, S>, EncError>
where
    R: RngCore + CryptoRng,
    S: Suite,
    S::Mac: digest::Mac + cipher::KeyInit,
    S::Enc: cipher::KeyIvInit + cipher::StreamCipher,
{
    // 1. Select ephemeral key pair
    let k = generic_ec::NonZero::<generic_ec::SecretScalar<S::E>>::random(rng);
    let r = generic_ec::Point::generator() * &k;

    // 2: Use compression unconditionally
    // 3: Use ECDH without small cofactor, as in generic-ec all scalars are
    // guaranteed to be in the prime order subgroup
    let z: generic_ec::NonZero<_> = k * q;
    // No need to check the point for zero, it's guaranteed by construction

    // 4: convert z to octet string
    let z_bs = z.to_bytes(true);

    // 5-6. Use KDF to produce keys for encryption and mac
    let kdf = hkdf::Hkdf::<sha2::Sha256>::new(None, &z_bs);
    let mut cipher_key = cipher::Key::<S::Enc>::default();
    let mut mac_key = cipher::Key::<S::Mac>::default();
    let mut all_bytes = vec![0u8; cipher_key.len() + mac_key.len()];

    kdf.expand(b"generic-ecies cipher and mac", &mut all_bytes)
        .map_err(EncError::Kdf)?;
    let mid = cipher_key.len();
    cipher_key.copy_from_slice(&all_bytes[..mid]);
    mac_key.copy_from_slice(&all_bytes[mid..]);

    // Use zero IV since the key never repeats
    let cipher_iv = cipher::Iv::<S::Enc>::default();
    let mut cipher: S::Enc = cipher::KeyIvInit::new(&cipher_key, &cipher_iv);
    let mac: S::Mac = digest::Mac::new(&mac_key);

    // 7. Encrypt message
    cipher::StreamCipher::try_apply_keystream(&mut cipher, m).map_err(EncError::StreamEnd)?;

    // 8. MAC-tag the message
    let d = mac.chain_update(&*m).finalize().into_bytes();

    // 9. Output as structured message. Byte conversion is done separately
    Ok(EncryptedMessage {
        ephemeral_key: r,
        message: m,
        tag: d,
    })
}

fn block_encrypt_in_place<'m, S: Suite, R>(
    m: &'m mut [u8],
    q: &generic_ec::NonZero<generic_ec::Point<S::E>>,
    rng: &mut R,
) -> Result<EncryptedMessage<'m, S>, EncError>
where
    R: RngCore + CryptoRng,
    S::Mac: digest::Mac + cipher::KeyInit,
    S::Enc: cipher::KeyIvInit + cipher::BlockEncryptMut,
{
    // 1. Select ephemeral key pair
    let k = generic_ec::NonZero::<generic_ec::SecretScalar<S::E>>::random(rng);
    let r = generic_ec::Point::generator() * &k;

    // 2: Use compression unconditionally
    // 3: Use ECDH without small cofactor, as in generic-ec all scalars are
    // guaranteed to be in the prime order subgroup
    let z: generic_ec::NonZero<_> = k * q;
    // No need to check the point for zero, it's guaranteed by construction

    // 4: convert z to octet string
    let z_bs = z.to_bytes(true);

    // 5-6. Use KDF to produce keys for encryption and mac
    let kdf = hkdf::Hkdf::<sha2::Sha256>::new(None, &z_bs);
    let mut cipher_key = cipher::Key::<S::Enc>::default();
    let mut mac_key = cipher::Key::<S::Mac>::default();
    let mut all_bytes = vec![0u8; cipher_key.len() + mac_key.len()];

    kdf.expand(b"generic-ecies cipher and mac", &mut all_bytes)
        .map_err(EncError::Kdf)?;
    let mid = cipher_key.len();
    cipher_key.copy_from_slice(&all_bytes[..mid]);
    mac_key.copy_from_slice(&all_bytes[mid..]);

    // Use zero IV since the key never repeats
    let cipher_iv = cipher::Iv::<S::Enc>::default();
    let cipher: S::Enc = cipher::KeyIvInit::new(&cipher_key, &cipher_iv);
    let mac: S::Mac = digest::Mac::new(&mac_key);

    // 7. Encrypt message
    cipher::BlockEncryptMut::encrypt_padded_mut::<cipher::block_padding::Pkcs7>(cipher, m, m.len())
        .map_err(EncError::PadError)?;

    // 8. MAC-tag the message
    let d = mac.chain_update(&*m).finalize().into_bytes();

    // 9. Output as structured message. Byte conversion is done separately
    Ok(EncryptedMessage {
        ephemeral_key: r,
        message: m,
        tag: d,
    })
}

fn stream_decrypt_in_place<'m, S: Suite>(
    message: EncryptedMessage<'m, S>,
    d: &generic_ec::NonZero<generic_ec::SecretScalar<S::E>>,
) -> Result<&'m mut [u8], DecError>
where
    S::Mac: digest::Mac + cipher::KeyInit,
    S::Enc: cipher::KeyIvInit + cipher::StreamCipher,
{
    // Byte conversion of step 1 and 2 is done separately

    let r = message.ephemeral_key;
    let m = message.message;
    let tag = message.tag;

    // 3. Verify the validity of the ephemeral key - unnecessary as all
    // verification steps outlined in 3.2.2.1 of SECG SEC-1 (including non-zero
    // point) are encoded in types and thus are achieved by construction

    // 4: Use ECDH without small cofactor, as in generic-ec all scalars are
    // guaranteed to be in the prime order subgroup
    let z: generic_ec::NonZero<_> = d * r;
    // No need to check the point for zero, it's guaranteed by construction

    // 5: convert z to octet string
    let z_bs = z.to_bytes(true);

    // 6-7. Use KDF to produce keys for encryption and mac
    let kdf = hkdf::Hkdf::<sha2::Sha256>::new(None, &z_bs);
    let mut cipher_key = cipher::Key::<S::Enc>::default();
    let mut mac_key = cipher::Key::<S::Mac>::default();
    let mut all_bytes = vec![0u8; cipher_key.len() + mac_key.len()];

    kdf.expand(b"generic-ecies cipher and mac", &mut all_bytes)
        .map_err(DecError::Kdf)?;
    let mid = cipher_key.len();
    cipher_key.copy_from_slice(&all_bytes[..mid]);
    mac_key.copy_from_slice(&all_bytes[mid..]);

    // Use zero IV since the key never repeats
    let cipher_iv = cipher::Iv::<S::Enc>::default();
    let mut cipher: S::Enc = cipher::KeyIvInit::new(&cipher_key, &cipher_iv);
    let mac: S::Mac = digest::Mac::new(&mac_key);

    // 8. Verify MAC
    mac.chain_update(&*m)
        .verify(&tag)
        .map_err(DecError::MacInvalid)?;

    // 9. Decrypt message
    cipher::StreamCipher::try_apply_keystream(&mut cipher, m).map_err(DecError::StreamEnd)?;

    // 10. Output message
    Ok(m)
}

impl<'m, S: Suite> EncryptedMessage<'m, S> {
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
        let compressed_len = generic_ec::Point::<S::E>::serialized_len(true);
        let (point_len, ephemeral_key) =
            match generic_ec::Point::<S::E>::from_bytes(&bytes[..compressed_len]) {
                Ok(point) => (compressed_len, point),
                Err(e1) => {
                    let len = generic_ec::Point::<S::E>::serialized_len(false);
                    match generic_ec::Point::<S::E>::from_bytes(&bytes[..len]) {
                        Ok(point) => (len, point),
                        Err(e2) => return Err(DeserializeError::InvalidPoint(e1, e2)),
                    }
                }
            };
        let ephemeral_key =
            generic_ec::NonZero::<generic_ec::Point<S::E>>::try_from(ephemeral_key)?;

        let tag_len = GenericArray::<u8, MacSize<S>>::default().len();
        let tag = &bytes[(l - tag_len)..];
        let tag = GenericArray::<u8, MacSize<S>>::clone_from_slice(tag);

        let message = &mut bytes[point_len..(l - tag_len)];

        Ok(EncryptedMessage {
            ephemeral_key,
            message,
            tag,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EncError {
    #[error("DH produced zero")]
    ZeroDH,
    #[error("KDF failed: {0}")]
    Kdf(hkdf::InvalidLength),
    #[error("Key stream end (too much data supplied): {0}")]
    StreamEnd(cipher::StreamCipherError),
    #[error("Pad error {0}")]
    PadError(cipher::inout::PadError),
}

#[derive(Debug, thiserror::Error)]
pub enum DecError {
    #[error("MAC verification failed: {0}")]
    MacInvalid(digest::MacError),
    #[error("DH produced zero")]
    ZeroDH,
    #[error("KDF failed: {0}")]
    Kdf(hkdf::InvalidLength),
    #[error("Key stream end (too much data supplied): {0}")]
    StreamEnd(cipher::StreamCipherError),
    #[error("Pad error {0}")]
    PadError(cipher::inout::PadError),
}

#[derive(Debug, thiserror::Error)]
pub enum DeserializeError {
    #[error("Ephemeral DH key is invalid: {0}; {1}")]
    InvalidPoint(
        generic_ec::errors::InvalidPoint,
        generic_ec::errors::InvalidPoint,
    ),
    #[error("Ephemeral DH key is zero")]
    ZeroPoint(#[from] generic_ec::errors::ZeroPoint),
}
