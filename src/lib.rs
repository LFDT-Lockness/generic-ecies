//! ECIES is a scheme for efficient ciphers with asymmetric key using elliptic
//! curves and symmetric ciphers. This implementation is generic in its
//! components, thanks to using [`generic_ec`] and `RustCrypto` traits. You can
//! use the ciphersuites defined by us in advance, like
//! [`ed25519xsalsa20hmac`] and [`ed25519aes128_cbchmac`], or you can
//! define your own [`Suite`].
//!
//! This implementation is based on [SECG
//! SEC-1](http://www.secg.org/sec1-v2.pdf)
//!
//! You can find examples of usage in the predefined ciphersuites:
//! [`ed25519xsalsa20hmac`] and [`ed25519aes128_cbchmac`]

#![forbid(clippy::disallowed_methods, missing_docs, unsafe_code)]
#![cfg_attr(not(test), forbid(unused_crate_dependencies))]

#[macro_use]
mod common;

#[cfg(feature = "ed25519aes128-cbchmac")]
pub mod ed25519aes128_cbchmac;
#[cfg(feature = "ed25519xsalsa20hmac")]
pub mod ed25519xsalsa20hmac;
pub mod kem;

use cipher::generic_array::GenericArray;
use digest::Mac as _;
use rand_core::{CryptoRng, RngCore};

pub use self::kem::Kem;

use self::kem::{DecodeOne, EncodeExactLen, Encoding};

/// A suite of cryptographic protocols to use for ECIES
///
/// Thanks for UC-security, any secure protocols can work together.
///
/// This crate has several suites ready-made, such as
/// [`ed25519xsalsa20hmac`] and [`ed25519aes128_cbchmac`].
pub trait Suite: core::fmt::Debug + Eq {
    /// Key Encapsulation Mechanism to be used. See [`kem`].
    type Kem: kem::Kem;
    /// MAC provided by [`digest`]
    type Mac: digest::Mac + digest::KeyInit;
    /// Encryption provided by [`cipher`], for use for symmetric encryption
    type Enc;
    /// Decryption corresponding to `Enc`. For stream cipher will usually be
    /// the same as `Enc`
    type Dec;
}

pub(crate) type MacSize<S> = <<S as Suite>::Mac as digest::OutputSizeUser>::OutputSize;

/// Amount of bytes padding of this message will take. When using
/// [`PublicKey::block_encrypt_in_place`], you will find this function useful to
/// find out how many bytes to append to the buffer so that the padding will fit
pub const fn pad_size<S: Suite>(message_len: usize) -> usize
where
    S::Enc: cipher::BlockSizeUser,
{
    let block_size = <<S::Enc as cipher::BlockSizeUser>::BlockSize as cipher::Unsigned>::USIZE;
    block_size - (message_len % block_size)
}

/// Private key is a scalar of the elliptic curve in the chosen suite.
///
/// You can obtain a private key by generating it with [`PrivateKey::generate`],
/// or by reading it from bytes with [`PrivateKey::from_bytes`].
///
/// The scalars are stored as bytes in big-endian format, which might not always
/// be compatible with other software working with this elliptic curve. For
/// example, for EdDSA compatibility we provide a method
/// [`PrivateKey::from_eddsa_pkey_bytes`]
#[derive(Clone)]
pub struct PrivateKey<S: Suite>(pub <S::Kem as Kem>::SecretKey);

/// Public key is a point on the elliptic curve of the chosen suite.
///
/// You can obtain a public key from a newly generated private key by
/// [`PrivateKey::public_key`], or by reading it from bytes with
/// [`PublicKey::from_bytes`]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey<S: Suite>(pub <S::Kem as Kem>::PublicKey);

/// Represents a parsed message. To convert to and from platform independent
/// wire bytes use [`EncryptedMessage::from_bytes`] and
/// [`EncryptedMessage::to_bytes`]
///
/// The borrows the bytes to be encrypted instead of owning them, which allows
/// for efficient in-place encryption and decryption.
#[derive(Debug, PartialEq, Eq)]
pub struct EncryptedMessage<'m, S: Suite> {
    /// Ephemeral key in DH in the protocol
    pub ephemeral_key: <S::Kem as Kem>::Ciphertext,
    /// Encrypted bytes of the message, stored elsewhere
    pub message: &'m mut [u8],
    /// MAC tag of encrypted bytes
    pub tag: GenericArray<u8, MacSize<S>>,
}

impl<S: Suite> PrivateKey<S> {
    /// Generate random key using the provided [`CryptoRng`]
    pub fn generate(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        Self(<S::Kem as Kem>::keygen(rng))
    }

    /// Decodes private key from its bytes representation
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Option<Self> {
        <<S::Kem as Kem>::SecretKey as Encoding>::decode(bytes.as_ref()).map(Self)
    }
    /// Encodes private key into bytes
    pub fn to_bytes(&self) -> <<S::Kem as Kem>::SecretKey as Encoding>::ByteArray {
        self.0.encode()
    }

    /// Compute the associated public key `Q = g * d`
    pub fn public_key(&self) -> PublicKey<S> {
        PublicKey(<S::Kem as Kem>::get_public_key(&self.0))
    }
}

impl<S: Suite> core::fmt::Debug for PrivateKey<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PrivateKey").finish_non_exhaustive()
    }
}

impl<S: Suite> PublicKey<S> {
    /// Decodes public key from its bytes representation
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Option<Self> {
        <<S::Kem as Kem>::PublicKey as Encoding>::decode(bytes.as_ref()).map(Self)
    }
    /// Encodes public key into bytes
    pub fn to_bytes(&self) -> <<S::Kem as Kem>::PublicKey as Encoding>::ByteArray {
        self.0.encode()
    }

    /// Encrypt the message bytes in place. Variant for suites with stream
    /// ciphers.
    ///
    /// You can interact with the encrypted bytes through the returned
    /// [`EncryptedMessage`], but be careful that changing them will invalidate
    /// the mac.
    pub fn stream_encrypt_in_place<'m>(
        &self,
        message: &'m mut [u8],
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<EncryptedMessage<'m, S>, EncError>
    where
        S::Enc: cipher::KeyIvInit + cipher::StreamCipher,
    {
        stream_encrypt_in_place::<S, _>(message, self, rng)
    }

    /// Encrypt the message bytes in place. Variant for suites with block
    /// ciphers. Uses PKCS7 padding.
    ///
    /// - `message` - the buffer containing the message to encrypt, plus enough
    ///   space for padding
    /// - `data_len` - length of the message in the buffer
    ///
    /// Given a message `m`, the size of the buffer should be at least `m.len() +
    /// pad_size(m.len())`. If the buffer size is too small, the function will
    /// return [`EncError::PadError`]
    ///
    /// You can interact with the encrypted bytes through the returned
    /// [`EncryptedMessage`], but be careful that changing them will invalidate
    /// the mac.
    pub fn block_encrypt_in_place<'m>(
        &self,
        message: &'m mut [u8],
        data_len: usize,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<EncryptedMessage<'m, S>, EncError>
    where
        S::Enc: cipher::KeyIvInit + cipher::BlockEncryptMut,
    {
        block_encrypt_in_place::<S, _>(message, data_len, self, rng)
    }

    /// Encrypt the message bytes into a new buffer. Variant for suites with
    /// stream ciphers.
    ///
    /// Returns the encoded bytes of [`EncryptedMessage`]
    pub fn stream_encrypt(
        &self,
        message: &[u8],
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Vec<u8>, EncError>
    where
        S::Enc: cipher::KeyIvInit + cipher::StreamCipher,
    {
        with_copy(message, |msg| self.stream_encrypt_in_place(msg, rng))
    }

    /// Encrypt the message bytes into a new buffer. Variant for suites with
    /// block ciphers. Uses PKCS7 padding.
    ///
    /// Returns the encoded bytes of [`EncryptedMessage`]
    pub fn block_encrypt(
        &self,
        message: &[u8],
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Vec<u8>, EncError>
    where
        S::Enc: cipher::KeyIvInit + cipher::BlockEncryptMut,
    {
        let key_len = <<S::Kem as Kem>::Ciphertext as EncodeExactLen>::encode_output_len();
        let mac_len = <MacSize<S> as cipher::typenum::Unsigned>::USIZE;
        let msg_len = message.len();
        let pad_len = pad_size::<S>(msg_len);

        let mut bytes = vec![0; key_len + msg_len + pad_len + mac_len];
        bytes[key_len..(key_len + msg_len)].copy_from_slice(message);
        // contains space for padding
        let message_slice = &mut bytes[key_len..(key_len + msg_len + pad_len)];

        let EncryptedMessage {
            ephemeral_key, tag, ..
        } = self.block_encrypt_in_place(message_slice, msg_len, rng)?;

        bytes[..key_len].copy_from_slice(ephemeral_key.encode().as_ref());
        bytes[(key_len + msg_len + pad_len)..].copy_from_slice(&tag);
        Ok(bytes)
    }
}

impl<S: Suite> PrivateKey<S> {
    /// Decrypt the message bytes in place. Variant for suites with stream
    /// ciphers.
    ///
    /// When you have a buffer of bytes to decrypt, you first need to parse it
    /// with `EncryptedMessage::from_bytes`, and then decrypt the structure
    /// using this funciton. It will modify the bytes in the buffer and return a
    /// slice to them.
    pub fn stream_decrypt_in_place<'m>(
        &self,
        message: EncryptedMessage<'m, S>,
    ) -> Result<&'m mut [u8], DecError>
    where
        S::Dec: cipher::KeyIvInit + cipher::StreamCipher,
    {
        stream_decrypt_in_place(message, self)
    }

    /// Decrypt the message bytes into a new buffer. Variant for suites with
    /// stream ciphers.
    ///
    /// When you have a buffer of bytes to decrypt, you first need to parse it
    /// with `EncryptedMessage::from_bytes`, and then decrypt the structure
    /// using this funciton. It will copy the message bytes into a new buffer
    /// and return a [`Vec`] containing them.
    pub fn stream_decrypt(&self, message: &EncryptedMessage<'_, S>) -> Result<Vec<u8>, DecError>
    where
        S::Dec: cipher::KeyIvInit + cipher::StreamCipher,
    {
        let mut msg_bytes = Vec::with_capacity(message.message.len());
        msg_bytes.extend_from_slice(message.message);
        let msg = EncryptedMessage {
            ephemeral_key: message.ephemeral_key.clone(),
            tag: message.tag.clone(),
            message: &mut msg_bytes,
        };
        let _ = self.stream_decrypt_in_place(msg)?;
        Ok(msg_bytes)
    }

    /// Decrypt the message bytes in place. Variant for suites with block
    /// ciphers. Uses PKCS7 padding.
    ///
    /// When you have a buffer of bytes to decrypt, you first need to parse it
    /// with `EncryptedMessage::from_bytes`, and then decrypt the structure
    /// using this funciton. It will modify the bytes in the buffer and return a
    /// slice to them.
    pub fn block_decrypt_in_place<'m>(
        &self,
        message: EncryptedMessage<'m, S>,
    ) -> Result<&'m mut [u8], DecError>
    where
        S::Dec: cipher::KeyIvInit + cipher::BlockDecryptMut,
    {
        block_decrypt_in_place(message, self)
    }

    /// Decrypt the message bytes into a new buffer. Variant for suites with
    /// block ciphers. Uses PKCS7 padding.
    ///
    /// When you have a buffer of bytes to decrypt, you first need to parse it
    /// with `EncryptedMessage::from_bytes`, and then decrypt the structure
    /// using this funciton. It will copy the message bytes into a new buffer
    /// and return a [`Vec`] containing them.
    pub fn block_decrypt(&self, message: &EncryptedMessage<'_, S>) -> Result<Vec<u8>, DecError>
    where
        S::Dec: cipher::KeyIvInit + cipher::BlockDecryptMut,
    {
        let mut msg_bytes = Vec::with_capacity(message.message.len());
        msg_bytes.extend_from_slice(message.message);
        let msg = EncryptedMessage {
            ephemeral_key: message.ephemeral_key.clone(),
            tag: message.tag.clone(),
            message: &mut msg_bytes,
        };
        let s = self.block_decrypt_in_place(msg)?;
        let len_without_pad = s.len();
        msg_bytes.truncate(len_without_pad);
        Ok(msg_bytes)
    }
}

fn derive_keys_from_kdf_output<K: Kem>(
    kdf: K::KdfOutput,
    cipher_key: &mut [u8],
    mac_key: &mut [u8],
) -> Result<(), crate::kem::InvalidLength> {
    use crate::kem::KdfOutput;

    // 5-6 in enc, 6-7 in dec: use KDF to produce keys for encryption and mac
    let mut all_bytes = vec![0u8; cipher_key.len() + mac_key.len()];

    kdf.expand(b"generic-ecies cipher and mac", &mut all_bytes)?;
    let mid = cipher_key.len();
    cipher_key.copy_from_slice(&all_bytes[..mid]);
    mac_key.copy_from_slice(&all_bytes[mid..]);
    Ok(())
}

fn stream_encrypt_in_place<'m, S, R>(
    m: &'m mut [u8],
    q: &PublicKey<S>,
    rng: &mut R,
) -> Result<EncryptedMessage<'m, S>, EncError>
where
    R: RngCore + CryptoRng,
    S: Suite,
    S::Enc: cipher::KeyIvInit + cipher::StreamCipher,
{
    // Steps 1-4 are done within Kem::encaps
    let (r, z) = S::Kem::encaps(rng, &q.0);

    // Steps 5-6: given KDF output `z`, derive cipher and mac keys
    let mut cipher_key = cipher::Key::<S::Enc>::default();
    let mut mac_key = cipher::Key::<S::Mac>::default();
    derive_keys_from_kdf_output::<S::Kem>(z, &mut cipher_key, &mut mac_key)
        .map_err(EncError::Kdf)?;

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
    data_len: usize,
    q: &PublicKey<S>,
    rng: &mut R,
) -> Result<EncryptedMessage<'m, S>, EncError>
where
    R: RngCore + CryptoRng,
    S::Enc: cipher::KeyIvInit + cipher::BlockEncryptMut,
{
    // Steps 1-4 are done within Kem::encaps
    let (r, z) = S::Kem::encaps(rng, &q.0);

    // Steps 5-6: given KDF output `z`, derive cipher and mac keys
    let mut cipher_key = cipher::Key::<S::Enc>::default();
    let mut mac_key = cipher::Key::<S::Mac>::default();
    derive_keys_from_kdf_output::<S::Kem>(z, &mut cipher_key, &mut mac_key)
        .map_err(EncError::Kdf)?;

    // Use zero IV since the key never repeats
    let cipher_iv = cipher::Iv::<S::Enc>::default();
    let cipher: S::Enc = cipher::KeyIvInit::new(&cipher_key, &cipher_iv);
    let mac: S::Mac = digest::Mac::new(&mac_key);

    // 7. Encrypt message
    cipher::BlockEncryptMut::encrypt_padded_mut::<cipher::block_padding::Pkcs7>(
        cipher, m, data_len,
    )
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
    d: &PrivateKey<S>,
) -> Result<&'m mut [u8], DecError>
where
    S::Dec: cipher::KeyIvInit + cipher::StreamCipher,
{
    // Byte conversion of step 1 and 2 is done separately

    let r = message.ephemeral_key;
    let m = message.message;
    let tag = message.tag;

    // 3. Verify the validity of the ephemeral key - unnecessary as all
    // verification steps outlined in 3.2.2.1 of SECG SEC-1 (including non-zero
    // point) are encoded in types and thus are achieved by construction

    // Steps 4-6 are done within KEM::decaps
    let z = S::Kem::decaps(&d.0, &r);

    // Step 7: given KDF output `z`, derive cipher and mac keys
    let mut cipher_key = cipher::Key::<S::Dec>::default();
    let mut mac_key = cipher::Key::<S::Mac>::default();
    derive_keys_from_kdf_output::<S::Kem>(z, &mut cipher_key, &mut mac_key)
        .map_err(DecError::Kdf)?;

    // Use zero IV since the key never repeats
    let cipher_iv = cipher::Iv::<S::Dec>::default();
    let mut cipher: S::Dec = cipher::KeyIvInit::new(&cipher_key, &cipher_iv);
    let mac: S::Mac = digest::Mac::new(&mac_key);

    // 8. Verify MAC
    mac.chain_update(&*m)
        .verify(&tag)
        .map_err(|_| DecError::MacInvalid)?;

    // 9. Decrypt message
    cipher::StreamCipher::try_apply_keystream(&mut cipher, m).map_err(DecError::StreamEnd)?;

    // 10. Output message
    Ok(m)
}

fn block_decrypt_in_place<'m, S: Suite>(
    message: EncryptedMessage<'m, S>,
    d: &PrivateKey<S>,
) -> Result<&'m mut [u8], DecError>
where
    S::Dec: cipher::KeyIvInit + cipher::BlockDecryptMut,
{
    // Byte conversion of step 1 and 2 is done separately

    let r = message.ephemeral_key;
    let m = message.message;
    let tag = message.tag;

    // 3. Verify the validity of the ephemeral key - unnecessary as all
    // verification steps outlined in 3.2.2.1 of SECG SEC-1 (including non-zero
    // point) are encoded in types and thus are achieved by construction

    // Steps 4-6 are done within KEM::decaps
    let z = S::Kem::decaps(&d.0, &r);

    // Step 7: given KDF output `z`, derive cipher and mac keys
    let mut cipher_key = cipher::Key::<S::Dec>::default();
    let mut mac_key = cipher::Key::<S::Mac>::default();
    derive_keys_from_kdf_output::<S::Kem>(z, &mut cipher_key, &mut mac_key)
        .map_err(DecError::Kdf)?;

    // Use zero IV since the key never repeats
    let cipher_iv = cipher::Iv::<S::Dec>::default();
    let cipher: S::Dec = cipher::KeyIvInit::new(&cipher_key, &cipher_iv);
    let mac: S::Mac = digest::Mac::new(&mac_key);

    // 8. Verify MAC
    mac.chain_update(&*m)
        .verify(&tag)
        .map_err(|_| DecError::MacInvalid)?;

    // 9. Decrypt message
    let s = cipher::BlockDecryptMut::decrypt_padded_mut::<cipher::block_padding::Pkcs7>(cipher, m)
        .map_err(DecError::PadError)?;
    let len_without_padding = s.len();

    // 10. Output message
    Ok(&mut m[..len_without_padding])
}

impl<'m, S: Suite> EncryptedMessage<'m, S> {
    /// Convert the message triplet to bytes following the description in SECG
    /// SEC-1: `ephemeral_key || message || MAC`. Ephemeral key is stored in
    /// compressed form when supported.
    pub fn to_bytes(&self) -> Vec<u8> {
        // Following SECG SEC-1 part 5.1.3, byte representation is a
        // concatenation of component representations
        let r = self.ephemeral_key.encode();
        let mut bytes = Vec::with_capacity(r.as_ref().len() + self.message.len() + self.tag.len());
        bytes.extend_from_slice(r.as_ref());
        bytes.extend_from_slice(self.message);
        bytes.extend_from_slice(&self.tag);
        bytes
    }

    /// Read the message triplet from bytes
    pub fn from_bytes(bytes: &'m mut [u8]) -> Result<Self, DeserializeError> {
        // Following SECG SEC-1 part 5.1.4, byte representation is a
        // concatenation of component representations. Care must be taken
        // to parse the point correctly if it's compressed or not.
        let (ephemeral_key, eph_key_len) =
            <<S::Kem as Kem>::Ciphertext as DecodeOne>::decode_one(bytes)
                .ok_or(DeserializeError::ParseEphKey)?;

        let bytes = bytes
            .get_mut(eph_key_len..)
            .ok_or(DeserializeError::CiphertextDecodeOneBuggyImpl)?;

        let tag_len = <MacSize<S> as cipher::typenum::Unsigned>::USIZE;
        let tag_pos = bytes
            .len()
            .checked_sub(tag_len)
            .ok_or(DeserializeError::NoTag)?;
        let (message, tag) = bytes
            .split_at_mut_checked(tag_pos)
            .ok_or(DeserializeError::NoTag)?;
        let tag = GenericArray::<u8, MacSize<S>>::clone_from_slice(tag);

        Ok(EncryptedMessage {
            ephemeral_key,
            message,
            tag,
        })
    }
}

fn with_copy<S: Suite>(
    message: &[u8],
    run: impl FnOnce(&mut [u8]) -> Result<EncryptedMessage<'_, S>, EncError>,
) -> Result<Vec<u8>, EncError> {
    let key_len = <<S::Kem as Kem>::Ciphertext as EncodeExactLen>::encode_output_len();
    let mac_len = <MacSize<S> as cipher::typenum::Unsigned>::USIZE;
    let mut bytes = vec![0; key_len + message.len() + mac_len];
    let message_slice = &mut bytes[key_len..(key_len + message.len())];
    message_slice.copy_from_slice(message);
    let EncryptedMessage {
        ephemeral_key, tag, ..
    } = run(message_slice)?;
    bytes[..key_len].copy_from_slice(ephemeral_key.encode().as_ref());
    bytes[(key_len + message.len())..].copy_from_slice(&tag);
    Ok(bytes)
}

/// Error when encrypting message
///
/// [`EncError::PadError`] may happen when an invalid size buffer is supplied for in-place
/// encryption. Other errors should happen in very rare cases.
#[derive(Debug, thiserror::Error)]
pub enum EncError {
    /// Rare error for KDF. May be caused by invalid EC instance
    #[error("KDF failed")]
    Kdf(#[source] crate::kem::InvalidLength),
    /// Rare error fo symmetric encryption. May be cause by trying to encrypt
    /// too much data
    #[error("Key stream end (too much data supplied): {0}")]
    StreamEnd(cipher::StreamCipherError),
    /// Error of symmetric encryption, caused by passing a too small buffer to
    /// [`PublicKey::block_encrypt_in_place`]
    #[error("Pad error {0}")]
    PadError(cipher::inout::PadError),
}

/// Error when encrypting message
///
/// Most errors can happen when a message has been tampered with.
#[derive(Debug, thiserror::Error)]
pub enum DecError {
    /// Invalid MAC, caused by tampering with the message or using the wrong key
    #[error("MAC verification failed")]
    MacInvalid,
    /// Rare error for KDF. May be caused by invalid EC instance
    #[error("KDF failed")]
    Kdf(#[source] crate::kem::InvalidLength),
    /// Rare error fo symmetric encryption. May be cause by trying to encrypt
    /// too much data
    #[error("Key stream end (too much data supplied): {0}")]
    StreamEnd(cipher::StreamCipherError),
    /// Error unpadding, might be caused by sender sending a corrupted message
    #[error("Pad error {0}")]
    PadError(cipher::block_padding::UnpadError),
}

/// Error when deserializing the byte representation of a message
#[derive(Debug, thiserror::Error)]
pub enum DeserializeError {
    /// Could not parse ephemeral key
    #[error("parse eph key")]
    ParseEphKey,
    /// [`DecodeOne`] implementation is buggy
    #[error("DecodeOne impl for Kem::Ciphertext is buggy: it returned wrong length")]
    CiphertextDecodeOneBuggyImpl,
    /// Message is too small to fit a tag
    #[error("message to small, there's no tag")]
    NoTag,
}
