//! Key Encapsulation Mechanism (KEM) used in ECIES

#[cfg(feature = "ecdh-ed25519")]
pub use self::ecdh_prime_group::Ed25519;
#[cfg(feature = "ecdh-secp256k1")]
pub use self::ecdh_prime_group::Secp256k1;
#[cfg(feature = "ecdh-secp256r1")]
pub use self::ecdh_prime_group::Secp256r1;

#[cfg(feature = "ecdh-x25519")]
pub use self::x25519::X25519;

/// Key Encapsulation Mechanism (KEM) used in ECIES
///
/// KEM allows one party, who knows a public key of the other, to generate (encapsulate) and send a high-entropy
/// value over public communication channel such as only owner of the secret key can open (decapsulate) the
/// high-entropy value, which can then be used to derive symmetric encryption keys.
///
/// ECIES is instantiated with KEM based on Elliptic-Curve Diffie-Hellman (ECDH). We provide standard ECDH based
/// on [secp256k1](Secp256k1), [secp256r1](Secp256r1) and [x25519](X25519) curves.
pub trait Kem {
    /// Public key
    type PublicKey: Encoding + Clone + Eq + core::fmt::Debug;
    /// Secret key
    type SecretKey: Encoding + Clone;
    /// Ciphertext
    type Ciphertext: Encoding + EncodeExactLen + DecodeOne + Clone + Eq + core::fmt::Debug;
    /// KDF output
    type KdfOutput: KdfOutput;

    /// Generates [`Kem::SecretKey`]
    fn keygen(rng: &mut impl rand_core::CryptoRngCore) -> Self::SecretKey;

    /// Derives a public key from the secret key
    fn get_public_key(secret_key: &Self::SecretKey) -> Self::PublicKey;

    /// Key Encapsulation
    ///
    /// Takes cryptographic source of randomness, a public key, and performs key encapsulation.
    /// Returns a ciphertext to be sent to counterparty, and a shared secret.
    ///
    /// Encapsulation carries out steps 1-4 from 5.1.3 Encryption Operation as defined in [SECG
    /// SEC-1](http://www.secg.org/sec1-v2.pdf)
    fn encaps(
        rng: &mut impl rand_core::CryptoRngCore,
        public_key: &Self::PublicKey,
    ) -> (Self::Ciphertext, Self::KdfOutput);

    /// Key Decapsulation
    ///
    /// Takes the secret key, the ciphertext received from the counterparty, and performs key
    /// decapsulation. Returns `None` if ciphertext is invalid, otherwise returns a shared secret.
    ///
    /// Decapsulation carries out steps 4-6 from 5.1.4 Decryption Operation as defined in [SECG
    /// SEC-1](http://www.secg.org/sec1-v2.pdf)
    fn decaps(secret_key: &Self::SecretKey, ciphertext: &Self::Ciphertext) -> Self::KdfOutput;
}

/// Extracts output of KDF
pub trait KdfOutput {
    /// Extracts a uniformly distributed string from stored entropy and writes it to `out`
    fn expand(&self, info: &[u8], out: &mut [u8]) -> Result<(), InvalidLength>;
}

/// Error produced by [`KdfOutput::expand`] indicating that output buffer is too long
#[derive(Debug, thiserror::Error)]
#[error("invalid length")]
pub struct InvalidLength;

/// Byte encoding
pub trait Encoding: Sized {
    /// Byte arrays that fits entire byte representation of the type
    type ByteArray: AsRef<[u8]>;

    /// Encodes `self` into bytes
    fn encode(&self) -> Self::ByteArray;

    /// Decodes bytes encoding of the type
    ///
    /// Returns `None` if the encoding doesn't correspond to a valid value of the type.
    fn decode(encoding: &[u8]) -> Option<Self>;
}

/// Encoding has always the same length
///
/// Implementing this trait guarantees that [`Encoding::encode`] always returns a bytestring
/// of the same length, which is equal to [`encode_output_len()`](EncodeExactLen::encode_output_len).
pub trait EncodeExactLen: Encoding {
    /// Length of encoded value
    ///
    /// [`Encoding::encode`] always returns a bytestring of this length.
    ///
    /// Note that `decode` function might accept byte strings of different length though.
    fn encode_output_len() -> usize;
}

/// Decoding of ciphertext required for compliance with SEC1
pub trait DecodeOne: Sized {
    /// Takes a byte string of form `concat(encoding, following_data)`, parses
    /// `encoding`, on success, returns decoded value and `len(encoding)`
    ///
    /// We use it to decode a SEC1 ciphertext which has form `concat(eph_point, message, tag)`
    /// where `eph_point` can be in both compressed and uncompressed form. `decode_one` can
    /// extract `eph_point`, decode it (regardless whether it's compressed or not) and return
    /// `len(eph_point)` which then can be used to extract `concat(message, tag)`
    fn decode_one(bytes: &[u8]) -> Option<(Self, usize)>;
}

#[cfg(feature = "hkdf")]
impl KdfOutput for hkdf::Hkdf<sha2::Sha256> {
    fn expand(&self, info: &[u8], out: &mut [u8]) -> Result<(), InvalidLength> {
        self.expand(info, out).map_err(|_| InvalidLength)
    }
}

/// KEM based on ECDH in large prime subgroup of the curve
#[cfg(feature = "ecdh-prime-group")]
pub mod ecdh_prime_group {
    use generic_ec::{Curve, NonZero, Point, Scalar, SecretScalar};

    use super::{DecodeOne, EncodeExactLen, Encoding, Kem};

    /// ECDH in prime group of secp256k1 curve
    #[cfg(feature = "ecdh-secp256k1")]
    pub type Secp256k1 = EcdhPrimeGroup<generic_ec::curves::Secp256k1>;
    /// ECDH in prime group of secp256r1 curve
    #[cfg(feature = "ecdh-secp256r1")]
    pub type Secp256r1 = EcdhPrimeGroup<generic_ec::curves::Secp256r1>;
    /// ECDH in prime subgroup of ed25519 curve
    ///
    /// **Warning:** this ECDH is non-standard. Prefer using [X25519](super::X25519) which is
    /// standard and more efficient.
    #[cfg(feature = "ecdh-ed25519")]
    pub type Ed25519 = EcdhPrimeGroup<generic_ec::curves::Ed25519>;

    /// KEM based on ECDH in large prime subgroup of the curve
    #[derive(Debug, PartialEq, Eq)]
    pub struct EcdhPrimeGroup<E: Curve> {
        _ph: core::marker::PhantomData<E>,
    }

    impl<E: Curve> Kem for EcdhPrimeGroup<E> {
        type PublicKey = NonZero<Point<E>>;

        type SecretKey = NonZero<SecretScalar<E>>;

        type Ciphertext = NonZero<Point<E>>;

        type KdfOutput = hkdf::Hkdf<sha2::Sha256>;

        fn keygen(rng: &mut impl rand_core::CryptoRngCore) -> Self::SecretKey {
            NonZero::<SecretScalar<E>>::random(rng)
        }

        fn get_public_key(secret_key: &Self::SecretKey) -> Self::PublicKey {
            Point::generator() * secret_key
        }

        fn encaps(
            rng: &mut impl rand_core::CryptoRngCore,
            public_key: &Self::PublicKey,
        ) -> (Self::Ciphertext, Self::KdfOutput) {
            // Step 1. Select an ephemeral key pair
            let eph_key = NonZero::<SecretScalar<E>>::random(rng);
            let ciphertext = Point::generator() * &eph_key;
            // Step 2. Choose whether to use point compression - our implementation enforces
            // point compression when `ciphertext` is encoded

            // Step 3. Carry out DH in prime (sub)group of the curve
            let shared_secret = public_key * &eph_key;

            // Step 4. Output `KDF(shared_secret)`
            // Note: shared_secret is serialized as compressed form of the point, which is
            // actually contradicts SEC1 spec that says that we have to hash an X-coordinate
            // of `shared_secret`.
            let kdf_output =
                hkdf::Hkdf::<sha2::Sha256>::new(None, shared_secret.to_bytes(true).as_ref());
            (ciphertext, kdf_output)
        }

        fn decaps(secret_key: &Self::SecretKey, ciphertext: &Self::Ciphertext) -> Self::KdfOutput {
            let shared_secret = secret_key * ciphertext;
            hkdf::Hkdf::<sha2::Sha256>::new(None, shared_secret.to_bytes(true).as_ref())
        }
    }

    impl<E: Curve> Encoding for NonZero<Point<E>> {
        type ByteArray = generic_ec::EncodedPoint<E>;

        fn encode(&self) -> Self::ByteArray {
            let bytes = self.to_bytes(true);
            debug_assert_eq!(bytes.len(), Self::encode_output_len());
            bytes
        }

        fn decode(encoding: &[u8]) -> Option<Self> {
            Point::from_bytes(encoding)
                .ok()
                .and_then(NonZero::from_point)
        }
    }

    impl<E: Curve> EncodeExactLen for NonZero<Point<E>> {
        fn encode_output_len() -> usize {
            generic_ec::Point::<E>::serialized_len(true)
        }
    }

    impl<E: Curve> DecodeOne for NonZero<Point<E>> {
        fn decode_one(bytes: &[u8]) -> Option<(Self, usize)> {
            let compressed_len = Point::<E>::serialized_len(true);
            let encoding = bytes.get(..compressed_len)?;
            if let Ok(point) = Point::<E>::from_bytes(encoding) {
                let point = NonZero::from_point(point)?;
                return Some((point, encoding.len()));
            }

            let uncompressed_len = Point::<E>::serialized_len(false);
            let encoding = bytes.get(..uncompressed_len)?;
            let point = Point::<E>::from_bytes(encoding).ok()?;
            let point = NonZero::from_point(point)?;
            Some((point, encoding.len()))
        }
    }

    impl<E: Curve> Encoding for NonZero<SecretScalar<E>> {
        type ByteArray = generic_ec::EncodedScalar<E>;

        fn encode(&self) -> Self::ByteArray {
            let sk: &Scalar<E> = self.as_ref();
            sk.to_be_bytes()
        }

        fn decode(encoding: &[u8]) -> Option<Self> {
            SecretScalar::from_be_bytes(encoding)
                .ok()
                .and_then(NonZero::from_secret_scalar)
        }
    }
}

#[cfg(feature = "ecdh-x25519")]
mod x25519 {
    use super::{DecodeOne, EncodeExactLen, Encoding, Kem};

    /// ECDH on X25519 curve as defined in [RFC7748](https://datatracker.ietf.org/doc/html/rfc7748)
    pub struct X25519;

    impl Kem for X25519 {
        type PublicKey = x25519::PublicKey;
        type SecretKey = x25519::StaticSecret;
        type Ciphertext = x25519::PublicKey;
        type KdfOutput = hkdf::Hkdf<sha2::Sha256>;

        fn keygen(rng: &mut impl rand_core::CryptoRngCore) -> Self::SecretKey {
            x25519::StaticSecret::random_from_rng(rng)
        }

        fn get_public_key(secret_key: &Self::SecretKey) -> Self::PublicKey {
            secret_key.into()
        }

        fn encaps(
            rng: &mut impl rand_core::CryptoRngCore,
            public_key: &Self::PublicKey,
        ) -> (Self::Ciphertext, Self::KdfOutput) {
            let local_sk = x25519::StaticSecret::random_from_rng(rng);
            let ciphertext: x25519::PublicKey = (&local_sk).into();
            let shared_secret = local_sk.diffie_hellman(public_key);
            let kdf_output = hkdf::Hkdf::<sha2::Sha256>::new(None, &shared_secret.to_bytes());
            (ciphertext, kdf_output)
        }

        fn decaps(secret_key: &Self::SecretKey, ciphertext: &Self::Ciphertext) -> Self::KdfOutput {
            let shared_secret = secret_key.diffie_hellman(ciphertext);
            hkdf::Hkdf::<sha2::Sha256>::new(None, &shared_secret.to_bytes())
        }
    }

    impl Encoding for x25519::PublicKey {
        type ByteArray = [u8; 32];
        fn encode(&self) -> Self::ByteArray {
            self.to_bytes()
        }
        fn decode(encoding: &[u8]) -> Option<Self> {
            let encoding: [u8; 32] = encoding.try_into().ok()?;
            Some(Self::from(encoding))
        }
    }
    impl EncodeExactLen for x25519::PublicKey {
        fn encode_output_len() -> usize {
            32
        }
    }
    impl DecodeOne for x25519::PublicKey {
        fn decode_one(bytes: &[u8]) -> Option<(Self, usize)> {
            const N: usize = 32;
            let key_bytes = bytes.first_chunk::<{ N }>()?;
            let key = Self::from(*key_bytes);
            Some((key, N))
        }
    }

    impl Encoding for x25519::StaticSecret {
        type ByteArray = [u8; 32];
        fn encode(&self) -> Self::ByteArray {
            self.to_bytes()
        }
        fn decode(encoding: &[u8]) -> Option<Self> {
            let encoding: [u8; 32] = encoding.try_into().ok()?;
            Some(Self::from(encoding))
        }
    }
}
