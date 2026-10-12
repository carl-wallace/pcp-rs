//! Enum that defines the types of key pairs that are supported

use ed448_goldilocks::Ed448;
use ml_dsa::{B32, Keypair as _, MlDsa44, MlDsa65, MlDsa87, MlDsaParams, VerifyingKey};
use rsa::RsaPrivateKey;
use slh_dsa::{
    Sha2_128f, Sha2_128s, Sha2_192f, Sha2_192s, Sha2_256f, Sha2_256s, Shake128f, Shake128s,
    Shake192f, Shake192s, Shake256f, Shake256s, SigningKey,
};

/// An ML-DSA key pair, generated from a seed.
///
/// ml-dsa 0.1.1 removed its own `KeyPair`; the seed-backed `SigningKey` now carries both halves.
/// This keeps the methods pcp-rs calls on a key pair.
pub struct KeyPair<P: MlDsaParams>(ml_dsa::SigningKey<P>);

impl<P: MlDsaParams> KeyPair<P> {
    /// Derives the key pair from `xi` (FIPS 204 ML-DSA.KeyGen_internal).
    pub fn from_seed(xi: &B32) -> Self {
        Self(ml_dsa::SigningKey::from_seed(xi))
    }

    /// The signing key.
    pub fn signing_key(&self) -> &ml_dsa::SigningKey<P> {
        &self.0
    }

    /// The verifying key.
    pub fn verifying_key(&self) -> VerifyingKey<P> {
        self.0.verifying_key()
    }
}

#[allow(dead_code)]
#[allow(missing_docs)]
pub enum PqcKeyPair {
    MlDsa44(Box<KeyPair<MlDsa44>>),
    MlDsa65(Box<KeyPair<MlDsa65>>),
    MlDsa87(Box<KeyPair<MlDsa87>>),
    Sha2_128f(Box<SigningKey<Sha2_128f>>),
    Sha2_128s(Box<SigningKey<Sha2_128s>>),
    Sha2_192f(Box<SigningKey<Sha2_192f>>),
    Sha2_192s(Box<SigningKey<Sha2_192s>>),
    Sha2_256f(Box<SigningKey<Sha2_256f>>),
    Sha2_256s(Box<SigningKey<Sha2_256s>>),
    Shake128f(Box<SigningKey<Shake128f>>),
    Shake128s(Box<SigningKey<Shake128s>>),
    Shake192f(Box<SigningKey<Shake192f>>),
    Shake192s(Box<SigningKey<Shake192s>>),
    Shake256f(Box<SigningKey<Shake256f>>),
    Shake256s(Box<SigningKey<Shake256s>>),
    Mldsa44Rsa2048PssSha256(Box<(KeyPair<MlDsa44>, RsaPrivateKey)>),
    Mldsa44Rsa2048Pkcs15Sha256(Box<(KeyPair<MlDsa44>, RsaPrivateKey)>),
    Mldsa44Ed25519Sha512(Box<(KeyPair<MlDsa44>, ed25519_dalek::SigningKey)>),
    Mldsa44EcdsaP256Sha256(Box<(KeyPair<MlDsa44>, p256::ecdsa::SigningKey)>),
    Mldsa65Rsa3072PssSha512(Box<(KeyPair<MlDsa65>, RsaPrivateKey)>),
    Mldsa65Rsa4096PssSha512(Box<(KeyPair<MlDsa65>, RsaPrivateKey)>),
    Mldsa65Rsa4096Pkcs15Sha512(Box<(KeyPair<MlDsa65>, RsaPrivateKey)>),
    Mldsa65EcdsaP256Sha512(Box<(KeyPair<MlDsa65>, p256::ecdsa::SigningKey)>),
    Mldsa65EcdsaP384Sha512(Box<(KeyPair<MlDsa65>, p384::ecdsa::SigningKey)>),
    Mldsa65Ed25519Sha512(Box<(KeyPair<MlDsa65>, ed25519_dalek::SigningKey)>),
    Mldsa87EcdsaP384Sha512(Box<(KeyPair<MlDsa87>, p384::ecdsa::SigningKey)>),
    Mldsa87Ed448Shake256(Box<(KeyPair<MlDsa87>, elliptic_curve::SecretKey<Ed448>)>),
    Mldsa87Rsa3072PssSha512(Box<(KeyPair<MlDsa87>, RsaPrivateKey)>),
    Mldsa87Rsa4096PssSha512(Box<(KeyPair<MlDsa87>, RsaPrivateKey)>),
    Mldsa87EcdsaP521Sha512(Box<(KeyPair<MlDsa87>, p521::ecdsa::SigningKey)>),
}
