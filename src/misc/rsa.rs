//! RSA KEM implementation

use rand_core::Rng;
use sha2::Sha256;

use crate::error::Error;
use rsa::{
    Oaep, PrivateKey, PublicKey,
    pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey},
};

/// Provides an RSA KEM implementation given an [PrivateKey]
pub struct RsaKem {
    sk: PrivateKey,
}

/// Shared secret for RSA KEM
pub type SharedSecret = [u8; 32];
/// Ciphertext for RSA KEM
pub type Ciphertext = Vec<u8>;
/// Plaintext for RSA KEM
pub type Plaintext = Vec<u8>;
impl RsaKem {
    /// Constructs an [RsaKem] from a PKCS#1 DER-encoded private key.
    pub fn new(sk: &[u8]) -> crate::error::Result<Self> {
        Ok(Self {
            sk: PrivateKey::from_pkcs1_der(sk).map_err(|_| Error::Rsa)?,
        })
    }
    /// Generates a new RSA key pair
    pub fn keygen(num_bits: usize) -> crate::error::Result<Self> {
        let mut rng = rand::rng();
        Ok(Self {
            sk: PrivateKey::new(&mut rng, num_bits)?,
        })
    }

    /// Returns an [PublicKey] containing the public key value
    pub fn to_public_key(&self) -> PublicKey {
        self.sk.to_public_key()
    }

    /// Returns DER-encoding of PKCS #1 representation of the private key
    pub fn to_pkcs1_der(&self) -> crate::error::Result<Vec<u8>> {
        Ok(self
            .sk
            .to_pkcs1_der()
            .map_err(|_| Error::Rsa)?
            .as_bytes()
            .to_vec())
    }

    /// RSA KEM encapsulation implementation
    pub fn encap(recip_pub_key_bytes: &[u8]) -> crate::error::Result<(SharedSecret, Ciphertext)> {
        let recip_pub_key =
            PublicKey::from_pkcs1_der(recip_pub_key_bytes).map_err(|_| Error::Rsa)?;
        let mut rng = rand::rng();
        let mut ss: SharedSecret = [0x00; 32];
        rng.fill_bytes(&mut ss);

        let padding = Oaep::<Sha256>::new();
        let ciphertext = recip_pub_key.encrypt(&mut rng, padding, &ss)?;

        Ok((ss, ciphertext))
    }

    /// RSA KEM decapsulation implementation
    pub fn decap(&self, ciphertext: &[u8]) -> crate::error::Result<Plaintext> {
        Ok(self.sk.decrypt(Oaep::<Sha256>::new(), ciphertext)?)
    }
}
