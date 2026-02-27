//! Supported MAC and encryption algorithms

use const_oid::{
    ObjectIdentifier,
    db::rfc5912::{ID_SHA_256, ID_SHA_384, ID_SHA_512},
};

/// Supported MAC algorithms.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MacAlgorithm {
    /// HMAC SHA256
    HmacSha256,
    /// HMAC SHA384
    HmacSha384,
    /// HMAC SHA512
    HmacSha512,
}

impl MacAlgorithm {
    /// Return the OID of the algorithm.
    pub fn oid(&self) -> ObjectIdentifier {
        match self {
            MacAlgorithm::HmacSha256 => ID_SHA_256,
            MacAlgorithm::HmacSha384 => ID_SHA_384,
            MacAlgorithm::HmacSha512 => ID_SHA_512,
        }
    }

    /// Return the block size of the associated digest algorithm.
    pub fn block_size(&self) -> i16 {
        match self {
            MacAlgorithm::HmacSha256 => 32,
            MacAlgorithm::HmacSha384 => 48,
            MacAlgorithm::HmacSha512 => 64,
        }
    }

    /// Return encoded parameters for inclusion in an AlgorithmIdentifier
    pub fn parameters(&self) -> Vec<u8> {
        vec![0x05, 0x00]
    }
}

/// Supported encryption algorithms.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EncryptionAlgorithm {
    /// AES128 CBC
    Aes128Cbc,
    /// AES-192 CBC
    Aes192Cbc,
    /// AES-256 CBC
    Aes256Cbc,
}

impl EncryptionAlgorithm {
    /// Return the OID of the algorithm.
    pub fn oid(&self) -> ObjectIdentifier {
        match self {
            EncryptionAlgorithm::Aes128Cbc => const_oid::db::rfc5911::ID_AES_128_CBC,
            EncryptionAlgorithm::Aes192Cbc => const_oid::db::rfc5911::ID_AES_192_CBC,
            EncryptionAlgorithm::Aes256Cbc => const_oid::db::rfc5911::ID_AES_256_CBC,
        }
    }
}
