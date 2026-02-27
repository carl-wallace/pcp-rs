//! Structure to help with generating [MacData] objects

use hmac::{Hmac, KeyInit, Mac};
use pkcs8::spki::AlgorithmIdentifier;
use sha2::{Sha256, Sha384, Sha512};

use der::{Any, AnyRef, Decode, asn1::OctetString};
use pkcs12::{
    DigestInfo, MacData,
    kdf::{Pkcs12KeyType, derive_key_utf8},
};

use crate::Error;

use crate::pkcs12_builder::supported_algs::MacAlgorithm;

/// Helper for building password-based [MacData] objects for inclusion in a [PKCS #12 object](pkcs12::pfx::Pfx)
pub struct MacDataBuilder {
    digest_algorithm: MacAlgorithm,
    salt: Option<Vec<u8>>,
    iterations: Option<i32>,
}
impl MacDataBuilder {
    /// Creates a new MacDataBuilder instance with no salt, suitable for use with build_with_rng as-is
    /// or for further customization prior to invoking build. By default, iterations will be set to 2048.
    pub fn new(digest_algorithm: MacAlgorithm) -> MacDataBuilder {
        MacDataBuilder {
            digest_algorithm,
            salt: None,
            iterations: None,
        }
    }

    /// Creates a new MacDataBuilder instance with the provided salt suitable for further
    /// customization prior to invoking build. By default, iterations will be set to 2048.
    pub fn new_with_salt(digest_algorithm: MacAlgorithm, salt: Vec<u8>) -> MacDataBuilder {
        MacDataBuilder {
            digest_algorithm,
            salt: Some(salt),
            iterations: None,
        }
    }

    /// Specify a salt value for use on subsequent build or build_with_rng invocation.
    pub fn salt(&mut self, salt: Option<Vec<u8>>) {
        self.salt = salt;
    }

    /// Returns true is a `salt` value has been specified and false if not.
    pub fn has_salt(&self) -> bool {
        self.salt.is_none()
    }

    /// Specify an iterations value for use on subsequent build or build_with_rng invocations.
    pub fn iterations(&mut self, iterations: Option<i32>) {
        self.iterations = iterations;
    }

    /// Generate MAC key given a password and a salt
    fn generate_mac_key(&self, password: &str, salt: &[u8]) -> crate::Result<Vec<u8>> {
        let iterations = self.iterations.unwrap_or(2048);

        match self.digest_algorithm {
            MacAlgorithm::HmacSha256 => Ok(derive_key_utf8::<Sha256>(
                password,
                salt,
                Pkcs12KeyType::Mac,
                iterations,
                self.digest_algorithm.block_size() as usize,
            )?),
            MacAlgorithm::HmacSha384 => Ok(derive_key_utf8::<Sha384>(
                password,
                salt,
                Pkcs12KeyType::Mac,
                iterations,
                self.digest_algorithm.block_size() as usize,
            )?),
            MacAlgorithm::HmacSha512 => Ok(derive_key_utf8::<Sha512>(
                password,
                salt,
                Pkcs12KeyType::Mac,
                iterations,
                self.digest_algorithm.block_size() as usize,
            )?),
        }
    }

    /// Generate a MAC given a MAC key and content
    fn generate_mac(&self, mac_key: &[u8], content: &[u8]) -> crate::Result<Vec<u8>> {
        match self.digest_algorithm {
            MacAlgorithm::HmacSha256 => {
                type HmacSha256 = Hmac<Sha256>;
                let mut mac = HmacSha256::new_from_slice(mac_key)?;
                mac.update(content);
                Ok(mac.finalize().into_bytes().to_vec())
            }
            MacAlgorithm::HmacSha384 => {
                type HmacSha384 = Hmac<Sha384>;
                let mut mac = HmacSha384::new_from_slice(mac_key)?;
                mac.update(content);
                Ok(mac.finalize().into_bytes().to_vec())
            }
            MacAlgorithm::HmacSha512 => {
                type HmacSha512 = Hmac<Sha512>;
                let mut mac = HmacSha512::new_from_slice(mac_key)?;
                mac.update(content);
                Ok(mac.finalize().into_bytes().to_vec())
            }
        }
    }

    /// Builds a MacData instance using a previously specified salt value and a previously specified
    /// (or default) iterations value. If no iterations value has been specified, a default of 2048
    /// is used.
    pub fn build(&self, password: &str, content: &[u8]) -> crate::Result<MacData> {
        let salt = match &self.salt {
            Some(salt) => salt,
            None => return Err(Error::General(String::from("No salt provided for MacData"))),
        };

        let mac_key = self.generate_mac_key(password, salt)?;
        let result = self.generate_mac(&mac_key, content)?;
        let mac_os = OctetString::new(result.as_slice())?;
        let mac_salt = OctetString::new(salt.as_slice())?;
        let params_bytes = self.digest_algorithm.parameters();
        let params_ref = Some(Any::from(AnyRef::from_der(&params_bytes)?));

        Ok(MacData {
            mac: DigestInfo {
                algorithm: AlgorithmIdentifier {
                    oid: self.digest_algorithm.oid(),
                    parameters: params_ref,
                },
                digest: mac_os,
            },
            mac_salt,
            iterations: self.iterations.unwrap_or(2048),
        })
    }
}
