//! Generation-related settings

use core::str::FromStr;
use log::error;
use serde::{Deserialize, Serialize};
use serde_json::Result as SerdeResult;
use std::path::Path;

use const_oid::{ObjectIdentifier, db::fips204::ID_ML_DSA_44};
use x509_cert::Certificate;

use crate::misc::utils::get_file_as_byte_vec;
use crate::{Result, misc::utils::cert_type};

/// Settings controlling which source algorithms are mapped to which target algorithms.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GenerationSettings {
    /// List of algorithm mappings from source to target OID.
    pub alg_mappings: Vec<AlgMapping>,
}

/// Reads a JSON-formatted [GenerationSettings] instance from a file.
pub fn read_generation_settings(file_name: &str) -> GenerationSettings {
    if Path::exists(Path::new(file_name))
        && let Ok(json) = get_file_as_byte_vec(Path::new(file_name))
    {
        let r: SerdeResult<GenerationSettings> = serde_json::from_slice(&json);
        if let Ok(ss) = r {
            return ss;
        }
    }
    GenerationSettings::default()
}

impl Default for GenerationSettings {
    fn default() -> Self {
        Self {
            alg_mappings: vec![AlgMapping::default()],
        }
    }
}

impl GenerationSettings {
    /// Tries to load [GenerationSettings] from a file (currently unimplemented; returns default).
    pub fn try_from(_file: &str) -> Result<Self> {
        // todo
        Ok(GenerationSettings::default())
    }

    /// Returns the target [ObjectIdentifier] for the source algorithm found in `cert`.
    pub fn get_target(&self, cert: &Certificate, orig_path: &str) -> Result<ObjectIdentifier> {
        let source = cert
            .tbs_certificate()
            .subject_public_key_info()
            .algorithm
            .oid;
        let source_str = source.to_string();
        for alg_mapping in &self.alg_mappings {
            if alg_mapping.source_alg == source_str {
                if let Some(key_usage) = alg_mapping.source_key_usage {
                    if Ok(key_usage) == cert_type(cert) {
                        return Ok(ObjectIdentifier::from_str(&alg_mapping.target_alg)?);
                    }
                } else {
                    return Ok(ObjectIdentifier::from_str(&alg_mapping.target_alg)?);
                }
            }
        }
        error!(
            "Failed to map source algorithm for {orig_path}: {}. Using ID_ML_DSA_44.",
            source_str
        );
        Ok(ID_ML_DSA_44)
    }
}

/// Describes the key-usage profile of a certificate.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum KeyUsageProfile {
    /// Certificate is used only for digital signatures.
    SignatureOnly,
    /// Certificate is used only for key encipherment or key agreement.
    EncryptionOnly,
    /// Certificate is used for both signatures and encryption.
    SignatureAndEncryption,
}

/// Maps a source algorithm OID (and optional key-usage profile) to a target algorithm OID.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AlgMapping {
    /// OID string of the source algorithm.
    pub source_alg: String,
    /// Optional key-usage profile to narrow the match.
    pub source_key_usage: Option<KeyUsageProfile>,
    /// OID string of the target algorithm.
    pub target_alg: String,
}

impl Default for AlgMapping {
    /// Defaults to RSA_ENCRYPTION to ID_ML_DSA_44
    fn default() -> Self {
        AlgMapping {
            source_alg: "1.2.840.113549.1.1.1".to_string(),
            source_key_usage: None,
            target_alg: "2.16.840.1.101.3.4.3.17".to_string(),
        }
    }
}
