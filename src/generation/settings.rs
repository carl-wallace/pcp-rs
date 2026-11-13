//! Generation-related settings

extern crate alloc;
use alloc::collections::BTreeSet;
use core::str::FromStr;
use log::error;
use serde::{Deserialize, Serialize};
use serde_json::Result as SerdeResult;
use std::path::Path;

use const_oid::ObjectIdentifier;
use x509_cert::Certificate;

use crate::misc::utils::get_file_as_byte_vec;
use crate::{Error, Result, misc::utils::cert_type};

/// Settings controlling which source algorithms are mapped to which target algorithms.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GenerationSettings {
    /// List of algorithm mappings from source to target OID.
    pub alg_mappings: Vec<AlgMapping>,
    /// Optional change to names in generated artifacts, used to give each generated set distinct names.
    #[serde(default)]
    pub name_suffix: Option<NameSuffix>,
    /// Replace each SKID with one computed from the generated key (RFC 7093 method 1) and each
    /// AKID key identifier with the issuer's, rather than keeping the values from the original
    /// artifacts, which identify the original keys.
    #[serde(default)]
    pub regenerate_key_identifiers: bool,
    /// Optional text appended to the most specific attribute of each CA name, i.e., each name that
    /// appears as an issuer, usually a common name, used to give the CAs and trust anchors in a
    /// generated set names distinct from the original ones while leaving end entity names and
    /// the names in name constraints unchanged. Applied wherever a matching directory string
    /// appears, as for [NameSuffix], once [GenerationSettings::resolve_ca_names] has collected the
    /// values from the certificates being cloned.
    #[serde(default)]
    pub ca_name_suffix: Option<String>,
    /// The most specific attribute values of the CA names in the certificates being cloned, to
    /// which `ca_name_suffix` is appended
    #[serde(skip)]
    pub ca_names: BTreeSet<String>,
}

/// Appends `suffix` (after a space) to each directory string that matches `matching`, ignoring
/// case and whitespace differences, e.g., `O=Test Certificates 2011` becomes
/// `O=Test Certificates 2011 ML-DSA-44`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NameSuffix {
    /// Directory string value to match
    pub matching: String,
    /// Text to append to matching values
    pub suffix: String,
}

impl NameSuffix {
    /// Returns `der` with the suffix appended to matching directory strings.
    pub fn apply(&self, der: &[u8]) -> Vec<u8> {
        crate::storage::asn1::append_suffix_to_matching_strings(
            der,
            [self.matching.as_str()],
            &self.suffix,
        )
    }
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
            name_suffix: None,
            regenerate_key_identifiers: false,
            ca_name_suffix: None,
            ca_names: BTreeSet::new(),
        }
    }
}

impl GenerationSettings {
    /// Returns `der` with `name_suffix` and `ca_name_suffix` applied to the names in it.
    pub fn rename(&self, der: &[u8]) -> Vec<u8> {
        let der = match &self.name_suffix {
            Some(name_suffix) => name_suffix.apply(der),
            None => der.to_vec(),
        };
        if let Some(suffix) = &self.ca_name_suffix
            && !self.ca_names.is_empty()
        {
            return crate::storage::asn1::append_suffix_to_matching_strings(
                &der,
                self.ca_names.iter().map(String::as_str),
                suffix,
            );
        }
        der
    }

    /// Collects the most specific attribute value of each issuer name in `certs_folder` into
    /// `ca_names` when `ca_name_suffix` is set. Any certificate's issuer is a CA, whether or not
    /// its own certificate asserts cA, which some PKITS CAs deliberately do not.
    pub fn resolve_ca_names(&mut self, certs_folder: &str) {
        if self.ca_name_suffix.is_none() {
            return;
        }
        let mut names = BTreeSet::new();
        for entry in walkdir::WalkDir::new(certs_folder).into_iter().flatten() {
            if !entry.file_type().is_file() {
                continue;
            }
            if let Ok(cert) = crate::misc::utils::get_file_as_cert(entry.path()) {
                names.extend(crate::storage::asn1::most_specific_value(
                    cert.tbs_certificate().issuer(),
                ));
            }
        }
        self.ca_names = names;
    }

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
        error!("No mapping for source algorithm {source_str} in {orig_path}. Skipping it.");
        Err(Error::NotFound)
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
