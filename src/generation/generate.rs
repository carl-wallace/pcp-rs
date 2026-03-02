//! Generates fake certificates, CRLs, and PKCS #12 files

use const_oid::ObjectIdentifier;
use const_oid::db::fips204::{ID_ML_DSA_44, ID_ML_DSA_65, ID_ML_DSA_87};
use log::error;
use std::{ffi::OsStr, path::Path};
use walkdir::WalkDir;

use der::{Decode, Encode, zeroize::Zeroizing};
use pqckeys::oak::{OneAsymmetricKey, PrivateKey};
use spki::AlgorithmIdentifier;
use x509_cert::Certificate;

use crate::asn1::private_key::{
    MlDsa44Both, MlDsa44Expanded, MlDsa65Both, MlDsa65Expanded, MlDsa87Both, MlDsa87Expanded,
    MlDsaSeed,
};
use crate::misc::utils::get_file_as_byte_vec;
use crate::pkcs12_builder::asn1_utils::get_key_and_cert;
use crate::{
    Error, generation::settings::GenerationSettings, misc::utils::get_file_as_cert,
    pkcs12_builder::pkcs12_builder::Pkcs12Builder, storage::settings::StorageSettings,
};

/// Walks the input folder, generates a fresh key pair for each certificate per the generation
/// settings the saves the private key and public key per the storage settings.
pub fn generate(
    input_folder: &str,
    _generation_settings: &GenerationSettings,
    storage_settings: &StorageSettings,
) -> crate::Result<usize> {
    if !Path::is_dir(Path::new(input_folder)) {
        error!("{input_folder} does not exist or is not a directory");
        return Err(Error::NotFound);
    }

    let mut counter = 0;
    for entry in WalkDir::new(input_folder) {
        match entry {
            Ok(file) => {
                let path = file.path();
                if file.file_type().is_dir() {
                    if let Some(s) = path.to_str()
                        && s != input_folder
                    {
                        error!("Recursing {}", path.display());
                        if let Err(_e) = generate(
                            path.to_str().unwrap_or_default(),
                            _generation_settings,
                            storage_settings,
                        ) {
                            continue;
                        }
                    }
                    continue;
                } else {
                    let file_exts = ["der", "crt", "cer"];
                    if let Some(ext) = path.extension().and_then(OsStr::to_str) {
                        if !file_exts.contains(&ext) {
                            continue;
                        }
                    } else {
                        continue;
                    }
                    let cert = match get_file_as_cert(file.path()) {
                        Ok(c) => {
                            counter += 1;
                            c
                        }
                        Err(e) => {
                            error!(
                                "Failed to read certificate from file {:?}: {e:?}",
                                file.path()
                            );
                            continue;
                        }
                    };

                    let (oak, cert_bytes, skid) = match storage_settings
                        .generate_fake_cert(&cert, file.path().to_str().unwrap_or_default())
                    {
                        Ok((oak, cert_bytes, skid)) => (oak, cert_bytes, skid),
                        Err(e) => {
                            error!(
                                "Failed to generate fake certificate for {:?}: {e:?}",
                                file.path()
                            );
                            continue;
                        }
                    };

                    let cert = Certificate::from_der(&cert_bytes)?;

                    let oid = cert
                        .tbs_certificate()
                        .subject_public_key_info()
                        .algorithm
                        .oid;
                    if is_ml_dsa(oid) {
                        generate_and_save_pkcs12(
                            storage_settings,
                            &cert,
                            &oak,
                            &skid,
                            file.path(),
                            "_expanded",
                        );
                        let seed = match storage_settings.get_seed(&skid) {
                            Ok(seed) => seed,
                            Err(e) => {
                                error!("Failed to read seed for {skid} to prepare PKCS #12: {e:?}");
                                continue;
                            }
                        };

                        let oak_leaf_seed = OneAsymmetricKey {
                            version: pqckeys::oak::Version::V1, // V1 per rfc5958 section 2
                            private_key_alg: AlgorithmIdentifier {
                                oid,
                                parameters: None,
                            },
                            private_key: MlDsaSeed::new(seed.clone())?,
                            attributes: None,
                            public_key: None,
                        };
                        let der_oak_seed = match oak_leaf_seed.to_der() {
                            Ok(der_oak_seed) => der_oak_seed,
                            Err(e) => {
                                error!(
                                    "Failed to encode OneAsymmetricKey with seed for {skid} to prepare PKCS #12: {e:?}"
                                );
                                continue;
                            }
                        };
                        generate_and_save_pkcs12(
                            storage_settings,
                            &cert,
                            &der_oak_seed,
                            &skid,
                            file.path(),
                            "_seed",
                        );

                        let parsed_oak = OneAsymmetricKey::from_der(&oak)?;
                        let private_key = parsed_oak.private_key.as_bytes();

                        let private_key_bytes_both = match oid {
                            ID_ML_DSA_44 => {
                                let pk = MlDsa44Both {
                                    seed: MlDsaSeed::new(seed)
                                        .map_err(|e| Error::MlKem(format!("{e:?}")))?,
                                    expanded_key: MlDsa44Expanded::new(private_key)
                                        .map_err(|e| Error::MlKem(format!("{e:?}")))?,
                                };
                                pk.to_der()?
                            }
                            ID_ML_DSA_65 => {
                                let pk = MlDsa65Both {
                                    seed: MlDsaSeed::new(seed)
                                        .map_err(|e| Error::MlKem(format!("{e:?}")))?,
                                    expanded_key: MlDsa65Expanded::new(private_key)
                                        .map_err(|e| Error::MlKem(format!("{e:?}")))?,
                                };
                                pk.to_der()?
                            }
                            ID_ML_DSA_87 => {
                                let pk = MlDsa87Both {
                                    seed: MlDsaSeed::new(seed)
                                        .map_err(|e| Error::MlKem(format!("{e:?}")))?,
                                    expanded_key: MlDsa87Expanded::new(private_key)
                                        .map_err(|e| Error::MlKem(format!("{e:?}")))?,
                                };
                                pk.to_der()?
                            }
                            _ => {
                                error!(
                                    "Unrecognized OID ({oid}) when preparing OneAsymmetricKey with both private key formats for {skid}"
                                );
                                continue;
                            }
                        };

                        let oak_leaf_both = OneAsymmetricKey {
                            version: pqckeys::oak::Version::V1, // V1 per rfc5958 section 2
                            private_key_alg: AlgorithmIdentifier {
                                oid,
                                parameters: None,
                            },
                            private_key: PrivateKey::new(private_key_bytes_both)?,
                            attributes: None,
                            public_key: None,
                        };
                        let der_oak_both = match oak_leaf_both.to_der() {
                            Ok(der_oak_both) => der_oak_both,
                            Err(e) => {
                                error!(
                                    "Failed to encode OneAsymmetricKey with both private key formats for {skid} to prepare PKCS #12: {e:?}"
                                );
                                continue;
                            }
                        };
                        generate_and_save_pkcs12(
                            storage_settings,
                            &cert,
                            &der_oak_both,
                            &skid,
                            file.path(),
                            "_both",
                        );
                    } else {
                        generate_and_save_pkcs12(
                            storage_settings,
                            &cert,
                            &oak,
                            &skid,
                            file.path(),
                            "",
                        );
                    }
                }
            }
            _ => {
                error!("Failed to unwrap entry in certs_folder_to_certfile_vec");
                continue;
            }
        }
    }
    Ok(counter)
}

fn is_ml_dsa(oid: ObjectIdentifier) -> bool {
    oid == ID_ML_DSA_44 || oid == ID_ML_DSA_65 || oid == ID_ML_DSA_87
}

/// Builds a PKCS #12 bundle from `cert` and `oak`, verifies it, then saves it via `storage_settings`.
pub fn generate_and_save_pkcs12(
    storage_settings: &StorageSettings,
    cert: &Certificate,
    oak: &[u8],
    skid: &str,
    orig_path: &Path,
    suffix: &str,
) {
    let mut p12_builder = Pkcs12Builder::new();
    let password = Zeroizing::new(String::from("password"));
    match p12_builder.build_with_rng(cert, oak, &password, &mut rand::rng()) {
        Ok(pkcs12) => {
            match get_key_and_cert(&pkcs12, &password) {
                Ok((recovered_key, recovered_cert)) => {
                    assert_eq!(&recovered_cert, cert);
                    assert_eq!(&recovered_key, oak);
                }
                Err(e) => {
                    error!("Failed to parse generated PKCS #12: {e:?}. Ignoring and continuing.");
                }
            }

            if let Err(e) = storage_settings.save_p12(&pkcs12, oak, skid, orig_path, suffix) {
                error!(
                    "Failed to save PKCS #12 and/or private key for {:?}: {e:?}",
                    orig_path
                );
            }
        }
        Err(e) => {
            error!("Failed to build PKCS#12 with {e:?}");
        }
    }
}

/// Walks the input folder, generates a fresh key pair for each certificate per the generation
/// settings the saves the private key and public key per the storage settings.
pub fn generate_crls(
    input_folder: &str,
    _generation_settings: &GenerationSettings,
    storage_settings: &StorageSettings,
) -> crate::Result<usize> {
    if !Path::is_dir(Path::new(input_folder)) {
        error!("{input_folder} does not exist or is not a directory");
        return Err(Error::NotFound);
    }

    let mut counter = 0;
    for entry in WalkDir::new(input_folder) {
        match entry {
            Ok(file) => {
                let path = file.path();
                if file.file_type().is_dir() {
                    if let Some(s) = path.to_str()
                        && s != input_folder
                    {
                        error!("Recursing {}", path.display());
                        if let Err(_e) = generate(
                            path.to_str().unwrap_or_default(),
                            _generation_settings,
                            storage_settings,
                        ) {
                            continue;
                        }
                    }
                    continue;
                } else {
                    let file_exts = ["crl"];
                    if let Some(ext) = path.extension().and_then(OsStr::to_str) {
                        if !file_exts.contains(&ext) {
                            continue;
                        }
                    } else {
                        continue;
                    }
                    let crl_bytes = match get_file_as_byte_vec(file.path()) {
                        Ok(c) => {
                            counter += 1;
                            c
                        }
                        Err(e) => {
                            error!("Failed to read CRL from file {:?}: {e:?}", file.path());
                            continue;
                        }
                    };

                    if let Err(e) = storage_settings
                        .generate_fake_crl(&crl_bytes, file.path().to_str().unwrap_or_default())
                    {
                        error!(
                            "Failed to generate fake certificate for {:?}: {e:?}",
                            file.path()
                        );
                        continue;
                    }
                }
            }
            _ => {
                error!("Failed to unwrap entry in certs_folder_to_certfile_vec");
                continue;
            }
        }
    }
    Ok(counter)
}
