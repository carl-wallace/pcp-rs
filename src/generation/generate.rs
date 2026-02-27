//! Generates fake certificates, CRLs, and PKCS #12 files

use std::{ffi::OsStr, path::Path};

use log::error;
use walkdir::WalkDir;

use der::{Decode, zeroize::Zeroizing};
use x509_cert::Certificate;

use crate::misc::utils::get_file_as_byte_vec;
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

                    let mut p12_builder = Pkcs12Builder::new();
                    let password = Zeroizing::new(String::from("password"));
                    match p12_builder.build_with_rng(&cert, &oak, &password, &mut rand::rng()) {
                        Ok(pkcs12) => {
                            if let Err(e) =
                                storage_settings.save_p12(&pkcs12, &oak, &skid, file.path())
                            {
                                error!(
                                    "Failed to save PKCS #12 and/or private key for {:?}: {e:?}",
                                    file.path()
                                );
                            }
                        }
                        Err(e) => {
                            error!("Failed to build PKCS#12 with {e:?}");
                            continue;
                        }
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
