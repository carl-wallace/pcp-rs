//! Ingests fake certificates and generates a fresh key pair for each

use std::{ffi::OsStr, path::Path};

use log::error;
use walkdir::WalkDir;

use x509_cert::Certificate;

use crate::{
    Error, Result,
    generation::settings::GenerationSettings,
    misc::{
        algs::{KemAlgorithms, SigAlgorithms},
        utils::get_file_as_cert,
    },
    storage::settings::StorageSettings,
};

pub fn generate_key_pair(
    cert: &Certificate,
    generation_settings: &GenerationSettings,
    storage_settings: &mut StorageSettings,
    orig_path: &str,
) -> Result<()> {
    let target = generation_settings.get_target(cert, orig_path)?;
    match SigAlgorithms::from_oid(target) {
        Ok(sig_alg) => {
            match sig_alg.generate_key_pair() {
                Ok(pqc_signer) => {
                    let seed = pqc_signer.seed.clone();
                    let private_key = pqc_signer.private_key();
                    let public_key = pqc_signer.public_key_der();
                    storage_settings.save_key_pair_for_cert(
                        cert,
                        &seed,
                        &private_key,
                        &public_key,
                        orig_path,
                    )?;
                }
                Err(e) => {
                    error!("Error generating sigature key pair for {target}: {e:?}");
                    return Err(Error::Unrecognized);
                }
            };
        }
        Err(_e1) => match KemAlgorithms::from_oid(target) {
            Ok(_kem_alg) => {
                todo!()
            }
            Err(e2) => {
                error!(
                    "Failed to recognize target ({target}) as signature algorithm (e1:?) or KEM algorithm ({e2:?})."
                );
                return Err(Error::Unrecognized);
            }
        },
    }
    Ok(())
}

/// Walks the input folder, generates a fresh key pair for each certificate per the generation
/// settings the saves the private key and public key per the storage settings.
pub fn ingest(
    input_folder: &str,
    generation_settings: &GenerationSettings,
    storage_settings: &mut StorageSettings,
) -> Result<usize> {
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
                        if let Err(_e) = ingest(
                            path.to_str().unwrap_or_default(),
                            generation_settings,
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
                    if let Err(e) = generate_key_pair(
                        &cert,
                        generation_settings,
                        storage_settings,
                        file.path().to_str().unwrap_or_default(),
                    ) {
                        error!(
                            "Failed to generate key pair for certificate from file {:?}: {e:?}",
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
