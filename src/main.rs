#![forbid(unsafe_code)]
#![warn(
    clippy::alloc_instead_of_core,
    clippy::mod_module_files,
    clippy::std_instead_of_alloc,
    clippy::std_instead_of_core,
    clippy::unwrap_used,
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]
#![doc = include_str!("../README.md")]

use clap::Parser;

use crate::{args::PcpArgs, logging::configure_logging};

pub mod args;
pub mod asn1;
pub mod error;
pub mod generation;
pub mod logging;
pub mod misc;
pub mod pqc;
pub mod storage;

use crate::generation::generate::{generate, generate_crls};
use crate::generation::ingest::ingest;
use crate::generation::settings::{GenerationSettings, read_generation_settings};
use crate::storage::settings::{StorageSettings, read_storage_settings};
pub use error::{Error, Result};
pub use misc::utils::buffer_to_hex;

/// ```bash
/// $ ./target/release/pcp-rs
///
/// Usage: pcp-rs [OPTIONS] --certs-folder <CERTS_FOLDER>
///
/// Options:
///   -h, --help     Print help (see more with '--help')
///   -V, --version  Print version
///
/// Logging:
///   -c, --log-to-console
///           Log output to the console
///   -l, --logging-config <LOGGING_CONFIG>
///           Full path and filename of YAML-formatted configuration file for log4rs logging mechanism. See https://docs.rs/log4rs/latest/log4rs/ for details
///
/// Source Artifacts:
///   -x, --certs-folder <CERTS_FOLDER>
///           Full path and name of the folder containing certificate artifacts. The folder will be recursively traversed in search of target file extensions
///   -r, --crls-folder <CRLS_FOLDER>
///           Full path and name of the folder containing CRL artifacts. The folder will be recursively traversed in search of target file extensions
///   -f, --file-extensions <FILE_EXTENSIONS>
///           Semi-colon delimited list of file extensions to ingest from the `certs-folder` [default: .der;.crt;.cer;.pem]
///
/// Generated Artifacts:
///   -g, --generation-settings <GENERATION_SETTINGS>
///          Full path and filename of the file containing JSON-formatted settings that govern preparation of generated artifacts
///   -s, --storage-settings <STORAGE_SETTINGS>
///           Full path and filename of the file containing JSON-formatted settings that govern storage of generated artifacts
/// ```
fn main() {
    let args = PcpArgs::parse();
    configure_logging(&args);

    let mut storage_settings = if let Some(storage_settings) = args.storage_settings {
        read_storage_settings(&storage_settings)
    } else {
        StorageSettings::default()
    };

    let generation_settings = if let Some(generation_settings) = args.generation_settings {
        read_generation_settings(&generation_settings)
    } else {
        GenerationSettings::default()
    };

    let _ = ingest(
        &args.certs_folder,
        &generation_settings,
        &mut storage_settings,
    );
    let _ = generate(&args.certs_folder, &generation_settings, &storage_settings);
    if let Some(crls_folder) = &args.crls_folder {
        let _ = generate_crls(crls_folder, &generation_settings, &storage_settings);
    }
}
