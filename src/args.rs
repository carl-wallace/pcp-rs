//! Command line arguments

use clap::Parser;

/// Command line arguments for `pcp-rs`
#[derive(Parser, Debug)]
#[command(arg_required_else_help(true))]
#[command(author, version, about = "", long_about = "")]
pub struct PcpArgs {
    // ------------------------------------------------------------------------------------------
    // Logging
    // ------------------------------------------------------------------------------------------
    /// Log output to the console
    #[clap(
        conflicts_with = "logging_config",
        help_heading = "Logging",
        long,
        short = 'c'
    )]
    pub log_to_console: bool,

    #[allow(rustdoc::bare_urls)]
    /// Full path and filename of YAML-formatted configuration file for log4rs logging mechanism.
    /// See https://docs.rs/log4rs/latest/log4rs/ for details.
    #[clap(
        conflicts_with = "log_to_console",
        help_heading = "Logging",
        long,
        short
    )]
    pub logging_config: Option<String>,

    /// Full path and name of the folder containing certificate artifacts. The folder will
    /// be recursively traversed in search of target file extensions.
    #[clap(help_heading = "Source Artifacts", long, short = 'x')]
    pub certs_folder: String,

    /// Full path and name of the folder containing CRL artifacts. The folder will
    /// be recursively traversed in search of target file extensions.
    #[clap(help_heading = "Source Artifacts", long, short = 'r')]
    pub crls_folder: Option<String>,

    /// Semi-colon delimited list of file extensions to ingest from the
    /// `source_folder`.
    #[clap(
        help_heading = "Source Artifacts",
        long,
        short = 'f',
        default_value = ".der;.crt;.cer;.pem"
    )]
    pub file_extensions: Option<String>,

    /// Full path and filename of the file containing JSON-formatted settings that govern
    /// preparation of generated artifacts.
    #[clap(help_heading = "Generated Artifacts", long, short)]
    pub generation_settings: Option<String>,

    /// Full path and filename of the file containing JSON-formatted settings that govern
    /// storage of generated artifacts
    #[clap(help_heading = "Generated Artifacts", long, short)]
    pub storage_settings: Option<String>,
}
