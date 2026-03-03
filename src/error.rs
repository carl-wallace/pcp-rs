//! Error and Result types for `pcp-rs`
use core::array::TryFromSliceError;
use log::error;

/// Result type for `pcp-rs`
pub type Result<T> = core::result::Result<T, Error>;

/// Error type for `pcp-rs`
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// Asn1Error is used to propagate error information from the x509 crate.
    Asn1(der::Error),
    /// Generic string-based error related to CMS processing
    Builder(String),
    /// Indicates error during fake certificate generation
    CertBuilder,
    /// Generic string-based error
    General(String),
    /// InvalidLength
    InvalidLength(crypto_common::InvalidLength),
    /// General input/output error
    Io,
    /// Issue generating or processing ML KEM artifacts
    MlKem(String),
    /// Issue generating or processing ML DSA artifacts
    MlDsa(String),
    /// Something that was sought was not found
    NotFound,
    /// Object identifier-related error
    Oid(const_oid::Error),
    /// PKCS5-related errors
    Pkcs5(pkcs5::Error),
    /// Generic string-based error associated with PKCS #12 generation
    Pkcs12Builder(String),
    /// Issue generating or processing RSA artifacts
    Rsa,
    /// Issue generating or processing SLH DSA artifacts
    SlhDsa(String),
    /// A slice error
    Slice,
    /// A value other than the expected value was observed
    UnexpectedValue,
    /// Catch-all error
    Unrecognized,
}

impl From<const_oid::Error> for Error {
    fn from(err: const_oid::Error) -> Error {
        Error::Oid(err)
    }
}
impl From<crypto_common::InvalidLength> for Error {
    fn from(err: crypto_common::InvalidLength) -> Error {
        Error::InvalidLength(err)
    }
}

impl From<der::Error> for Error {
    fn from(err: der::Error) -> Error {
        Error::Asn1(err)
    }
}
impl From<pkcs5::Error> for Error {
    fn from(err: pkcs5::Error) -> Error {
        Error::Pkcs5(err)
    }
}

impl From<rsa::Error> for Error {
    fn from(err: rsa::Error) -> Error {
        error!("rsa::Error: {err:?}");
        Error::Rsa
    }
}

impl From<TryFromSliceError> for Error {
    fn from(err: TryFromSliceError) -> Error {
        error!("TryFromSliceError: {err:?}");
        Error::Slice
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Error {
        error!("std::io::Error: {err:?}");
        Error::Io
    }
}

impl From<x509_cert::builder::Error> for Error {
    fn from(err: x509_cert::builder::Error) -> Error {
        error!("x509_cert::builder::Error: {err:?}");
        Error::CertBuilder
    }
}

impl From<pkcs12_builder::Error> for Error {
    fn from(err: pkcs12_builder::Error) -> Error {
        match err {
            pkcs12_builder::Error::Asn1(e) => Error::Asn1(e),
            pkcs12_builder::Error::InvalidLength(e) => Error::InvalidLength(e),
            pkcs12_builder::Error::General(s) => Error::General(s),
            pkcs12_builder::Error::NotFound => Error::NotFound,
            pkcs12_builder::Error::Pkcs5(e) => Error::Pkcs5(e),
            pkcs12_builder::Error::Pkcs12Builder(s) => Error::Pkcs12Builder(s),
        }
    }
}
