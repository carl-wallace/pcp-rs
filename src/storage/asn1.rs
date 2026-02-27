//! ASN.1 structures used to generate facsimile artifacts

use log::error;

use der::{Decode, Sequence, ValueOrd, asn1::BitString};
use spki::{
    AlgorithmIdentifierOwned, AlgorithmIdentifierOwned as AlgorithmIdentifier,
    SubjectPublicKeyInfoOwned as SubjectPublicKeyInfo,
};
use x509_cert::{
    Certificate, Version,
    crl::CertificateList,
    crl::TbsCertList,
    ext,
    ext::pkix::{AuthorityKeyIdentifier, SubjectKeyIdentifier},
    name::Name,
    serial_number::SerialNumber,
    time::Validity,
};

use crate::{Error, buffer_to_hex};

/// [`DeferDecodeSigned`] used to parse only the top-level Certificate structure, without parsing the details of the
/// TBSCertificate, AlgorithmIdentifier or BIT STRING fields.
///
/// Deferred decoding is useful when verifying certificates to avoid re-encoding the TBSCertificate
/// (and potentially encountering problems with structures that were not DER-encoded prior to signing).
pub struct DeferDecodeSigned {
    /// tbsCertificate       TBSCertificate,
    pub tbs_field: Vec<u8>,
    /// signatureAlgorithm   AlgorithmIdentifier,
    pub signature_algorithm: AlgorithmIdentifierOwned,
    /// signature            BIT STRING
    pub signature: BitString,
}

impl ::der::FixedTag for DeferDecodeSigned {
    const TAG: ::der::Tag = ::der::Tag::Sequence;
}

impl<'a> ::der::DecodeValue<'a> for DeferDecodeSigned {
    type Error = der::Error;

    fn decode_value<R: ::der::Reader<'a>>(
        reader: &mut R,
        header: ::der::Header,
    ) -> ::der::Result<Self> {
        reader.read_nested(header.length(), |reader| {
            let tbs_certificate = reader.tlv_bytes()?;
            let signature_algorithm = reader.decode()?;
            let signature = reader.decode()?;
            Ok(Self {
                tbs_field: tbs_certificate.to_vec(),
                signature_algorithm,
                signature,
            })
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
#[allow(missing_docs)]
pub struct FakeTbsCertificate {
    /// The certificate version.
    ///
    /// Note that this value defaults to Version 1 per the RFC. However,
    /// fields such as `issuer_unique_id`, `subject_unique_id` and `extensions`
    /// require later versions. Care should be taken in order to ensure
    /// standards compliance.
    #[asn1(context_specific = "0", default = "Default::default")]
    pub version: Version,

    pub serial_number: SerialNumber,
    pub signature: AlgorithmIdentifier,
    pub issuer: Name,
    pub validity: Validity,
    pub subject: Name,
    pub subject_public_key_info: SubjectPublicKeyInfo,

    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub issuer_unique_id: Option<BitString>,

    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
    pub subject_unique_id: Option<BitString>,

    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", optional = "true")]
    pub extensions: Option<ext::Extensions>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
#[allow(missing_docs)]
pub struct FakeCertificate {
    pub tbs_certificate: FakeTbsCertificate,
    pub signature_algorithm: AlgorithmIdentifier,
    pub signature: BitString,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
#[allow(missing_docs)]
pub struct FakeCrl {
    pub tbs_cert_list: TbsCertList,
    pub signature_algorithm: AlgorithmIdentifier,
    pub signature: BitString,
}

pub fn get_akid(cert: &Certificate) -> crate::Result<String> {
    if let Some(exts) = &cert.tbs_certificate().extensions() {
        for ext in exts.as_slice() {
            if let Ok(akid) = AuthorityKeyIdentifier::from_der(ext.extn_value.as_bytes())
                && let Some(kid) = akid.key_identifier
            {
                return Ok(buffer_to_hex(kid.as_bytes()));
            }
        }
    }
    // todo - assuming self-signed for the moment
    get_skid(cert)
}

pub fn get_skid(cert: &Certificate) -> crate::Result<String> {
    if let Some(exts) = &cert.tbs_certificate().extensions() {
        for ext in exts.as_slice() {
            if let Ok(skid) = SubjectKeyIdentifier::from_der(ext.extn_value.as_bytes()) {
                return Ok(buffer_to_hex(skid.0.as_bytes()));
            }
        }
    }
    error!(
        "No SubjectKeyIdentifier extension found for certificate issued to {}",
        cert.tbs_certificate().subject()
    );
    Err(Error::Unrecognized)
}

pub fn get_akid_from_crl(crl: &CertificateList, orig_path: &str) -> crate::Result<String> {
    if let Some(exts) = &crl.tbs_cert_list.crl_extensions {
        for ext in exts.as_slice() {
            if let Ok(akid) = AuthorityKeyIdentifier::from_der(ext.extn_value.as_bytes())
                && let Some(kid) = akid.key_identifier
            {
                return Ok(buffer_to_hex(kid.as_bytes()));
            }
        }
    }
    error!("No AuthorityKeyIdentifier extension found for CRL read from {orig_path}");
    Err(Error::NotFound)
}
