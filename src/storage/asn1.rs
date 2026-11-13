//! ASN.1 structures used to generate facsimile artifacts

extern crate alloc;
use alloc::collections::BTreeSet;
use log::error;

use const_oid::db::rfc5280::{ID_CE_AUTHORITY_KEY_IDENTIFIER, ID_CE_SUBJECT_KEY_IDENTIFIER};
use der::{
    Decode, Encode, Sequence, ValueOrd,
    asn1::{BitString, OctetString},
};
use sha2::{Digest, Sha256};
use spki::{
    AlgorithmIdentifierOwned, AlgorithmIdentifierOwned as AlgorithmIdentifier,
    SubjectPublicKeyInfoOwned as SubjectPublicKeyInfo,
};
use x509_cert::{
    Certificate, Version,
    crl::CertificateList,
    crl::TbsCertList,
    ext,
    ext::Extension,
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

/// Returns the value of the most specific attribute in `name`, i.e., the last attribute of its last
/// relative distinguished name, e.g., the common name in `C=US, O=Example, CN=Example CA`.
pub fn most_specific_value(name: &Name) -> Option<String> {
    name.iter()
        .last()
        .map(|atv| String::from_utf8_lossy(atv.value.value()).into_owned())
}

/// Returns the key identifier for `spki` per RFC 7093 Section 2 method 1, i.e., the leftmost 160
/// bits of the SHA-256 hash of the value of the subjectPublicKey BIT STRING.
pub fn key_identifier(spki: &SubjectPublicKeyInfo) -> Vec<u8> {
    Sha256::digest(spki.subject_public_key.raw_bytes())[..20].to_vec()
}

/// Sets the SKID in `extensions` to `skid`, when given, and the keyIdentifier in the AKID to
/// `akid`. Other AKID fields are left unchanged, as are extensions that are absent.
pub fn replace_key_identifiers(
    extensions: &mut [Extension],
    skid: Option<&[u8]>,
    akid: &[u8],
) -> crate::Result<()> {
    for ext in extensions.iter_mut() {
        if ext.extn_id == ID_CE_SUBJECT_KEY_IDENTIFIER
            && let Some(skid) = skid
        {
            let value = SubjectKeyIdentifier(OctetString::new(skid)?).to_der()?;
            ext.extn_value = OctetString::new(value)?;
        } else if ext.extn_id == ID_CE_AUTHORITY_KEY_IDENTIFIER {
            let mut value = AuthorityKeyIdentifier::from_der(ext.extn_value.as_bytes())?;
            value.key_identifier = Some(OctetString::new(akid)?);
            ext.extn_value = OctetString::new(value.to_der()?)?;
        }
    }
    Ok(())
}

/// Gets the key identifier values from an AKID extension, and failing that tries to get a value
/// from a SKID extension.
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
    get_skid(cert)
}

/// Gets the key identifier values from an SKID extension.
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

/// Appends ` {suffix}` to every UTF8String, PrintableString or TeletexString in `der` whose value
/// equals `matching` when compared ignoring case and runs of whitespace. The walk descends into
/// constructed values and into OCTET STRINGs that contain DER (i.e., extension values), so names
/// in name constraints, CRL distribution points, AKID issuers, etc. change along with subject and
/// issuer names. Values that do not match are re-emitted unchanged.
pub fn append_suffix_to_matching_strings<'a>(
    der: &[u8],
    matching: impl IntoIterator<Item = &'a str>,
    suffix: &str,
) -> Vec<u8> {
    let matching: BTreeSet<String> = matching.into_iter().map(normalize_string).collect();
    match rewrite_tlvs(der, &matching, suffix) {
        Some((rewritten, true)) => rewritten,
        _ => der.to_vec(),
    }
}

fn normalize_string(s: &str) -> String {
    s.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

/// Returns (tag, header length, content length) for the TLV at the start of `buf`, or None if
/// `buf` does not start with a DER TLV with a low tag number and a definite length that fits.
fn parse_tlv_header(buf: &[u8]) -> Option<(u8, usize, usize)> {
    let tag = *buf.first()?;
    if tag & 0x1F == 0x1F {
        return None;
    }
    let first_len = *buf.get(1)?;
    let (header_len, content_len) = if first_len < 0x80 {
        (2, first_len as usize)
    } else {
        let num_bytes = (first_len & 0x7F) as usize;
        if num_bytes == 0 || num_bytes > 4 {
            return None;
        }
        let mut len = 0usize;
        for b in buf.get(2..2 + num_bytes)? {
            len = (len << 8) | *b as usize;
        }
        (2 + num_bytes, len)
    };
    if buf.len() < header_len + content_len {
        return None;
    }
    Some((tag, header_len, content_len))
}

fn encode_length(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
}

/// Rewrites the series of TLVs in `buf`. Returns None if `buf` is not a series of TLVs, else the
/// rewritten bytes and whether anything changed.
fn rewrite_tlvs(buf: &[u8], matching: &BTreeSet<String>, suffix: &str) -> Option<(Vec<u8>, bool)> {
    const OCTET_STRING: u8 = 0x04;
    const UTF8_STRING: u8 = 0x0C;
    const PRINTABLE_STRING: u8 = 0x13;
    const TELETEX_STRING: u8 = 0x14;

    let mut out = Vec::with_capacity(buf.len());
    let mut changed = false;
    let mut pos = 0;
    while pos < buf.len() {
        let (tag, header_len, content_len) = parse_tlv_header(&buf[pos..])?;
        let tlv = &buf[pos..pos + header_len + content_len];
        let content = &tlv[header_len..];
        let new_content = if tag & 0x20 == 0x20 {
            match rewrite_tlvs(content, matching, suffix)? {
                (c, true) => Some(c),
                _ => None,
            }
        } else if tag == OCTET_STRING {
            match rewrite_tlvs(content, matching, suffix) {
                Some((c, true)) => Some(c),
                _ => None,
            }
        } else if [UTF8_STRING, PRINTABLE_STRING, TELETEX_STRING].contains(&tag)
            && matching.contains(&normalize_string(&String::from_utf8_lossy(content)))
        {
            let mut c = content.to_vec();
            c.push(b' ');
            c.extend_from_slice(suffix.as_bytes());
            Some(c)
        } else {
            None
        };
        match new_content {
            Some(c) => {
                out.push(tag);
                encode_length(c.len(), &mut out);
                out.extend_from_slice(&c);
                changed = true;
            }
            None => out.extend_from_slice(tlv),
        }
        pos += header_len + content_len;
    }
    Some((out, changed))
}

/// Gets the key identifier values from an AKID extension.
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
