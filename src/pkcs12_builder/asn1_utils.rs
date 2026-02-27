//! Utility functions for interacting with ASN.1 structures associated with [PKCS #12 objects](pkcs12::pfx::Pfx)

use log::error;

use rsa::pkcs8::EncryptedPrivateKeyInfo;

use cms::encrypted_data::EncryptedData;
use const_oid::db::rfc5911::{ID_DATA, ID_ENCRYPTED_DATA};
use der::{
    Any, Decode, Encode,
    asn1::{ContextSpecific, OctetString},
};
use pkcs12::pfx::Pfx;
use pkcs12::{AuthenticatedSafe, CertBag, safe_bag::SafeContents};
use x509_cert::Certificate;

use crate::{Error, Result};

/// Takes an [Any] that notionally contains an [OctetString] and returns an [AuthenticateSafe](AuthenticatedSafe)
/// object or error.
///
/// The [Any] value is typically the value from the [ContentInfo](cms::content_info::ContentInfo) included in the `auth_safe` field
/// of a [Pfx] object. The resulting [AuthenticatedSafe] contains a vector of
/// [ContentInfo](cms::content_info::ContentInfo) objects
///
/// ```rust,ignore
/// use der::Decode;
/// use pkcs12::pfx::Pfx;
/// use pkcs12_builder::get_auth_safes;
/// // instantiate der_p12
/// let pfx = Pfx::from_der(der_p12).unwrap();
/// let auth_safes = get_auth_safes(&pfx.auth_safe.content).unwrap();
/// ```
pub fn get_auth_safes(content: &Any) -> Result<AuthenticatedSafe<'_>> {
    let auth_safes_os = OctetString::from_der(&content.to_der()?)?;
    Ok(AuthenticatedSafe::from_der(auth_safes_os.as_bytes())?)
}

/// Takes an [Any] that notionally contains an [OctetString] and returns a [SafeContents]
/// object or error.
///
/// The [Any] value is typically the value from the [ContentInfo](cms::content_info::ContentInfo) included in an [AuthenticatedSafe]
/// read from the `auth_safe` field of a [Pfx] object. The resulting [AuthenticatedSafe] contains a vector of
/// [SafeBag](pkcs12::safe_bag::SafeBag) objects
///
/// ```rust,ignore
/// use const_oid::db::rfc5911::ID_DATA;
/// use der::Decode;
/// use pkcs12::pfx::Pfx;
/// use pkcs12_builder::{get_auth_safes, get_safe_bags};
/// // instantiate der_p12
/// let pfx = Pfx::from_der(der_p12).unwrap();
/// let auth_safes = get_auth_safes(&pfx.auth_safe.content).unwrap();
/// for auth_safe in &auth_safes {
///     if ID_DATA == auth_safe.content_type {
///         let safe_bags = get_safe_bags(&auth_safe.content).unwrap();
///     }   
/// }
/// ```
pub fn get_safe_bags(content: &Any) -> Result<SafeContents> {
    let safe_bags_os = OctetString::from_der(&content.to_der()?)?;
    Ok(SafeContents::from_der(safe_bags_os.as_bytes())?)
}

/// Takes an [Any] that notionally contains an [OctetString] that contains a [SafeContents] object.
/// It iterates over the list of [SafeBag](pkcs12::safe_bag::SafeBag) objects and tries to decrypt the first object of type
/// [PKCS_12_PKCS8_KEY_BAG_OID](pkcs12::PKCS_12_PKCS8_KEY_BAG_OID) using the provided password.
pub fn get_key(content: &Any, password: &str) -> Result<Vec<u8>> {
    let safe_bags = get_safe_bags(content)?;
    for safe_bag in safe_bags {
        match safe_bag.bag_id {
            pkcs12::PKCS_12_PKCS8_KEY_BAG_OID => {
                let cs: ContextSpecific<EncryptedPrivateKeyInfo<OctetString>> =
                    ContextSpecific::from_der(&safe_bag.bag_value)?;
                let mut ciphertext = cs.value.encrypted_data.as_bytes().to_vec();
                let plaintext = cs
                    .value
                    .encryption_algorithm
                    .decrypt_in_place(password, &mut ciphertext)?;
                return Ok(plaintext.to_vec());
            }
            _ => {
                error!("Unexpected SafeBag type. Ignoring and continuing...");
            }
        };
    }
    Err(Error::Pkcs12Builder(String::from(
        "Failed to find SafeBag containing key",
    )))
}

/// Takes an [Any] that notionally contains an [EncryptedData] that contains an encrypted [SafeContents]
/// object that contains a certificate and a password. It attempted to recover the plaintext from
/// the [EncryptedData] object, parse it and return a DER-encoded certificate.
pub fn get_cert(content: &Any, password: &str) -> Result<Vec<u8>> {
    let enc_data = EncryptedData::from_der(&content.to_der()?)?;

    let enc_params = match enc_data
        .enc_content_info
        .content_enc_alg
        .parameters
        .as_ref()
    {
        Some(r) => r.to_der()?,
        None => {
            return Err(Error::Pkcs12Builder(String::from(
                "Failed to obtain reference to parameters",
            )));
        }
    };

    let params = pkcs5::pbes2::Parameters::from_der(&enc_params)?;
    if let Some(ciphertext_os) = enc_data.enc_content_info.encrypted_content {
        let mut ciphertext = ciphertext_os.as_bytes().to_vec();
        let scheme = pkcs5::EncryptionScheme::from(params.clone());
        let plaintext = scheme.decrypt_in_place(password, &mut ciphertext)?;
        let safe_bags = SafeContents::from_der(plaintext)?;
        for safe_bag in safe_bags {
            match safe_bag.bag_id {
                pkcs12::PKCS_12_CERT_BAG_OID => {
                    let cs: ContextSpecific<CertBag> =
                        ContextSpecific::from_der(&safe_bag.bag_value)?;
                    let cb = cs.value;
                    return Ok(cb.cert_value.as_bytes().to_vec());
                }
                _ => {
                    error!("Unexpected SafeBag type. Ignoring and continuing.");
                }
            };
        }
        Ok(plaintext.to_vec())
    } else {
        Err(Error::Pkcs12Builder(String::from(
            "Failed to read encrypted content",
        )))
    }
}

/// Takes a DER-encoded [PKCS #12 object](pkcs12::pfx::Pfx) and password, attempts to decrypt it and, if successful, returns
/// a tuple containing a private key and a [Certificate] object.
///
/// This method assumes this basic high-level representation of the structure (though the order of
/// the AuthenticatedSafe elements is unimportant).
///
/// ```text
/// SEQUENCE {          -- PFX
///   SEQUENCE {        -- AuthSafe
///     [0] {
///       SEQUENCE {    -- AuthenticatedSafes
///         SEQUENCE {  -- AuthenticatedSafe
///             contentType: ID_ENCRYPTED_DATA
///             content: SafeContents (including SafeBag of type PKCS_12_CERT_BAG_OID)
///           }
///         SEQUENCE {  -- AuthenticatedSafe
///             contentType: ID_DATA
///             content: SafeContents (including SafeBag of type PKCS_12_PKCS8_KEY_BAG_OID)
///           }
///         }
///       }
///     }
///   SEQUENCE {        -- MacData
///     SEQUENCE {
///       SEQUENCE {
///         }
///       }
///     }
///   }
/// ```
pub fn get_key_and_cert(der_p12: &[u8], password: &str) -> Result<(Vec<u8>, Certificate)> {
    let mut recovered_cert = None;
    let mut recovered_key = None;
    let pfx = Pfx::from_der(der_p12)?;
    let auth_safes = get_auth_safes(&pfx.auth_safe.content)?;
    for auth_safe in auth_safes {
        if ID_ENCRYPTED_DATA == auth_safe.content_type {
            recovered_cert = Some(get_cert(&auth_safe.content, password)?);
        } else if ID_DATA == auth_safe.content_type {
            recovered_key = Some(get_key(&auth_safe.content, password)?);
        }
    }
    if let Some(recovered_cert) = recovered_cert
        && let Some(recovered_key) = recovered_key
    {
        return Ok((recovered_key, Certificate::from_der(&recovered_cert)?));
    }
    Err(Error::NotFound)
}
