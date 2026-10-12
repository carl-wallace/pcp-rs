//! Utility functions that support `pcp-rs` operations

use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

use log::{debug, error};
use zerocopy::IntoBytes;

use aes::{Aes128, Aes192, Aes256};
use aes_gcm::{
    Aes128Gcm, Aes256Gcm, Key,
    aead::{AeadInOut, Nonce},
};
use aes_kw::AesKw;
use cipher::{BlockModeDecrypt, Iv, KeyInit, KeyIvInit};
use elliptic_curve::{
    CurveArithmetic, FieldBytesSize,
    sec1::{FromSec1Point, ModulusSize, ToSec1Point, ValidatePublicKey},
};
use hkdf::Hkdf;
use ml_dsa::{KeyGen, MlDsa44, MlDsa65, MlDsa87};
#[allow(deprecated)]
use ml_kem::ExpandedKeyEncoding;
use ml_kem::{
    B32, ExpandedDecapsulationKey, FromSeed, KeyExport, MlKem512, MlKem768, MlKem1024,
    array::ArrayN, kem::Decapsulate,
};

use rsa::pkcs1::EncodeRsaPublicKey;
use sha2::{Digest, Sha256, Sha384, Sha512};
use tari_tiny_keccak::{Hasher, Kmac};

use cms::{
    builder::{ContentEncryptionAlgorithm, EnvelopedDataBuilder},
    cert::IssuerAndSerialNumber,
    content_info::ContentInfo,
    enveloped_data::{
        EnvelopedData, KeyTransRecipientInfo, OtherRecipientInfo, RecipientIdentifier,
        RecipientInfo,
    },
    kemri::CmsOriForKemOtherInfo,
};
use const_oid::{
    AssociatedOid, ObjectIdentifier,
    db::{
        fips203::{ID_ALG_ML_KEM_512, ID_ALG_ML_KEM_768, ID_ALG_ML_KEM_1024},
        fips204::*,
        fips205::*,
        rfc5280::{ID_CE_KEY_USAGE, ID_CE_SUBJECT_KEY_IDENTIFIER},
        rfc5911::{
            ID_AES_128_CBC, ID_AES_128_GCM, ID_AES_128_WRAP, ID_AES_192_CBC, ID_AES_192_WRAP,
            ID_AES_256_CBC, ID_AES_256_GCM, ID_AES_256_WRAP, ID_CT_AUTH_ENVELOPED_DATA,
            ID_ENVELOPED_DATA,
        },
    },
};

use der::{Any, AnyRef, Decode, Encode, asn1::OctetString};
use x509_cert::{
    Certificate,
    ext::pkix::{KeyUsage, KeyUsages, SubjectKeyIdentifier},
};

use pqckeys::{oak::OneAsymmetricKey, pqc_oids::*};

use crate::{
    asn1::{
        EcPrivateKey,
        auth_env_data::{AuthEnvelopedData, GcmParameters},
        auth_env_data_builder::AuthEnvelopedDataBuilder,
        kemri_builder,
        oids::{
            ID_ALG_HKDF_WITH_SHA256, ID_ALG_HKDF_WITH_SHA384, ID_ALG_HKDF_WITH_SHA512, ID_KMAC128,
            ID_KMAC256,
        },
        private_key::{
            MlDsa44PrivateKey, MlDsa65PrivateKey, MlDsa87PrivateKey, MlKem512PrivateKey,
            MlKem768PrivateKey, MlKem1024PrivateKey,
        },
        utils,
    },
    error::{Error, Result},
    generation::settings::KeyUsageProfile,
    misc::{ecdh::EcdhKem, rsa::RsaKem},
};

/// Reads a file and tried to parse the contents as a certificate
pub fn get_file_as_cert(filename: &Path) -> Result<Certificate> {
    let der_cert = get_file_as_byte_vec_pem(filename)?;
    Ok(Certificate::from_der(&der_cert)?)
}

/// Reads a file and returns the contents as a `Vec<u8>`
pub fn get_file_as_byte_vec(filename: &Path) -> Result<Vec<u8>> {
    match File::open(filename) {
        Ok(mut f) => match std::fs::metadata(filename) {
            Ok(metadata) => {
                let mut buffer = vec![0; metadata.len() as usize];
                match f.read_exact(&mut buffer) {
                    Ok(_) => Ok(buffer),
                    Err(_e) => Err(Error::UnexpectedValue),
                }
            }
            Err(_e) => Err(Error::UnexpectedValue),
        },
        Err(e) => {
            error!("Failed to open file {filename:?}: {e:?}");
            Err(Error::UnexpectedValue)
        }
    }
}

/// Gets the contents of a file indicated in an optional `PathBuf` as a `Vec<u8>`.
pub fn get_buffer_from_file_arg(file_name: &Option<PathBuf>) -> Result<Vec<u8>> {
    match file_name {
        Some(file_name) => {
            if !file_name.exists() {
                error!("{} does not exist", file_name.to_str().unwrap_or_default());
                Err(Error::UnexpectedValue)
            } else {
                get_file_as_byte_vec(file_name)
            }
        }
        None => Err(Error::UnexpectedValue),
    }
}

/// Reads a buffer from a file. If the buffer starts with a '-', the buffer is PEM decoded and
/// returned. Otherwise, the buffer read from the file is returned.
pub fn get_file_as_byte_vec_pem(filename: &Path) -> Result<Vec<u8>> {
    let b = get_file_as_byte_vec(filename)?;
    if b[0] == 0x2D {
        return match pem_rfc7468::decode_vec(b.as_slice()) {
            Ok(b) => Ok(b.1),
            Err(e) => {
                error!("Failed to PEM decode data from {filename:?}: {e:?}");
                Err(Error::Unrecognized)
            }
        };
    }
    Ok(b)
}

/// Determines the [KeyUsageProfile] of a certificate based on its key usage extension.
pub fn cert_type(cert: &Certificate) -> Result<KeyUsageProfile> {
    if let Some(exts) = &cert.tbs_certificate().extensions() {
        for ext in exts.as_slice() {
            if let Ok(ku) = KeyUsage::from_der(ext.extn_value.as_bytes())
                && ext.extn_id == ID_CE_KEY_USAGE
            {
                return if (ku.0.contains(KeyUsages::KeyEncipherment)
                    || ku.0.contains(KeyUsages::KeyAgreement))
                    && !ku.0.contains(KeyUsages::DigitalSignature)
                {
                    Ok(KeyUsageProfile::SignatureOnly)
                } else if !(ku.0.contains(KeyUsages::KeyEncipherment)
                    || ku.0.contains(KeyUsages::KeyAgreement))
                    && ku.0.contains(KeyUsages::DigitalSignature)
                {
                    Ok(KeyUsageProfile::EncryptionOnly)
                } else if (ku.0.contains(KeyUsages::KeyEncipherment)
                    || ku.0.contains(KeyUsages::KeyAgreement))
                    && ku.0.contains(KeyUsages::DigitalSignature)
                {
                    Ok(KeyUsageProfile::SignatureAndEncryption)
                } else {
                    error!("Unrecognized key usage profile");
                    Err(Error::Unrecognized)
                };
            }
        }
    }
    error!("Key usage extension not found");
    Err(Error::NotFound)
}

/// Buffer to hex conversion for logging
pub fn buffer_to_hex(buffer: &[u8]) -> String {
    core::str::from_utf8(&subtle_encoding::hex::encode_upper(buffer))
        .unwrap_or_default()
        .to_string()
}

/// Macro to decrypt data using Aes128Gcm or Aes256Gcn
macro_rules! decrypt_gcm_mode {
    ($data:expr, $aead:ty, $key:expr, $aad:ident, $nonce:ident, $mac:ident) => {{
        #[allow(deprecated)]
        let aes_key = Key::<$aead>::from_slice($key.as_slice());
        let cipher = <$aead>::new(aes_key);
        $data.extend_from_slice($mac);
        #[allow(deprecated)]
        let aes_nonce = Nonce::<$aead>::from_slice($nonce);
        cipher.decrypt_in_place(aes_nonce, $aad.as_slice(), $data)
    }};
}

/// Macro to decrypt data using Aes128, Aes192 or Aes256
macro_rules! decrypt_block_mode {
    ($ct:expr, $alg:ty, $key:expr, $iv:ident) => {{
        type AesType = cbc::Decryptor<$alg>;
        #[allow(deprecated)]
        let aes_key: &Key<AesType> = Key::<AesType>::from_slice($key);
        #[allow(deprecated)]
        let aes_nonce: &Iv<AesType> = Iv::<AesType>::from_slice($iv);
        let cipher = <AesType>::new(aes_key, aes_nonce);
        cipher.decrypt_padded_vec::<cipher::block_padding::Pkcs7>($ct)
    }};
}

/// Macro to decrypt data using ML-KEM512, ML-KEM768 or ML-KEM1024
macro_rules! decrypt_kem_rust_crypto {
    ($kem_ct:expr, $ct_ty:ty, $ee_sk:expr) => {{
        let exp = ExpandedDecapsulationKey::<$ct_ty>::try_from($ee_sk.as_slice()).unwrap();
        #[allow(deprecated)]
        let dk = <$ct_ty as ml_kem::Kem>::DecapsulationKey::from_expanded(&exp)
            .map_err(|e| Error::MlKem(format!("{e:?}")))?;
        let c = ml_kem::Ciphertext::<$ct_ty>::try_from($kem_ct)
            .map_err(|e| Error::MlKem(format!("{e:?}")))?;
        let k = dk.decapsulate(&c);
        k.to_vec()
    }};
}
macro_rules! decrypt_kem_rust_crypto_seed {
    ($kem_ct:expr, $ct_ty:ty, $ee_sk:expr) => {{
        let dk = <$ct_ty as ml_kem::Kem>::DecapsulationKey::new_from_slice($ee_sk.as_slice())
            .map_err(|e| Error::MlKem(format!("{e:?}")))?;
        let c = ml_kem::Ciphertext::<$ct_ty>::try_from($kem_ct)
            .map_err(|e| Error::MlKem(format!("{e:?}")))?;
        let k = dk.decapsulate(&c);
        k.to_vec()
    }};
}

macro_rules! private_key_from_seed {
    ($seed:expr, $ct_ty:ty) => {{
        let (d_bytes, z_bytes) = $seed.as_bytes().split_at(32);
        let d = ArrayN::<u8, 32>::try_from(d_bytes).unwrap();
        let z = ArrayN::<u8, 32>::try_from(z_bytes).unwrap();
        let (dk, _) = <$ct_ty>::from_seed(&d.concat(z));
        let dk_bytes = dk.to_bytes().to_vec();
        dk_bytes
    }};
}

/// Extract subject key identifier value from a certificate
pub(crate) fn skid_from_cert(cert: &Certificate) -> Result<Vec<u8>> {
    if let Some(exts) = cert.tbs_certificate().extensions() {
        for ext in exts {
            if ext.extn_id == ID_CE_SUBJECT_KEY_IDENTIFIER {
                match OctetString::from_der(ext.extn_value.as_bytes()) {
                    Ok(b) => return Ok(b.as_bytes().to_vec()),
                    Err(e) => {
                        error!(
                            "Failed to parse SKID extension: {e:?}. Ignoring error and will use calculated value."
                        );
                    }
                }
            }
        }
    }

    let working_spki = &cert.tbs_certificate().subject_public_key_info();
    match working_spki.subject_public_key.as_bytes() {
        Some(spki) => Ok(Sha256::digest(spki).to_vec()),
        None => {
            error!("Failed to render SPKI as bytes");
            Err(Error::Unrecognized)
        }
    }
}

/// Create a RecipientIdentifier corresponding to certificate
pub fn recipient_identifier_from_cert(cert: &Certificate) -> Result<RecipientIdentifier> {
    match skid_from_cert(cert) {
        Ok(skid_bytes) => {
            let os = match OctetString::new(skid_bytes) {
                Ok(os) => os,
                Err(e) => return Err(Error::Asn1(e)),
            };
            let skid = SubjectKeyIdentifier::from(os);

            Ok(RecipientIdentifier::SubjectKeyIdentifier(skid))
        }
        Err(_) => Ok(RecipientIdentifier::IssuerAndSerialNumber(
            IssuerAndSerialNumber {
                issuer: cert.tbs_certificate().issuer().clone(),
                serial_number: cert.tbs_certificate().serial_number().clone(),
            },
        )),
    }
}

/// Generate an EnvelopedData object
pub fn generate_enveloped_data(
    plaintext: &[u8],
    ee_cert: &Certificate,
    kdf: ObjectIdentifier,
    ukm: Option<Vec<u8>>,
    wrap: ObjectIdentifier,
    enc: ObjectIdentifier,
) -> Result<Vec<u8>> {
    let recipient_info_builder = kemri_builder::kemri_builder_from_cert(ee_cert, kdf, ukm, wrap)?;

    let cea = match enc {
        ID_AES_128_CBC => ContentEncryptionAlgorithm::Aes128Cbc,
        ID_AES_192_CBC => ContentEncryptionAlgorithm::Aes192Cbc,
        ID_AES_256_CBC => ContentEncryptionAlgorithm::Aes256Cbc,
        _ => return Err(Error::Unrecognized),
    };

    let mut enveloped_data_builder = EnvelopedDataBuilder::new(
        None, plaintext, // data to be encrypted...
        cea,       // ... with this algorithm
        None,
    )
    .map_err(|_| Error::Unrecognized)?;

    let enveloped_data = enveloped_data_builder
        .add_recipient_info(recipient_info_builder)
        .map_err(|_| Error::Unrecognized)?
        .build_with_rng(&mut rand::rng())
        .map_err(|_| Error::Unrecognized)?;

    let enveloped_data_der = enveloped_data.to_der()?;
    let content = AnyRef::try_from(enveloped_data_der.as_slice())?;
    let content_info = ContentInfo {
        content_type: ID_ENVELOPED_DATA,
        content: Any::from(content),
    };
    Ok(content_info.to_der()?)
}

/// AEAD content encryption algorithms supported for AuthEnvelopedData.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContentEncryptionAlgorithmAead {
    /// AES-128 GCM
    Aes128Gcm,
    /// AES-256 GCM
    Aes256Gcm,
}

impl ContentEncryptionAlgorithmAead {
    /// Return the OID of the algorithm.
    pub fn oid(&self) -> ObjectIdentifier {
        match self {
            ContentEncryptionAlgorithmAead::Aes128Gcm => ID_AES_128_GCM,
            ContentEncryptionAlgorithmAead::Aes256Gcm => ID_AES_256_GCM,
        }
    }
}

/// Generate an AuthEnvelopedData object
pub fn generate_auth_enveloped_data(
    plaintext: &[u8],
    ee_cert: &Certificate,
    kdf: ObjectIdentifier,
    ukm: Option<Vec<u8>>,
    wrap: ObjectIdentifier,
    enc: ObjectIdentifier,
) -> Result<Vec<u8>> {
    let recipient_info_builder = kemri_builder::kemri_builder_from_cert(ee_cert, kdf, ukm, wrap)?;

    let cea = match enc {
        ID_AES_128_GCM => ContentEncryptionAlgorithmAead::Aes128Gcm,
        ID_AES_256_GCM => ContentEncryptionAlgorithmAead::Aes256Gcm,
        _ => return Err(Error::Unrecognized),
    };

    let mut enveloped_data_builder = AuthEnvelopedDataBuilder::new(
        None, plaintext, // data to be encrypted...
        cea,       // ... with this algorithm
        None, None,
    )
    .map_err(|_| Error::Unrecognized)?;

    let mut rng = rand::rng();
    let enveloped_data = enveloped_data_builder
        .add_recipient_info(recipient_info_builder)
        .map_err(|_| Error::Unrecognized)?
        .build_with_rng(&mut rng)
        .map_err(|_| Error::Unrecognized)?;

    let enveloped_data_der = enveloped_data.to_der()?;
    let content = AnyRef::try_from(enveloped_data_der.as_slice())?;
    let content_info = ContentInfo {
        content_type: ID_CT_AUTH_ENVELOPED_DATA,
        content: Any::from(content),
    };
    Ok(content_info.to_der()?)
}

/// Decrypts the content-encryption key from a [KeyTransRecipientInfo] using the provided RSA private key.
pub fn process_ktri(ktri: &KeyTransRecipientInfo, ee_sk: &[u8]) -> Result<Vec<u8>> {
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::{Pkcs1v15Encrypt, RsaPrivateKey};

    let recipient_private_key = match RsaPrivateKey::from_pkcs1_der(ee_sk) {
        Ok(pk) => pk,
        Err(e) => {
            return Err(Error::General(format!(
                "Failed to parse RSA private key: {e:?}"
            )));
        }
    };
    let content_encryption_key =
        match recipient_private_key.decrypt(Pkcs1v15Encrypt, ktri.enc_key.as_bytes()) {
            Ok(cek) => cek,
            Err(e) => {
                return Err(Error::General(format!(
                    "Failed to decrypt CEK using RSA private key: {e:?}"
                )));
            }
        };

    Ok(content_encryption_key)
}

#[allow(deprecated)] // allow ExpandedKeyEncoding
pub(crate) fn extract_private_key(
    oid: ObjectIdentifier,
    private_key_bytes: &[u8],
) -> Result<Vec<u8>> {
    match oid {
        ID_ALG_ML_KEM_512 => {
            let key = MlKem512PrivateKey::from_der(private_key_bytes)?;
            match key {
                MlKem512PrivateKey::Seed(seed) => {
                    let (d_bytes, z_bytes) = seed.as_bytes().split_at(32);
                    let d = ArrayN::<u8, 32>::try_from(d_bytes)
                        .map_err(|e| Error::General(format!("{e:?}")))?;
                    let z = ArrayN::<u8, 32>::try_from(z_bytes)
                        .map_err(|e| Error::General(format!("{e:?}")))?;
                    let (dk, _) = MlKem512::from_seed(&d.concat(z));
                    Ok(dk.to_expanded_bytes().to_vec())
                }
                MlKem512PrivateKey::ExpandedKey(exp_key) => Ok(exp_key.as_bytes().to_vec()),
                MlKem512PrivateKey::Both(both) => {
                    let (d_bytes, z_bytes) = both.seed.as_bytes().split_at(32);
                    let d = ArrayN::<u8, 32>::try_from(d_bytes)
                        .map_err(|e| Error::General(format!("{e:?}")))?;
                    let z = ArrayN::<u8, 32>::try_from(z_bytes)
                        .map_err(|e| Error::General(format!("{e:?}")))?;
                    let (dk, _) = MlKem512::from_seed(&d.concat(z));
                    if dk.to_expanded_bytes().to_vec() != both.expanded_key.as_bytes().to_vec() {
                        return Err(Error::MlKem(
                            "Inconsistent values in both option".to_string(),
                        ));
                    }
                    Ok(both.expanded_key.as_bytes().to_vec())
                }
            }
        }
        ID_ALG_ML_KEM_768 => {
            let key = MlKem768PrivateKey::from_der(private_key_bytes)?;
            match key {
                MlKem768PrivateKey::Seed(seed) => {
                    let (d_bytes, z_bytes) = seed.as_bytes().split_at(32);
                    let d = ArrayN::<u8, 32>::try_from(d_bytes)
                        .map_err(|e| Error::General(format!("{e:?}")))?;
                    let z = ArrayN::<u8, 32>::try_from(z_bytes)
                        .map_err(|e| Error::General(format!("{e:?}")))?;
                    let (dk, _) = MlKem768::from_seed(&d.concat(z));
                    Ok(dk.to_expanded_bytes().to_vec())
                }
                MlKem768PrivateKey::ExpandedKey(exp_key) => Ok(exp_key.as_bytes().to_vec()),
                MlKem768PrivateKey::Both(both) => {
                    let (d_bytes, z_bytes) = both.seed.as_bytes().split_at(32);
                    let d = ArrayN::<u8, 32>::try_from(d_bytes)
                        .map_err(|e| Error::General(format!("{e:?}")))?;
                    let z = ArrayN::<u8, 32>::try_from(z_bytes)
                        .map_err(|e| Error::General(format!("{e:?}")))?;
                    let (dk, _) = MlKem768::from_seed(&d.concat(z));
                    if dk.to_expanded_bytes().to_vec() != both.expanded_key.as_bytes().to_vec() {
                        return Err(Error::MlKem(
                            "Inconsistent values in both option".to_string(),
                        ));
                    }
                    Ok(both.expanded_key.as_bytes().to_vec())
                }
            }
        }
        ID_ALG_ML_KEM_1024 => {
            let key = MlKem1024PrivateKey::from_der(private_key_bytes)?;
            match key {
                MlKem1024PrivateKey::Seed(seed) => {
                    let (d_bytes, z_bytes) = seed.as_bytes().split_at(32);
                    let d = ArrayN::<u8, 32>::try_from(d_bytes)
                        .map_err(|e| Error::General(format!("{e:?}")))?;
                    let z = ArrayN::<u8, 32>::try_from(z_bytes)
                        .map_err(|e| Error::General(format!("{e:?}")))?;
                    let (dk, _) = MlKem1024::from_seed(&d.concat(z));
                    Ok(dk.to_expanded_bytes().to_vec())
                }
                MlKem1024PrivateKey::ExpandedKey(exp_key) => Ok(exp_key.as_bytes().to_vec()),
                MlKem1024PrivateKey::Both(both) => {
                    let (d_bytes, z_bytes) = both.seed.as_bytes().split_at(32);
                    let d = ArrayN::<u8, 32>::try_from(d_bytes)
                        .map_err(|e| Error::General(format!("{e:?}")))?;
                    let z = ArrayN::<u8, 32>::try_from(z_bytes)
                        .map_err(|e| Error::General(format!("{e:?}")))?;
                    let (dk, _) = MlKem1024::from_seed(&d.concat(z));
                    if dk.to_expanded_bytes().to_vec() != both.expanded_key.as_bytes().to_vec() {
                        return Err(Error::MlKem(
                            "Inconsistent values in both option".to_string(),
                        ));
                    }
                    Ok(both.expanded_key.as_bytes().to_vec())
                }
            }
        }
        ID_ML_DSA_44 => {
            let key = MlDsa44PrivateKey::from_der(private_key_bytes)?;
            match key {
                MlDsa44PrivateKey::Seed(seed) => {
                    let b32 = B32::try_from(seed.as_bytes())?;
                    Ok(MlDsa44::from_seed(&b32)
                        .signing_key()
                        .to_expanded()
                        .as_bytes()
                        .to_vec())
                }
                MlDsa44PrivateKey::ExpandedKey(exp_key) => Ok(exp_key.as_bytes().to_vec()),
                MlDsa44PrivateKey::Both(both) => {
                    let b32 = B32::try_from(both.seed.as_bytes())?;
                    let ek = MlDsa44::from_seed(&b32)
                        .signing_key()
                        .to_expanded()
                        .as_bytes()
                        .to_vec();
                    if ek.as_bytes().to_vec() != both.expanded_key.as_bytes().to_vec() {
                        return Err(Error::MlKem(
                            "Inconsistent values in both option".to_string(),
                        ));
                    }
                    Ok(both.expanded_key.as_bytes().to_vec())
                }
            }
        }
        ID_ML_DSA_65 => {
            let key = MlDsa65PrivateKey::from_der(private_key_bytes)?;
            match key {
                MlDsa65PrivateKey::Seed(seed) => {
                    let b32 = B32::try_from(seed.as_bytes())?;
                    Ok(MlDsa65::from_seed(&b32)
                        .signing_key()
                        .to_expanded()
                        .as_bytes()
                        .to_vec())
                }
                MlDsa65PrivateKey::ExpandedKey(exp_key) => Ok(exp_key.as_bytes().to_vec()),
                MlDsa65PrivateKey::Both(both) => {
                    let b32 = B32::try_from(both.seed.as_bytes())?;
                    let ek = MlDsa65::from_seed(&b32)
                        .signing_key()
                        .to_expanded()
                        .as_bytes()
                        .to_vec();
                    if ek.as_bytes().to_vec() != both.expanded_key.as_bytes().to_vec() {
                        return Err(Error::MlKem(
                            "Inconsistent values in both option".to_string(),
                        ));
                    }
                    Ok(both.expanded_key.as_bytes().to_vec())
                }
            }
        }
        ID_ML_DSA_87 => {
            let key = MlDsa87PrivateKey::from_der(private_key_bytes)?;
            match key {
                MlDsa87PrivateKey::Seed(seed) => {
                    let b32 = B32::try_from(seed.as_bytes())?;
                    Ok(MlDsa87::from_seed(&b32)
                        .signing_key()
                        .to_expanded()
                        .as_bytes()
                        .to_vec())
                }
                MlDsa87PrivateKey::ExpandedKey(exp_key) => Ok(exp_key.as_bytes().to_vec()),
                MlDsa87PrivateKey::Both(both) => {
                    let b32 = B32::try_from(both.seed.as_bytes())?;
                    let ek = MlDsa87::from_seed(&b32)
                        .signing_key()
                        .to_expanded()
                        .as_bytes()
                        .to_vec();
                    if ek.as_bytes().to_vec() != both.expanded_key.as_bytes().to_vec() {
                        return Err(Error::MlKem(
                            "Inconsistent values in both option".to_string(),
                        ));
                    }
                    Ok(both.expanded_key.as_bytes().to_vec())
                }
            }
        }
        _ => Ok(private_key_bytes.to_vec()),
    }
}

fn parse_composite_key(private_key_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    // mlkemSeed || tradSK
    let (pqc_seed, trad_sk) = private_key_bytes.split_at(64);
    Ok((pqc_seed.to_vec(), trad_sk.to_vec()))
}

fn ml_kem768_rsa(
    kem_ct: &[u8],
    private_key_bytes: &[u8],
    domain: ObjectIdentifier,
) -> Result<Vec<u8>> {
    let (pqc_ct, trad_ct) = kem_ct.split_at(1088);
    let (pqc_seed, trad_sk) = parse_composite_key(private_key_bytes)?;

    let dk_bytes = private_key_from_seed!(pqc_seed, MlKem768);
    let pqc_ss = decrypt_kem_rust_crypto_seed!(pqc_ct, MlKem768, dk_bytes);

    let rsa = RsaKem::new(&trad_sk)?;
    let trad_ss = rsa.decap(trad_ct)?;
    let trad_pk = rsa
        .to_public_key()
        .to_pkcs1_der()
        .map_err(|e| Error::General(format!("{e:?}")))?
        .to_vec();
    utils::kem_combiner(&pqc_ss, &trad_ss, trad_ct, &trad_pk, domain)
}

fn ml_kem1024_rsa(
    kem_ct: &[u8],
    private_key_bytes: &[u8],
    domain: ObjectIdentifier,
) -> Result<Vec<u8>> {
    let (pqc_ct, trad_ct) = kem_ct.split_at(1568);
    let (pqc_seed, trad_sk) = parse_composite_key(private_key_bytes)?;

    let dk_bytes = private_key_from_seed!(pqc_seed, MlKem1024);
    let pqc_ss = decrypt_kem_rust_crypto_seed!(pqc_ct, MlKem1024, dk_bytes);

    let rsa = RsaKem::new(&trad_sk)?;
    let trad_ss = rsa.decap(trad_ct)?;
    let trad_pk = rsa
        .to_public_key()
        .to_pkcs1_der()
        .map_err(|e| Error::General(format!("{e:?}")))?
        .to_vec();
    utils::kem_combiner(&pqc_ss, &trad_ss, trad_ct, &trad_pk, domain)
}

fn ml_kem768_ecdh<C>(
    kem_ct: &[u8],
    private_key_bytes: &[u8],
    domain: ObjectIdentifier,
) -> Result<Vec<u8>>
where
    C: AssociatedOid + elliptic_curve::Curve + CurveArithmetic + ValidatePublicKey,
    FieldBytesSize<C>: ModulusSize,
    <C as CurveArithmetic>::AffinePoint: FromSec1Point<C>,
    <C as CurveArithmetic>::AffinePoint: ToSec1Point<C>,
{
    let (pqc_ct, trad_ct) = kem_ct.split_at(1088);
    let (pqc_seed, trad_sk) = parse_composite_key(private_key_bytes)?;

    let dk_bytes = private_key_from_seed!(pqc_seed, MlKem768);
    let pqc_ss = decrypt_kem_rust_crypto_seed!(pqc_ct, MlKem768, dk_bytes);

    let oak = EcPrivateKey::from_der(&trad_sk)?;

    let ecdh = EcdhKem::<C>::new(oak.private_key.as_bytes())?;
    let trad_ss = ecdh.decap(trad_ct)?;
    let trad_pk = ecdh
        .to_public_key()
        .to_sec1_point(false)
        .as_bytes()
        .to_vec();
    utils::kem_combiner(&pqc_ss, &trad_ss, trad_ct, &trad_pk, domain)
}

fn ml_kem1024_ecdh<C>(
    kem_ct: &[u8],
    private_key_bytes: &[u8],
    domain: ObjectIdentifier,
) -> Result<Vec<u8>>
where
    C: AssociatedOid + elliptic_curve::Curve + CurveArithmetic + ValidatePublicKey,
    FieldBytesSize<C>: ModulusSize,
    <C as CurveArithmetic>::AffinePoint: FromSec1Point<C>,
    <C as CurveArithmetic>::AffinePoint: ToSec1Point<C>,
{
    let (pqc_ct, trad_ct) = kem_ct.split_at(1568);
    let (pqc_seed, trad_sk) = parse_composite_key(private_key_bytes)?;

    let dk_bytes = private_key_from_seed!(pqc_seed, MlKem1024);
    let pqc_ss = decrypt_kem_rust_crypto_seed!(pqc_ct, MlKem1024, dk_bytes);

    let oak = EcPrivateKey::from_der(&trad_sk)?;

    let ecdh = EcdhKem::<C>::new(oak.private_key.as_bytes())?;
    let trad_ss = ecdh.decap(trad_ct)?;
    let trad_pk = ecdh
        .to_public_key()
        .to_sec1_point(false)
        .as_bytes()
        .to_vec();
    utils::kem_combiner(&pqc_ss, &trad_ss, trad_ct, &trad_pk, domain)
}
/// Process KemRecipientInfo using the provided private key
pub fn process_kemri(ori: &OtherRecipientInfo, private_key_bytes: &[u8]) -> Result<Vec<u8>> {
    let ori_value = ori.ori_value.to_der()?;
    let kemri = cms::kemri::KemRecipientInfo::from_der(&ori_value)?;
    let kem_ct = kemri.kem_ct.as_bytes();
    let ss = match kemri.kem.oid {
        ID_ALG_ML_KEM_512 => {
            let ee_sk = extract_private_key(ID_ALG_ML_KEM_512, private_key_bytes)?;
            decrypt_kem_rust_crypto!(kem_ct, MlKem512, ee_sk)
        }
        ID_ALG_ML_KEM_768 => {
            let ee_sk = extract_private_key(ID_ALG_ML_KEM_768, private_key_bytes)?;
            decrypt_kem_rust_crypto!(kem_ct, MlKem768, ee_sk)
        }
        ID_ALG_ML_KEM_1024 => {
            let ee_sk = extract_private_key(ID_ALG_ML_KEM_1024, private_key_bytes)?;
            decrypt_kem_rust_crypto!(kem_ct, MlKem1024, ee_sk)
        }
        ID_MLKEM768_RSA2048_SHA3_256 => {
            ml_kem768_rsa(kem_ct, private_key_bytes, ID_MLKEM768_RSA2048_SHA3_256)?
        }
        ID_MLKEM768_RSA3072_SHA3_256 => {
            ml_kem768_rsa(kem_ct, private_key_bytes, ID_MLKEM768_RSA3072_SHA3_256)?
        }
        ID_MLKEM768_RSA4096_SHA3_256 => {
            ml_kem768_rsa(kem_ct, private_key_bytes, ID_MLKEM768_RSA4096_SHA3_256)?
        }
        ID_MLKEM1024_RSA3072_SHA3_256 => {
            ml_kem1024_rsa(kem_ct, private_key_bytes, ID_MLKEM1024_RSA3072_SHA3_256)?
        }
        ID_MLKEM768_X25519_SHA3_256 => {
            todo!("Decrypt with EC variants")
        }
        ID_MLKEM768_ECDH_P256_SHA3_256 => ml_kem768_ecdh::<p256::NistP256>(
            kem_ct,
            private_key_bytes,
            ID_MLKEM768_ECDH_P256_SHA3_256,
        )?,
        ID_MLKEM768_ECDH_P384_SHA3_256 => ml_kem768_ecdh::<p384::NistP384>(
            kem_ct,
            private_key_bytes,
            ID_MLKEM768_ECDH_P384_SHA3_256,
        )?,
        ID_MLKEM1024_ECDH_P384_SHA3_256 => ml_kem1024_ecdh::<p384::NistP384>(
            kem_ct,
            private_key_bytes,
            ID_MLKEM1024_ECDH_P384_SHA3_256,
        )?,
        ID_MLKEM1024_X448_SHA3_256 => {
            todo!("Decrypt with EC variants")
        }
        ID_MLKEM1024_ECDH_P521_SHA3_256 => ml_kem1024_ecdh::<p521::NistP521>(
            kem_ct,
            private_key_bytes,
            ID_MLKEM1024_ECDH_P521_SHA3_256,
        )?,
        _ => {
            error!("Unrecognized KEM algorithm: {}", kemri.kem.oid);
            return Err(Error::Unrecognized);
        }
    };

    let kdf_input = CmsOriForKemOtherInfo {
        wrap: kemri.wrap.clone(),
        kek_length: kemri.kek_length,
        ukm: kemri.ukm,
    };
    let der_kdf_input = kdf_input.to_der()?;

    debug!("Shared Secret: {}", buffer_to_hex(&ss));
    debug!("CMSORIforKEMOtherInfo: {}", buffer_to_hex(&der_kdf_input));
    let mut okm = vec![0; utils::get_block_size(&kemri.wrap.oid)?];
    match kemri.kdf.oid {
        ID_ALG_HKDF_WITH_SHA256 => {
            let hk = Hkdf::<Sha256>::new(None, &ss);
            hk.expand(&der_kdf_input, &mut okm)
                .map_err(|_e| Error::Unrecognized)?;
        }
        ID_ALG_HKDF_WITH_SHA384 => {
            let hk = Hkdf::<Sha384>::new(None, &ss);
            hk.expand(&der_kdf_input, &mut okm)
                .map_err(|_e| Error::Unrecognized)?;
        }
        ID_ALG_HKDF_WITH_SHA512 => {
            let hk = Hkdf::<Sha512>::new(None, &ss);
            hk.expand(&der_kdf_input, &mut okm)
                .map_err(|_e| Error::Unrecognized)?;
        }
        ID_KMAC128 => {
            let custom = b"";
            let mut kmac = Kmac::v128(&ss, custom);
            kmac.update(&der_kdf_input);
            kmac.finalize(&mut okm);
        }
        ID_KMAC256 => {
            let custom = b"";
            let mut kmac = Kmac::v256(&ss, custom);
            kmac.update(&der_kdf_input);
            kmac.finalize(&mut okm);
        }
        _ => {
            error!("Unrecognized KDF algorithm: {}", kemri.kdf.oid);
            return Err(Error::Unrecognized);
        }
    };

    debug!("KEK: {}", buffer_to_hex(&okm));
    debug!(
        "Wrapped CEK: {}",
        buffer_to_hex(kemri.encrypted_key.as_bytes())
    );

    let mut wrapped_key = vec![0; kemri.kek_length as usize];
    match kemri.wrap.oid {
        ID_AES_128_WRAP => {
            let kek: AesKw<Aes128> = AesKw::<Aes128>::new_from_slice(okm.as_slice())
                .map_err(|_e| Error::Unrecognized)?;
            if let Err(e) = kek.unwrap_key(kemri.encrypted_key.as_bytes(), &mut wrapped_key) {
                error!("Unwrap failed: {e:?}");
            }
            wrapped_key.to_vec()
        }
        ID_AES_192_WRAP => {
            let kek: AesKw<Aes192> = AesKw::<Aes192>::new_from_slice(okm.as_slice())
                .map_err(|_e| Error::Unrecognized)?;
            if let Err(e) = kek.unwrap_key(kemri.encrypted_key.as_bytes(), &mut wrapped_key) {
                error!("Unwrap failed: {e:?}");
            }
            wrapped_key.to_vec()
        }
        ID_AES_256_WRAP => {
            let kek: AesKw<Aes256> = AesKw::<Aes256>::new_from_slice(okm.as_slice())
                .map_err(|_e| Error::Unrecognized)?;
            if let Err(e) = kek.unwrap_key(kemri.encrypted_key.as_bytes(), &mut wrapped_key) {
                error!("Unwrap failed: {e:?}");
            }
            wrapped_key.to_vec()
        }
        _ => panic!(),
    };
    Ok(wrapped_key.to_vec())
}

/// Process a ContentInfo as an EnvelopedData or AuthEnvelopedData using the provided private key
pub fn process_content_info(enveloped_data: &[u8], ee_oak: &[u8]) -> Result<Vec<u8>> {
    let oak = if 0x30 == ee_oak[0] {
        OneAsymmetricKey::from_der(ee_oak)?
    } else {
        panic!()
        // todo - fix trait bounds error
        // OneAsymmetricKey::from_pem(ee_oak)?
    };
    let ci = ContentInfo::from_der(enveloped_data)?;
    if ci.content_type == ID_ENVELOPED_DATA {
        process_enveloped_data(&ci.content.to_der()?, oak.private_key.as_bytes())
    } else if ci.content_type == ID_CT_AUTH_ENVELOPED_DATA {
        process_auth_enveloped_data(&ci.content.to_der()?, oak.private_key.as_bytes())
    } else {
        Err(Error::Unrecognized)
    }
}

/// Process AuthEnvelopedData using the provided private key
pub fn process_auth_enveloped_data(enveloped_data_bytes: &[u8], ee_sk: &[u8]) -> Result<Vec<u8>> {
    let ed = AuthEnvelopedData::from_der(enveloped_data_bytes)?;
    let params = match ed.auth_encrypted_content.content_enc_alg.parameters {
        Some(p) => p,
        None => {
            error!("Failed to read encrypted content algorithm parameters field");
            return Err(Error::Unrecognized);
        }
    };
    let enc_params = params.to_der()?;

    let gcm_params = GcmParameters::from_der(&enc_params)?;

    let mut ct = match ed.auth_encrypted_content.encrypted_content {
        Some(ct) => ct.as_bytes().to_vec(),
        None => {
            error!("Failed to read encrypted content field");
            return Err(Error::Unrecognized);
        }
    };

    let aad = match &ed.auth_attrs {
        Some(attrs) => attrs.to_der()?,
        None => "".as_bytes().to_vec(),
    };

    for ri in ed.recip_infos.0.iter() {
        let key = match ri {
            RecipientInfo::Ori(ori) => process_kemri(ori, ee_sk)?,
            RecipientInfo::Ktri(ktri) => process_ktri(ktri, ee_sk)?,
            _ => {
                // todo implement support for recipient info types other than KEMRecipientInfo
                continue;
            }
        };

        debug!("CEK: {}", buffer_to_hex(&key));
        debug!("Nonce: {}", buffer_to_hex(gcm_params.nonce.as_bytes()));
        let nonce = gcm_params.nonce.as_bytes();
        let mac = ed.mac.as_bytes();
        match ed.auth_encrypted_content.content_enc_alg.oid {
            ID_AES_128_GCM => {
                if decrypt_gcm_mode!(&mut ct, Aes128Gcm, &key, aad, nonce, mac).is_ok() {
                    return Ok(ct);
                }
            }
            ID_AES_256_GCM => {
                if decrypt_gcm_mode!(&mut ct, Aes256Gcm, &key, aad, nonce, mac).is_ok() {
                    return Ok(ct);
                }
            }
            _ => {
                error!(
                    "Unrecognized content encryption algorithm: {}",
                    ed.auth_encrypted_content.content_enc_alg.oid
                );
                return Err(Error::Unrecognized);
            }
        }
    }

    error!("Failed to process AuthEnvelopedData");
    Err(Error::Unrecognized)
}

/// Process EnvelopedData using the provided private key
pub fn process_enveloped_data(enveloped_data_bytes: &[u8], ee_sk: &[u8]) -> Result<Vec<u8>> {
    let ed = EnvelopedData::from_der(enveloped_data_bytes)?;

    let params = match ed.encrypted_content.content_enc_alg.parameters {
        Some(p) => p,
        None => {
            error!("Failed to read encrypted content algorithm parameters field");
            return Err(Error::Unrecognized);
        }
    };
    let enc_params = params.to_der()?;

    let os_iv = OctetString::from_der(&enc_params)?;
    let iv = os_iv.as_bytes();

    let ct = match ed.encrypted_content.encrypted_content {
        Some(ct) => ct.as_bytes().to_vec(),
        None => {
            error!("Failed to read encrypted content field");
            return Err(Error::Unrecognized);
        }
    };

    for ri in ed.recip_infos.0.iter() {
        let key = match ri {
            RecipientInfo::Ori(ori) => process_kemri(ori, ee_sk)?,
            RecipientInfo::Ktri(ktri) => process_ktri(ktri, ee_sk)?,
            _ => continue,
        };

        match ed.encrypted_content.content_enc_alg.oid {
            ID_AES_128_CBC => {
                return decrypt_block_mode!(&ct, Aes128, &key, iv)
                    .map_err(|_e| Error::Unrecognized);
            }
            ID_AES_192_CBC => {
                return decrypt_block_mode!(&ct, Aes192, &key, iv)
                    .map_err(|_e| Error::Unrecognized);
            }
            ID_AES_256_CBC => {
                return decrypt_block_mode!(&ct, Aes256, &key, iv)
                    .map_err(|_e| Error::Unrecognized);
            }
            _ => {
                error!(
                    "Unrecognized content encryption algorithm: {}",
                    ed.encrypted_content.content_enc_alg.oid
                );
                continue;
            }
        }
    }

    error!("Failed to process EnvelopedData");
    Err(Error::Unrecognized)
}

/// Read certificate from file identified in file_name param, if present
pub fn get_cert_from_file_arg(file_name: &Option<PathBuf>) -> Result<Certificate> {
    let der = get_buffer_from_file_arg(file_name)?;
    Ok(Certificate::from_der(&der)?)
}

/// Returns a human-readable filename fragment for the given algorithm OID.
pub fn get_filename_from_oid(oid: ObjectIdentifier) -> String {
    match oid {
        ID_ALG_ML_KEM_512 => "mlkem512".to_string(),
        ID_ALG_ML_KEM_768 => "mlkem768".to_string(),
        ID_ALG_ML_KEM_1024 => "mlkem1024".to_string(),
        ID_MLKEM768_RSA2048_SHA3_256 => "id-MLKEM768-RSA2048-SHA3-256".to_string(),
        ID_MLKEM768_RSA3072_SHA3_256 => "id-MLKEM768-RSA3072-SHA3-256".to_string(),
        ID_MLKEM768_RSA4096_SHA3_256 => "id-MLKEM768-RSA4096-SHA3-256".to_string(),
        ID_MLKEM1024_RSA3072_SHA3_256 => "id-MLKEM1024-RSA3072-SHA3-256".to_string(),
        ID_MLKEM768_X25519_SHA3_256 => "id-MLKEM768-x25519-SHA3-256".to_string(),
        ID_MLKEM768_ECDH_P256_SHA3_256 => "id-MLKEM768-ECDH-P256-SHA3-256".to_string(),
        ID_MLKEM768_ECDH_P384_SHA3_256 => "id-MLKEM768-ECDH-P384-SHA3-256".to_string(),
        ID_MLKEM1024_ECDH_P384_SHA3_256 => "id-MLKEM1024-ECDH-P384-SHA3-256".to_string(),
        ID_MLKEM1024_X448_SHA3_256 => "id-MLKEM768-RSA2048-SHA3-256".to_string(),
        ID_MLKEM1024_ECDH_P521_SHA3_256 => "id-MLKEM1024-ECDH-P521-SHA3-256".to_string(),
        ID_ML_DSA_44 => "ml-dsa-44".to_string(),
        ID_ML_DSA_65 => "ml-dsa-65".to_string(),
        ID_ML_DSA_87 => "ml-dsa-87".to_string(),
        ID_SLH_DSA_SHA_2_128_S => "slh-dsa-sha2-128s".to_string(),
        ID_SLH_DSA_SHA_2_128_F => "slh-dsa-sha2-128f".to_string(),
        ID_SLH_DSA_SHA_2_192_S => "slh-dsa-sha2-192s".to_string(),
        ID_SLH_DSA_SHA_2_192_F => "slh-dsa-sha2-192f".to_string(),
        ID_SLH_DSA_SHA_2_256_S => "slh-dsa-sha2-256s".to_string(),
        ID_SLH_DSA_SHA_2_256_F => "slh-dsa-sha2-256f".to_string(),
        ID_SLH_DSA_SHAKE_128_S => "slh-dsa-shake-128s".to_string(),
        ID_SLH_DSA_SHAKE_128_F => "slh-dsa-shake-128f".to_string(),
        ID_SLH_DSA_SHAKE_192_S => "slh-dsa-shake-192s".to_string(),
        ID_SLH_DSA_SHAKE_192_F => "slh-dsa-shake-192f".to_string(),
        ID_SLH_DSA_SHAKE_256_S => "slh-dsa-shake-256s".to_string(),
        ID_SLH_DSA_SHAKE_256_F => "slh-dsa-shake-256f".to_string(),
        ID_MLDSA44_RSA2048_PSS_SHA256 => "ml-dsa-44-rsa2048-pss".to_string(),
        ID_MLDSA44_RSA2048_PKCS15_SHA256 => "ml-dsa-44-rsa2048-pkcs15".to_string(),
        ID_MLDSA44_ED25519_SHA512 => "ml-dsa-44-ed25519".to_string(),
        ID_MLDSA44_ECDSA_P256_SHA256 => "ml-dsa-44-ecdsa-p256".to_string(),
        ID_MLDSA65_RSA3072_PSS_SHA512 => "ml-dsa-65-rsa3072-pss".to_string(),
        ID_MLDSA65_RSA4096_PSS_SHA512 => "ml-dsa-65-rsa4096-pss".to_string(),
        ID_MLDSA65_RSA4096_PKCS15_SHA512 => "ml-dsa-65-rsa4096-pkcs15".to_string(),
        ID_MLDSA65_ECDSA_P256_SHA512 => "ml-dsa-65-ecdsa-p256".to_string(),
        ID_MLDSA65_ECDSA_P384_SHA512 => "ml-dsa-65-ecdsa-p384".to_string(),
        ID_MLDSA65_ED25519_SHA512 => "ml-dsa-65-ed25519".to_string(),
        ID_MLDSA87_ECDSA_P384_SHA512 => "ml-dsa-87-ecdsa-p384".to_string(),
        ID_MLDSA87_ED448_SHAKE256 => "ml-dsa-87-ed448".to_string(),
        ID_MLDSA87_RSA3072_PSS_SHA512 => "ml-dsa-87-rsa3072-pss".to_string(),
        ID_MLDSA87_RSA4096_PSS_SHA512 => "ml-dsa-87-rsa4096-pss".to_string(),
        ID_MLDSA87_ECDSA_P521_SHA512 => "ml-dsa-87-ecdsa-p521".to_string(),
        _ => "Unrecognized".to_string(),
    }
}
