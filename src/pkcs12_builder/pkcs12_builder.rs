//! Structure to help with generating [PKCS #12 objects](pkcs12::pfx::Pfx)

use rand_core::CryptoRng;

use pkcs5::{
    pbes2,
    pbes2::{AES_256_CBC_OID, Kdf, PBES2_OID, Pbkdf2Params, Pbkdf2Prf},
};
use pkcs8::EncryptedPrivateKeyInfo;
use spki::AlgorithmIdentifier;

use cms::{
    content_info::{CmsVersion, ContentInfo},
    encrypted_data::EncryptedData,
    enveloped_data::EncryptedContentInfo,
};
use const_oid::{
    ObjectIdentifier,
    db::rfc5911::{ID_DATA, ID_ENCRYPTED_DATA},
};
use der::{
    Any, AnyRef, Decode, Encode,
    asn1::{OctetString, SetOfVec},
};
use pkcs5::pbes2::Salt;
use pkcs12::{
    CertBag, PKCS_12_CERT_BAG_OID, PKCS_12_PKCS8_KEY_BAG_OID, PKCS_12_X509_CERT_OID,
    pfx::{Pfx, Version},
    safe_bag::SafeBag,
};
use x509_cert::{Certificate, attr::Attribute, spki::AlgorithmIdentifierOwned};

use crate::{Error, Result};

use crate::pkcs12_builder::{
    mac_data_builder::MacDataBuilder,
    supported_algs::{EncryptionAlgorithm, MacAlgorithm},
};

/// Helper for building [PKCS #12 objects](pkcs12::pfx::Pfx) that feature one key and one certificate (for which no
/// pairwise consistency check is performed). For each of key and certificate, a KDF algorithm, a
/// certificate algorithm and a set of attributes may be specified. By default, PBKDF2 with SHA 256 HMAC
/// is used as the KDF algorithm and AES 256 CBC is used as the encryption algorithm.
pub struct Pkcs12Builder {
    cert_attributes: Option<SetOfVec<Attribute>>,
    cert_kdf_algorithm: Option<Pbkdf2Prf>,
    cert_enc_algorithm: Option<EncryptionAlgorithm>,
    cert_kdf_algorithm_identifier: Option<AlgorithmIdentifierOwned>,
    cert_enc_algorithm_identifier: Option<AlgorithmIdentifierOwned>,
    key_attributes: Option<SetOfVec<Attribute>>,
    key_kdf_algorithm: Option<Pbkdf2Prf>,
    key_enc_algorithm: Option<EncryptionAlgorithm>,
    key_kdf_algorithm_identifier: Option<AlgorithmIdentifierOwned>,
    key_enc_algorithm_identifier: Option<AlgorithmIdentifierOwned>,
    mac_data_builder: Option<MacDataBuilder>,
}

impl Default for Pkcs12Builder {
    /// Generate a new Pkcs12Builder instance with all default values.
    fn default() -> Self {
        Pkcs12Builder::new()
    }
}

impl Pkcs12Builder {
    /// Generate a new Pkcs12Builder instance with all default values.
    pub fn new() -> Pkcs12Builder {
        Pkcs12Builder {
            cert_attributes: None,
            cert_kdf_algorithm: None,
            cert_enc_algorithm: None,
            cert_kdf_algorithm_identifier: None,
            cert_enc_algorithm_identifier: None,
            key_attributes: None,
            key_kdf_algorithm: None,
            key_enc_algorithm: None,
            key_kdf_algorithm_identifier: None,
            key_enc_algorithm_identifier: None,
            mac_data_builder: None,
        }
    }

    /// Set attributes to associated with the certificate included in the generated [PKCS #12 object](pkcs12::pfx::Pfx).
    pub fn cert_attributes(&mut self, attrs: Option<SetOfVec<Attribute>>) -> &mut Self {
        self.cert_attributes = attrs;
        self
    }
    /// Set the KDF algorithm to use when protecting the certificate included in the generated [PKCS #12 object](pkcs12::pfx::Pfx).
    pub fn cert_kdf_algorithm(&mut self, alg: Option<Pbkdf2Prf>) -> &mut Self {
        self.cert_kdf_algorithm_identifier = None;
        self.cert_kdf_algorithm = alg;
        self
    }
    /// Set the encryption algorithm to use when protecting the certificate included in the generated [PKCS #12 object](pkcs12::pfx::Pfx).
    pub fn cert_enc_algorithm(&mut self, alg: Option<EncryptionAlgorithm>) -> &mut Self {
        self.cert_enc_algorithm_identifier = None;
        self.cert_enc_algorithm = alg;
        self
    }
    /// Set the KDF algorithm to use when protecting the certificate included in the generated PKCS
    /// #12 object using a fully populated AlgorithmIdentifier instance.
    pub fn cert_kdf_algorithm_identifier(
        &mut self,
        alg: Option<AlgorithmIdentifierOwned>,
    ) -> &mut Self {
        self.cert_kdf_algorithm = None;
        self.cert_kdf_algorithm_identifier = alg;
        self
    }
    /// Set the encryption algorithm to use when protecting the certificate included in the generated PKCS
    /// #12 object using a fully populated AlgorithmIdentifier instance.
    pub fn cert_enc_algorithm_identifier(
        &mut self,
        alg: Option<AlgorithmIdentifierOwned>,
    ) -> &mut Self {
        self.cert_enc_algorithm = None;
        self.cert_enc_algorithm_identifier = alg;
        self
    }
    /// Set attributes to associated with the key included in the generated [PKCS #12 object](pkcs12::pfx::Pfx).
    pub fn key_attributes(&mut self, attrs: Option<SetOfVec<Attribute>>) -> &mut Self {
        self.key_attributes = attrs;
        self
    }
    /// Set the KDF algorithm to use when protecting the key included in the generated [PKCS #12 object](pkcs12::pfx::Pfx).
    pub fn key_kdf_algorithm(&mut self, alg: Option<Pbkdf2Prf>) -> &mut Self {
        self.key_kdf_algorithm_identifier = None;
        self.key_kdf_algorithm = alg;
        self
    }
    /// Set the encryption algorithm to use when protecting the key included in the generated [PKCS #12 object](pkcs12::pfx::Pfx).
    pub fn key_enc_algorithm(&mut self, alg: Option<EncryptionAlgorithm>) -> &mut Self {
        self.key_enc_algorithm_identifier = None;
        self.key_enc_algorithm = alg;
        self
    }
    /// Set the KDF algorithm to use when protecting the key included in the generated PKCS
    /// #12 object using a fully populated AlgorithmIdentifier instance.
    pub fn key_kdf_algorithm_identifier(
        &mut self,
        alg: Option<AlgorithmIdentifierOwned>,
    ) -> &mut Self {
        self.key_kdf_algorithm = None;
        self.key_kdf_algorithm_identifier = alg;
        self
    }
    /// Set the encryption algorithm to use when protecting the key included in the generated PKCS
    /// #12 object using a fully populated AlgorithmIdentifier instance.
    pub fn key_enc_algorithm_identifier(
        &mut self,
        alg: Option<AlgorithmIdentifierOwned>,
    ) -> &mut Self {
        self.key_enc_algorithm = None;
        self.key_enc_algorithm_identifier = alg;
        self
    }
    /// Set a MacDataBuilder instance for use in generating a MAC for the [PKCS #12 object](pkcs12::pfx::Pfx).
    pub fn mac_data_builder(&mut self, mdb: Option<MacDataBuilder>) -> &mut Self {
        self.mac_data_builder = mdb;
        self
    }

    fn default_mac_data<R>(rng: &mut R) -> Result<MacDataBuilder>
    where
        R: CryptoRng,
    {
        let mut salt = vec![0_u8; 8];
        rng.fill_bytes(salt.as_mut_slice());

        let mut md_builder = MacDataBuilder::new(MacAlgorithm::HmacSha256);
        md_builder.iterations(Some(2048));
        md_builder.salt(Some(salt.to_vec()));
        Ok(md_builder)
    }
    fn default_kdf_alg<R>(rng: &mut R) -> Result<AlgorithmIdentifierOwned>
    where
        R: CryptoRng,
    {
        let mut salt = vec![0_u8; 8];
        rng.fill_bytes(salt.as_mut_slice());

        let cert_kdf_params = Pbkdf2Params {
            salt: Salt::new(salt)?,
            iteration_count: 2048,
            key_length: None,
            prf: Pbkdf2Prf::HmacWithSha256,
        };
        let enc_cert_kdf_params = cert_kdf_params.to_der()?;
        let enc_cert_kdf_params_ref = AnyRef::try_from(enc_cert_kdf_params.as_slice())?;
        Ok(AlgorithmIdentifierOwned {
            oid: PBES2_OID,
            parameters: Some(Any::from(enc_cert_kdf_params_ref)),
        })
    }

    fn default_enc_alg<R>(rng: &mut R) -> Result<AlgorithmIdentifierOwned>
    where
        R: CryptoRng,
    {
        let mut iv = vec![0_u8; 16];
        rng.fill_bytes(iv.as_mut_slice());

        let cert_iv = OctetString::new(iv)?.to_der()?;
        let cert_iv_ref = AnyRef::try_from(cert_iv.as_slice())?;
        Ok(AlgorithmIdentifier {
            oid: AES_256_CBC_OID,
            parameters: Some(Any::from(cert_iv_ref)),
        })
    }

    /// Builds a [PKCS #12 object](pkcs12::pfx::Pfx) containing the provided certificate and key protected using password-based
    /// encryption and MAC. Where KDF, encryption or MAC details have not been previously specified
    /// default values are used with the provided RNG used to generate any necessary random values.
    pub fn build_with_rng<R>(
        &mut self,
        certificate: &Certificate,
        key: &[u8],
        password: &str,
        rng: &mut R,
    ) -> Result<Vec<u8>>
    where
        R: CryptoRng,
    {
        if let Some(prf) = self.cert_kdf_algorithm {
            let mut salt = vec![0_u8; 8];
            rng.fill_bytes(salt.as_mut_slice());

            let cert_kdf_params = Pbkdf2Params {
                salt: Salt::new(salt)?,
                iteration_count: 2048,
                key_length: None,
                prf,
            };
            let enc_cert_kdf_params = cert_kdf_params.to_der()?;
            let enc_cert_kdf_params_ref = AnyRef::try_from(enc_cert_kdf_params.as_slice())?;
            self.cert_kdf_algorithm_identifier(Some(AlgorithmIdentifierOwned {
                oid: PBES2_OID,
                parameters: Some(Any::from(enc_cert_kdf_params_ref)),
            }));
        }

        if let Some(enc_alg) = &self.cert_enc_algorithm {
            let mut iv = vec![0_u8; 16];
            rng.fill_bytes(iv.as_mut_slice());

            let cert_iv = OctetString::new(iv)?.to_der()?;
            let cert_iv_ref = AnyRef::try_from(cert_iv.as_slice())?;
            self.cert_enc_algorithm_identifier(Some(AlgorithmIdentifier {
                oid: enc_alg.oid(),
                parameters: Some(Any::from(cert_iv_ref)),
            }));
        }

        if let Some(prf) = self.key_kdf_algorithm {
            let mut salt = vec![0_u8; 8];
            rng.fill_bytes(salt.as_mut_slice());

            let cert_kdf_params = Pbkdf2Params {
                salt: Salt::new(salt)?,
                iteration_count: 2048,
                key_length: None,
                prf,
            };
            let enc_cert_kdf_params = cert_kdf_params.to_der()?;
            let enc_cert_kdf_params_ref = AnyRef::try_from(enc_cert_kdf_params.as_slice())?;
            self.key_kdf_algorithm_identifier(Some(AlgorithmIdentifierOwned {
                oid: PBES2_OID,
                parameters: Some(Any::from(enc_cert_kdf_params_ref)),
            }));
        }

        if let Some(enc_alg) = &self.key_enc_algorithm {
            let mut iv = vec![0_u8; 16];
            rng.fill_bytes(iv.as_mut_slice());

            let cert_iv = OctetString::new(iv)?.to_der()?;
            let cert_iv_ref = AnyRef::try_from(cert_iv.as_slice())?;
            self.key_enc_algorithm_identifier(Some(AlgorithmIdentifier {
                oid: enc_alg.oid(),
                parameters: Some(Any::from(cert_iv_ref)),
            }));
        }

        if self.cert_kdf_algorithm_identifier.is_none() {
            self.cert_kdf_algorithm_identifier = Some(Self::default_kdf_alg(rng)?);
        }
        if self.cert_enc_algorithm_identifier.is_none() {
            self.cert_enc_algorithm_identifier = Some(Self::default_enc_alg(rng)?);
        }
        if self.key_kdf_algorithm_identifier.is_none() {
            self.key_kdf_algorithm_identifier = Some(Self::default_kdf_alg(rng)?);
        }
        if self.key_enc_algorithm_identifier.is_none() {
            self.key_enc_algorithm_identifier = Some(Self::default_enc_alg(rng)?);
        }
        if self.mac_data_builder.is_none() {
            self.mac_data_builder = Some(Self::default_mac_data(rng)?);
        }
        if let Some(mdb) = &mut self.mac_data_builder
            && !mdb.has_salt()
        {
            let mut salt = vec![0_u8; 8];
            rng.fill_bytes(salt.as_mut_slice());
            mdb.salt(Some(salt));
        }
        self.build(certificate, key, password)
    }

    /// Builds a [PKCS #12 object](pkcs12::pfx::Pfx) containing the provided certificate and key protected using password-based
    /// encryption and MAC. KDF, encryption and MAC information must have been previously provided to
    /// successfully use this function. To use default values, use the build_with_rng function.
    pub fn build(&self, certificate: &Certificate, key: &[u8], password: &str) -> Result<Vec<u8>> {
        let der_cert = certificate.to_der()?;
        let cert_bag = CertBag {
            cert_id: PKCS_12_X509_CERT_OID,
            cert_value: OctetString::new(der_cert.clone())?,
        };
        let der_cert_bag_inner = cert_bag.to_der()?;
        let cert_safe_bag = SafeBag {
            bag_id: PKCS_12_CERT_BAG_OID,
            bag_value: der_cert_bag_inner,
            bag_attributes: self.cert_attributes.clone(),
        };
        let der_cert_safe_bags = vec![cert_safe_bag].to_der()?;

        let der_cert_kdf_alg = match &self.cert_kdf_algorithm_identifier {
            Some(cert_kdf_alg) => match &cert_kdf_alg.parameters {
                Some(params) => params.to_der()?,
                None => {
                    return Err(Error::General(String::from(
                        "No parameters provided for certificate KDF algorithm",
                    )));
                }
            },
            None => {
                return Err(Error::General(String::from(
                    "No certificate KDF algorithm provided",
                )));
            }
        };

        let cert_kdf = Kdf::from(Pbkdf2Params::from_der(&der_cert_kdf_alg)?);

        let der_cert_enc_alg = match &self.cert_enc_algorithm_identifier {
            Some(cert_enc_alg) => cert_enc_alg.to_der()?,
            None => {
                return Err(Error::General(String::from(
                    "No certificate encryption algorithm provided",
                )));
            }
        };
        let cert_encryption = pbes2::EncryptionScheme::from_der(&der_cert_enc_alg)?;

        let cert_params = pbes2::Parameters {
            kdf: cert_kdf,
            encryption: cert_encryption,
        };
        let cert_scheme = pkcs5::EncryptionScheme::from(cert_params.clone());
        let mut enc_buf = vec![];
        enc_buf.extend_from_slice(&der_cert_safe_bags);
        enc_buf.extend_from_slice(vec![0x00; 16].as_slice());
        let cert_ciphertext =
            match cert_scheme.encrypt_in_place(password, &mut enc_buf, der_cert_safe_bags.len()) {
                Ok(ct) => ct,
                Err(e) => {
                    return Err(Error::General(
                        format!("Failed to encrypt certificate: {e:?}").to_string(),
                    ));
                }
            };

        let der_cert_params = cert_params.to_der()?;
        let der_cert_params_ref = AnyRef::try_from(der_cert_params.as_slice())?;

        let enc_data1 = EncryptedData {
            version: CmsVersion::V0,
            enc_content_info: EncryptedContentInfo {
                content_type: ID_DATA,
                content_enc_alg: AlgorithmIdentifier {
                    oid: PBES2_OID,
                    parameters: Some(Any::from(der_cert_params_ref)),
                },
                encrypted_content: Some(OctetString::new(cert_ciphertext)?),
            },
            unprotected_attrs: None,
        };
        let der_enc_data1 = enc_data1.to_der()?;
        let der_data_ref1 = AnyRef::try_from(der_enc_data1.as_slice())?;

        let der_key_kdf_alg = match &self.key_kdf_algorithm_identifier {
            Some(key_kdf_alg) => match &key_kdf_alg.parameters {
                Some(params) => params.to_der()?,
                None => {
                    return Err(Error::General(String::from(
                        "No parameters provided for key KDF algorithm",
                    )));
                }
            },
            None => {
                return Err(Error::General(String::from(
                    "No key KDF algorithm provided",
                )));
            }
        };
        let key_kdf = Kdf::from(Pbkdf2Params::from_der(&der_key_kdf_alg)?);

        let der_key_enc_alg = match &self.key_enc_algorithm_identifier {
            Some(key_enc_alg) => key_enc_alg.to_der()?,
            None => {
                return Err(Error::General(String::from(
                    "No key encryption algorithm provided",
                )));
            }
        };
        let key_encryption = pbes2::EncryptionScheme::from_der(&der_key_enc_alg)?;

        let key_params = pbes2::Parameters {
            kdf: key_kdf,
            encryption: key_encryption,
        };
        let key_scheme = pkcs5::EncryptionScheme::from(key_params.clone());
        let mut enc_buf = key.to_vec();
        enc_buf.extend_from_slice(vec![0x00; 16].as_slice());
        let key_ciphertext = match key_scheme.encrypt_in_place(password, &mut enc_buf, key.len()) {
            Ok(ct) => ct,
            Err(e) => {
                return Err(Error::General(
                    format!("Failed to encrypt key: {e:?}").to_string(),
                ));
            }
        };

        // let der_key_params = key_params.to_der().unwrap();
        // let der_key_params_ref = AnyRef::try_from(der_key_params.as_slice()).unwrap();

        let enc_epki = EncryptedPrivateKeyInfo {
            encryption_algorithm: key_scheme,
            encrypted_data: OctetString::new(key_ciphertext)?,
        };
        let der_enc_epki = enc_epki.to_der()?;

        let shrouded_key_bag = SafeBag {
            bag_id: PKCS_12_PKCS8_KEY_BAG_OID,
            bag_value: der_enc_epki,
            bag_attributes: self.key_attributes.clone(),
        };
        let sb = vec![shrouded_key_bag];
        let der_enc_data2 = sb.to_der()?;
        let os2 = OctetString::new(der_enc_data2)?.to_der()?;
        let der_data_ref2 = AnyRef::try_from(os2.as_slice())?;

        let auth_safes = vec![
            ContentInfo {
                content_type: ID_ENCRYPTED_DATA,
                content: Any::from(der_data_ref1),
            },
            ContentInfo {
                content_type: ID_DATA,
                content: Any::from(der_data_ref2),
            },
        ];

        let content_bytes = auth_safes.to_der()?;
        let os = OctetString::new(content_bytes.clone())?.to_der()?;
        let content = AnyRef::try_from(os.as_slice())?;

        let auth_safe = ContentInfo {
            content_type: ID_DATA,
            content: Any::from(content),
        };

        let md_build = match &self.mac_data_builder {
            Some(md_build) => md_build,
            None => {
                return Err(Error::General(String::from(
                    "No MacData builder was provided",
                )));
            }
        };
        let mac_data = Some(md_build.build(password, &content_bytes)?);

        let pfx = Pfx {
            version: Version::V3,
            auth_safe,
            mac_data,
        };
        Ok(pfx.to_der()?)
    }
}

/// Adds an [Attribute] containing the provided key ID to the provided set of attributes.
pub fn add_key_id_attr(attrs: &mut SetOfVec<Attribute>, key_id: &[u8]) -> Result<()> {
    pub const PKCS_9_AT_LOCAL_KEY_ID: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.21");

    let attr_bytes = OctetString::new(key_id)?.to_der()?;
    let attr_bytes_ref = AnyRef::try_from(attr_bytes.as_slice())?;
    let mut values = SetOfVec::new();
    values.insert(Any::from(attr_bytes_ref))?;
    let attr = Attribute {
        oid: PKCS_9_AT_LOCAL_KEY_ID,
        values,
    };
    Ok(attrs.insert(attr)?)
}
