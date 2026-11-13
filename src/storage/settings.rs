//! Storage settings

extern crate alloc;
use alloc::collections::BTreeMap;
use std::{fs, fs::File, io::Write, path::Path};

use log::error;
use serde::{Deserialize, Serialize};
use serde_json::Result as SerdeResult;

use ml_dsa::{B32, MlDsa44, MlDsa65, MlDsa87};
use slh_dsa::{
    Sha2_128f, Sha2_128s, Sha2_192f, Sha2_192s, Sha2_256f, Sha2_256s, Shake128f, Shake128s,
    Shake192f, Shake192s, Shake256f, Shake256s, SigningKey,
};

use const_oid::db::fips204::{ID_ML_DSA_44, ID_ML_DSA_65, ID_ML_DSA_87};
use const_oid::db::fips205::{
    ID_SLH_DSA_SHA_2_128_F, ID_SLH_DSA_SHA_2_128_S, ID_SLH_DSA_SHA_2_192_F, ID_SLH_DSA_SHA_2_192_S,
    ID_SLH_DSA_SHA_2_256_F, ID_SLH_DSA_SHA_2_256_S, ID_SLH_DSA_SHAKE_128_F, ID_SLH_DSA_SHAKE_128_S,
    ID_SLH_DSA_SHAKE_192_F, ID_SLH_DSA_SHAKE_192_S, ID_SLH_DSA_SHAKE_256_F, ID_SLH_DSA_SHAKE_256_S,
};
use const_oid::db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION;
use der::asn1::BitString;
use der::{Decode, Encode};
use rsa::{
    PublicKey,
    pkcs1v15::{Signature as RsaSignature, VerifyingKey},
};
use sha2::Sha256;
use signature::Verifier;
use spki::{AlgorithmIdentifierOwned, DecodePublicKey, SignatureBitStringEncoding};
use x509_cert::{
    Certificate, SubjectPublicKeyInfo, TbsCertificate,
    crl::{CertificateList, TbsCertList},
};

use pqckeys::oak::{OneAsymmetricKey, PrivateKey};

use crate::{
    Error, Result,
    generation::settings::NameSuffix,
    misc::utils::{get_file_as_byte_vec, get_file_as_cert},
    pqc::{
        key_pair::{KeyPair, PqcKeyPair},
        signer::PqcSigner,
    },
    storage::{
        asn1,
        asn1::{DeferDecodeSigned, FakeCertificate, FakeCrl, FakeTbsCertificate},
    },
};

/// Governs where fake artifacts are saved and maintains an internal map from original artifacts
/// to `SubjectKeyIdentifier` values, which is used to associate fake artifacts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StorageSettings {
    folder: String,
    #[serde(skip)]
    skid_to_orig_file: BTreeMap<String, String>,
}

impl Default for StorageSettings {
    fn default() -> Self {
        Self::new("./storage")
    }
}

/// Reads a JSON-formated [StorageSettings] instance and initializes it for use
pub fn read_storage_settings(file_name: &str) -> StorageSettings {
    if Path::exists(Path::new(file_name))
        && let Ok(json) = get_file_as_byte_vec(Path::new(file_name))
    {
        let r: SerdeResult<StorageSettings> = serde_json::from_slice(&json);
        if let Ok(ss) = r {
            ss.init();
            return ss;
        }
    }
    StorageSettings::default()
}
impl StorageSettings {
    /// Creates a new [StorageSettings] rooted at `folder` and initializes the directory structure.
    pub fn new(folder: &str) -> Self {
        let ss = StorageSettings {
            folder: folder.to_string(),
            skid_to_orig_file: Default::default(),
        };
        ss.init();
        ss
    }

    /// Creates the output folder hierarchy if it does not already exist.
    pub fn init(&self) {
        let path = Path::new(&self.folder);
        if !Path::exists(path)
            && let Err(e) = fs::create_dir_all(path)
        {
            error!(
                "Error creating storage settings folder: {}. Ignoring and continuing...",
                e
            );
        }
        let certs_path = path.join("certs");
        if !Path::exists(certs_path.as_path())
            && let Err(e) = fs::create_dir_all(certs_path.as_path())
        {
            error!(
                "Error creating certs folder in storage settings folder: {}. Ignoring and continuing...",
                e
            );
        }
        let crls_path = path.join("crls");
        if !Path::exists(crls_path.as_path())
            && let Err(e) = fs::create_dir_all(crls_path.as_path())
        {
            error!(
                "Error creating crls folder in storage settings folder: {}. Ignoring and continuing...",
                e
            );
        }
        let pkcs12_path = path.join("pkcs12");
        if !Path::exists(pkcs12_path.as_path())
            && let Err(e) = fs::create_dir_all(pkcs12_path.as_path())
        {
            error!(
                "Error creating pkcs12 folder in storage settings folder: {}. Ignoring and continuing...",
                e
            );
        }
        let keys_path = path.join("keys");
        if !Path::exists(keys_path.as_path())
            && let Err(e) = fs::create_dir_all(keys_path.as_path())
        {
            error!(
                "Error creating keys folder in storage settings folder: {}. Ignoring and continuing...",
                e
            );
        }
    }

    /// Gets the original filename that corresponds to the SKID.
    pub fn get_file_name_for_skid(&self, skid: &str) -> String {
        if let Some(v) = self.skid_to_orig_file.get(skid) {
            let path = Path::new(v);
            if let Some(s) = path.file_stem() {
                return s.to_string_lossy().into_owned();
            }
        }
        String::from(skid)
    }

    /// Saves a PKCS #12 file and its corresponding private key (OAK) to disk.
    pub fn save_p12(
        &self,
        pkcs12: &[u8],
        oak: &[u8],
        skid: &str,
        orig_path: &Path,
        suffix: &str,
    ) -> Result<()> {
        let pkcs12_storage = Path::new(&self.folder).join("pkcs12");
        let mut p12_file = File::create(
            pkcs12_storage.join(format!("{}{suffix}.p12", self.get_file_name_for_skid(skid))),
        )?;
        if let Err(e) = p12_file.write_all(pkcs12) {
            error!(
                "Failed to write PKCS #12 generated for {} to file ({skid}): {e}. Ignoring and continuing...",
                orig_path.to_str().unwrap_or_default()
            );
            return Err(Error::Io);
        }
        let key_storage = Path::new(&self.folder).join("keys");
        let mut priv_file = File::create(
            key_storage.join(format!("{}{suffix}.oak", self.get_file_name_for_skid(skid))),
        )?;
        if let Err(e) = priv_file.write_all(oak) {
            error!(
                "Failed to write private key generated for {} to file ({skid}): {e}. Ignoring and continuing...",
                orig_path.to_str().unwrap_or_default()
            );
            return Err(Error::Io);
        }
        Ok(())
    }

    /// Saves the seed, private key, and public key for a certificate's key pair to disk.
    pub fn save_key_pair_for_cert(
        &mut self,
        cert: &Certificate,
        seed: &[u8],
        priv_key: &[u8],
        pub_key: &[u8],
        orig_path: &str,
    ) -> Result<()> {
        let skid = asn1::get_skid(cert)?;
        self.skid_to_orig_file
            .insert(skid.to_string(), orig_path.to_string());

        let key_storage = Path::new(&self.folder).join("keys");
        let mut seed_file =
            File::create(key_storage.join(format!("{}.seed", self.get_file_name_for_skid(&skid))))?;
        if let Err(e) = seed_file.write_all(seed) {
            error!(
                "Failed to write private key generated for {orig_path} to file ({skid}): {e}. Ignoring and continuing..."
            );
        }
        let mut priv_file =
            File::create(key_storage.join(format!("{}.priv", self.get_file_name_for_skid(&skid))))?;
        if let Err(e) = priv_file.write_all(priv_key) {
            error!(
                "Failed to write private key generated for {orig_path} to file ({skid}): {e}. Ignoring and continuing..."
            );
        }
        let mut pub_file =
            File::create(key_storage.join(format!("{}.spki", self.get_file_name_for_skid(&skid))))?;
        if let Err(e) = pub_file.write_all(pub_key) {
            error!(
                "Failed to write private key generated for {orig_path} to file ({skid}): {e}. Ignoring and continuing..."
            );
        }

        Ok(())
    }

    /// Loads the generated public key and a signer for the key identified by `skid`.
    fn load_signer(&self, skid: &str) -> Result<(SubjectPublicKeyInfo, PqcSigner)> {
        let key_storage = Path::new(&self.folder).join("keys");
        let public_key = get_file_as_byte_vec(
            &key_storage.join(format!("{}.spki", self.get_file_name_for_skid(skid))),
        )?;
        let spki = SubjectPublicKeyInfo::from_der(&public_key)?;

        let signer = match spki.algorithm.oid {
            ID_ML_DSA_44 => {
                let seed_bytes = get_file_as_byte_vec(
                    &key_storage.join(format!("{}.seed", self.get_file_name_for_skid(skid))),
                )?;
                let seed = B32::try_from(seed_bytes.as_slice()).map_err(|_| Error::Unrecognized)?;
                PqcSigner::new(
                    &seed_bytes,
                    PqcKeyPair::MlDsa44(Box::new(KeyPair::<MlDsa44>::from_seed(&seed))),
                )
            }
            ID_ML_DSA_65 => {
                let seed_bytes = get_file_as_byte_vec(
                    &key_storage.join(format!("{}.seed", self.get_file_name_for_skid(skid))),
                )?;
                let seed = B32::try_from(seed_bytes.as_slice()).map_err(|_| Error::Unrecognized)?;
                PqcSigner::new(
                    &seed_bytes,
                    PqcKeyPair::MlDsa65(Box::new(KeyPair::<MlDsa65>::from_seed(&seed))),
                )
            }
            ID_ML_DSA_87 => {
                let seed_bytes = get_file_as_byte_vec(
                    &key_storage.join(format!("{}.seed", self.get_file_name_for_skid(skid))),
                )?;
                let seed = B32::try_from(seed_bytes.as_slice()).map_err(|_| Error::Unrecognized)?;
                PqcSigner::new(
                    &seed_bytes,
                    PqcKeyPair::MlDsa87(Box::new(KeyPair::<MlDsa87>::from_seed(&seed))),
                )
            }
            ID_SLH_DSA_SHA_2_128_F => {
                let priv_bytes = get_file_as_byte_vec(
                    &key_storage.join(format!("{}.priv", self.get_file_name_for_skid(skid))),
                )?;
                let sk = SigningKey::<Sha2_128f>::try_from(priv_bytes.as_slice())
                    .map_err(|_| Error::Unrecognized)?;
                PqcSigner::new(&[], PqcKeyPair::Sha2_128f(Box::new(sk)))
            }
            ID_SLH_DSA_SHA_2_128_S => {
                let priv_bytes = get_file_as_byte_vec(
                    &key_storage.join(format!("{}.priv", self.get_file_name_for_skid(skid))),
                )?;
                let sk = SigningKey::<Sha2_128s>::try_from(priv_bytes.as_slice())
                    .map_err(|_| Error::Unrecognized)?;
                PqcSigner::new(&[], PqcKeyPair::Sha2_128s(Box::new(sk)))
            }
            ID_SLH_DSA_SHA_2_192_F => {
                let priv_bytes = get_file_as_byte_vec(
                    &key_storage.join(format!("{}.priv", self.get_file_name_for_skid(skid))),
                )?;
                let sk = SigningKey::<Sha2_192f>::try_from(priv_bytes.as_slice())
                    .map_err(|_| Error::Unrecognized)?;
                PqcSigner::new(&[], PqcKeyPair::Sha2_192f(Box::new(sk)))
            }
            ID_SLH_DSA_SHA_2_192_S => {
                let priv_bytes = get_file_as_byte_vec(
                    &key_storage.join(format!("{}.priv", self.get_file_name_for_skid(skid))),
                )?;
                let sk = SigningKey::<Sha2_192s>::try_from(priv_bytes.as_slice())
                    .map_err(|_| Error::Unrecognized)?;
                PqcSigner::new(&[], PqcKeyPair::Sha2_192s(Box::new(sk)))
            }
            ID_SLH_DSA_SHA_2_256_F => {
                let priv_bytes = get_file_as_byte_vec(
                    &key_storage.join(format!("{}.priv", self.get_file_name_for_skid(skid))),
                )?;
                let sk = SigningKey::<Sha2_256f>::try_from(priv_bytes.as_slice())
                    .map_err(|_| Error::Unrecognized)?;
                PqcSigner::new(&[], PqcKeyPair::Sha2_256f(Box::new(sk)))
            }
            ID_SLH_DSA_SHA_2_256_S => {
                let priv_bytes = get_file_as_byte_vec(
                    &key_storage.join(format!("{}.priv", self.get_file_name_for_skid(skid))),
                )?;
                let sk = SigningKey::<Sha2_256s>::try_from(priv_bytes.as_slice())
                    .map_err(|_| Error::Unrecognized)?;
                PqcSigner::new(&[], PqcKeyPair::Sha2_256s(Box::new(sk)))
            }
            ID_SLH_DSA_SHAKE_128_F => {
                let priv_bytes = get_file_as_byte_vec(
                    &key_storage.join(format!("{}.priv", self.get_file_name_for_skid(skid))),
                )?;
                let sk = SigningKey::<Shake128f>::try_from(priv_bytes.as_slice())
                    .map_err(|_| Error::Unrecognized)?;
                PqcSigner::new(&[], PqcKeyPair::Shake128f(Box::new(sk)))
            }
            ID_SLH_DSA_SHAKE_128_S => {
                let priv_bytes = get_file_as_byte_vec(
                    &key_storage.join(format!("{}.priv", self.get_file_name_for_skid(skid))),
                )?;
                let sk = SigningKey::<Shake128s>::try_from(priv_bytes.as_slice())
                    .map_err(|_| Error::Unrecognized)?;
                PqcSigner::new(&[], PqcKeyPair::Shake128s(Box::new(sk)))
            }
            ID_SLH_DSA_SHAKE_192_F => {
                let priv_bytes = get_file_as_byte_vec(
                    &key_storage.join(format!("{}.priv", self.get_file_name_for_skid(skid))),
                )?;
                let sk = SigningKey::<Shake192f>::try_from(priv_bytes.as_slice())
                    .map_err(|_| Error::Unrecognized)?;
                PqcSigner::new(&[], PqcKeyPair::Shake192f(Box::new(sk)))
            }
            ID_SLH_DSA_SHAKE_192_S => {
                let priv_bytes = get_file_as_byte_vec(
                    &key_storage.join(format!("{}.priv", self.get_file_name_for_skid(skid))),
                )?;
                let sk = SigningKey::<Shake192s>::try_from(priv_bytes.as_slice())
                    .map_err(|_| Error::Unrecognized)?;
                PqcSigner::new(&[], PqcKeyPair::Shake192s(Box::new(sk)))
            }
            ID_SLH_DSA_SHAKE_256_F => {
                let priv_bytes = get_file_as_byte_vec(
                    &key_storage.join(format!("{}.priv", self.get_file_name_for_skid(skid))),
                )?;
                let sk = SigningKey::<Shake256f>::try_from(priv_bytes.as_slice())
                    .map_err(|_| Error::Unrecognized)?;
                PqcSigner::new(&[], PqcKeyPair::Shake256f(Box::new(sk)))
            }
            ID_SLH_DSA_SHAKE_256_S => {
                let priv_bytes = get_file_as_byte_vec(
                    &key_storage.join(format!("{}.priv", self.get_file_name_for_skid(skid))),
                )?;
                let sk = SigningKey::<Shake256s>::try_from(priv_bytes.as_slice())
                    .map_err(|_| Error::Unrecognized)?;
                PqcSigner::new(&[], PqcKeyPair::Shake256s(Box::new(sk)))
            }
            _ => return Err(Error::Unrecognized),
        };
        Ok((spki, signer))
    }

    /// Checks the signature on an original artifact using the original certificate for the issuer
    /// identified by `issuer_skid`. Generated artifacts reproduce a failure here with a bad
    /// signature, e.g., for BadSignedCACert, InvalidEESignatureTest3EE and BadCRLSignatureCACRL.
    fn orig_signature_verifies(
        &self,
        issuer_skid: &str,
        defer: &DeferDecodeSigned,
    ) -> Result<bool> {
        let issuer_file = match self.skid_to_orig_file.get(issuer_skid) {
            Some(name) => name,
            None => {
                error!("Did not find original cert for {issuer_skid}");
                return Err(Error::Unrecognized);
            }
        };
        let issuer = get_file_as_cert(Path::new(issuer_file))?;
        if defer.signature_algorithm.oid != SHA_256_WITH_RSA_ENCRYPTION {
            error!(
                "Unable to check original signature with algorithm {}. Treating it as good.",
                defer.signature_algorithm.oid
            );
            return Ok(true);
        }
        let spki_der = issuer
            .tbs_certificate()
            .subject_public_key_info()
            .to_der()?;
        let public_key = PublicKey::from_public_key_der(&spki_der).map_err(|_| Error::Rsa)?;
        let verifying_key = VerifyingKey::<Sha256>::new(public_key);
        let signature =
            RsaSignature::try_from(defer.signature.raw_bytes()).map_err(|_| Error::Rsa)?;
        Ok(verifying_key
            .verify(defer.tbs_field.as_slice(), &signature)
            .is_ok())
    }

    /// Signs `tbs`, corrupting the signature if `good` is false.
    fn sign(signer: &PqcSigner, tbs: &[u8], good: bool) -> Result<BitString> {
        let mut sig = signer.sign(tbs)?.to_bitstring()?.raw_bytes().to_vec();
        if !good && let Some(last) = sig.last_mut() {
            *last ^= 0xFF;
        }
        Ok(BitString::from_bytes(&sig)?)
    }

    fn generate_fake_tbs_cert(
        &self,
        skid: &str,
        orig_tbs: &[u8],
        issuer_alg: &AlgorithmIdentifierOwned,
        name_suffix: Option<&NameSuffix>,
    ) -> Result<FakeTbsCertificate> {
        let key_storage = Path::new(&self.folder).join("keys");

        let ee_public_key = get_file_as_byte_vec(
            &key_storage.join(format!("{}.spki", self.get_file_name_for_skid(skid))),
        )?;
        let fake_ee_spki = SubjectPublicKeyInfo::from_der(&ee_public_key)?;
        let orig_tbs = match name_suffix {
            Some(ns) => TbsCertificate::from_der(&ns.apply(orig_tbs))?,
            None => TbsCertificate::from_der(orig_tbs)?,
        };
        let fake_tbs = FakeTbsCertificate {
            version: orig_tbs.version(),
            serial_number: orig_tbs.serial_number().clone(),
            signature: issuer_alg.clone(),
            issuer: orig_tbs.issuer().clone(),
            validity: *orig_tbs.validity(),
            subject: orig_tbs.subject().clone(),
            subject_public_key_info: fake_ee_spki.clone(),
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: orig_tbs.extensions().cloned(),
        };
        Ok(fake_tbs)
    }

    /// Re-signs a CRL using the stored key for its issuer and saves it to the output folder using
    /// the original file name.
    pub fn generate_fake_crl(
        &self,
        crl_bytes: &[u8],
        orig_path: &str,
        name_suffix: Option<&NameSuffix>,
    ) -> Result<()> {
        let crl = CertificateList::from_der(crl_bytes)?;
        let akid = asn1::get_akid_from_crl(&crl, orig_path)?;
        let defer = DeferDecodeSigned::from_der(crl_bytes)?;
        let good = self.orig_signature_verifies(&akid, &defer)?;

        let (fake_ca_spki, pqc_signer) = self.load_signer(&akid)?;

        let tbs_der = match name_suffix {
            Some(ns) => ns.apply(&defer.tbs_field),
            None => defer.tbs_field.clone(),
        };
        let mut tbs_cert_list = TbsCertList::from_der(&tbs_der)?;
        tbs_cert_list.signature = fake_ca_spki.algorithm.clone();
        let der_tbs_cert_list = tbs_cert_list.to_der()?;

        let fake_crl = FakeCrl {
            tbs_cert_list,
            signature_algorithm: fake_ca_spki.algorithm.clone(),
            signature: Self::sign(&pqc_signer, &der_tbs_cert_list, good)?,
        };
        let der_fake_crl = fake_crl.to_der()?;

        let file_name = match Path::new(orig_path).file_name() {
            Some(file_name) => file_name,
            None => {
                error!("Failed to get file name from {orig_path}");
                return Err(Error::Unrecognized);
            }
        };
        let crl_storage = Path::new(&self.folder).join("crls");
        let mut crl_file = File::create(crl_storage.join(file_name))?;
        if let Err(e) = crl_file.write_all(&der_fake_crl) {
            error!("Failed to write CRL generated for {orig_path} to file ({akid}): {e}.");
            return Err(Error::Io);
        }
        Ok(())
    }

    /// Re-signs a certificate using the stored key for its issuer and returns the OAK, DER cert, and SKID.
    pub fn generate_fake_cert(
        &self,
        cert: &Certificate,
        orig_path: &str,
        name_suffix: Option<&NameSuffix>,
    ) -> Result<(Vec<u8>, Vec<u8>, String)> {
        let skid = match asn1::get_skid(cert) {
            Ok(h) => h,
            Err(e) => {
                error!("Failed to get SKID for {orig_path}: {e:?}");
                return Err(e);
            }
        };
        let akid = match asn1::get_akid(cert) {
            Ok(h) => h,
            Err(e) => {
                error!("Failed to get AKID for {orig_path}: {e:?}");
                return Err(e);
            }
        };
        let orig_cert = get_file_as_byte_vec(Path::new(orig_path))?;
        let defer = DeferDecodeSigned::from_der(&orig_cert)?;
        let good = self.orig_signature_verifies(&akid, &defer)?;

        let (fake_ca_spki, pqc_signer) = self.load_signer(&akid)?;
        let fake_tbs = self.generate_fake_tbs_cert(
            &skid,
            &defer.tbs_field,
            &fake_ca_spki.algorithm,
            name_suffix,
        )?;
        let der_fake_tbs = fake_tbs.to_der()?;

        let private_key_alg = fake_tbs.subject_public_key_info.algorithm.clone();
        let fake_cert = FakeCertificate {
            tbs_certificate: fake_tbs,
            signature_algorithm: fake_ca_spki.algorithm.clone(),
            signature: Self::sign(&pqc_signer, &der_fake_tbs, good)?,
        };
        let der_fake_cert = fake_cert.to_der()?;

        let key_storage = Path::new(&self.folder).join("keys");
        let cert_storage = Path::new(&self.folder).join("certs");

        let mut pub_file =
            File::create(cert_storage.join(format!("{}.der", self.get_file_name_for_skid(&skid))))?;
        if let Err(e) = pub_file.write_all(&der_fake_cert) {
            error!(
                "Failed to write private key generated for {orig_path} to file ({skid}): {e}. Ignoring and continuing..."
            );
        }
        let ee_private_key = get_file_as_byte_vec(
            &key_storage.join(format!("{}.priv", self.get_file_name_for_skid(&skid))),
        )?;
        let oak_leaf = OneAsymmetricKey {
            version: pqckeys::oak::Version::V1, // V1 per rfc5958 section 2
            private_key_alg,
            private_key: PrivateKey::new(ee_private_key)?,
            attributes: None,
            public_key: None,
        };
        let oak_der = oak_leaf.to_der()?;

        Ok((oak_der, der_fake_cert, skid))
    }

    /// Returns the seed bytes stored for the key identified by `skid`.
    pub fn get_seed(&self, skid: &str) -> Result<Vec<u8>> {
        let key_storage = Path::new(&self.folder).join("keys");
        get_file_as_byte_vec(
            &key_storage.join(format!("{}.seed", self.get_file_name_for_skid(skid))),
        )
    }
}
