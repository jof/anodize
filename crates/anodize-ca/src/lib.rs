use std::time::SystemTime;

use anodize_hsm::{Hsm, KeyHandle, SignMech};
use der::asn1::{Ia5String, ObjectIdentifier, OctetString, Uint};
use der::oid::AssociatedOid;
use der::{Decode, Encode};
use p384::{
    ecdsa::{
        signature::{self, Keypair, Signer},
        DerSignature, VerifyingKey,
    },
    pkcs8::DecodePublicKey,
};
use spki::{AlgorithmIdentifierOwned, DynSignatureAlgorithmIdentifier};
use thiserror::Error;
use x509_cert::{
    builder::{Builder, CertificateBuilder, Profile},
    certificate::Certificate,
    crl::{CertificateList, RevokedCert, TbsCertList},
    ext::{
        pkix::{
            crl::{dp::DistributionPoint, CrlDistributionPoints, CrlNumber},
            name::{DistributionPointName, GeneralName},
            AuthorityKeyIdentifier, SubjectKeyIdentifier,
        },
        Extension,
    },
    request::{CertReq, ExtensionReq},
    serial_number::SerialNumber,
    time::{Time, Validity},
    Version,
};

const ECDSA_WITH_SHA384_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");

const ID_EXTENSION_REQ: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.14");

// OIDs allowed in CSR extension requests. Anything else causes rejection.
const ALLOWED_EXTENSION_OIDS: &[ObjectIdentifier] = &[
    ObjectIdentifier::new_unwrap("2.5.29.19"), // BasicConstraints
    ObjectIdentifier::new_unwrap("2.5.29.15"), // KeyUsage
    ObjectIdentifier::new_unwrap("2.5.29.14"), // SubjectKeyIdentifier
    ObjectIdentifier::new_unwrap("2.5.29.35"), // AuthorityKeyIdentifier
    ObjectIdentifier::new_unwrap("2.5.29.31"), // CRLDistributionPoints
];

#[derive(Debug, Error)]
pub enum CaError {
    #[error("HSM error: {0}")]
    Hsm(#[from] anodize_hsm::HsmError),
    #[error("SPKI decode failed: {0}")]
    SpkiDecode(String),
    #[error("X.509 build failed: {0}")]
    X509Build(String),
    #[error("CSR signature invalid")]
    CsrSignatureInvalid,
    #[error("CSR contains rejected extension OID: {0}")]
    CsrExtensionRejected(String),
    #[error("DER error: {0}")]
    Der(String),
}

impl From<der::Error> for CaError {
    fn from(e: der::Error) -> Self {
        CaError::Der(e.to_string())
    }
}

impl From<x509_cert::builder::Error> for CaError {
    fn from(e: x509_cert::builder::Error) -> Self {
        CaError::X509Build(e.to_string())
    }
}

/// Bridges the `Hsm` trait to the x509-cert builder signer API.
///
/// Signing uses `CKM_ECDSA_SHA384`: the full message is passed to the HSM
/// and the hash-then-sign operation occurs entirely inside the hardware boundary.
/// Raw private key material never crosses into this process.
pub struct P384HsmSigner<H: Hsm> {
    hsm: H,
    key_handle: KeyHandle,
    verifying_key: VerifyingKey,
}

impl<H: Hsm> P384HsmSigner<H> {
    pub fn new(hsm: H, key_handle: KeyHandle) -> Result<Self, CaError> {
        let spki_der = hsm.public_key_der(key_handle)?;
        let verifying_key = VerifyingKey::from_public_key_der(&spki_der)
            .map_err(|e| CaError::SpkiDecode(e.to_string()))?;
        Ok(Self {
            hsm,
            key_handle,
            verifying_key,
        })
    }
}

impl<H: Hsm> Keypair for P384HsmSigner<H> {
    type VerifyingKey = VerifyingKey;

    fn verifying_key(&self) -> VerifyingKey {
        self.verifying_key
    }
}

impl<H: Hsm> DynSignatureAlgorithmIdentifier for P384HsmSigner<H> {
    fn signature_algorithm_identifier(&self) -> spki::Result<AlgorithmIdentifierOwned> {
        Ok(AlgorithmIdentifierOwned {
            oid: ECDSA_WITH_SHA384_OID,
            parameters: None,
        })
    }
}

impl<H: Hsm> Signer<DerSignature> for P384HsmSigner<H> {
    fn try_sign(&self, msg: &[u8]) -> Result<DerSignature, signature::Error> {
        let p1363 = self
            .hsm
            .sign(self.key_handle, SignMech::EcdsaSha384, msg)
            .map_err(signature::Error::from_source)?;
        let sig = p384::ecdsa::Signature::try_from(p1363.as_slice())
            .map_err(signature::Error::from_source)?;
        Ok(sig.to_der())
    }
}

/// Build a self-signed root CA certificate.
///
/// `validity_days` controls the certificate lifetime; 7305 (20 years) is the recommended default.
pub fn build_root_cert<H: Hsm>(
    signer: &P384HsmSigner<H>,
    common_name: &str,
    organization: &str,
    country: &str,
    validity_days: u32,
) -> Result<Certificate, CaError> {
    use std::time::Duration;

    let subject = parse_dn(common_name, organization, country)?;
    let spki = spki::SubjectPublicKeyInfoOwned::from_key(signer.verifying_key())
        .map_err(|e| CaError::X509Build(e.to_string()))?;

    let validity = Validity::from_now(Duration::from_secs(u64::from(validity_days) * 86400))
        .map_err(|e| CaError::Der(e.to_string()))?;

    let builder = CertificateBuilder::new(
        Profile::Root,
        SerialNumber::from(1u64),
        validity,
        subject,
        spki,
        signer,
    )?;

    Ok(builder.build::<DerSignature>()?)
}

/// Sign an intermediate CA CSR, applying the hardcoded extension policy.
///
/// The CSR signature is verified **before** any fields are read. Extensions not
/// in the allowlist (BasicConstraints, KeyUsage, SKID, AKID, CDP) cause rejection.
pub fn sign_intermediate_csr<H: Hsm>(
    signer: &P384HsmSigner<H>,
    root_cert: &Certificate,
    csr_der: &[u8],
    path_len: Option<u8>,
    validity_days: u32,
    cdp_url: Option<&str>,
) -> Result<Certificate, CaError> {
    use p384::ecdsa::signature::Verifier;
    use std::time::Duration;

    let csr = CertReq::from_der(csr_der).map_err(|e| CaError::Der(e.to_string()))?;

    // Verify the CSR self-signature BEFORE reading any other fields.
    {
        let tbs_bytes = csr.info.to_der()?;
        let spki_der = csr.info.public_key.to_der()?;
        let vk = VerifyingKey::from_public_key_der(&spki_der)
            .map_err(|_| CaError::CsrSignatureInvalid)?;
        let sig_bytes = csr
            .signature
            .as_bytes()
            .ok_or(CaError::CsrSignatureInvalid)?;
        let der_sig =
            DerSignature::try_from(sig_bytes).map_err(|_| CaError::CsrSignatureInvalid)?;
        vk.verify(&tbs_bytes, &der_sig)
            .map_err(|_| CaError::CsrSignatureInvalid)?;
    }

    // Check extension policy before processing subject/key fields.
    for attr in csr.info.attributes.iter() {
        if attr.oid == ID_EXTENSION_REQ {
            for value in attr.values.iter() {
                let ext_req: ExtensionReq =
                    value.decode_as().map_err(|e| CaError::Der(e.to_string()))?;
                for ext in &ext_req.0 {
                    if !ALLOWED_EXTENSION_OIDS.contains(&ext.extn_id) {
                        return Err(CaError::CsrExtensionRejected(ext.extn_id.to_string()));
                    }
                }
            }
        }
    }

    let issuer = root_cert.tbs_certificate.subject.clone();
    let serial = SerialNumber::from(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64,
    );
    let validity = Validity::from_now(Duration::from_secs(u64::from(validity_days) * 86400))
        .map_err(|e| CaError::Der(e.to_string()))?;

    let mut builder = CertificateBuilder::new(
        Profile::SubCA {
            issuer,
            path_len_constraint: path_len,
        },
        serial,
        validity,
        csr.info.subject.clone(),
        csr.info.public_key.clone(),
        signer,
    )?;

    if let Some(url) = cdp_url {
        let cdp = build_cdp(url)?;
        builder.add_extension(&cdp)?;
    }

    Ok(builder.build::<DerSignature>()?)
}

/// Issue a CRL signed by the root CA.
///
/// `crl_number` must be monotonically increasing across all CRLs issued by this CA.
/// Returns DER-encoded `CertificateList` bytes.
pub fn issue_crl<H: Hsm>(
    signer: &P384HsmSigner<H>,
    root_cert: &Certificate,
    revoked: &[(u64, SystemTime)],
    next_update: SystemTime,
    crl_number: u64,
) -> Result<Vec<u8>, CaError> {
    use spki::SignatureBitStringEncoding;

    let algorithm = signer
        .signature_algorithm_identifier()
        .map_err(|e| CaError::X509Build(e.to_string()))?;

    let this_update = Time::try_from(SystemTime::now()).map_err(|e| CaError::Der(e.to_string()))?;
    let next_update_time = Time::try_from(next_update).map_err(|e| CaError::Der(e.to_string()))?;

    let revoked_certificates = if revoked.is_empty() {
        None
    } else {
        let certs = revoked
            .iter()
            .map(|(serial, rev_time)| {
                Ok(RevokedCert {
                    serial_number: SerialNumber::from(*serial),
                    revocation_date: Time::try_from(*rev_time)
                        .map_err(|e| CaError::Der(e.to_string()))?,
                    crl_entry_extensions: None,
                })
            })
            .collect::<Result<Vec<_>, CaError>>()?;
        Some(certs)
    };

    let crl_extensions = Some(build_crl_extensions(root_cert, crl_number)?);

    let tbs_cert_list = TbsCertList {
        version: Version::V2,
        signature: algorithm.clone(),
        issuer: root_cert.tbs_certificate.subject.clone(),
        this_update,
        next_update: Some(next_update_time),
        revoked_certificates,
        crl_extensions,
    };

    let tbs_bytes = tbs_cert_list.to_der()?;
    let der_sig = Signer::<DerSignature>::try_sign(signer, &tbs_bytes)
        .map_err(|e| CaError::X509Build(e.to_string()))?;
    let signature = der_sig
        .to_bitstring()
        .map_err(|e| CaError::Der(e.to_string()))?;

    CertificateList {
        tbs_cert_list,
        signature_algorithm: algorithm,
        signature,
    }
    .to_der()
    .map_err(|e| CaError::Der(e.to_string()))
}

/// Build the standard CRL extensions: CRL Number and Authority Key Identifier.
fn build_crl_extensions(
    root_cert: &Certificate,
    crl_number: u64,
) -> Result<Vec<Extension>, CaError> {
    let crl_num_bytes = crl_number.to_be_bytes();
    let crl_num_uint = Uint::new(&crl_num_bytes).map_err(|e| CaError::Der(e.to_string()))?;
    let crl_num_encoded = CrlNumber(crl_num_uint).to_der()?;
    let crl_num_ext = Extension {
        extn_id: CrlNumber::OID,
        critical: false,
        extn_value: OctetString::new(crl_num_encoded).map_err(|e| CaError::Der(e.to_string()))?,
    };

    // Derive key_identifier from the root cert's SubjectKeyIdentifier extension.
    let key_id = root_cert
        .tbs_certificate
        .extensions
        .as_deref()
        .and_then(|exts| {
            exts.iter()
                .find(|ext| ext.extn_id == SubjectKeyIdentifier::OID)
        })
        .and_then(|ext| SubjectKeyIdentifier::from_der(ext.extn_value.as_bytes()).ok())
        .map(|skid| skid.0);

    let akid = AuthorityKeyIdentifier {
        key_identifier: key_id,
        authority_cert_issuer: None,
        authority_cert_serial_number: None,
    };
    let akid_encoded = akid.to_der()?;
    let akid_ext = Extension {
        extn_id: AuthorityKeyIdentifier::OID,
        critical: false,
        extn_value: OctetString::new(akid_encoded).map_err(|e| CaError::Der(e.to_string()))?,
    };

    Ok(vec![crl_num_ext, akid_ext])
}

fn parse_dn(cn: &str, org: &str, country: &str) -> Result<x509_cert::name::Name, CaError> {
    use std::str::FromStr;
    x509_cert::name::Name::from_str(&format!("CN={cn},O={org},C={country}"))
        .map_err(|e| CaError::Der(e.to_string()))
}

fn build_cdp(url: &str) -> Result<CrlDistributionPoints, CaError> {
    let uri = Ia5String::new(url).map_err(|e| CaError::Der(e.to_string()))?;
    let dp = DistributionPoint {
        distribution_point: Some(DistributionPointName::FullName(vec![
            GeneralName::UniformResourceIdentifier(uri),
        ])),
        reasons: None,
        crl_issuer: None,
    };
    Ok(CrlDistributionPoints(vec![dp]))
}
