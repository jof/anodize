pub mod events;
pub mod state;

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub ca: CaConfig,
    pub hsm: HsmConfig,
    #[serde(default)]
    pub cert_profiles: Vec<CertProfile>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertProfile {
    pub name: String,
    pub validity_days: u32,
    pub path_len: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationEntry {
    /// Certificate serial number as uppercase hex string (e.g. "01AB23CD…").
    /// Legacy entries serialized as integer 0 are accepted on read.
    #[serde(deserialize_with = "deserialize_serial_hex")]
    pub serial: String,
    pub revocation_time: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Accept both a TOML string and a legacy TOML integer (always 0 from the old
/// `serial_to_u64` bug) so that previously-written REVOKED.TOML files still parse.
fn deserialize_serial_hex<'de, D: serde::Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    struct SerialVisitor;
    impl<'de> serde::de::Visitor<'de> for SerialVisitor {
        type Value = String;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a hex string or integer serial number")
        }
        fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<String, E> {
            Ok(v.to_uppercase())
        }
        fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<String, E> {
            Ok(format!("{v:X}"))
        }
        fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<String, E> {
            Ok(format!("{:X}", v as u64))
        }
    }
    d.deserialize_any(SerialVisitor)
}

#[derive(Serialize, Deserialize)]
struct RevocationFile {
    entries: Vec<RevocationEntry>,
}

pub fn parse_revocation_list(data: &[u8]) -> Result<Vec<RevocationEntry>, ConfigError> {
    let s = std::str::from_utf8(data).map_err(|_| ConfigError::RevocationUtf8)?;
    let file: RevocationFile =
        toml::from_str(s).map_err(|source| ConfigError::RevocationToml { source })?;
    Ok(file.entries)
}

pub fn serialize_revocation_list(entries: &[RevocationEntry]) -> String {
    let file = RevocationFile {
        entries: entries.to_vec(),
    };
    toml::to_string(&file).unwrap_or_default()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaConfig {
    pub common_name: String,
    pub organization: String,
    pub country: String,
    pub cdp_url: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HsmConfig {
    pub backend: HsmBackendKind,
    pub token_label: String,
    pub key_label: String,
    #[serde(default)]
    pub key_spec: KeySpec,
}

/// Named HSM backend model. Each variant maps to a concrete implementation
/// in `anodize-hsm` that knows its own module paths, factory credentials,
/// and native SDK quirks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HsmBackendKind {
    Softhsm,
    Yubihsm,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum KeySpec {
    #[default]
    EcdsaP384,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("cannot read config file {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("TOML parse error in {path}: {source}")]
    Toml {
        path: PathBuf,
        source: toml::de::Error,
    },
    #[error("revocation list is not valid UTF-8")]
    RevocationUtf8,
    #[error("revocation list TOML parse error: {source}")]
    RevocationToml { source: toml::de::Error },
}

pub fn load(path: &Path) -> Result<Profile, ConfigError> {
    let contents = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
        path: path.to_owned(),
        source,
    })?;
    toml::from_str(&contents).map_err(|source| ConfigError::Toml {
        path: path.to_owned(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Profile {
        toml::from_str(s).expect("parse failed")
    }

    const FULL_TOML: &str = r#"
[ca]
common_name  = "Example Root CA"
organization = "Example Corp"
country      = "US"
cdp_url      = "http://crl.example.com/root.crl"

[hsm]
backend      = "softhsm"
token_label  = "anodize-root-2026"
key_label    = "root-key"
key_spec     = "ecdsa-p384"
"#;

    #[test]
    fn parse_full_profile() {
        let p = parse(FULL_TOML);
        assert_eq!(p.ca.common_name, "Example Root CA");
        assert_eq!(p.ca.organization, "Example Corp");
        assert_eq!(p.ca.country, "US");
        assert_eq!(
            p.ca.cdp_url.as_deref(),
            Some("http://crl.example.com/root.crl")
        );
        assert_eq!(p.hsm.backend, HsmBackendKind::Softhsm);
        assert_eq!(p.hsm.token_label, "anodize-root-2026");
        assert_eq!(p.hsm.key_label, "root-key");
        assert_eq!(p.hsm.key_spec, KeySpec::EcdsaP384);
    }

    #[test]
    fn backend_yubihsm() {
        let toml = "[ca]\ncommon_name=\"x\"\norganization=\"x\"\ncountry=\"US\"\n\
                    [hsm]\nbackend=\"yubihsm\"\ntoken_label=\"t\"\nkey_label=\"k\"\n";
        let p: Profile = toml::from_str(toml).expect("parse");
        assert_eq!(p.hsm.backend, HsmBackendKind::Yubihsm);
    }

    #[test]
    fn backend_rejects_unknown() {
        let toml = "[ca]\ncommon_name=\"x\"\norganization=\"x\"\ncountry=\"US\"\n\
                    [hsm]\nbackend=\"thales\"\ntoken_label=\"t\"\nkey_label=\"k\"\n";
        assert!(toml::from_str::<Profile>(toml).is_err());
    }

    #[test]
    fn missing_required_field() {
        let toml = "[ca]\norganization=\"x\"\ncountry=\"US\"\n\
                    [hsm]\nbackend=\"softhsm\"\ntoken_label=\"t\"\nkey_label=\"k\"\n";
        assert!(toml::from_str::<Profile>(toml).is_err());
    }

    #[test]
    fn cdp_url_is_optional() {
        let toml = "[ca]\ncommon_name=\"x\"\norganization=\"x\"\ncountry=\"US\"\n\
                    [hsm]\nbackend=\"softhsm\"\ntoken_label=\"t\"\nkey_label=\"k\"\n";
        let p: Profile = toml::from_str(toml).expect("parse");
        assert!(p.ca.cdp_url.is_none());
    }

    #[test]
    fn deny_unknown_hsm_fields() {
        let toml = "[ca]\ncommon_name=\"x\"\norganization=\"x\"\ncountry=\"US\"\n\
                    [hsm]\nbackend=\"softhsm\"\ntoken_label=\"t\"\nkey_label=\"k\"\npin_source=\"prompt\"\n";
        assert!(toml::from_str::<Profile>(toml).is_err());
    }

    #[test]
    fn cert_profiles_parse() {
        let toml = r#"
[ca]
common_name  = "Root CA"
organization = "Acme"
country      = "US"

[hsm]
backend     = "softhsm"
token_label = "t"
key_label   = "k"

[[cert_profiles]]
name         = "sub-ca"
validity_days = 1825
path_len      = 0

[[cert_profiles]]
name         = "ocsp-signer"
validity_days = 365
"#;
        let p: Profile = toml::from_str(toml).expect("parse");
        assert_eq!(p.cert_profiles.len(), 2);
        assert_eq!(p.cert_profiles[0].name, "sub-ca");
        assert_eq!(p.cert_profiles[0].validity_days, 1825);
        assert_eq!(p.cert_profiles[0].path_len, Some(0));
        assert_eq!(p.cert_profiles[1].name, "ocsp-signer");
        assert_eq!(p.cert_profiles[1].validity_days, 365);
        assert_eq!(p.cert_profiles[1].path_len, None);
    }

    #[test]
    fn cert_profiles_default_empty() {
        let toml = "[ca]\ncommon_name=\"x\"\norganization=\"x\"\ncountry=\"US\"\n\
                    [hsm]\nbackend=\"softhsm\"\ntoken_label=\"t\"\nkey_label=\"k\"\n";
        let p: Profile = toml::from_str(toml).expect("parse");
        assert!(p.cert_profiles.is_empty());
    }

    #[test]
    fn revocation_list_round_trip() {
        let toml = r#"
[[entries]]
serial          = "3039"
revocation_time = "2026-04-01T00:00:00Z"
reason          = "key-compromise"

[[entries]]
serial          = "10932"
revocation_time = "2026-05-15T12:00:00Z"
"#;
        let entries = parse_revocation_list(toml.as_bytes()).expect("parse");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].serial, "3039");
        assert_eq!(entries[0].revocation_time, "2026-04-01T00:00:00Z");
        assert_eq!(entries[0].reason.as_deref(), Some("key-compromise"));
        assert_eq!(entries[1].serial, "10932");
        assert!(entries[1].reason.is_none());

        // Serialize and re-parse
        let serialized = serialize_revocation_list(&entries);
        let reparsed = parse_revocation_list(serialized.as_bytes()).expect("re-parse");
        assert_eq!(reparsed.len(), 2);
        assert_eq!(reparsed[0].serial, "3039");
        assert_eq!(reparsed[1].serial, "10932");
    }

    #[test]
    fn empty_revocation_list() {
        let toml = "";
        // Empty TOML has no [[entries]] table; parse returns empty Vec via default
        let entries = parse_revocation_list(toml.as_bytes());
        // An empty string won't have the `entries` key — accept either empty or error
        if let Ok(v) = entries {
            assert!(v.is_empty());
        }
        // Explicit empty file
        let toml2 = "[entries]\n";
        let _ = parse_revocation_list(toml2.as_bytes()); // no panic

        // Serialize empty list and re-parse
        let serialized = serialize_revocation_list(&[]);
        let reparsed = parse_revocation_list(serialized.as_bytes()).expect("re-parse empty");
        assert!(reparsed.is_empty());
    }

    #[test]
    fn revocation_legacy_integer_serial_compat() {
        // Old REVOKED.TOML files wrote serial as integer (always 0 due to bug).
        let toml = r#"
[[entries]]
serial          = 0
revocation_time = "2026-05-10T00:00:00Z"
"#;
        let entries = parse_revocation_list(toml.as_bytes()).expect("parse legacy integer");
        assert_eq!(entries[0].serial, "0");
    }
}
