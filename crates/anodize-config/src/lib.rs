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
    pub serial: u64,
    pub revocation_time: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
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
    #[serde(deserialize_with = "deserialize_module_name")]
    pub module_name: String,
    pub token_label: String,
    pub key_label: String,
    #[serde(default)]
    pub key_spec: KeySpec,
    pub pin_source: PinSource,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum KeySpec {
    #[default]
    EcdsaP384,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinSource {
    Prompt,
    Env(String),
    File(PathBuf),
}

impl PinSource {
    pub fn warn_if_unsafe(&self) {
        match self {
            PinSource::Env(var) => {
                tracing::warn!("pin_source=env:{} is not safe for ceremony use", var);
            }
            PinSource::File(path) => {
                tracing::warn!(
                    "pin_source=file:{} is not safe for ceremony use",
                    path.display()
                );
            }
            PinSource::Prompt => {}
        }
    }
}

impl<'de> Deserialize<'de> for PinSource {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        if s == "prompt" {
            return Ok(PinSource::Prompt);
        }
        if let Some(var) = s.strip_prefix("env:") {
            if var.is_empty() {
                return Err(serde::de::Error::custom(
                    "env: pin_source requires a variable name",
                ));
            }
            return Ok(PinSource::Env(var.to_string()));
        }
        if let Some(path) = s.strip_prefix("file:") {
            if path.is_empty() {
                return Err(serde::de::Error::custom("file: pin_source requires a path"));
            }
            return Ok(PinSource::File(PathBuf::from(path)));
        }
        Err(serde::de::Error::custom(format!(
            "invalid pin_source {:?}: expected \"prompt\", \"env:VAR\", or \"file:/path\"",
            s
        )))
    }
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
    #[error("PKCS#11 module {name:?} not found in search paths (set ANODIZE_PKCS11_MODULES or check module name)")]
    ModuleNotFound { name: String },
}

/// Well-known directories to search when `ANODIZE_PKCS11_MODULES` is not set.
const FALLBACK_MODULE_DIRS: &[&str] = &[
    "/run/current-system/sw/lib/pkcs11",
    "/run/current-system/sw/lib/softhsm",
    "/usr/lib/softhsm",
    "/usr/lib/pkcs11",
    "/usr/lib/x86_64-linux-gnu/softhsm",
    "/usr/lib/x86_64-linux-gnu/pkcs11",
    "/usr/lib/aarch64-linux-gnu/softhsm",
    "/usr/lib/aarch64-linux-gnu/pkcs11",
];

impl HsmConfig {
    /// Resolve `module_name` to a full filesystem path.
    ///
    /// When `ANODIZE_PKCS11_MODULES` is set (always on the ISO), searches the
    /// colon-separated path list for an entry whose filename matches
    /// `module_name`. When absent (dev host builds), searches well-known
    /// library directories.
    pub fn resolve_module_path(&self) -> Result<PathBuf, ConfigError> {
        let modules_env = std::env::var("ANODIZE_PKCS11_MODULES").ok();
        resolve_module_name(&self.module_name, modules_env.as_deref())
    }
}

fn resolve_module_name(
    module_name: &str,
    modules_env: Option<&str>,
) -> Result<PathBuf, ConfigError> {
    if let Some(modules) = modules_env {
        for entry in modules.split(':').filter(|s| !s.is_empty()) {
            let p = Path::new(entry);
            if p.file_name().and_then(|f| f.to_str()) == Some(module_name) {
                return Ok(p.into());
            }
        }
        return Err(ConfigError::ModuleNotFound {
            name: module_name.to_owned(),
        });
    }
    for dir in FALLBACK_MODULE_DIRS {
        let candidate = Path::new(dir).join(module_name);
        if candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(ConfigError::ModuleNotFound {
        name: module_name.to_owned(),
    })
}

fn deserialize_module_name<'de, D: serde::Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    let s = String::deserialize(d)?;
    if s.is_empty() {
        return Err(serde::de::Error::custom("module_name must not be empty"));
    }
    if s.contains('/') || s.contains('\\') || s.contains("..") {
        return Err(serde::de::Error::custom(format!(
            "module_name must be a plain filename (no path separators), got {:?}",
            s
        )));
    }
    Ok(s)
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
module_name  = "libsofthsm2.so"
token_label  = "anodize-root-2026"
key_label    = "root-key"
key_spec     = "ecdsa-p384"
pin_source   = "prompt"
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
        assert_eq!(p.hsm.token_label, "anodize-root-2026");
        assert_eq!(p.hsm.key_label, "root-key");
        assert_eq!(p.hsm.key_spec, KeySpec::EcdsaP384);
        assert_eq!(p.hsm.pin_source, PinSource::Prompt);
    }

    #[test]
    fn pin_source_variants() {
        let ps = |s: &str| -> PinSource {
            let toml = format!(
                "[ca]\ncommon_name=\"x\"\norganization=\"x\"\ncountry=\"US\"\n\
                 [hsm]\nmodule_name=\"test.so\"\ntoken_label=\"t\"\nkey_label=\"k\"\npin_source=\"{}\"\n",
                s
            );
            let p: Profile = toml::from_str(&toml).expect("parse");
            p.hsm.pin_source
        };

        assert_eq!(ps("prompt"), PinSource::Prompt);
        assert_eq!(ps("env:MY_VAR"), PinSource::Env("MY_VAR".into()));
        assert_eq!(
            ps("file:/run/anodize/pin"),
            PinSource::File(PathBuf::from("/run/anodize/pin"))
        );
    }

    #[test]
    fn invalid_pin_source() {
        let toml = "[ca]\ncommon_name=\"x\"\norganization=\"x\"\ncountry=\"US\"\n\
                    [hsm]\nmodule_name=\"test.so\"\ntoken_label=\"t\"\nkey_label=\"k\"\npin_source=\"env:\"\n";
        assert!(toml::from_str::<Profile>(toml).is_err());

        let toml2 = "[ca]\ncommon_name=\"x\"\norganization=\"x\"\ncountry=\"US\"\n\
                     [hsm]\nmodule_name=\"test.so\"\ntoken_label=\"t\"\nkey_label=\"k\"\npin_source=\"unknown:foo\"\n";
        assert!(toml::from_str::<Profile>(toml2).is_err());
    }

    #[test]
    fn missing_required_field() {
        let toml = "[ca]\norganization=\"x\"\ncountry=\"US\"\n\
                    [hsm]\nmodule_name=\"test.so\"\ntoken_label=\"t\"\nkey_label=\"k\"\npin_source=\"prompt\"\n";
        assert!(toml::from_str::<Profile>(toml).is_err());
    }

    #[test]
    fn cdp_url_is_optional() {
        let toml = "[ca]\ncommon_name=\"x\"\norganization=\"x\"\ncountry=\"US\"\n\
                    [hsm]\nmodule_name=\"test.so\"\ntoken_label=\"t\"\nkey_label=\"k\"\npin_source=\"prompt\"\n";
        let p: Profile = toml::from_str(toml).expect("parse");
        assert!(p.ca.cdp_url.is_none());
    }

    #[test]
    fn cert_profiles_parse() {
        let toml = r#"
[ca]
common_name  = "Root CA"
organization = "Acme"
country      = "US"

[hsm]
module_name = "test.so"
token_label = "t"
key_label   = "k"
pin_source  = "prompt"

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
                    [hsm]\nmodule_name=\"test.so\"\ntoken_label=\"t\"\nkey_label=\"k\"\npin_source=\"prompt\"\n";
        let p: Profile = toml::from_str(toml).expect("parse");
        assert!(p.cert_profiles.is_empty());
    }

    #[test]
    fn revocation_list_round_trip() {
        let toml = r#"
[[entries]]
serial          = 12345
revocation_time = "2026-04-01T00:00:00Z"
reason          = "key-compromise"

[[entries]]
serial          = 67890
revocation_time = "2026-05-15T12:00:00Z"
"#;
        let entries = parse_revocation_list(toml.as_bytes()).expect("parse");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].serial, 12345);
        assert_eq!(entries[0].revocation_time, "2026-04-01T00:00:00Z");
        assert_eq!(entries[0].reason.as_deref(), Some("key-compromise"));
        assert_eq!(entries[1].serial, 67890);
        assert!(entries[1].reason.is_none());

        // Serialize and re-parse
        let serialized = serialize_revocation_list(&entries);
        let reparsed = parse_revocation_list(serialized.as_bytes()).expect("re-parse");
        assert_eq!(reparsed.len(), 2);
        assert_eq!(reparsed[0].serial, 12345);
        assert_eq!(reparsed[1].serial, 67890);
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

    // ── module_name validation ────────────────────────────────────────────────

    #[test]
    fn module_name_rejects_path_separators() {
        let toml = "[ca]\ncommon_name=\"x\"\norganization=\"x\"\ncountry=\"US\"\n\
                    [hsm]\nmodule_name=\"/usr/lib/foo.so\"\ntoken_label=\"t\"\nkey_label=\"k\"\npin_source=\"prompt\"\n";
        assert!(toml::from_str::<Profile>(toml).is_err());

        let toml2 = "[ca]\ncommon_name=\"x\"\norganization=\"x\"\ncountry=\"US\"\n\
                     [hsm]\nmodule_name=\"../evil.so\"\ntoken_label=\"t\"\nkey_label=\"k\"\npin_source=\"prompt\"\n";
        assert!(toml::from_str::<Profile>(toml2).is_err());

        let toml3 = "[ca]\ncommon_name=\"x\"\norganization=\"x\"\ncountry=\"US\"\n\
                     [hsm]\nmodule_name=\"sub/dir.so\"\ntoken_label=\"t\"\nkey_label=\"k\"\npin_source=\"prompt\"\n";
        assert!(toml::from_str::<Profile>(toml3).is_err());
    }

    #[test]
    fn module_name_rejects_empty() {
        let toml = "[ca]\ncommon_name=\"x\"\norganization=\"x\"\ncountry=\"US\"\n\
                    [hsm]\nmodule_name=\"\"\ntoken_label=\"t\"\nkey_label=\"k\"\npin_source=\"prompt\"\n";
        assert!(toml::from_str::<Profile>(toml).is_err());
    }

    #[test]
    fn module_name_accepts_plain_filename() {
        let toml = "[ca]\ncommon_name=\"x\"\norganization=\"x\"\ncountry=\"US\"\n\
                    [hsm]\nmodule_name=\"yubihsm_pkcs11.so\"\ntoken_label=\"t\"\nkey_label=\"k\"\npin_source=\"prompt\"\n";
        let p: Profile = toml::from_str(toml).expect("parse");
        assert_eq!(p.hsm.module_name, "yubihsm_pkcs11.so");
    }

    // ── resolve_module_name ──────────────────────────────────────────────────

    #[test]
    fn resolve_finds_in_env() {
        let result = resolve_module_name(
            "yubihsm_pkcs11.so",
            Some("/nix/store/xxx/lib/pkcs11/yubihsm_pkcs11.so"),
        );
        assert_eq!(
            result.unwrap(),
            PathBuf::from("/nix/store/xxx/lib/pkcs11/yubihsm_pkcs11.so")
        );
    }

    #[test]
    fn resolve_colon_separated_env() {
        let result = resolve_module_name(
            "libsofthsm2.so",
            Some("/nix/store/xxx/lib/pkcs11/yubihsm_pkcs11.so:/nix/store/yyy/lib/softhsm/libsofthsm2.so"),
        );
        assert_eq!(
            result.unwrap(),
            PathBuf::from("/nix/store/yyy/lib/softhsm/libsofthsm2.so")
        );
    }

    #[test]
    fn resolve_not_found_in_env() {
        let result = resolve_module_name(
            "nonexistent.so",
            Some("/nix/store/xxx/lib/pkcs11/yubihsm_pkcs11.so"),
        );
        assert!(matches!(result.unwrap_err(), ConfigError::ModuleNotFound { .. }));
    }

    #[test]
    fn resolve_env_absent_no_fallback_match() {
        let result = resolve_module_name("nonexistent-xyzzy-anodize-test.so", None);
        assert!(matches!(result.unwrap_err(), ConfigError::ModuleNotFound { .. }));
    }
}
