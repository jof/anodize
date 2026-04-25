use std::path::{Path, PathBuf};

use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Deserialize)]
pub struct Profile {
    pub ca: CaConfig,
    pub hsm: HsmConfig,
}

#[derive(Debug, Deserialize)]
pub struct CaConfig {
    pub common_name: String,
    pub organization: String,
    pub country: String,
    pub cdp_url: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct HsmConfig {
    pub module_path: PathBuf,
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
module_path  = "/usr/lib/softhsm/libsofthsm2.so"
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
                 [hsm]\nmodule_path=\"/x\"\ntoken_label=\"t\"\nkey_label=\"k\"\npin_source=\"{}\"\n",
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
                    [hsm]\nmodule_path=\"/x\"\ntoken_label=\"t\"\nkey_label=\"k\"\npin_source=\"env:\"\n";
        assert!(toml::from_str::<Profile>(toml).is_err());

        let toml2 = "[ca]\ncommon_name=\"x\"\norganization=\"x\"\ncountry=\"US\"\n\
                     [hsm]\nmodule_path=\"/x\"\ntoken_label=\"t\"\nkey_label=\"k\"\npin_source=\"unknown:foo\"\n";
        assert!(toml::from_str::<Profile>(toml2).is_err());
    }

    #[test]
    fn missing_required_field() {
        let toml = "[ca]\norganization=\"x\"\ncountry=\"US\"\n\
                    [hsm]\nmodule_path=\"/x\"\ntoken_label=\"t\"\nkey_label=\"k\"\npin_source=\"prompt\"\n";
        assert!(toml::from_str::<Profile>(toml).is_err());
    }

    #[test]
    fn cdp_url_is_optional() {
        let toml = "[ca]\ncommon_name=\"x\"\norganization=\"x\"\ncountry=\"US\"\n\
                    [hsm]\nmodule_path=\"/x\"\ntoken_label=\"t\"\nkey_label=\"k\"\npin_source=\"prompt\"\n";
        let p: Profile = toml::from_str(toml).expect("parse");
        assert!(p.ca.cdp_url.is_none());
    }
}
