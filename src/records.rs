//! The records: prefixes, schemes, the canonical list, and root key rotations.

use crate::error::{Error, Result};
use crate::names;
use crate::signed::{Role, Signed, decode_key, encode_key};
use libp2p_identity::{Keypair, PublicKey};
use serde::{Deserialize, Serialize};

/// The record format.
pub const FORMAT: u32 = 1;

/// A prefix registration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrefixRecord {
    /// [`FORMAT`].
    pub format: u32,
    /// The prefix, such as `acme` or `weirdnet-morph`.
    pub prefix: String,
    /// The holder's public key (see [`crate::signed::encode_key`]).
    pub publisher: String,
    /// Higher replaces lower.
    pub seq: u64,
    /// Unix seconds after which it is ignored.
    pub expires: u64,
    /// A withdrawal (tombstone).
    #[serde(default)]
    pub withdrawn: bool,
}

/// Where a missing app can be had. Shown to the user; never fetched on its own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum InstallHint {
    /// A Salty Gull app id (desktop and sideloaded builds).
    SaltyGull(String),
    /// An Apple App Store id.
    AppStore(String),
    /// A Google Play package name.
    Play(String),
    /// An F-Droid package name.
    FDroid(String),
    /// An HTTPS page.
    Https(String),
}

/// What a build is, for picking install hints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// Linux, macOS, Windows (and sideloaded builds).
    Desktop,
    /// iOS from the App Store.
    Ios,
    /// Android from Google Play.
    AndroidPlay,
    /// Android from F-Droid.
    AndroidFDroid,
}

impl InstallHint {
    fn check(&self) -> Result<()> {
        let v = match self {
            InstallHint::Https(u) => {
                if !u.starts_with("https://") {
                    return Err(Error::Invalid("install pages must be https".into()));
                }
                u
            }
            InstallHint::SaltyGull(v) | InstallHint::AppStore(v) | InstallHint::Play(v) | InstallHint::FDroid(v) => v,
        };
        if v.is_empty() || v.len() > 512 || v.chars().any(char::is_control) {
            return Err(Error::Invalid("bad install hint".into()));
        }
        Ok(())
    }

    /// True if this hint fits `p` (HTTPS pages fit everywhere).
    pub fn fits(&self, p: Platform) -> bool {
        matches!(
            (self, p),
            (InstallHint::Https(_), _)
                | (InstallHint::SaltyGull(_), Platform::Desktop)
                | (InstallHint::AppStore(_), Platform::Ios)
                | (InstallHint::Play(_), Platform::AndroidPlay)
                | (InstallHint::FDroid(_), Platform::AndroidFDroid)
        )
    }
}

/// A scheme registration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemeRecord {
    /// [`FORMAT`].
    pub format: u32,
    /// The scheme, such as `weirdnet-morph`.
    pub scheme: String,
    /// The prefix it falls under (the publisher must hold it).
    pub prefix: String,
    /// A stable app id, such as `org.weirdbrains.morph`.
    pub app_id: String,
    /// The publisher's public key.
    pub publisher: String,
    /// The app's name.
    pub display_name: String,
    /// What the handler does: such as `browse`, `join`, `answer`.
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Where to get the app.
    #[serde(default)]
    pub install: Vec<InstallHint>,
    /// Higher replaces lower.
    pub seq: u64,
    /// Unix seconds after which it is ignored.
    pub expires: u64,
    /// A withdrawal (tombstone).
    #[serde(default)]
    pub withdrawn: bool,
}

impl PrefixRecord {
    /// A new registration for `key`.
    pub fn new(prefix: &str, key: &PublicKey, seq: u64, expires: u64) -> Self {
        Self { format: FORMAT, prefix: prefix.into(), publisher: encode_key(key), seq, expires, withdrawn: false }
    }

    /// Checks names and shape (not signatures).
    pub fn check(&self) -> Result<()> {
        if self.format != FORMAT {
            return Err(Error::Invalid(format!("format {}", self.format)));
        }
        names::check_prefix(&self.prefix)?;
        decode_key(&self.publisher)?;
        Ok(())
    }

    /// Signs as the publisher.
    pub fn sign(&self, publisher: &Keypair) -> Result<Signed> {
        self.check()?;
        Signed::new("prefix", self).sign(Role::Publisher, publisher)
    }
}

impl SchemeRecord {
    /// Checks names and shape (not signatures).
    pub fn check(&self) -> Result<()> {
        if self.format != FORMAT {
            return Err(Error::Invalid(format!("format {}", self.format)));
        }
        names::check_scheme(&self.scheme)?;
        names::check_prefix(&self.prefix)?;
        if !names::under(&self.scheme, &self.prefix) {
            return Err(Error::Invalid(format!("{} is not under the prefix {}", self.scheme, self.prefix)));
        }
        let app_ok =
            (3..=128).contains(&self.app_id.len()) && self.app_id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));
        if !app_ok {
            return Err(Error::Invalid("bad app id".into()));
        }
        if self.display_name.trim().is_empty() || self.display_name.len() > 128 {
            return Err(Error::Invalid("bad display name".into()));
        }
        if self.capabilities.len() > 32
            || self.capabilities.iter().any(|c| c.is_empty() || c.len() > 64 || !c.bytes().all(|b| b.is_ascii_lowercase() || b == b'-' || b == b'.'))
        {
            return Err(Error::Invalid("bad capabilities".into()));
        }
        if self.install.len() > 16 {
            return Err(Error::Invalid("too many install hints".into()));
        }
        for h in &self.install {
            h.check()?;
        }
        decode_key(&self.publisher)?;
        Ok(())
    }

    /// Signs as the publisher.
    pub fn sign(&self, publisher: &Keypair) -> Result<Signed> {
        self.check()?;
        Signed::new("scheme", self).sign(Role::Publisher, publisher)
    }

    /// The install hints for `p`.
    pub fn hints_for(&self, p: Platform) -> Vec<&InstallHint> {
        self.install.iter().filter(|h| h.fits(p)).collect()
    }
}

/// The WeirdBrains canonical list: authoritative for reserved prefixes and first-party
/// schemes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalList {
    /// [`FORMAT`].
    pub format: u32,
    /// Higher replaces lower.
    pub seq: u64,
    /// Unix seconds.
    pub issued: u64,
    /// Unix seconds after which it is stale (keep using it, but refresh).
    pub expires: u64,
    /// Signed prefix records.
    pub prefixes: Vec<Signed>,
    /// Signed scheme records.
    pub schemes: Vec<Signed>,
}

impl CanonicalList {
    /// Signs with the root key.
    pub fn sign(&self, root: &Keypair) -> Result<Signed> {
        Signed::new("list", self).sign(Role::Root, root)
    }
}

/// A root key rotation, signed by the old and the new root keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootRotation {
    /// [`FORMAT`].
    pub format: u32,
    /// The old key.
    pub old: String,
    /// The new key.
    pub new: String,
    /// Unix seconds.
    pub at: u64,
}

impl RootRotation {
    /// Signs the rotation with both keys.
    pub fn sign(old: &Keypair, new: &Keypair, at: u64) -> Result<Signed> {
        let r = RootRotation { format: FORMAT, old: encode_key(&old.public()), new: encode_key(&new.public()), at };
        Signed::new("root-rotation", &r).sign(Role::Root, old)?.sign(Role::NewRoot, new)
    }
}

/// Root keys an app trusts (shipped in its defaults).
#[derive(Debug, Clone, Default)]
pub struct TrustAnchors {
    keys: Vec<PublicKey>,
}

impl TrustAnchors {
    /// From public keys in text form.
    pub fn new<S: AsRef<str>>(keys: &[S]) -> Result<Self> {
        Ok(Self { keys: keys.iter().map(|k| decode_key(k.as_ref())).collect::<Result<_>>()? })
    }

    /// From public keys.
    pub fn from_keys(keys: Vec<PublicKey>) -> Self {
        Self { keys }
    }

    /// The keys.
    pub fn keys(&self) -> &[PublicKey] {
        &self.keys
    }

    /// Follows a rotation from a trusted key to a new one (both must have signed). The old
    /// key stops being trusted.
    pub fn rotate(&mut self, s: &Signed) -> Result<()> {
        let r: RootRotation = s.record("root-rotation")?;
        let (old, new) = (decode_key(&r.old)?, decode_key(&r.new)?);
        if !self.keys.contains(&old) {
            return Err(Error::Signature("the rotation is not from a trusted root key".into()));
        }
        if !s.signed_by(Role::Root, &old) || !s.signed_by(Role::NewRoot, &new) {
            return Err(Error::Signature("the rotation needs both the old and the new key".into()));
        }
        self.keys.retain(|k| k != &old);
        if !self.keys.contains(&new) {
            self.keys.push(new);
        }
        Ok(())
    }
}
