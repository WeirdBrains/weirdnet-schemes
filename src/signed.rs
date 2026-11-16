//! Signed envelopes: the exact JSON bytes of a record and the signatures over them.

use crate::error::{Error, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use libp2p_identity::{Keypair, PublicKey};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

/// Who a signature speaks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// The record's publisher.
    Publisher,
    /// The WeirdBrains root key (reserved prefixes, the canonical list, root rotations).
    Root,
    /// The previous holder handing a prefix to a new publisher.
    Transfer,
    /// The new root key accepting a rotation.
    NewRoot,
}

impl Role {
    fn name(self) -> &'static str {
        match self {
            Role::Publisher => "publisher",
            Role::Root => "root",
            Role::Transfer => "transfer",
            Role::NewRoot => "new-root",
        }
    }
}

/// One signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sig {
    /// What it speaks for.
    pub role: Role,
    /// The signer's public key (libp2p protobuf encoding, base64).
    pub key: String,
    /// The signature (base64).
    pub sig: String,
}

/// A record and its signatures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signed {
    /// The record kind: "prefix", "scheme", "list" or "root-rotation".
    pub kind: String,
    /// The exact JSON of the record.
    pub body: String,
    /// The signatures.
    pub sigs: Vec<Sig>,
}

fn message(kind: &str, role: Role, body: &str) -> Vec<u8> {
    [format!("weirdnet-schemes/{kind}/{}/v1\n", role.name()).as_bytes(), body.as_bytes()].concat()
}

/// A public key from its text form.
pub fn decode_key(s: &str) -> Result<PublicKey> {
    let b = B64.decode(s).map_err(|_| Error::Invalid("bad key".into()))?;
    PublicKey::try_decode_protobuf(&b).map_err(|_| Error::Invalid("bad key".into()))
}

/// The text form of a public key.
pub fn encode_key(k: &PublicKey) -> String {
    B64.encode(k.encode_protobuf())
}

/// A short id for a key: 32 hex characters of the SHA-256 of its protobuf encoding (the
/// Weirdnet user id when it is a user key).
pub fn key_id(k: &PublicKey) -> String {
    use sha2::Digest;
    hex::encode(&sha2::Sha256::digest(k.encode_protobuf())[..16])
}

impl Signed {
    /// Wraps a record.
    pub fn new<T: Serialize>(kind: &str, record: &T) -> Self {
        Self { kind: kind.into(), body: serde_json::to_string(record).expect("records serialize"), sigs: Vec::new() }
    }

    /// Adds a signature.
    pub fn sign(mut self, role: Role, key: &Keypair) -> Result<Self> {
        let sig = key.sign(&message(&self.kind, role, &self.body)).map_err(|e| Error::Signature(e.to_string()))?;
        self.sigs.retain(|s| s.role != role);
        self.sigs.push(Sig { role, key: encode_key(&key.public()), sig: B64.encode(sig) });
        Ok(self)
    }

    /// The record.
    pub fn record<T: DeserializeOwned>(&self, kind: &str) -> Result<T> {
        if self.kind != kind {
            return Err(Error::Invalid(format!("expected a {kind} record, got {}", self.kind)));
        }
        serde_json::from_str(&self.body).map_err(|e| Error::Invalid(format!("{kind}: {e}")))
    }

    /// True if there is a valid `role` signature by `key`.
    pub fn signed_by(&self, role: Role, key: &PublicKey) -> bool {
        let want = encode_key(key);
        self.sigs
            .iter()
            .filter(|s| s.role == role && s.key == want)
            .any(|s| B64.decode(&s.sig).is_ok_and(|sig| key.verify(&message(&self.kind, role, &self.body), &sig)))
    }

    /// True if any of `keys` made a valid `role` signature.
    pub fn signed_by_any(&self, role: Role, keys: &[PublicKey]) -> bool {
        keys.iter().any(|k| self.signed_by(role, k))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_bind_kind_role_and_body() {
        let k = Keypair::generate_ed25519();
        let s = Signed::new("prefix", &serde_json::json!({"a": 1})).sign(Role::Publisher, &k).unwrap();
        assert!(s.signed_by(Role::Publisher, &k.public()));
        assert!(!s.signed_by(Role::Root, &k.public()));
        assert!(!s.signed_by(Role::Publisher, &Keypair::generate_ed25519().public()));
        let mut other = s.clone();
        other.kind = "scheme".into();
        assert!(!other.signed_by(Role::Publisher, &k.public()));
        let mut other = s.clone();
        other.body = "{\"a\":2}".into();
        assert!(!other.signed_by(Role::Publisher, &k.public()));
        // A signature claimed for another role doesn't count.
        let mut other = s.clone();
        other.sigs[0].role = Role::Root;
        assert!(!other.signed_by(Role::Root, &k.public()));
    }
}
