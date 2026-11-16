//! The local registry and resolver.
//!
//! Records come from the canonical list (authoritative for reserved `weirdnet…` prefixes
//! and first-party schemes), from relays, later from the DHT, and from apps installed on
//! the device. Resolution prefers, in order: the user's pin, the canonical list, an
//! installed app whose publisher matches, and otherwise asks the user. It never picks a
//! stranger's record on its own.

use crate::error::{Error, Result};
use crate::names;
use crate::records::{CanonicalList, PrefixRecord, SchemeRecord, TrustAnchors};
use crate::signed::{Role, Signed, decode_key, key_id};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Where a record came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// The WeirdBrains canonical list.
    Canonical,
    /// A relay's cache.
    Relay,
    /// The DHT.
    Dht,
    /// An app installed on this device.
    Local,
}

/// A held record with its envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Held<T> {
    /// The record.
    pub record: T,
    /// The signed envelope (to pass on).
    pub signed: Signed,
    /// Where it came from.
    pub source: Source,
}

/// What a scheme resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// The app to hand the link to.
    App {
        /// Its record.
        record: SchemeRecord,
        /// Whether that app is installed here (if not, offer [`SchemeRecord::hints_for`]).
        installed: bool,
        /// Why this one.
        because: Because,
    },
    /// Several (or one unknown) publishers claim it: ask the user, showing publisher, name
    /// and capabilities; pin the choice.
    Choose(Vec<SchemeRecord>),
    /// `weirdnet://`: internal only, never handed to an app.
    Internal,
    /// No trusted record. Say so; don't look for a handler.
    Unknown,
}

/// Why a record won.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Because {
    /// The user pinned this publisher.
    Pinned,
    /// It is on the canonical list.
    Canonical,
    /// An installed app with this publisher handles it.
    Installed,
}

/// What [`Registry::add`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Added {
    /// A new record.
    New,
    /// It replaced an older one.
    Updated,
    /// It withdrew a record.
    Withdrawn,
}

/// The registry, serializable as the device's local cache.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Registry {
    canonical_seq: Option<u64>,
    /// prefix → publisher id → record
    prefixes: BTreeMap<String, BTreeMap<String, Held<PrefixRecord>>>,
    /// scheme → publisher id → record
    schemes: BTreeMap<String, BTreeMap<String, Held<SchemeRecord>>>,
    /// scheme → publisher id
    pins: BTreeMap<String, String>,
    /// app id → publisher id
    installed: BTreeMap<String, String>,
    #[serde(skip)]
    anchors: TrustAnchors,
}

fn pid(key: &str) -> Result<String> {
    Ok(key_id(&decode_key(key)?))
}

impl Registry {
    /// An empty registry trusting `anchors` for the canonical list.
    pub fn new(anchors: TrustAnchors) -> Self {
        Self { anchors, ..Default::default() }
    }

    /// Restores a saved cache (from `serde_json`); the anchors aren't saved.
    pub fn restore(json: &[u8], anchors: TrustAnchors) -> Result<Self> {
        let mut r: Registry = serde_json::from_slice(json).map_err(|e| Error::Invalid(format!("cache: {e}")))?;
        r.anchors = anchors;
        Ok(r)
    }

    /// The cache, to save.
    pub fn save(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("registry serializes")
    }

    /// The anchors (to follow a root rotation).
    pub fn anchors_mut(&mut self) -> &mut TrustAnchors {
        &mut self.anchors
    }

    /// The canonical list seq held, if any.
    pub fn canonical_seq(&self) -> Option<u64> {
        self.canonical_seq
    }

    /// Loads a canonical list signed by a trusted root key. It replaces every record that
    /// came from an older list.
    pub fn load_canonical(&mut self, signed: &Signed, now: u64) -> Result<()> {
        let list: CanonicalList = signed.record("list")?;
        if !signed.signed_by_any(Role::Root, self.anchors.keys()) {
            return Err(Error::Signature("the canonical list is not signed by a trusted root key".into()));
        }
        if let Some(have) = self.canonical_seq
            && list.seq <= have
        {
            return Err(Error::Stale { got: list.seq, have });
        }
        if list.expires <= now {
            return Err(Error::Expired);
        }
        // Check everything before changing anything.
        let mut prefixes = Vec::new();
        for s in &list.prefixes {
            let r: PrefixRecord = s.record("prefix")?;
            r.check()?;
            self.check_prefix_sigs(&r, s, true)?;
            prefixes.push((r, s.clone()));
        }
        let mut schemes = Vec::new();
        for s in &list.schemes {
            let r: SchemeRecord = s.record("scheme")?;
            r.check()?;
            if !s.signed_by(Role::Publisher, &decode_key(&r.publisher)?) {
                return Err(Error::Signature(format!("{} is not signed by its publisher", r.scheme)));
            }
            if names::is_reserved(&r.prefix) && !s.signed_by_any(Role::Root, self.anchors.keys()) {
                return Err(Error::Signature(format!("{} needs the root signature", r.scheme)));
            }
            let owner = prefixes.iter().any(|(p, _)| p.prefix == r.prefix && p.publisher == r.publisher && !p.withdrawn);
            if !owner {
                return Err(Error::NotOwner { prefix: r.prefix.clone() });
            }
            schemes.push((r, s.clone()));
        }
        for m in self.prefixes.values_mut() {
            m.retain(|_, h| h.source != crate::registry::Source::Canonical);
        }
        for m in self.schemes.values_mut() {
            m.retain(|_, h| h.source != Source::Canonical);
        }
        for (r, s) in prefixes {
            let id = pid(&r.publisher)?;
            // The canonical list is authoritative: drop any other claim on a reserved prefix.
            let m = self.prefixes.entry(r.prefix.clone()).or_default();
            if names::is_reserved(&r.prefix) {
                m.clear();
            }
            m.insert(id, Held { record: r, signed: s, source: Source::Canonical });
        }
        for (r, s) in schemes {
            let id = pid(&r.publisher)?;
            let m = self.schemes.entry(r.scheme.clone()).or_default();
            if names::is_reserved(&r.prefix) {
                m.clear();
            }
            m.insert(id, Held { record: r, signed: s, source: Source::Canonical });
        }
        self.prefixes.retain(|_, m| !m.is_empty());
        self.schemes.retain(|_, m| !m.is_empty());
        self.canonical_seq = Some(list.seq);
        Ok(())
    }

    fn check_prefix_sigs(&self, r: &PrefixRecord, s: &Signed, canonical: bool) -> Result<()> {
        if !s.signed_by(Role::Publisher, &decode_key(&r.publisher)?) {
            return Err(Error::Signature(format!("{} is not signed by its publisher", r.prefix)));
        }
        if names::is_reserved(&r.prefix) {
            if !canonical {
                return Err(Error::Reserved(r.prefix.clone()));
            }
            if !s.signed_by_any(Role::Root, self.anchors.keys()) {
                return Err(Error::Signature(format!("{} needs the root signature", r.prefix)));
            }
        }
        Ok(())
    }

    /// Adds a prefix or scheme record from a relay, the DHT or an installed app. Reserved
    /// prefixes come only from the canonical list.
    pub fn add(&mut self, s: &Signed, source: Source, now: u64) -> Result<Added> {
        if source == Source::Canonical {
            return Err(Error::Invalid("canonical records come with the list".into()));
        }
        match s.kind.as_str() {
            "prefix" => self.add_prefix(s, source, now),
            "scheme" => self.add_scheme(s, source, now),
            k => Err(Error::Invalid(format!("unknown record kind {k}"))),
        }
    }

    fn add_prefix(&mut self, s: &Signed, source: Source, now: u64) -> Result<Added> {
        let r: PrefixRecord = s.record("prefix")?;
        r.check()?;
        self.check_prefix_sigs(&r, s, false)?;
        if r.expires <= now {
            return Err(Error::Expired);
        }
        let id = pid(&r.publisher)?;
        let m = self.prefixes.entry(r.prefix.clone()).or_default();
        if let Some(h) = m.get(&id)
            && r.seq <= h.record.seq
        {
            return Err(Error::Stale { got: r.seq, have: h.record.seq });
        }
        // A transfer: a previous holder signed this record over to the new publisher.
        let given_up: Vec<String> = m
            .iter()
            .filter(|(other, h)| **other != id && decode_key(&h.record.publisher).is_ok_and(|k| s.signed_by(Role::Transfer, &k)))
            .map(|(other, _)| other.clone())
            .collect();
        for g in &given_up {
            m.remove(g);
            for schemes in self.schemes.values_mut() {
                schemes.retain(|id, h| !(id == g && h.record.prefix == r.prefix));
            }
        }
        let added = if r.withdrawn {
            Added::Withdrawn
        } else if m.contains_key(&id) {
            Added::Updated
        } else {
            Added::New
        };
        m.insert(id, Held { record: r, signed: s.clone(), source });
        Ok(added)
    }

    fn add_scheme(&mut self, s: &Signed, source: Source, now: u64) -> Result<Added> {
        let r: SchemeRecord = s.record("scheme")?;
        r.check()?;
        if names::is_reserved(&r.prefix) {
            return Err(Error::Reserved(r.prefix.clone()));
        }
        if !s.signed_by(Role::Publisher, &decode_key(&r.publisher)?) {
            return Err(Error::Signature(format!("{} is not signed by its publisher", r.scheme)));
        }
        if r.expires <= now {
            return Err(Error::Expired);
        }
        let id = pid(&r.publisher)?;
        if !self.holds_prefix(&r.prefix, &id, now) {
            return Err(Error::NotOwner { prefix: r.prefix.clone() });
        }
        let m = self.schemes.entry(r.scheme.clone()).or_default();
        let added = match m.get(&id) {
            Some(h) if r.seq <= h.record.seq => return Err(Error::Stale { got: r.seq, have: h.record.seq }),
            Some(_) if r.withdrawn => Added::Withdrawn,
            Some(_) => Added::Updated,
            None if r.withdrawn => Added::Withdrawn,
            None => Added::New,
        };
        m.insert(id, Held { record: r, signed: s.clone(), source });
        Ok(added)
    }

    fn holds_prefix(&self, prefix: &str, id: &str, now: u64) -> bool {
        self.prefixes.get(prefix).and_then(|m| m.get(id)).is_some_and(|h| !h.record.withdrawn && h.record.expires > now)
    }

    /// Pins a scheme to a publisher (by its key id), as the user chose.
    pub fn pin(&mut self, scheme: &str, publisher_id: &str) {
        self.pins.insert(scheme.into(), publisher_id.into());
    }

    /// Removes a pin.
    pub fn unpin(&mut self, scheme: &str) {
        self.pins.remove(scheme);
    }

    /// Notes an installed app and its publisher (from the app's own signed record).
    pub fn set_installed(&mut self, app_id: &str, publisher_id: &str) {
        self.installed.insert(app_id.into(), publisher_id.into());
    }

    /// Forgets an installed app.
    pub fn uninstalled(&mut self, app_id: &str) {
        self.installed.remove(app_id);
    }

    /// Every live record, signed, to serve to others (relays cache these).
    pub fn records(&self) -> Vec<Signed> {
        let p = self.prefixes.values().flat_map(|m| m.values().map(|h| h.signed.clone()));
        let s = self.schemes.values().flat_map(|m| m.values().map(|h| h.signed.clone()));
        p.chain(s).collect()
    }

    fn live(&self, scheme: &str, now: u64) -> Vec<(String, &Held<SchemeRecord>)> {
        let Some(m) = self.schemes.get(scheme) else { return vec![] };
        m.iter()
            .filter(|(id, h)| {
                let current = !h.record.withdrawn && h.record.expires > now;
                // Canonical records stand on the list; others need a live prefix registration.
                current && (h.source == Source::Canonical || self.holds_prefix(&h.record.prefix, id, now))
            })
            .map(|(id, h)| (id.clone(), h))
            .collect()
    }

    /// Resolves a scheme at time `now`.
    pub fn resolve(&self, scheme: &str, now: u64) -> Resolution {
        let scheme = scheme.to_ascii_lowercase();
        if scheme == names::INTERNAL_SCHEME {
            return Resolution::Internal;
        }
        let live = self.live(&scheme, now);
        let app = |h: &Held<SchemeRecord>, id: &str, because| Resolution::App {
            installed: self.installed.get(&h.record.app_id).is_some_and(|p| p == id),
            record: h.record.clone(),
            because,
        };
        if let Some(p) = self.pins.get(&scheme) {
            return match live.iter().find(|(id, _)| id == p) {
                Some((id, h)) => app(h, id, Because::Pinned),
                None => Resolution::Unknown,
            };
        }
        if let Some((id, h)) = live.iter().find(|(_, h)| h.source == Source::Canonical) {
            return app(h, id, Because::Canonical);
        }
        if names::is_reserved(&scheme) {
            // Reserved schemes resolve only through the canonical list.
            return Resolution::Unknown;
        }
        let installed: Vec<_> = live.iter().filter(|(id, h)| self.installed.get(&h.record.app_id) == Some(id)).collect();
        if let [(id, h)] = installed.as_slice() {
            return app(h, id, Because::Installed);
        }
        match live.len() {
            0 => Resolution::Unknown,
            _ => Resolution::Choose(live.into_iter().map(|(_, h)| h.record.clone()).collect()),
        }
    }
}
