//! Scheme and prefix names.

use crate::error::{Error, Result};

/// The scheme reserved for internal Weirdnet messages. It is never registered with the OS
/// and nothing resolves through it.
pub const INTERNAL_SCHEME: &str = "weirdnet";
/// Prefixes starting with this are WeirdBrains-only.
pub const RESERVED_PREFIX: &str = "weirdnet";

/// IANA-registered (permanent and common provisional) schemes and ones browsers and OSes
/// treat specially; no prefix may be one of these or start with one followed by `-`.
pub const STANDARD_SCHEMES: &[&str] = &[
    "aaa",
    "aaas",
    "about",
    "acap",
    "acct",
    "app",
    "attachment",
    "bitcoin",
    "blob",
    "cap",
    "cid",
    "chrome",
    "chrome-extension",
    "coap",
    "coaps",
    "content",
    "crid",
    "data",
    "dav",
    "dict",
    "dns",
    "edge",
    "example",
    "facetime",
    "fax",
    "feed",
    "file",
    "filesystem",
    "ftp",
    "geo",
    "git",
    "go",
    "gopher",
    "h323",
    "http",
    "https",
    "iax",
    "icap",
    "im",
    "imap",
    "info",
    "intent",
    "ipfs",
    "ipns",
    "ipp",
    "ipps",
    "irc",
    "irc6",
    "ircs",
    "itms",
    "jabber",
    "javascript",
    "ldap",
    "ldaps",
    "magnet",
    "mailto",
    "market",
    "matrix",
    "mid",
    "moz-extension",
    "msrp",
    "msrps",
    "mtqp",
    "mupdate",
    "news",
    "nfs",
    "ni",
    "nih",
    "nntp",
    "opaquelocktoken",
    "pkcs11",
    "pop",
    "pres",
    "reload",
    "resource",
    "rtsp",
    "rtsps",
    "rtspu",
    "service",
    "session",
    "sftp",
    "sip",
    "sips",
    "skype",
    "sms",
    "snmp",
    "soap.beep",
    "soap.beeps",
    "spotify",
    "ssh",
    "steam",
    "stun",
    "stuns",
    "tag",
    "tel",
    "telnet",
    "tftp",
    "thismessage",
    "tip",
    "tn3270",
    "turn",
    "turns",
    "tv",
    "udp",
    "urn",
    "vemmi",
    "view-source",
    "vnc",
    "ws",
    "wss",
    "xcon",
    "xcon-userid",
    "xmlrpc.beep",
    "xmlrpc.beeps",
    "xmpp",
    "z39.50r",
    "z39.50s",
];

/// Checks a scheme name: RFC 3986 (`ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`), lowercase,
/// 2 to 64 characters, and not the internal `weirdnet` scheme or a standard one.
pub fn check_scheme(s: &str) -> Result<()> {
    let b = s.as_bytes();
    let ok = (2..=64).contains(&b.len())
        && b[0].is_ascii_lowercase()
        && b.iter().all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'+' | b'-' | b'.'));
    if !ok {
        return Err(Error::Invalid(format!("bad scheme {s:?}")));
    }
    if s == INTERNAL_SCHEME {
        return Err(Error::Reserved(s.into()));
    }
    if STANDARD_SCHEMES.contains(&s) {
        return Err(Error::Reserved(s.into()));
    }
    Ok(())
}

/// Checks a prefix: lowercase letters, digits and `-`, 2 to 32 characters, starting with a
/// letter, not ending with `-`, and not a standard scheme.
pub fn check_prefix(p: &str) -> Result<()> {
    let b = p.as_bytes();
    let ok = (2..=32).contains(&b.len())
        && b[0].is_ascii_lowercase()
        && *b.last().unwrap() != b'-'
        && b.iter().all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-');
    if !ok {
        return Err(Error::Invalid(format!("bad prefix {p:?}")));
    }
    if STANDARD_SCHEMES.iter().any(|s| p == *s || p.starts_with(&format!("{s}-"))) {
        return Err(Error::Reserved(p.into()));
    }
    Ok(())
}

/// True for prefixes only WeirdBrains may hold.
pub fn is_reserved(prefix: &str) -> bool {
    prefix.starts_with(RESERVED_PREFIX)
}

/// True if `scheme` falls under `prefix` (it is the prefix, or starts with `prefix-`).
pub fn under(scheme: &str, prefix: &str) -> bool {
    scheme == prefix || (scheme.len() > prefix.len() + 1 && scheme.starts_with(prefix) && scheme.as_bytes()[prefix.len()] == b'-')
}

/// The first-party scheme of an app: `weirdnet-<app>`.
pub fn first_party(app: &str) -> String {
    format!("{RESERVED_PREFIX}-{app}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        check_scheme("weirdnet-morph").unwrap();
        check_scheme("acme-notes").unwrap();
        for bad in ["weirdnet", "https", "file", "Morph", "1abc", "a", "a_b", "a b"] {
            assert!(check_scheme(bad).is_err(), "{bad}");
        }
        check_prefix("acme").unwrap();
        for bad in ["http", "https-x", "-a", "a-", "A", "a.b", "x"] {
            assert!(check_prefix(bad).is_err(), "{bad}");
        }
        assert!(is_reserved("weirdnet") && is_reserved("weirdnetx") && !is_reserved("acme"));
        assert!(under("weirdnet-morph", "weirdnet-morph") && under("acme-notes", "acme"));
        assert!(!under("acmenotes", "acme") && !under("acme-", "acme") && !under("acm", "acme"));
        assert_eq!(first_party("muninn"), "weirdnet-muninn");
    }
}
