//! App links: `<scheme>://join/<code>`, `<scheme>://answer/<code>`, and resources.

use crate::error::{Error, Result};
use crate::names;

/// What a link asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// An invite (`join/<code>`).
    Join(String),
    /// An invite answer (`answer/<code>`).
    Answer(String),
    /// A resource held by peers: `<authority>/<path>` (a name or user id, then a path).
    Resource {
        /// A name (`home.example.com`) or user id.
        authority: String,
        /// The rest, without the leading `/`.
        path: String,
    },
}

/// A parsed app link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    /// The scheme, lowercase.
    pub scheme: String,
    /// What it asks for.
    pub action: Action,
}

impl Link {
    /// Parses `scheme://…`. Refuses `weirdnet://` (internal only) and standard schemes.
    pub fn parse(url: &str) -> Result<Self> {
        let (scheme, rest) = url.split_once("://").ok_or_else(|| Error::Invalid("not a scheme link".into()))?;
        let scheme = scheme.to_ascii_lowercase();
        names::check_scheme(&scheme)?;
        if url.len() > 8192 || rest.chars().any(|c| c.is_control() || c == ' ') {
            return Err(Error::Invalid("bad link".into()));
        }
        let rest = rest.split(['?', '#']).next().unwrap_or("");
        let (first, tail) = rest.split_once('/').unwrap_or((rest, ""));
        let code = |t: &str| -> Result<String> {
            let t = t.trim_end_matches('/');
            if t.is_empty() || t.contains('/') {
                return Err(Error::Invalid("bad invite code".into()));
            }
            Ok(t.to_string())
        };
        let action = match first {
            "join" => Action::Join(code(tail)?),
            "answer" => Action::Answer(code(tail)?),
            "" => return Err(Error::Invalid("no authority".into())),
            a => Action::Resource { authority: a.to_ascii_lowercase(), path: tail.to_string() },
        };
        Ok(Self { scheme, action })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links() {
        assert_eq!(Link::parse("weirdnet-morph://join/ABCD-1234").unwrap().action, Action::Join("ABCD-1234".into()));
        assert_eq!(
            Link::parse("WEIRDNET-MUNINN://answer/xyz/").unwrap(),
            Link { scheme: "weirdnet-muninn".into(), action: Action::Answer("xyz".into()) }
        );
        assert_eq!(
            Link::parse("weirdnet-morph://Home.Example.com/notes/a.md?x=1").unwrap().action,
            Action::Resource { authority: "home.example.com".into(), path: "notes/a.md".into() }
        );
        for bad in [
            "weirdnet://open/x",
            "https://x",
            "weirdnet-morph://join/",
            "weirdnet-morph://join/a/b",
            "weirdnet-morph://",
            "nope",
            "weirdnet-morph://a b",
        ] {
            assert!(Link::parse(bad).is_err(), "{bad}");
        }
    }
}
