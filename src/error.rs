/// Errors from the registry.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// A name, record or URL is malformed.
    #[error("invalid: {0}")]
    Invalid(String),
    /// A signature is missing or does not check out.
    #[error("signature: {0}")]
    Signature(String),
    /// The prefix is reserved for WeirdBrains (`weirdnet…`) or is a standard scheme.
    #[error("{0} is reserved")]
    Reserved(String),
    /// The record is older than (or the same as) one already held.
    #[error("stale record (seq {got}, have {have})")]
    Stale {
        /// The record's seq.
        got: u64,
        /// The held seq.
        have: u64,
    },
    /// The record has expired.
    #[error("expired")]
    Expired,
    /// The prefix belongs to another publisher (and no transfer signature was given).
    #[error("{prefix} belongs to another publisher")]
    NotOwner {
        /// The prefix.
        prefix: String,
    },
}

/// `Result` with [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;
