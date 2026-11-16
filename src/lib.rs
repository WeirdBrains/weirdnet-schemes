#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

mod error;
pub mod link;
pub mod names;
pub mod os;
pub mod records;
pub mod registry;
pub mod signed;

pub use error::{Error, Result};
pub use link::{Action, Link};
pub use records::{CanonicalList, InstallHint, Platform, PrefixRecord, RootRotation, SchemeRecord, TrustAnchors};
pub use registry::{Added, Because, Registry, Resolution, Source};
pub use signed::{Role, Signed};
