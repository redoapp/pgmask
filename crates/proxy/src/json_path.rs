//! Shape facts carried from SQL attribution into JSON pointer planning.
//!
//! This type deliberately says only what syntax proves. Actual document walks
//! create `ObjectKey` / `ArrayIndex` segments from `serde_json::Value`; text
//! paths stay `Ambiguous` because their meaning depends on that unavailable
//! runtime parent.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonPathNavigation {
    /// A quoted object-key operator, or an object node in an actual walk.
    ObjectKey,
    /// An integer array operator, or an array node in an actual walk.
    ArrayIndex,
    /// A PostgreSQL text-path segment whose parent shape is unavailable.
    Ambiguous,
}
