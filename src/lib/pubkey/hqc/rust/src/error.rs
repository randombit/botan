//! Errors returned by the public API.
//!
//! The crate previously had no error type: every failure was a panic. That is
//! unacceptable for the Botan binding, because a panic unwinding across an
//! `extern "C"` boundary is undefined behaviour. Every public entry point now
//! returns [`Result`], and the internal `assert!`s that remain are invariants
//! the public layer checks up front so they cannot be reached from outside.

use core::fmt;

/// An error from an HQC operation.
///
/// Deliberately coarse: an error returned to a caller must not describe *why*
/// a secret-dependent step failed, or it becomes an oracle. Length and
/// parameter mismatches are caller errors and safe to describe precisely;
/// anything touching key or ciphertext content is not.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HqcError {
    /// A caller-provided buffer has the wrong length.
    ///
    /// Sizes come from the parameter set, so this is always a programming
    /// error rather than a data-dependent condition.
    BufferLength {
        what: &'static str,
        expected: usize,
        got: usize,
    },

    /// The encapsulation or decapsulation key is not valid for this set.
    InvalidKey,

    /// The ciphertext is not valid for this parameter set.
    ///
    /// Note this covers only *structural* problems such as a wrong length. An
    /// HQC decapsulation never reports a decryption failure: the FO transform
    /// returns a pseudo-random shared secret instead, and distinguishing those
    /// cases is exactly the oracle implicit rejection exists to deny.
    InvalidCiphertext,

    /// The randomness source failed.
    RandomnessFailure,

    /// A hash callback supplied by the caller returned a failure.
    HashCallback,

    /// The callback struct is missing, incomplete, or of an unsupported version.
    BadCallbacks,

    /// The caller's secure allocator could not provide memory.
    Alloc,

    /// An internal invariant did not hold.
    ///
    /// Reaching this indicates a bug in this crate, not bad input. It exists
    /// so the FFI boundary can turn a caught panic into a return code rather
    /// than unwinding into C.
    Internal,
}

impl fmt::Display for HqcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferLength {
                what,
                expected,
                got,
            } => write!(f, "{what} must be {expected} bytes, got {got}"),
            Self::InvalidKey => f.write_str("invalid key for this parameter set"),
            Self::InvalidCiphertext => f.write_str("invalid ciphertext for this parameter set"),
            Self::RandomnessFailure => f.write_str("randomness source failed"),
            Self::HashCallback => f.write_str("hash callback failed"),
            Self::BadCallbacks => f.write_str("callback struct is null, incomplete or of an unsupported version"),
            Self::Alloc => f.write_str("secure memory allocation failed"),
            Self::Internal => f.write_str("internal error"),
        }
    }
}

impl core::error::Error for HqcError {}

/// Shorthand for results from this crate.
pub type Result<T> = core::result::Result<T, HqcError>;

/// Checks a caller-provided buffer length.
pub(crate) fn check_len(what: &'static str, buf: &[u8], expected: usize) -> Result<()> {
    if buf.len() == expected {
        Ok(())
    } else {
        Err(HqcError::BufferLength {
            what,
            expected,
            got: buf.len(),
        })
    }
}
