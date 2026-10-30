//! Hash and XOF abstractions required by HQC.
//!
//! The crate contains no hash implementation. The caller supplies SHA3-256,
//! SHA3-512 and SHAKE256 through [`HashProvider`] and [`Xof`]. The C callback
//! implementation lives in [`crate::callbacks::CallbackProvider`].

use crate::error::Result;

/// A SHAKE256 state in squeezing mode.
pub trait Xof {
    /// Fills `out` with the next bytes of the output stream.
    fn squeeze(&mut self, out: &mut [u8]) -> Result<()>;
}

/// The hash functions HQC needs.
///
/// Every input is given as a list of parts that are hashed as if concatenated;
/// this avoids copying secret inputs into a temporary buffer.
pub trait HashProvider {
    fn sha3_256(&self, parts: &[&[u8]], out: &mut [u8; 32]) -> Result<()>;

    fn sha3_512(&self, parts: &[&[u8]], out: &mut [u8; 64]) -> Result<()>;

    /// Absorbs the parts into a fresh SHAKE256 state and returns it ready for
    /// squeezing.
    fn shake256<'s>(&'s self, parts: &[&[u8]]) -> Result<Box<dyn Xof + 's>>;
}
