//! Secret memory: volatile zeroization and buffers served by the caller's
//! secure allocator.
//!
//! Two kinds of secret storage exist in this crate:
//!
//! * [`SecureBuffer`]: memory obtained from the caller through the
//!   `secure_alloc`/`secure_free` callbacks of `hqc_callbacks_t`. Botan serves
//!   these from its mlock'ed pool (for requests up to 256 bytes) or from
//!   `calloc`, and scrubs them on release. The crate does **not** zeroize such
//!   buffers itself; the provider is responsible. Used for key material and
//!   per-message secrets.
//! * [`SecretVec`]: a `Vec` on the Rust heap that is zeroized with volatile
//!   writes when dropped. Used for arithmetic and decoder temporaries.
//!
//! Stack-resident secrets (fixed-size arrays) are cleared with
//! [`zeroize_slice`] before they go out of scope.

use crate::error::{HqcError, Result};
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;
use core::sync::atomic::{compiler_fence, Ordering};

/// Overwrites `s` with zeros using volatile writes, so the optimizer cannot
/// elide the stores even if the memory is never read again.
pub fn zeroize_slice<T: Copy + Default>(s: &mut [T]) {
    for x in s.iter_mut() {
        // SAFETY: `x` is a valid, aligned, exclusively borrowed element.
        unsafe { core::ptr::write_volatile(x, T::default()) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// A heap vector of secret values, zeroized with volatile writes on drop.
pub struct SecretVec<T: Copy + Default>(Vec<T>);

impl<T: Copy + Default> SecretVec<T> {
    /// A zero-filled vector of `len` elements.
    pub fn zeroed(len: usize) -> Self {
        Self(vec![T::default(); len])
    }

    /// Takes ownership of `v`; it will be zeroized on drop.
    pub fn from_vec(v: Vec<T>) -> Self {
        Self(v)
    }
}

impl<T: Copy + Default> Deref for SecretVec<T> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        &self.0
    }
}

impl<T: Copy + Default> DerefMut for SecretVec<T> {
    fn deref_mut(&mut self) -> &mut [T] {
        &mut self.0
    }
}

impl<T: Copy + Default> Drop for SecretVec<T> {
    fn drop(&mut self) {
        zeroize_slice(&mut self.0);
    }
}

/// Memory for secrets, provided by the caller.
pub trait SecureAllocator {
    /// Returns `bytes` bytes of memory aligned for any integer type up to
    /// 8 bytes. The contents are unspecified; [`SecureBuffer`] zero-fills.
    ///
    /// # Errors
    /// [`HqcError::Alloc`] if the provider cannot satisfy the request.
    fn secure_alloc(&self, bytes: usize) -> Result<NonNull<u8>>;

    /// Scrubs and releases memory obtained from [`Self::secure_alloc`].
    ///
    /// # Safety
    /// `ptr` must come from `secure_alloc` of the same provider with the same
    /// `bytes`, and must not be used afterwards.
    unsafe fn secure_free(&self, ptr: NonNull<u8>, bytes: usize);
}

/// A fixed-size buffer of secret values living in provider memory.
///
/// Released, and thereby scrubbed by the provider, on drop; on every path,
/// including a caught panic. Not `Clone`, not `Send`: a buffer never outlives
/// the operation that created it.
pub struct SecureBuffer<'a, T: Copy + Default> {
    alloc: &'a dyn SecureAllocator,
    ptr: NonNull<T>,
    len: usize,
}

impl<'a, T: Copy + Default> SecureBuffer<'a, T> {
    /// A zero-filled buffer of `len` elements.
    pub fn zeroed(alloc: &'a dyn SecureAllocator, len: usize) -> Result<Self> {
        const { assert!(core::mem::align_of::<T>() <= 8, "element type too strictly aligned") };

        let bytes = len.checked_mul(core::mem::size_of::<T>()).ok_or(HqcError::Internal)?;
        if bytes == 0 {
            return Ok(Self {
                alloc,
                ptr: NonNull::dangling(),
                len,
            });
        }

        let raw = alloc.secure_alloc(bytes)?;
        if (raw.as_ptr() as usize) % core::mem::align_of::<T>() != 0 {
            // SAFETY: `raw` was just obtained from `alloc` with `bytes`.
            unsafe { alloc.secure_free(raw, bytes) };
            return Err(HqcError::Internal);
        }
        let ptr = raw.cast::<T>();
        // SAFETY: `ptr` is valid for `bytes` = `len * size_of::<T>()` bytes.
        unsafe { core::ptr::write_bytes(ptr.as_ptr(), 0, len) };
        Ok(Self { alloc, ptr, len })
    }

    /// A buffer holding a copy of `src`.
    pub fn from_slice(alloc: &'a dyn SecureAllocator, src: &[T]) -> Result<Self> {
        let mut b = Self::zeroed(alloc, src.len())?;
        b.copy_from_slice(src);
        Ok(b)
    }

    fn bytes(&self) -> usize {
        self.len * core::mem::size_of::<T>()
    }
}

impl<T: Copy + Default> Deref for SecureBuffer<'_, T> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        // SAFETY: `ptr` is valid for `len` initialized elements for the
        // lifetime of `self`, or dangling with `len == 0`.
        unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
}

impl<T: Copy + Default> DerefMut for SecureBuffer<'_, T> {
    fn deref_mut(&mut self) -> &mut [T] {
        // SAFETY: as in `deref`, with exclusive access through `&mut self`.
        unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }
}

impl<T: Copy + Default> Drop for SecureBuffer<'_, T> {
    fn drop(&mut self) {
        let bytes = self.bytes();
        if bytes > 0 {
            // SAFETY: `ptr` came from `alloc.secure_alloc(bytes)` and is
            // released exactly once.
            unsafe { self.alloc.secure_free(self.ptr.cast::<u8>(), bytes) };
        }
    }
}
