//! Hash functions and secure memory supplied by the caller.
//!
//! The crate contains no hash implementation and no allocator for secrets.
//! Everything HQC needs (SHA3-256, SHA3-512, SHAKE256 as an incrementally
//! squeezed XOF, and memory for secret buffers) is obtained through the
//! [`HashProvider`] and [`SecureAllocator`] traits, combined as [`Callbacks`].
//! The only production implementation is [`CallbackProvider`], which forwards
//! to the C function pointers of `hqc_callbacks_t` (declared in
//! `include/hqc_c_api.h`); Botan fills that struct with its own hash objects
//! and its secure allocator. The crate's tests supply their own C-signature
//! callbacks, so `cargo test` exercises the same path as the Botan build.

use crate::error::{HqcError, Result};
use crate::secmem::{zeroize_slice, SecureAllocator};
use core::ffi::c_void;
use core::ptr::NonNull;

/// The version of `hqc_callbacks_t` this crate understands.
pub const HQC_CALLBACKS_VERSION: u32 = 2;

/// `hqc_buffer_t`: one input part of a hash computation.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct HqcBuffer {
    pub data: *const u8,
    pub len: usize,
}

/// `hqc_xof_t`: an opaque SHAKE256 state owned by the callback provider.
#[repr(C)]
pub struct HqcXof {
    _private: [u8; 0],
}

pub type Sha3Fn =
    Option<unsafe extern "C" fn(ctx: *mut c_void, parts: *const HqcBuffer, n_parts: usize, out: *mut u8) -> i32>;

pub type XofInitFn = Option<
    unsafe extern "C" fn(ctx: *mut c_void, parts: *const HqcBuffer, n_parts: usize, out_xof: *mut *mut HqcXof) -> i32,
>;

pub type XofSqueezeFn =
    Option<unsafe extern "C" fn(ctx: *mut c_void, xof: *mut HqcXof, out: *mut u8, out_len: usize) -> i32>;

pub type XofFreeFn = Option<unsafe extern "C" fn(ctx: *mut c_void, xof: *mut HqcXof)>;

pub type SecureAllocFn = Option<unsafe extern "C" fn(ctx: *mut c_void, len: usize) -> *mut c_void>;

pub type SecureFreeFn = Option<unsafe extern "C" fn(ctx: *mut c_void, ptr: *mut c_void, len: usize)>;

/// `hqc_hash_callbacks_t`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct HqcHashCallbacks {
    pub ctx: *mut c_void,
    pub sha3_256: Sha3Fn,
    pub sha3_512: Sha3Fn,
    pub shake256_init: XofInitFn,
    pub shake256_squeeze: XofSqueezeFn,
    pub shake256_free: XofFreeFn,
}

/// `hqc_alloc_callbacks_t`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct HqcAllocCallbacks {
    pub ctx: *mut c_void,
    pub secure_alloc: SecureAllocFn,
    pub secure_free: SecureFreeFn,
}

/// `hqc_callbacks_t`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct HqcCallbacks {
    pub version: u32,
    pub hash: HqcHashCallbacks,
    pub alloc: HqcAllocCallbacks,
}

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

/// Everything the caller supplies: hashing and secret memory.
pub trait Callbacks: HashProvider + SecureAllocator {}

impl<T: HashProvider + SecureAllocator> Callbacks for T {}

/// Number of bytes squeezed from the provider at once.
///
/// The fixed-weight sampler asks for three bytes per rejection-sampling step;
/// buffering one SHAKE256 block avoids a callback invocation for each of them.
/// The output stream is unchanged by the buffering.
const XOF_BUFFER_BYTES: usize = 136;

/// A [`Callbacks`] implementation forwarding to C callbacks.
pub struct CallbackProvider<'a> {
    hash: &'a HqcHashCallbacks,
    alloc: &'a HqcAllocCallbacks,
}

impl<'a> CallbackProvider<'a> {
    /// Validates `callbacks` and wraps it.
    ///
    /// # Errors
    /// [`HqcError::BadCallbacks`] if `callbacks` is null, its version is not
    /// [`HQC_CALLBACKS_VERSION`], or any function pointer is null.
    ///
    /// # Safety
    /// If non-null, `callbacks` must point to a valid `hqc_callbacks_t` whose
    /// function pointers stay valid for the lifetime `'a`, and the callbacks
    /// must behave as documented in `hqc_c_api.h`.
    pub unsafe fn new(callbacks: *const HqcCallbacks) -> Result<Self> {
        if callbacks.is_null() {
            return Err(HqcError::BadCallbacks);
        }
        let cb: &'a HqcCallbacks = unsafe { &*callbacks };
        if cb.version != HQC_CALLBACKS_VERSION {
            return Err(HqcError::BadCallbacks);
        }
        let h = &cb.hash;
        let a = &cb.alloc;
        if h.sha3_256.is_none()
            || h.sha3_512.is_none()
            || h.shake256_init.is_none()
            || h.shake256_squeeze.is_none()
            || h.shake256_free.is_none()
            || a.secure_alloc.is_none()
            || a.secure_free.is_none()
        {
            return Err(HqcError::BadCallbacks);
        }
        Ok(Self { hash: h, alloc: a })
    }

    fn fixed_output(&self, f: Sha3Fn, parts: &[&[u8]], out: &mut [u8]) -> Result<()> {
        let bufs = to_buffers(parts);
        // SAFETY: `f` was checked to be non-null in `new`; the buffers point
        // into `parts`, which outlive the call.
        let rc = unsafe { f.unwrap()(self.hash.ctx, bufs.as_ptr(), bufs.len(), out.as_mut_ptr()) };
        if rc == 0 { Ok(()) } else { Err(HqcError::HashCallback) }
    }
}

fn to_buffers(parts: &[&[u8]]) -> Vec<HqcBuffer> {
    parts
        .iter()
        .map(|p| HqcBuffer {
            data: p.as_ptr(),
            len: p.len(),
        })
        .collect()
}

impl HashProvider for CallbackProvider<'_> {
    fn sha3_256(&self, parts: &[&[u8]], out: &mut [u8; 32]) -> Result<()> {
        self.fixed_output(self.hash.sha3_256, parts, out)
    }

    fn sha3_512(&self, parts: &[&[u8]], out: &mut [u8; 64]) -> Result<()> {
        self.fixed_output(self.hash.sha3_512, parts, out)
    }

    fn shake256<'s>(&'s self, parts: &[&[u8]]) -> Result<Box<dyn Xof + 's>> {
        let bufs = to_buffers(parts);
        let mut handle: *mut HqcXof = core::ptr::null_mut();
        // SAFETY: checked non-null in `new`; buffers outlive the call.
        let rc = unsafe { self.hash.shake256_init.unwrap()(self.hash.ctx, bufs.as_ptr(), bufs.len(), &mut handle) };
        if rc != 0 || handle.is_null() {
            return Err(HqcError::HashCallback);
        }
        Ok(Box::new(CallbackXof {
            cb: self.hash,
            handle,
            buf: [0u8; XOF_BUFFER_BYTES],
            pos: XOF_BUFFER_BYTES,
        }))
    }
}

impl SecureAllocator for CallbackProvider<'_> {
    fn secure_alloc(&self, bytes: usize) -> Result<NonNull<u8>> {
        // SAFETY: checked non-null in `new`.
        let p = unsafe { self.alloc.secure_alloc.unwrap()(self.alloc.ctx, bytes) };
        NonNull::new(p.cast::<u8>()).ok_or(HqcError::Alloc)
    }

    unsafe fn secure_free(&self, ptr: NonNull<u8>, bytes: usize) {
        // SAFETY: checked non-null in `new`; the caller guarantees `ptr`.
        unsafe { self.alloc.secure_free.unwrap()(self.alloc.ctx, ptr.as_ptr().cast::<c_void>(), bytes) };
    }
}

/// A SHAKE256 state held by the callback provider, released on drop.
struct CallbackXof<'a> {
    cb: &'a HqcHashCallbacks,
    handle: *mut HqcXof,
    buf: [u8; XOF_BUFFER_BYTES],
    /// Index of the first unconsumed byte in `buf`; `buf.len()` when empty.
    pos: usize,
}

impl CallbackXof<'_> {
    fn squeeze_raw(&mut self, out: &mut [u8]) -> Result<()> {
        // SAFETY: checked non-null in `CallbackProvider::new`; `handle` is a
        // live state created by the same provider.
        let rc = unsafe { self.cb.shake256_squeeze.unwrap()(self.cb.ctx, self.handle, out.as_mut_ptr(), out.len()) };
        if rc == 0 { Ok(()) } else { Err(HqcError::HashCallback) }
    }
}

impl Xof for CallbackXof<'_> {
    fn squeeze(&mut self, out: &mut [u8]) -> Result<()> {
        // First hand out what is left in the buffer, then squeeze the rest:
        // either directly into `out` if it is at least a buffer's worth, or
        // by refilling the buffer. The byte stream is the same as squeezing
        // `out.len()` bytes directly.
        let buffered = XOF_BUFFER_BYTES - self.pos;
        let from_buf = buffered.min(out.len());
        out[..from_buf].copy_from_slice(&self.buf[self.pos..self.pos + from_buf]);
        self.pos += from_buf;

        let rest = &mut out[from_buf..];
        if rest.is_empty() {
            return Ok(());
        }
        if rest.len() >= XOF_BUFFER_BYTES {
            return self.squeeze_raw(rest);
        }
        let mut fresh = [0u8; XOF_BUFFER_BYTES];
        self.squeeze_raw(&mut fresh)?;
        self.buf = fresh;
        zeroize_slice(&mut fresh);
        rest.copy_from_slice(&self.buf[..rest.len()]);
        self.pos = rest.len();
        Ok(())
    }
}

impl Drop for CallbackXof<'_> {
    fn drop(&mut self) {
        // The buffer holds not yet consumed XOF output (secret seed expansion).
        zeroize_slice(&mut self.buf);
        // SAFETY: as in `squeeze_raw`; the handle is released exactly once.
        unsafe { self.cb.shake256_free.unwrap()(self.cb.ctx, self.handle) };
    }
}
