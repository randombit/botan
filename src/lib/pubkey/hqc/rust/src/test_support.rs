//! Hash and secure-memory callbacks for the crate's own tests.
//!
//! The tests drive the crate through the same C-signature callbacks Botan
//! uses, implemented here with the `sha3` crate (a dev-dependency only) and
//! the Rust system allocator. A [`TestCtx`] can be attached as the `ctx`
//! pointer to count invocations, track live allocations and inject failures.

use crate::hash::{
    CallbackProvider, HqcAllocCallbacks, HqcBuffer, HqcCallbacks, HqcHashCallbacks, HqcXof, HQC_CALLBACKS_VERSION,
};
use core::ffi::c_void;
use core::sync::atomic::{AtomicUsize, Ordering};
use sha3::digest::{ExtendableOutput, FixedOutput, Update, XofReader};
use sha3::{Sha3_256, Sha3_512, Shake256};
use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::collections::HashMap;
use std::sync::Mutex;

/// Alignment of test allocations, matching what Botan's allocator delivers.
const ALLOC_ALIGN: usize = 16;

/// Optional per-test state reachable through the `ctx` pointer.
#[derive(Default)]
pub struct TestCtx {
    pub xofs_created: AtomicUsize,
    pub xofs_freed: AtomicUsize,
    pub squeezes: AtomicUsize,
    /// If set, the squeeze with this index (0-based) fails.
    pub fail_squeeze_at: Option<usize>,

    pub allocs: AtomicUsize,
    pub frees: AtomicUsize,
    pub bytes_live: AtomicUsize,
    /// Frees whose pointer was unknown or whose length did not match the allocation.
    pub bad_frees: AtomicUsize,
    /// If set, the allocation with this index (0-based) fails.
    pub fail_alloc_at: Option<usize>,
    live: Mutex<HashMap<usize, usize>>,
}

impl TestCtx {
    pub fn as_ptr(&self) -> *mut c_void {
        (self as *const TestCtx).cast_mut().cast()
    }

    /// True if every allocation was returned with its exact length.
    pub fn all_memory_returned(&self) -> bool {
        self.bytes_live.load(Ordering::SeqCst) == 0
            && self.bad_frees.load(Ordering::SeqCst) == 0
            && self.allocs.load(Ordering::SeqCst) == self.frees.load(Ordering::SeqCst)
    }
}

fn ctx<'a>(ptr: *mut c_void) -> Option<&'a TestCtx> {
    // SAFETY: tests only ever pass null or a pointer to a live `TestCtx`.
    unsafe { ptr.cast::<TestCtx>().as_ref() }
}

unsafe fn parts<'a>(parts: *const HqcBuffer, n_parts: usize) -> &'a [HqcBuffer] {
    if n_parts == 0 {
        return &[];
    }
    unsafe { core::slice::from_raw_parts(parts, n_parts) }
}

unsafe fn absorb<H: Update>(h: &mut H, bufs: &[HqcBuffer]) {
    for b in bufs {
        if b.len > 0 {
            h.update(unsafe { core::slice::from_raw_parts(b.data, b.len) });
        }
    }
}

unsafe extern "C" fn sha3_256_cb(_ctx: *mut c_void, p: *const HqcBuffer, n: usize, out: *mut u8) -> i32 {
    let mut h = Sha3_256::default();
    unsafe { absorb(&mut h, parts(p, n)) };
    let digest = h.finalize_fixed();
    unsafe { core::ptr::copy_nonoverlapping(digest.as_ptr(), out, 32) };
    0
}

unsafe extern "C" fn sha3_512_cb(_ctx: *mut c_void, p: *const HqcBuffer, n: usize, out: *mut u8) -> i32 {
    let mut h = Sha3_512::default();
    unsafe { absorb(&mut h, parts(p, n)) };
    let digest = h.finalize_fixed();
    unsafe { core::ptr::copy_nonoverlapping(digest.as_ptr(), out, 64) };
    0
}

type ReaderBox = Box<dyn XofReader>;

unsafe extern "C" fn shake256_init_cb(c: *mut c_void, p: *const HqcBuffer, n: usize, out: *mut *mut HqcXof) -> i32 {
    let mut h = Shake256::default();
    unsafe { absorb(&mut h, parts(p, n)) };
    let reader: ReaderBox = Box::new(h.finalize_xof());
    if let Some(t) = ctx(c) {
        t.xofs_created.fetch_add(1, Ordering::SeqCst);
    }
    unsafe { *out = Box::into_raw(Box::new(reader)).cast::<HqcXof>() };
    0
}

unsafe extern "C" fn shake256_squeeze_cb(c: *mut c_void, xof: *mut HqcXof, out: *mut u8, out_len: usize) -> i32 {
    if let Some(t) = ctx(c) {
        let idx = t.squeezes.fetch_add(1, Ordering::SeqCst);
        if t.fail_squeeze_at == Some(idx) {
            return -1;
        }
    }
    let reader = unsafe { &mut *xof.cast::<ReaderBox>() };
    reader.read(unsafe { core::slice::from_raw_parts_mut(out, out_len) });
    0
}

unsafe extern "C" fn shake256_free_cb(c: *mut c_void, xof: *mut HqcXof) {
    if let Some(t) = ctx(c) {
        t.xofs_freed.fetch_add(1, Ordering::SeqCst);
    }
    drop(unsafe { Box::from_raw(xof.cast::<ReaderBox>()) });
}

fn layout(len: usize) -> Layout {
    Layout::from_size_align(len, ALLOC_ALIGN).expect("valid layout")
}

unsafe extern "C" fn secure_alloc_cb(c: *mut c_void, len: usize) -> *mut c_void {
    if len == 0 {
        return core::ptr::null_mut();
    }
    if let Some(t) = ctx(c) {
        let idx = t.allocs.fetch_add(1, Ordering::SeqCst);
        if t.fail_alloc_at == Some(idx) {
            // Keep allocs == frees bookkeeping consistent for a failed request
            t.allocs.fetch_sub(1, Ordering::SeqCst);
            return core::ptr::null_mut();
        }
    }
    // SAFETY: `len > 0`, so the layout is non-zero-sized.
    let p = unsafe { alloc_zeroed(layout(len)) };
    if p.is_null() {
        return core::ptr::null_mut();
    }
    if let Some(t) = ctx(c) {
        t.bytes_live.fetch_add(len, Ordering::SeqCst);
        t.live.lock().unwrap().insert(p as usize, len);
    }
    p.cast()
}

unsafe extern "C" fn secure_free_cb(c: *mut c_void, ptr: *mut c_void, len: usize) {
    if ptr.is_null() {
        return;
    }
    if let Some(t) = ctx(c) {
        t.frees.fetch_add(1, Ordering::SeqCst);
        match t.live.lock().unwrap().remove(&(ptr as usize)) {
            Some(l) if l == len => {
                t.bytes_live.fetch_sub(len, Ordering::SeqCst);
            }
            _ => {
                // Unknown pointer or wrong length: record, and do not touch the memory.
                t.bad_frees.fetch_add(1, Ordering::SeqCst);
                return;
            }
        }
    }
    // Scrub as a real provider would, then release.
    // SAFETY: `ptr` came from `secure_alloc_cb` with the same `len`.
    unsafe {
        core::ptr::write_bytes(ptr.cast::<u8>(), 0, len);
        dealloc(ptr.cast::<u8>(), layout(len));
    }
}

/// The callback struct as Botan would fill it, with an optional context.
pub fn callbacks_with(ctx: *mut c_void) -> HqcCallbacks {
    HqcCallbacks {
        version: HQC_CALLBACKS_VERSION,
        hash: HqcHashCallbacks {
            ctx,
            sha3_256: Some(sha3_256_cb),
            sha3_512: Some(sha3_512_cb),
            shake256_init: Some(shake256_init_cb),
            shake256_squeeze: Some(shake256_squeeze_cb),
            shake256_free: Some(shake256_free_cb),
        },
        alloc: HqcAllocCallbacks {
            ctx,
            secure_alloc: Some(secure_alloc_cb),
            secure_free: Some(secure_free_cb),
        },
    }
}

/// The callback struct without a context.
pub fn callbacks() -> HqcCallbacks {
    callbacks_with(core::ptr::null_mut())
}

/// A provider over `cb`, for tests of the Rust-level API.
pub fn provider(cb: &HqcCallbacks) -> CallbackProvider<'_> {
    unsafe { CallbackProvider::new(cb) }.expect("test callbacks are valid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::HashProvider;
    use crate::secmem::{zeroize_slice, SecretVec, SecureBuffer};
    use hex_literal::hex;

    /// SHA3-256("abc") and SHA3-512("abc") from FIPS 202 examples; SHAKE256("abc")
    /// prefix from the same source.
    #[test]
    fn test_callbacks_compute_the_standard_functions() {
        let cb = callbacks();
        let h = provider(&cb);

        let mut out32 = [0u8; 32];
        h.sha3_256(&[b"a", b"bc"], &mut out32).unwrap();
        assert_eq!(out32, hex!("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"));

        let mut out64 = [0u8; 64];
        h.sha3_512(&[b"abc"], &mut out64).unwrap();
        assert_eq!(
            out64[..16],
            hex!("b751850b1a57168a5693cd924b6b096e")
        );

        let mut xof = h.shake256(&[b"ab", b"c"]).unwrap();
        let mut a = [0u8; 5];
        let mut b = [0u8; 11];
        xof.squeeze(&mut a).unwrap();
        xof.squeeze(&mut b).unwrap();
        let mut joined = [0u8; 16];
        joined[..5].copy_from_slice(&a);
        joined[5..].copy_from_slice(&b);
        assert_eq!(joined, hex!("483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739")[..16]);
    }

    #[test]
    fn every_xof_is_released_and_failures_propagate() {
        let mut t = TestCtx::default();
        t.fail_squeeze_at = Some(3);
        let cb = callbacks_with(t.as_ptr());
        let h = provider(&cb);

        {
            let mut xof = h.shake256(&[b"x"]).unwrap();
            let mut buf = [0u8; 300];
            xof.squeeze(&mut buf).unwrap(); // squeezes 0 (direct, 300 >= buffer)
            xof.squeeze(&mut buf[..3]).unwrap(); // squeeze 1 (refill)
            xof.squeeze(&mut buf[..200]).unwrap(); // rest of buffer + squeeze 2
            assert!(xof.squeeze(&mut buf[..3]).is_ok()); // served from buffer
            let mut big = [0u8; 400];
            assert!(xof.squeeze(&mut big).is_err()); // squeeze 3 fails
        }
        assert_eq!(t.xofs_created.load(Ordering::SeqCst), 1);
        assert_eq!(t.xofs_freed.load(Ordering::SeqCst), 1);
    }

    /// Buffered squeezing must not change the output stream.
    #[test]
    fn buffered_squeeze_matches_one_shot() {
        let cb = callbacks();
        let h = provider(&cb);

        let mut one_shot = vec![0u8; 1000];
        h.shake256(&[b"seed"]).unwrap().squeeze(&mut one_shot).unwrap();

        let mut pieces = Vec::new();
        let mut xof = h.shake256(&[b"seed"]).unwrap();
        for len in [3usize, 3, 32, 136, 1, 200, 500, 125] {
            let mut chunk = vec![0u8; len];
            xof.squeeze(&mut chunk).unwrap();
            pieces.extend_from_slice(&chunk);
        }
        assert_eq!(pieces, one_shot);
    }

    #[test]
    fn secure_buffers_are_zeroed_typed_and_returned_with_their_length() {
        let t = TestCtx::default();
        let cb = callbacks_with(t.as_ptr());
        let h = provider(&cb);

        {
            let mut words = SecureBuffer::<u64>::zeroed(&h, 7).unwrap();
            assert!(words.iter().all(|&w| w == 0));
            words[3] = 0x0123_4567_89ab_cdef;
            let bytes = SecureBuffer::<u8>::from_slice(&h, b"secret").unwrap();
            assert_eq!(&*bytes, b"secret");
            let empty = SecureBuffer::<u32>::zeroed(&h, 0).unwrap();
            assert!(empty.is_empty());
            assert_eq!(t.bytes_live.load(Ordering::SeqCst), 7 * 8 + 6);
        }
        assert!(t.all_memory_returned());
        assert_eq!(t.allocs.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn allocation_failure_is_an_error_not_a_panic() {
        let mut t = TestCtx::default();
        t.fail_alloc_at = Some(1);
        let cb = callbacks_with(t.as_ptr());
        let h = provider(&cb);

        let first = SecureBuffer::<u8>::zeroed(&h, 16).unwrap();
        assert!(matches!(SecureBuffer::<u8>::zeroed(&h, 16), Err(crate::error::HqcError::Alloc)));
        drop(first);
        assert!(t.all_memory_returned());
    }

    #[test]
    fn secret_vec_and_zeroize_slice_clear_memory() {
        let mut arr = [0xAAu8; 40];
        zeroize_slice(&mut arr);
        assert!(arr.iter().all(|&b| b == 0));

        let mut v = SecretVec::<u16>::zeroed(5);
        v[2] = 7;
        assert_eq!(v[2], 7);
        let w = SecretVec::from_vec(vec![1u64, 2, 3]);
        assert_eq!(&*w, &[1, 2, 3]);
    }
}
