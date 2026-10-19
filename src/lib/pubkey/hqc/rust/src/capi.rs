//! C ABI for the HQC-KEM, for binding from C++ (Botan) or C.
//!
//! Stateless by design. [`HqcParameters`] instances are `'static`, so there is
//! nothing to own across the boundary: a caller passes a parameter-set
//! discriminant and its hash callbacks on every call, and there is no
//! `hqc_new` / `hqc_free` pair to get wrong. A Botan `HQC_PublicKey` need hold
//! nothing beyond the enum.
//!
//! # Randomness
//!
//! The entry points are derandomized: `hqc_keypair` takes the 32-byte master
//! seed (which is the decapsulation key) and `hqc_encaps` takes the message
//! followed by the salt, exactly as the specification draws them from the
//! random number generator; `hqc_randomness_lengths` reports both lengths.
//! The crate performs no expansion of its own, so a caller feeding the NIST
//! KAT DRBG reproduces the reference known answer tests.
//!
//! # Hashing and secret memory
//!
//! The crate has neither a hash implementation nor an allocator for secrets.
//! Every operation takes a pointer to an `hqc_callbacks_t` (see
//! `include/hqc_c_api.h` and [`crate::hash`]) through which the caller
//! supplies SHA3-256, SHA3-512, SHAKE256 and secure memory.
//!
//! # Unwinding
//!
//! Every entry point wraps its work in [`catch_unwind`]. A panic crossing an
//! `extern "C"` boundary is undefined behaviour, and this crate still contains
//! internal `assert!`s guarding buffer-length invariants. Those are
//! unreachable through the checked [`crate::api`] layer, but "unreachable" is
//! not "impossible", and the cost of being wrong is UB rather than an error
//! code. A caught panic becomes [`HQC_ERR_INTERNAL`].
//!
//! # Safety
//!
//! Every function is `unsafe`: pointers must be non-null, correctly aligned,
//! and valid for the stated lengths. Output buffers must not alias the inputs.

use crate::api::Hqc;
use crate::error::HqcError;
use crate::hash::{CallbackProvider, HqcCallbacks};
use crate::parameters::{HqcParameterSet, HqcParameters};
use core::panic::AssertUnwindSafe;
use std::panic::catch_unwind;

pub const HQC_OK: i32 = 0;
pub const HQC_ERR_BUFFER_LENGTH: i32 = -1;
pub const HQC_ERR_INVALID_KEY: i32 = -2;
pub const HQC_ERR_INVALID_CIPHERTEXT: i32 = -3;
pub const HQC_ERR_RANDOMNESS: i32 = -4;
pub const HQC_ERR_INTERNAL: i32 = -5;
pub const HQC_ERR_BAD_PARAMETER_SET: i32 = -6;
pub const HQC_ERR_NULL_POINTER: i32 = -7;
pub const HQC_ERR_HASH_CALLBACK: i32 = -8;
pub const HQC_ERR_BAD_CALLBACKS: i32 = -9;
pub const HQC_ERR_ALLOC: i32 = -10;

fn code(e: HqcError) -> i32 {
    match e {
        HqcError::BufferLength { .. } => HQC_ERR_BUFFER_LENGTH,
        HqcError::InvalidKey => HQC_ERR_INVALID_KEY,
        HqcError::InvalidCiphertext => HQC_ERR_INVALID_CIPHERTEXT,
        HqcError::RandomnessFailure => HQC_ERR_RANDOMNESS,
        HqcError::HashCallback => HQC_ERR_HASH_CALLBACK,
        HqcError::BadCallbacks => HQC_ERR_BAD_CALLBACKS,
        HqcError::Alloc => HQC_ERR_ALLOC,
        HqcError::Internal => HQC_ERR_INTERNAL,
    }
}

fn parameter_set(param_set: u8) -> Option<HqcParameterSet> {
    match param_set {
        1 => Some(HqcParameterSet::Hqc1),
        3 => Some(HqcParameterSet::Hqc3),
        5 => Some(HqcParameterSet::Hqc5),
        _ => None,
    }
}

fn parameters(param_set: u8) -> Option<&'static HqcParameters> {
    parameter_set(param_set).map(HqcParameterSet::params)
}

fn guard(f: impl FnOnce() -> i32) -> i32 {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(HQC_ERR_INTERNAL)
}

/// Writes the byte sizes for `param_set` to the non-null out pointers.
///
/// # Safety
/// Each non-null pointer must be valid for a write of `usize`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hqc_sizes(
    param_set: u8,
    ek_len: *mut usize,
    dk_len: *mut usize,
    ct_len: *mut usize,
    ss_len: *mut usize,
) -> i32 {
    guard(|| {
        let Some(p) = parameters(param_set) else {
            return HQC_ERR_BAD_PARAMETER_SET;
        };
        unsafe {
            if !ek_len.is_null() {
                *ek_len = p.ek_bytes;
            }
            if !dk_len.is_null() {
                *dk_len = p.dk_bytes;
            }
            if !ct_len.is_null() {
                *ct_len = p.ct_bytes;
            }
            if !ss_len.is_null() {
                *ss_len = p.ss_bytes;
            }
        }
        HQC_OK
    })
}

/// Writes the number of random bytes `hqc_keypair` and `hqc_encaps` consume
/// for `param_set` to the non-null out pointers.
///
/// # Safety
/// Each non-null pointer must be valid for a write of `usize`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hqc_randomness_lengths(
    param_set: u8,
    keypair_len: *mut usize,
    encaps_len: *mut usize,
) -> i32 {
    guard(|| {
        let Some(p) = parameters(param_set) else {
            return HQC_ERR_BAD_PARAMETER_SET;
        };
        unsafe {
            if !keypair_len.is_null() {
                *keypair_len = p.keypair_randomness_bytes();
            }
            if !encaps_len.is_null() {
                *encaps_len = p.encapsulation_randomness_bytes();
            }
        }
        HQC_OK
    })
}

/// Generates a keypair from `seed`, the 32-byte master seed that is also the
/// decapsulation key (`seed_len` must equal the keypair length reported by
/// `hqc_randomness_lengths`).
///
/// # Safety
/// `callbacks` must be null or point to a valid `hqc_callbacks_t`; `ek`, `dk`
/// and `seed` must be valid for the stated lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hqc_keypair(
    param_set: u8,
    callbacks: *const HqcCallbacks,
    ek: *mut u8,
    ek_len: usize,
    dk: *mut u8,
    dk_len: usize,
    seed: *const u8,
    seed_len: usize,
) -> i32 {
    guard(|| {
        let Some(set) = parameter_set(param_set) else {
            return HQC_ERR_BAD_PARAMETER_SET;
        };
        let hash = match unsafe { CallbackProvider::new(callbacks) } {
            Ok(h) => h,
            Err(e) => return code(e),
        };
        if ek.is_null() || dk.is_null() || seed.is_null() {
            return HQC_ERR_NULL_POINTER;
        }
        let (ek, dk, seed) = unsafe {
            (
                core::slice::from_raw_parts_mut(ek, ek_len),
                core::slice::from_raw_parts_mut(dk, dk_len),
                core::slice::from_raw_parts(seed, seed_len),
            )
        };
        match Hqc::new(set, &hash).keypair(ek, dk, seed) {
            Ok(()) => HQC_OK,
            Err(e) => code(e),
        }
    })
}

/// Derives the encapsulation key belonging to the decapsulation key `dk`
/// into `ek`.
///
/// # Safety
/// `callbacks` must be null or point to a valid `hqc_callbacks_t`; `ek` and
/// `dk` must be valid for the stated lengths and must not alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hqc_public_key(
    param_set: u8,
    callbacks: *const HqcCallbacks,
    ek: *mut u8,
    ek_len: usize,
    dk: *const u8,
    dk_len: usize,
) -> i32 {
    guard(|| {
        let Some(set) = parameter_set(param_set) else {
            return HQC_ERR_BAD_PARAMETER_SET;
        };
        let hash = match unsafe { CallbackProvider::new(callbacks) } {
            Ok(h) => h,
            Err(e) => return code(e),
        };
        if ek.is_null() || dk.is_null() {
            return HQC_ERR_NULL_POINTER;
        }
        let (ek, dk) = unsafe {
            (
                core::slice::from_raw_parts_mut(ek, ek_len),
                core::slice::from_raw_parts(dk, dk_len),
            )
        };
        match Hqc::new(set, &hash).public_key(ek, dk) {
            Ok(()) => HQC_OK,
            Err(e) => code(e),
        }
    })
}

/// Encapsulates to `ek`, using `randomness` (the message followed by the
/// salt; `randomness_len` must equal the encapsulation length reported by
/// `hqc_randomness_lengths`).
///
/// # Safety
/// `callbacks` must be null or point to a valid `hqc_callbacks_t`; all other
/// pointers must be valid for the stated lengths and must not alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hqc_encaps(
    param_set: u8,
    callbacks: *const HqcCallbacks,
    ct: *mut u8,
    ct_len: usize,
    ss: *mut u8,
    ss_len: usize,
    ek: *const u8,
    ek_len: usize,
    randomness: *const u8,
    randomness_len: usize,
) -> i32 {
    guard(|| {
        let Some(set) = parameter_set(param_set) else {
            return HQC_ERR_BAD_PARAMETER_SET;
        };
        let hash = match unsafe { CallbackProvider::new(callbacks) } {
            Ok(h) => h,
            Err(e) => return code(e),
        };
        if ct.is_null() || ss.is_null() || ek.is_null() || randomness.is_null() {
            return HQC_ERR_NULL_POINTER;
        }
        let (ct, ss, ek, randomness) = unsafe {
            (
                core::slice::from_raw_parts_mut(ct, ct_len),
                core::slice::from_raw_parts_mut(ss, ss_len),
                core::slice::from_raw_parts(ek, ek_len),
                core::slice::from_raw_parts(randomness, randomness_len),
            )
        };
        match Hqc::new(set, &hash).encapsulate(ct, ss, ek, randomness) {
            Ok(()) => HQC_OK,
            Err(e) => code(e),
        }
    })
}

/// Decapsulates `ct` with `dk`.
///
/// Never signals a decryption failure: HQC's FO transform with implicit
/// rejection returns a pseudo-random shared secret for an invalid ciphertext,
/// and reporting that would be an oracle. A non-zero return means the inputs
/// were structurally wrong, not that decryption failed.
///
/// Includes variable-time expansion of the 32-byte seed key. For decapsulation
/// without seed expansion use the Rust `ExpandedDecapsulationKey` API.
///
/// # Safety
/// `callbacks` must be null or point to a valid `hqc_callbacks_t`; all other
/// pointers must be valid for the stated lengths and must not alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hqc_decaps(
    param_set: u8,
    callbacks: *const HqcCallbacks,
    ss: *mut u8,
    ss_len: usize,
    ct: *const u8,
    ct_len: usize,
    dk: *const u8,
    dk_len: usize,
) -> i32 {
    guard(|| {
        let Some(set) = parameter_set(param_set) else {
            return HQC_ERR_BAD_PARAMETER_SET;
        };
        let hash = match unsafe { CallbackProvider::new(callbacks) } {
            Ok(h) => h,
            Err(e) => return code(e),
        };
        if ss.is_null() || ct.is_null() || dk.is_null() {
            return HQC_ERR_NULL_POINTER;
        }
        let (ss, ct, dk) = unsafe {
            (
                core::slice::from_raw_parts_mut(ss, ss_len),
                core::slice::from_raw_parts(ct, ct_len),
                core::slice::from_raw_parts(dk, dk_len),
            )
        };
        match Hqc::new(set, &hash).decapsulate(ss, ct, dk) {
            Ok(()) => HQC_OK,
            Err(e) => code(e),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::HQC_CALLBACKS_VERSION;
    use crate::test_support::{callbacks, callbacks_with, TestCtx};
    use core::sync::atomic::Ordering;

    #[test]
    fn c_abi_roundtrip_for_every_parameter_set() {
        let cb = callbacks();
        for ps in [1u8, 3, 5] {
            let (mut ekl, mut dkl, mut ctl, mut ssl) = (0usize, 0, 0, 0);
            assert_eq!(
                unsafe { hqc_sizes(ps, &mut ekl, &mut dkl, &mut ctl, &mut ssl) },
                HQC_OK
            );

            let (mut kp_rand, mut enc_rand) = (0usize, 0usize);
            assert_eq!(
                unsafe { hqc_randomness_lengths(ps, &mut kp_rand, &mut enc_rand) },
                HQC_OK
            );
            assert_eq!(kp_rand, 32);
            assert_eq!(enc_rand, [0, 32, 0, 40, 0, 48][usize::from(ps)]);

            let (mut ek, mut dk) = (vec![0u8; ekl], vec![0u8; dkl]);
            let seed = [9u8; 32];
            assert_eq!(
                unsafe {
                    hqc_keypair(ps, &cb, ek.as_mut_ptr(), ekl, dk.as_mut_ptr(), dkl,
                                seed.as_ptr(), seed.len())
                },
                HQC_OK
            );
            assert_eq!(dk, seed);

            // The public key is reproducible from the 32-byte private key
            let mut ek2 = vec![0u8; ekl];
            assert_eq!(
                unsafe { hqc_public_key(ps, &cb, ek2.as_mut_ptr(), ekl, dk.as_ptr(), dkl) },
                HQC_OK
            );
            assert_eq!(ek, ek2, "param set {ps}");

            let randomness = vec![4u8; enc_rand];
            let (mut ct, mut ss) = (vec![0u8; ctl], vec![0u8; ssl]);
            assert_eq!(
                unsafe {
                    hqc_encaps(ps, &cb, ct.as_mut_ptr(), ctl, ss.as_mut_ptr(), ssl,
                               ek.as_ptr(), ekl, randomness.as_ptr(), randomness.len())
                },
                HQC_OK
            );

            let mut ss2 = vec![0u8; ssl];
            assert_eq!(
                unsafe {
                    hqc_decaps(ps, &cb, ss2.as_mut_ptr(), ssl, ct.as_ptr(), ctl,
                               dk.as_ptr(), dkl)
                },
                HQC_OK
            );
            assert_eq!(ss, ss2, "param set {ps}");
        }
    }

    /// The C header is hand-written, so nothing but this test keeps its
    /// enumerators in step with the constants above. Same idea as the
    /// compile-time pinning in `parameters.rs` and `nist.rs`, at test time
    /// because the header is not Rust.
    #[test]
    fn c_header_matches_the_rust_constants() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/include/hqc_c_api.h");
        let header = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("reading {path}: {e}"));

        // Every `NAME = value` enumerator line, whatever follows the value.
        let enumerator = |name: &str| -> i32 {
            header
                .lines()
                .map(str::trim)
                .find_map(|line| {
                    let rest = line.strip_prefix(name)?.trim_start();
                    let rest = rest.strip_prefix('=')?.trim_start();
                    let end = rest
                        .find(|c: char| !(c.is_ascii_digit() || c == '-'))
                        .unwrap_or(rest.len());
                    rest[..end].parse().ok()
                })
                .unwrap_or_else(|| panic!("{name} not found as an enumerator in {path}"))
        };

        // Pairs each constant with its own spelling, so the header name and
        // the Rust constant cannot be mismatched by a typo in a string.
        macro_rules! pinned {
            ($($name:ident),* $(,)?) => {
                [$((stringify!($name), $name)),*]
            };
        }

        for (name, value) in pinned![
            HQC_OK,
            HQC_ERR_BUFFER_LENGTH,
            HQC_ERR_INVALID_KEY,
            HQC_ERR_INVALID_CIPHERTEXT,
            HQC_ERR_RANDOMNESS,
            HQC_ERR_INTERNAL,
            HQC_ERR_BAD_PARAMETER_SET,
            HQC_ERR_NULL_POINTER,
            HQC_ERR_HASH_CALLBACK,
            HQC_ERR_BAD_CALLBACKS,
            HQC_ERR_ALLOC,
        ] {
            assert_eq!(enumerator(name), value, "{name}");
        }

        for (name, set) in [
            ("HQC_PARAM_SET_1", HqcParameterSet::Hqc1),
            ("HQC_PARAM_SET_3", HqcParameterSet::Hqc3),
            ("HQC_PARAM_SET_5", HqcParameterSet::Hqc5),
        ] {
            let value = enumerator(name);
            assert_eq!(value, i32::from(set.nist_level()), "{name}");
            // The discriminant the header advertises must be one `parameter_set` accepts.
            assert_eq!(parameter_set(value as u8), Some(set), "{name}");
        }

        for f in [
            "hqc_sizes",
            "hqc_randomness_lengths",
            "hqc_keypair",
            "hqc_public_key",
            "hqc_encaps",
            "hqc_decaps",
        ] {
            assert!(
                header.contains(&format!("int32_t {f}(")),
                "{f} is not declared with an int32_t return in {path}"
            );
        }

        // The callback struct: version macro and every member, in the order
        // of the Rust definition in `hash.rs`.
        assert!(
            header.contains(&format!("#define HQC_CALLBACKS_VERSION {HQC_CALLBACKS_VERSION}")),
            "HQC_CALLBACKS_VERSION is not {HQC_CALLBACKS_VERSION} in {path}"
        );
        let mut last = 0;
        for member in [
            "typedef struct hqc_hash_callbacks_t",
            "void* ctx;",
            "(*sha3_256)(void* ctx, const hqc_buffer_t* parts, size_t n_parts, uint8_t* out)",
            "(*sha3_512)(void* ctx, const hqc_buffer_t* parts, size_t n_parts, uint8_t* out)",
            "(*shake256_init)(void* ctx, const hqc_buffer_t* parts, size_t n_parts, hqc_xof_t** out_xof)",
            "(*shake256_squeeze)(void* ctx, hqc_xof_t* xof, uint8_t* out, size_t out_len)",
            "(*shake256_free)(void* ctx, hqc_xof_t* xof)",
            "typedef struct hqc_alloc_callbacks_t",
            "void* ctx;",
            "(*secure_alloc)(void* ctx, size_t len)",
            "(*secure_free)(void* ctx, void* ptr, size_t len)",
            "typedef struct hqc_callbacks_t",
            "uint32_t version;",
            "hqc_hash_callbacks_t hash;",
            "hqc_alloc_callbacks_t alloc;",
        ] {
            let pos = header[last..]
                .find(member)
                .unwrap_or_else(|| panic!("{member:?} not found (in order) in {path}"));
            last += pos + member.len();
        }
    }

    #[test]
    fn bad_inputs_return_codes_and_never_unwind() {
        let cb = callbacks();
        let mut ss = [0u8; 32];
        assert_eq!(
            unsafe { hqc_sizes(2, core::ptr::null_mut(), core::ptr::null_mut(),
                               core::ptr::null_mut(), core::ptr::null_mut()) },
            HQC_ERR_BAD_PARAMETER_SET
        );
        assert_eq!(
            unsafe { hqc_decaps(1, &cb, ss.as_mut_ptr(), 32, core::ptr::null(), 0,
                                core::ptr::null(), 0) },
            HQC_ERR_NULL_POINTER
        );
        // wrong ciphertext length -> structural error, not a panic
        let ct = [0u8; 10];
        let dk = vec![0u8; 32];
        assert_eq!(
            unsafe { hqc_decaps(1, &cb, ss.as_mut_ptr(), 32, ct.as_ptr(), ct.len(),
                                dk.as_ptr(), dk.len()) },
            HQC_ERR_INVALID_CIPHERTEXT
        );
        // randomness of the wrong length -> buffer-length error (no expansion is done)
        let (mut ek, mut dk) = (vec![0u8; 2241], vec![0u8; 32]);
        let seed48 = [0u8; 48];
        assert_eq!(
            unsafe { hqc_keypair(1, &cb, ek.as_mut_ptr(), ek.len(), dk.as_mut_ptr(), dk.len(),
                                 seed48.as_ptr(), seed48.len()) },
            HQC_ERR_BUFFER_LENGTH
        );
        let (mut ct, mut ss) = (vec![0u8; 4433], vec![0u8; 32]);
        assert_eq!(
            unsafe { hqc_encaps(1, &cb, ct.as_mut_ptr(), ct.len(), ss.as_mut_ptr(), ss.len(),
                                ek.as_ptr(), ek.len(), seed48.as_ptr(), 31) },
            HQC_ERR_BUFFER_LENGTH
        );
        // a private key of the wrong length is an invalid key
        assert_eq!(
            unsafe { hqc_public_key(1, &cb, ek.as_mut_ptr(), ek.len(), dk.as_ptr(), 31) },
            HQC_ERR_INVALID_KEY
        );
        assert_eq!(
            unsafe { hqc_public_key(2, &cb, ek.as_mut_ptr(), ek.len(), dk.as_ptr(), dk.len()) },
            HQC_ERR_BAD_PARAMETER_SET
        );
        assert_eq!(
            unsafe { hqc_randomness_lengths(4, core::ptr::null_mut(), core::ptr::null_mut()) },
            HQC_ERR_BAD_PARAMETER_SET
        );
    }

    #[test]
    fn unusable_callbacks_are_rejected() {
        let mut ss = [0u8; 32];
        let ct = vec![0u8; 4433];
        let dk = vec![0u8; 32];
        let mut decaps = |cb: *const HqcCallbacks| unsafe {
            hqc_decaps(1, cb, ss.as_mut_ptr(), 32, ct.as_ptr(), ct.len(), dk.as_ptr(), dk.len())
        };

        assert_eq!(decaps(core::ptr::null()), HQC_ERR_BAD_CALLBACKS);

        let mut wrong_version = callbacks();
        wrong_version.version = HQC_CALLBACKS_VERSION + 1;
        assert_eq!(decaps(&wrong_version), HQC_ERR_BAD_CALLBACKS);

        let mut missing = callbacks();
        missing.hash.shake256_free = None;
        assert_eq!(decaps(&missing), HQC_ERR_BAD_CALLBACKS);

        let mut no_alloc = callbacks();
        no_alloc.alloc.secure_alloc = None;
        assert_eq!(decaps(&no_alloc), HQC_ERR_BAD_CALLBACKS);
    }

    /// Every operation returns all provider memory it obtained, with the
    /// exact length, on success and on the failure paths.
    #[test]
    fn all_secure_memory_is_returned() {
        let t = TestCtx::default();
        let cb = callbacks_with(t.as_ptr());
        let seed = [5u8; 32];
        let randomness = [5u8; 40];
        let (mut ek, mut dk, mut ek2) = (vec![0u8; 4514], vec![0u8; 32], vec![0u8; 4514]);
        let (mut ct, mut ss, mut ss2) = (vec![0u8; 8978], vec![0u8; 32], vec![0u8; 32]);

        assert_eq!(
            unsafe { hqc_keypair(3, &cb, ek.as_mut_ptr(), ek.len(), dk.as_mut_ptr(), dk.len(),
                                 seed.as_ptr(), seed.len()) },
            HQC_OK
        );
        assert!(t.all_memory_returned(), "keypair");
        assert!(t.allocs.load(Ordering::SeqCst) > 0);

        assert_eq!(
            unsafe { hqc_public_key(3, &cb, ek2.as_mut_ptr(), ek2.len(), dk.as_ptr(), dk.len()) },
            HQC_OK
        );
        assert!(t.all_memory_returned(), "public_key");

        assert_eq!(
            unsafe { hqc_encaps(3, &cb, ct.as_mut_ptr(), ct.len(), ss.as_mut_ptr(), ss.len(),
                                ek.as_ptr(), ek.len(), randomness.as_ptr(), randomness.len()) },
            HQC_OK
        );
        assert!(t.all_memory_returned(), "encaps");

        assert_eq!(
            unsafe { hqc_decaps(3, &cb, ss2.as_mut_ptr(), ss2.len(), ct.as_ptr(), ct.len(),
                                dk.as_ptr(), dk.len()) },
            HQC_OK
        );
        assert!(t.all_memory_returned(), "decaps");
        assert_eq!(ss, ss2);
    }

    /// An allocation failure surfaces as HQC_ERR_ALLOC and releases what was
    /// allocated before it.
    #[test]
    fn allocation_failure_is_reported_and_memory_is_released() {
        for fail_at in [0usize, 1, 3, 5] {
            let mut t = TestCtx::default();
            t.fail_alloc_at = Some(fail_at);
            let cb = callbacks_with(t.as_ptr());
            let (mut ek, mut dk) = (vec![0u8; 2241], vec![0u8; 32]);
            let seed = [6u8; 32];
            assert_eq!(
                unsafe { hqc_keypair(1, &cb, ek.as_mut_ptr(), ek.len(), dk.as_mut_ptr(), dk.len(),
                                     seed.as_ptr(), seed.len()) },
                HQC_ERR_ALLOC,
                "fail_at = {fail_at}"
            );
            assert!(t.all_memory_returned(), "fail_at = {fail_at}");
        }
    }

    /// A failing callback surfaces as HQC_ERR_HASH_CALLBACK, and every XOF
    /// state the crate created is released even on that error path.
    #[test]
    fn failing_hash_callback_is_reported_and_states_are_released() {
        let mut t = TestCtx::default();
        t.fail_squeeze_at = Some(2);
        let cb = callbacks_with((&t as *const TestCtx).cast_mut().cast());

        let (mut ek, mut dk) = (vec![0u8; 2241], vec![0u8; 32]);
        let seed = [3u8; 32];
        assert_eq!(
            unsafe { hqc_keypair(1, &cb, ek.as_mut_ptr(), ek.len(), dk.as_mut_ptr(), dk.len(),
                                 seed.as_ptr(), seed.len()) },
            HQC_ERR_HASH_CALLBACK
        );
        assert!(t.xofs_created.load(Ordering::SeqCst) > 0);
        assert_eq!(
            t.xofs_created.load(Ordering::SeqCst),
            t.xofs_freed.load(Ordering::SeqCst)
        );
        assert!(t.all_memory_returned());

        // Without the injected failure, the same context sees every state released too.
        let t2 = TestCtx::default();
        let cb2 = callbacks_with((&t2 as *const TestCtx).cast_mut().cast());
        assert_eq!(
            unsafe { hqc_keypair(1, &cb2, ek.as_mut_ptr(), ek.len(), dk.as_mut_ptr(), dk.len(),
                                 seed.as_ptr(), seed.len()) },
            HQC_OK
        );
        assert_eq!(
            t2.xofs_created.load(Ordering::SeqCst),
            t2.xofs_freed.load(Ordering::SeqCst)
        );
    }
}
