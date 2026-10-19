//! The public HQC-KEM API.
//!
//! This is the surface a binding — Botan in particular — is expected to use.
//! It differs from the internal `kem` module in three ways that matter at an
//! FFI boundary:
//!
//! - every operation returns [`Result`] rather than panicking;
//! - the caller provides the output buffers, matching `std::span` on the
//!   Botan side, so nothing is allocated and returned across the boundary;
//! - sizes are queried from the instance, so a caller can allocate correctly
//!   without duplicating the parameter table.
//!
//! The previous hardcoded `CRYPTO_*BYTES` constants are gone: they described
//! HQC-1 only and were wrong for any other parameter set.
//!
//! # Randomness
//!
//! The API is *derandomized*: the caller passes exactly the bytes that the
//! specification's `KeyGen` and `Encaps` draw from the random number
//! generator (the 32-byte master seed, resp. the message `m` followed by the
//! salt), and the crate performs no expansion of its own. A caller that feeds
//! the output of the NIST KAT DRBG therefore reproduces the reference known
//! answer tests, and a caller such as Botan draws the bytes from its own RNG.

use crate::error::{HqcError, Result, check_len};
use crate::hash::Callbacks;
use crate::kem;
use crate::parameters::{HqcParameterSet, HqcParameters, SALT_BYTES, SEED_BYTES};

/// An HQC-KEM instance bound to one parameter set and one set of callbacks.
///
/// Two pointers wide: [`HqcParameters`] instances are `'static` and the
/// callbacks are borrowed, so this is free to copy and there is nothing to own
/// or free. That is what lets the C ABI stay stateless — a binding passes a
/// parameter-set discriminant and its callbacks on every call instead of
/// managing a handle lifetime.
#[derive(Clone, Copy)]
pub struct Hqc<'h> {
    p: &'static HqcParameters,
    cb: &'h dyn Callbacks,
}

impl<'h> Hqc<'h> {
    /// Creates an instance for `set` using `cb` for hashing and secret memory.
    pub fn new(set: HqcParameterSet, cb: &'h dyn Callbacks) -> Self {
        Self { p: set.params(), cb }
    }

    /// The parameter set in use.
    pub const fn parameter_set(&self) -> HqcParameterSet {
        self.p.set
    }

    /// The underlying parameters.
    pub const fn parameters(&self) -> &'static HqcParameters {
        self.p
    }

    /// Canonical name, e.g. `"HQC-1"`.
    pub const fn name(&self) -> &'static str {
        self.p.set.name()
    }

    /// Encapsulation key length in bytes. Botan: `Public_Key::key_length`.
    pub const fn encapsulation_key_len(&self) -> usize {
        self.p.ek_bytes
    }

    /// Decapsulation key length in bytes (the 32-byte master seed).
    pub const fn decapsulation_key_len(&self) -> usize {
        self.p.dk_bytes
    }

    /// Ciphertext length in bytes. Botan: `encapsulated_key_length`.
    pub const fn ciphertext_len(&self) -> usize {
        self.p.ct_bytes
    }

    /// Shared secret length in bytes. Botan: `shared_key_length`.
    pub const fn shared_secret_len(&self) -> usize {
        self.p.ss_bytes
    }

    /// Number of random bytes [`Hqc::keypair`] consumes: the 32-byte master
    /// seed, which is the decapsulation key.
    pub const fn keypair_randomness_len(&self) -> usize {
        self.p.keypair_randomness_bytes()
    }

    /// Number of random bytes [`Hqc::encapsulate`] consumes: the message `m`
    /// (16, 24 or 32 bytes) followed by the 16-byte salt.
    pub const fn encapsulation_randomness_len(&self) -> usize {
        self.p.encapsulation_randomness_bytes()
    }

    /// Generates a keypair into caller-provided buffers.
    ///
    /// `seed` is the master seed `seed_kem` of the specification's `KeyGen`,
    /// exactly [`Hqc::keypair_randomness_len`] bytes from a secure entropy
    /// source. It is used as is, without expansion, and is written to `dk`.
    ///
    /// # Errors
    /// [`HqcError::BufferLength`] if a buffer or the seed is the wrong size,
    /// [`HqcError::HashCallback`] or [`HqcError::Alloc`] if a callback fails.
    pub fn keypair(&self, ek: &mut [u8], dk: &mut [u8], seed: &[u8]) -> Result<()> {
        check_len("encapsulation key", ek, self.p.ek_bytes)?;
        check_len("decapsulation key", dk, self.p.dk_bytes)?;
        check_len("key generation randomness", seed, self.keypair_randomness_len())?;

        let seed: &[u8; SEED_BYTES] = seed.try_into().map_err(|_| HqcError::Internal)?;
        kem::crypto_kem_keypair_derand(self.p, self.cb, seed, ek, dk)
    }

    /// Derives the encapsulation key belonging to the decapsulation key `dk`
    /// into `ek`.
    ///
    /// Key generation is deterministic in the master seed, so this repeats
    /// its public half. It is what a binding uses to load a stored 32-byte
    /// private key. Variable-time, like key generation.
    ///
    /// # Errors
    /// [`HqcError::BufferLength`] if `ek` is the wrong size,
    /// [`HqcError::InvalidKey`] if `dk` is not the right length for this set,
    /// [`HqcError::HashCallback`] or [`HqcError::Alloc`] if a callback fails.
    pub fn public_key(&self, ek: &mut [u8], dk: &[u8]) -> Result<()> {
        check_len("encapsulation key", ek, self.p.ek_bytes)?;
        if dk.len() != self.p.dk_bytes {
            return Err(HqcError::InvalidKey);
        }
        let seed: &[u8; SEED_BYTES] = dk.try_into().map_err(|_| HqcError::Internal)?;

        let ek_v = kem::derive_encapsulation_key(self.p, self.cb, seed)?;
        if ek_v.len() != ek.len() {
            return Err(HqcError::Internal);
        }
        ek.copy_from_slice(&ek_v);
        Ok(())
    }

    /// Encapsulates to `ek`, writing the ciphertext and shared secret.
    ///
    /// `randomness` is the message `m` followed by the salt of the
    /// specification's `Encaps`, exactly
    /// [`Hqc::encapsulation_randomness_len`] bytes from a secure entropy
    /// source, used as is.
    ///
    /// # Errors
    /// [`HqcError::BufferLength`] on a wrong-sized output buffer or
    /// randomness, [`HqcError::InvalidKey`] if `ek` is not the right length
    /// for this set, [`HqcError::HashCallback`] or [`HqcError::Alloc`] if a
    /// callback fails.
    pub fn encapsulate(
        &self,
        ct: &mut [u8],
        ss: &mut [u8],
        ek: &[u8],
        randomness: &[u8],
    ) -> Result<()> {
        check_len("ciphertext", ct, self.p.ct_bytes)?;
        check_len("shared secret", ss, self.p.ss_bytes)?;
        check_len("encapsulation randomness", randomness, self.encapsulation_randomness_len())?;
        if ek.len() != self.p.ek_bytes {
            return Err(HqcError::InvalidKey);
        }

        let (m, salt) = randomness.split_at(self.p.security_bytes);
        let salt: &[u8; SALT_BYTES] = salt.try_into().map_err(|_| HqcError::Internal)?;
        let (ct_v, k) = kem::crypto_kem_enc_derand(self.p, self.cb, ek, m, salt)?;
        if ct_v.len() != ct.len() || k.len() != ss.len() {
            return Err(HqcError::Internal);
        }
        ct.copy_from_slice(&ct_v);
        ss.copy_from_slice(&k);
        Ok(())
    }

    /// Expands a 32-byte seed key once for repeated decapsulation.
    ///
    /// This setup step is variable-time because upstream's exact seed mapping
    /// uses rejection sampling. The returned object caches the secret vector
    /// in provider memory and binds it to this parameter set.
    pub fn expand_decapsulation_key(&self, dk: &[u8]) -> Result<ExpandedDecapsulationKey<'h>> {
        if dk.len() != self.p.dk_bytes {
            return Err(HqcError::InvalidKey);
        }
        Ok(ExpandedDecapsulationKey {
            hqc: *self,
            key: kem::expand_key(self.p, self.cb, dk)?,
        })
    }

    /// Decapsulates `ct` with a seed key, writing the shared secret.
    ///
    /// This includes variable-time seed expansion. Use
    /// [`Self::expand_decapsulation_key`] once and the expanded object's
    /// `decapsulate` method to avoid rejection sampling on repeated use.
    ///
    /// Never reports a decryption failure. HQC uses the Fujisaki-Okamoto
    /// transform with implicit rejection, so a ciphertext that does not
    /// re-encrypt yields a pseudo-random shared secret derived from the
    /// rejection key. Returning a distinguishable error here would hand an
    /// attacker exactly the oracle that construction removes.
    ///
    /// # Errors
    /// [`HqcError::BufferLength`], [`HqcError::InvalidCiphertext`] or
    /// [`HqcError::InvalidKey`] — all structural, none content-dependent;
    /// [`HqcError::HashCallback`] or [`HqcError::Alloc`] if a callback fails.
    pub fn decapsulate(&self, ss: &mut [u8], ct: &[u8], dk: &[u8]) -> Result<()> {
        check_len("shared secret", ss, self.p.ss_bytes)?;
        if ct.len() != self.p.ct_bytes {
            return Err(HqcError::InvalidCiphertext);
        }
        if dk.len() != self.p.dk_bytes {
            return Err(HqcError::InvalidKey);
        }

        let k = kem::crypto_kem_dec(self.p, self.cb, ct, dk)?;
        if k.len() != ss.len() {
            return Err(HqcError::Internal);
        }
        ss.copy_from_slice(&k);
        Ok(())
    }
}

/// Parameter-bound expanded key for decapsulation without secret-dependent
/// sampling, branches, or memory indices in the algorithm. Timing guarantees
/// still depend on the compiler and target; no machine-code audit is implied.
/// Secret buffers live in provider memory and are released on drop. This
/// object is intentionally not Clone or Debug and has no serialized
/// representation.
pub struct ExpandedDecapsulationKey<'h> {
    hqc: Hqc<'h>,
    key: kem::ExpandedKey<'h>,
}

impl ExpandedDecapsulationKey<'_> {
    pub fn parameter_set(&self) -> HqcParameterSet {
        self.hqc.parameter_set()
    }

    /// Decapsulates using cached secret material and branchless implicit rejection.
    pub fn decapsulate(&self, ss: &mut [u8], ct: &[u8]) -> Result<()> {
        check_len("shared secret", ss, self.hqc.p.ss_bytes)?;
        if ct.len() != self.hqc.p.ct_bytes {
            return Err(HqcError::InvalidCiphertext);
        }
        let k = kem::decapsulate_expanded(self.hqc.p, self.hqc.cb, ct, &self.key)?;
        ss.copy_from_slice(&k);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{callbacks, provider};

    #[test]
    fn sizes_match_the_specification() {
        let cb = callbacks();
        let hash = provider(&cb);
        // Table 6 of hqc_specifications_2025_08_22.pdf; dk is the 32-byte master seed.
        // The encapsulation randomness is m (16, 24, 32 bytes) and the 16-byte salt.
        for (set, ek, dk, ct, enc_rand) in [
            (HqcParameterSet::Hqc1, 2241, 32, 4433, 32),
            (HqcParameterSet::Hqc3, 4514, 32, 8978, 40),
            (HqcParameterSet::Hqc5, 7237, 32, 14421, 48),
        ] {
            let h = Hqc::new(set, &hash);
            assert_eq!(h.encapsulation_key_len(), ek);
            assert_eq!(h.decapsulation_key_len(), dk);
            assert_eq!(h.ciphertext_len(), ct);
            assert_eq!(h.shared_secret_len(), 32);
            assert_eq!(h.keypair_randomness_len(), 32);
            assert_eq!(h.encapsulation_randomness_len(), enc_rand);
        }
    }

    #[test]
    fn roundtrip_for_every_parameter_set() {
        let cb = callbacks();
        let hash = provider(&cb);
        for set in HqcParameterSet::ALL {
            let h = Hqc::new(set, &hash);
            let seed = [7u8; 32];

            let mut ek = vec![0u8; h.encapsulation_key_len()];
            let mut dk = vec![0u8; h.decapsulation_key_len()];
            h.keypair(&mut ek, &mut dk, &seed).unwrap();
            assert_eq!(dk, seed, "{}: dk is the seed", h.name());

            let mut ek2 = vec![0u8; h.encapsulation_key_len()];
            h.public_key(&mut ek2, &dk).unwrap();
            assert_eq!(ek, ek2, "{}: public_key reproduces ek", h.name());

            let randomness = vec![11u8; h.encapsulation_randomness_len()];
            let mut ct = vec![0u8; h.ciphertext_len()];
            let mut ss = vec![0u8; h.shared_secret_len()];
            h.encapsulate(&mut ct, &mut ss, &ek, &randomness).unwrap();

            let mut ss2 = vec![0u8; h.shared_secret_len()];
            h.decapsulate(&mut ss2, &ct, &dk).unwrap();

            assert_eq!(ss, ss2, "{}", h.name());
        }
    }

    #[test]
    fn wrong_buffer_lengths_are_errors_not_panics() {
        let cb = callbacks();
        let hash = provider(&cb);
        let h = Hqc::new(HqcParameterSet::Hqc1, &hash);
        let seed = [1u8; 32];

        let mut short = vec![0u8; 8];
        let mut dk = vec![0u8; h.decapsulation_key_len()];
        assert!(matches!(
            h.keypair(&mut short, &mut dk, &seed),
            Err(HqcError::BufferLength { .. })
        ));

        // The randomness is used as is, so its length is checked as well
        let mut ek = vec![0u8; h.encapsulation_key_len()];
        assert!(matches!(
            h.keypair(&mut ek, &mut dk, &[1u8; 48]),
            Err(HqcError::BufferLength { .. })
        ));
        h.keypair(&mut ek, &mut dk, &seed).unwrap();
        let mut ct = vec![0u8; h.ciphertext_len()];
        let mut ss = vec![0u8; h.shared_secret_len()];
        assert!(matches!(
            h.encapsulate(&mut ct, &mut ss, &ek, &[2u8; 48]),
            Err(HqcError::BufferLength { .. })
        ));
        assert!(matches!(
            h.public_key(&mut short, &dk),
            Err(HqcError::BufferLength { .. })
        ));
        assert_eq!(h.public_key(&mut ek, &dk[..31]), Err(HqcError::InvalidKey));

        // Key length errors are structural and reported as InvalidKey
        let randomness = vec![2u8; h.encapsulation_randomness_len()];
        assert_eq!(
            h.encapsulate(&mut ct, &mut ss, &ek[..ek.len() - 1], &randomness),
            Err(HqcError::InvalidKey)
        );
        h.encapsulate(&mut ct, &mut ss, &ek, &randomness).unwrap();
        assert_eq!(
            h.decapsulate(&mut ss, &ct, &dk[..31]),
            Err(HqcError::InvalidKey)
        );

        assert_eq!(
            h.decapsulate(&mut ss, &[0u8; 10], &vec![0u8; h.decapsulation_key_len()]),
            Err(HqcError::InvalidCiphertext)
        );
    }

    /// A ciphertext from one parameter set must be rejected by another,
    /// structurally, before any secret-dependent work happens.
    #[test]
    fn cross_parameter_set_inputs_are_rejected() {
        let cb = callbacks();
        let hash = provider(&cb);
        let h1 = Hqc::new(HqcParameterSet::Hqc1, &hash);
        let h5 = Hqc::new(HqcParameterSet::Hqc5, &hash);
        let mut ss = vec![0u8; h5.shared_secret_len()];
        let ct1 = vec![0u8; h1.ciphertext_len()];
        let dk5 = vec![0u8; h5.decapsulation_key_len()];
        assert_eq!(
            h5.decapsulate(&mut ss, &ct1, &dk5),
            Err(HqcError::InvalidCiphertext)
        );
    }
}

#[cfg(test)]
mod expanded_tests {
    use super::*;
    use crate::test_support::{callbacks, provider};

    #[test]
    fn expanded_key_binds_parameters_and_checks_lengths() {
        let cb = callbacks();
        let hash = provider(&cb);
        for set in HqcParameterSet::ALL {
            let hqc = Hqc::new(set, &hash);
            assert!(matches!(
                hqc.expand_decapsulation_key(&[0; 31]),
                Err(HqcError::InvalidKey)
            ));
            let key = hqc.expand_decapsulation_key(&[0; 32]).unwrap();
            assert_eq!(key.parameter_set(), set);
            assert!(matches!(
                key.decapsulate(&mut [0; 31], &vec![0; hqc.ciphertext_len()]),
                Err(HqcError::BufferLength { .. })
            ));
            assert_eq!(
                key.decapsulate(&mut [0; 32], &[0; 1]),
                Err(HqcError::InvalidCiphertext)
            );
        }
    }
}
