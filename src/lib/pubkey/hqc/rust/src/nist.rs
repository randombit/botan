//! The NIST reference API constants, one module per parameter set.
//!
//! These mirror `src/common/hqc-<n>/hqc-kem.h` in the HQC reference
//! implementation. The reference defines them per variant — each `hqc-kem.h` has
//! its own values — so a single flat set of `CRYPTO_*` constants can only ever
//! describe one parameter set. That is why they live in [`hqc1`], [`hqc3`] and
//! [`hqc5`] rather than at the crate root.
//!
//! Every value is *derived* from [`HqcParameters`] rather than transcribed,
//! then checked against the literal in the corresponding `hqc-kem.h` by a
//! compile-time assertion. A divergence between this crate and the reference
//! is therefore a build failure, not a runtime surprise.
//!
//! For runtime-selected code prefer the accessors on [`crate::api::Hqc`],
//! which give the same numbers for whichever set is in use. These constants
//! exist for callers that are statically bound to one variant — a NIST KAT
//! driver, or a C header generated per parameter set.

use crate::parameters::{HQC_1, HQC_3, HQC_5, HqcParameters};

macro_rules! nist_api {
    ($mod:ident, $params:expr, $algname:literal,
     $sk:literal, $pk:literal, $ct:literal) => {
        /// NIST API constants for this parameter set.
        pub mod $mod {
            use super::*;

            const P: &HqcParameters = &$params;

            /// `CRYPTO_ALGNAME`
            pub const CRYPTO_ALGNAME: &str = $algname;
            /// `CRYPTO_SECRETKEYBYTES` — the decapsulation key.
            pub const CRYPTO_SECRETKEYBYTES: usize = P.dk_bytes;
            /// `CRYPTO_PUBLICKEYBYTES` — the encapsulation key.
            pub const CRYPTO_PUBLICKEYBYTES: usize = P.ek_bytes;
            /// `CRYPTO_BYTES` — the shared secret.
            pub const CRYPTO_BYTES: usize = P.ss_bytes;
            /// `CRYPTO_CIPHERTEXTBYTES`
            pub const CRYPTO_CIPHERTEXTBYTES: usize = P.ct_bytes;

            // Pinned against the literals in the reference's hqc-kem.h. If this
            // crate's derivation ever disagrees with the reference, the build
            // stops here.
            const _: () = assert!(CRYPTO_SECRETKEYBYTES == $sk);
            const _: () = assert!(CRYPTO_PUBLICKEYBYTES == $pk);
            const _: () = assert!(CRYPTO_BYTES == 32);
            const _: () = assert!(CRYPTO_CIPHERTEXTBYTES == $ct);
        }
    };
}

nist_api!(hqc1, HQC_1, "HQC-1", 32, 2241, 4433);
nist_api!(hqc3, HQC_3, "HQC-3", 32, 4514, 8978);
nist_api!(hqc5, HQC_5, "HQC-5", 32, 7237, 14421);

#[cfg(test)]
mod tests {
    use crate::api::Hqc;
    use crate::parameters::HqcParameterSet;

    /// The static constants and the runtime accessors must agree. They are two
    /// views of the same table, and nothing else guarantees they stay in step.
    #[test]
    fn static_constants_match_the_runtime_accessors() {
        for (set, sk, pk, ct, name) in [
            (
                HqcParameterSet::Hqc1,
                super::hqc1::CRYPTO_SECRETKEYBYTES,
                super::hqc1::CRYPTO_PUBLICKEYBYTES,
                super::hqc1::CRYPTO_CIPHERTEXTBYTES,
                super::hqc1::CRYPTO_ALGNAME,
            ),
            (
                HqcParameterSet::Hqc3,
                super::hqc3::CRYPTO_SECRETKEYBYTES,
                super::hqc3::CRYPTO_PUBLICKEYBYTES,
                super::hqc3::CRYPTO_CIPHERTEXTBYTES,
                super::hqc3::CRYPTO_ALGNAME,
            ),
            (
                HqcParameterSet::Hqc5,
                super::hqc5::CRYPTO_SECRETKEYBYTES,
                super::hqc5::CRYPTO_PUBLICKEYBYTES,
                super::hqc5::CRYPTO_CIPHERTEXTBYTES,
                super::hqc5::CRYPTO_ALGNAME,
            ),
        ] {
            let cb = crate::test_support::callbacks();
            let hash = crate::test_support::provider(&cb);
            let h = Hqc::new(set, &hash);
            assert_eq!(h.decapsulation_key_len(), sk);
            assert_eq!(h.encapsulation_key_len(), pk);
            assert_eq!(h.ciphertext_len(), ct);
            assert_eq!(h.shared_secret_len(), super::hqc1::CRYPTO_BYTES);
            assert_eq!(h.name(), name);
        }
    }
}
