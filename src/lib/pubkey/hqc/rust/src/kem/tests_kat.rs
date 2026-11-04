use crate::kem::*;
use crate::parameters::*;
use crate::test_support::{callbacks, provider};
use crate::testvectors::nist_rng::NistRng;

use sha3::Shake256;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use std::collections::HashMap;

// Share Botan's vectors directly. include_str! also makes Cargo rebuild the
// test binary when the vectors change, independently of the working directory.
const KAT_VECTORS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../../tests/data/pubkey/hqc_kat.vec"
));

fn hex_decode(s: &str) -> Vec<u8> {
    assert!(s.is_ascii() && s.len() % 2 == 0, "invalid KAT hex string");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("invalid KAT hex digit"))
        .collect()
}

/// Botan stores PK and CT as 16-byte SHAKE-256 digests, and the rest in full.
struct KatVector {
    seed: Vec<u8>,
    pk: Vec<u8>,
    sk: Vec<u8>,
    ct: Vec<u8>,
    ss: Vec<u8>,
}

/// Read the same sections and Seed/SS/PK/SK/CT records as Botan's KAT test.
/// CT terminates each record, as required by the C++ test framework.
fn parse_kat_vectors(text: &str) -> HashMap<HqcParameterSet, Vec<KatVector>> {
    let mut vectors: HashMap<HqcParameterSet, Vec<KatVector>> = HashMap::new();
    let mut set = None;
    let mut fields = HashMap::new();

    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            assert!(fields.is_empty(), "incomplete KAT record before {line}");
            let current = match line {
                "[HQCr4-1]" => HqcParameterSet::Hqc1,
                "[HQCr4-3]" => HqcParameterSet::Hqc3,
                "[HQCr4-5]" => HqcParameterSet::Hqc5,
                _ => panic!("unknown KAT section: {line}"),
            };
            assert!(
                vectors.insert(current, Vec::new()).is_none(),
                "duplicate KAT section: {line}"
            );
            set = Some(current);
            continue;
        }

        let current = set.expect("KAT field outside a parameter-set section");
        let (key, value) = line.split_once('=').expect("invalid KAT field");
        let key = key.trim();
        assert!(
            matches!(key, "Seed" | "SS" | "PK" | "SK" | "CT"),
            "unknown KAT field: {key}"
        );
        assert!(
            fields.insert(key, hex_decode(value.trim())).is_none(),
            "duplicate KAT field: {key}"
        );
        if key == "CT" {
            vectors.get_mut(&current).unwrap().push(KatVector {
                seed: fields.remove("Seed").expect("missing KAT Seed"),
                ss: fields.remove("SS").expect("missing KAT SS"),
                pk: fields.remove("PK").expect("missing KAT PK"),
                sk: fields.remove("SK").expect("missing KAT SK"),
                ct: fields.remove("CT").unwrap(),
            });
        }
    }
    assert!(fields.is_empty(), "incomplete final KAT record");
    vectors
}

fn shake_256_16(value: &[u8]) -> [u8; 16] {
    let mut hash = Shake256::default();
    hash.update(value);
    let mut digest = [0; 16];
    hash.finalize_xof().read(&mut digest);
    digest
}

/// Runs the full HQC-KEM KAT suite against Botan's shared `hqc_kat.vec`, for
/// **every** parameter set.
///
/// Reproduces the sequential PRNG draw order from `PQCgenKAT_kem.c`:
/// `NistRng::new(seed)` once per vector, then `crypto_kem_keypair`
/// followed by `crypto_kem_enc` on the *same* PRNG stream, matching
/// the KAT generator exactly.
///
/// This is the acceptance test for runtime parameter selection: it fails if
/// any module still computes an HQC-1 size while running as HQC-3 or HQC-5.
/// It links no C.
#[test]
fn test_hqc_kem_kat_vectors() {
    let cb = callbacks();
    let hash = provider(&cb);
    let mut all_vectors = parse_kat_vectors(KAT_VECTORS);
    for set in HqcParameterSet::ALL {
        let p = set.params();

        let vectors = all_vectors.remove(&set).expect("missing KAT parameter set");

        assert_eq!(vectors.len(), 100, "{}: incomplete KAT corpus", set.name());

        for (index, v) in vectors.iter().enumerate() {
            assert_eq!(v.seed.len(), 48);
            assert_eq!(v.pk.len(), 16);
            assert_eq!(v.sk.len(), p.dk_bytes);
            assert_eq!(v.ct.len(), 16);
            assert_eq!(v.ss.len(), p.ss_bytes);
            // Single PRNG stream reused for both keypair and enc, as in the C KAT driver
            let mut reader = NistRng::new(v.seed.as_slice().try_into().unwrap());

            // 1. Keypair generation (compare the public-key digest, as Botan does)
            let mut pk = vec![0u8; p.ek_bytes];
            let mut sk = vec![0u8; p.dk_bytes];
            crypto_kem_keypair(p, &hash, &mut reader, &mut pk, &mut sk).unwrap();
            assert_eq!(
                shake_256_16(&pk).as_slice(),
                v.pk,
                "{}: pk mismatch at count = {}",
                set.name(),
                index
            );
            assert_eq!(sk, v.sk, "{}: sk mismatch at count = {}", set.name(), index);

            // 2. Encapsulation (continues the same PRNG stream; compare the CT digest)
            let (ct, ss) = crypto_kem_enc(p, &hash, &mut reader, &pk).unwrap();
            assert_eq!(
                shake_256_16(&ct).as_slice(),
                v.ct,
                "{}: ct mismatch at count = {}",
                set.name(),
                index
            );
            assert_eq!(
                &*ss,
                &v.ss[..],
                "{}: ss mismatch at count = {}",
                set.name(),
                index
            );

            // 3. Decapsulation (deterministic, no PRNG involved)
            let ss1 = crypto_kem_dec(p, &hash, &ct, &sk).unwrap();
            assert_eq!(
                &*ss1,
                &*ss,
                "{}: decapsulated ss mismatch at count = {}",
                set.name(),
                index
            );
            let expanded = crate::api::Hqc::new(set, &hash)
                .expand_decapsulation_key(&sk)
                .unwrap();
            let mut expanded_ss = [0; 32];
            expanded.decapsulate(&mut expanded_ss, &ct).unwrap();
            assert_eq!(expanded_ss.as_slice(), v.ss);
        }
    }
}
