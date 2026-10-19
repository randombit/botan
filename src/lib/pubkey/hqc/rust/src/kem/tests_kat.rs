use crate::kem::*;
use crate::parameters::*;
use crate::test_support::{callbacks, provider};
use crate::testvectors::nist_rng::NistRng;

/// Decodes a hex string (e.g. "DEADBEEF") into bytes.
fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("invalid hex digit"))
        .collect()
}

/// A single Known Answer Test vector from a `.rsp` file.
#[derive(Debug, Clone)]
pub struct KatVector {
    pub count: u32,
    pub seed: Vec<u8>, // 48 bytes
    pub pk: Vec<u8>,   // CRYPTO_PUBLICKEYBYTES
    pub sk: Vec<u8>,   // CRYPTO_SECRETKEYBYTES
    pub ct: Vec<u8>,   // CRYPTO_CIPHERTEXTBYTES
    pub ss: Vec<u8>,   // CRYPTO_BYTES
}

use std::fs::File;
use std::io::{self, BufRead, BufReader};

/// Extracts the hex value following a given field prefix (e.g. "seed = ").
///
/// Returns `None` if the line does not start with `prefix`.
fn parse_field(line: &str, prefix: &str) -> Option<Vec<u8>> {
    line.strip_prefix(prefix).map(|hex| hex_decode(hex.trim()))
}

/// Parses a PQCgenKAT-style `.rsp` file into a list of `KatVector`s.
///
/// Mirrors the field-by-field structure produced by `fprintBstr`/`fprintf`
/// in the C reference generator (`count`, `seed`, `pk`, `sk`, `ct`, `ss`,
/// separated by blank lines).
///
/// # Arguments
/// * `path` - Path to the `.rsp` KAT file.
///
/// # Returns
/// A vector of parsed `KatVector`s, one per `count = N` block.
pub fn parse_kat_file(path: &str) -> io::Result<Vec<KatVector>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let mut vectors = Vec::new();

    let mut count: Option<u32> = None;
    let mut seed: Option<Vec<u8>> = None;
    let mut pk: Option<Vec<u8>> = None;
    let mut sk: Option<Vec<u8>> = None;
    let mut ct: Option<Vec<u8>> = None;

    for line in reader.lines() {
        let line = line?;
        let line = line.trim_end();

        if line.is_empty() {
            continue; // blank line — separator between entries; state carried by field presence
        }

        if let Some(rest) = line.strip_prefix("count = ") {
            count = rest.trim().parse().ok();
        } else if let Some(v) = parse_field(line, "seed = ") {
            seed = Some(v);
        } else if let Some(v) = parse_field(line, "pk = ") {
            pk = Some(v);
        } else if let Some(v) = parse_field(line, "sk = ") {
            sk = Some(v);
        } else if let Some(v) = parse_field(line, "ct = ") {
            ct = Some(v);
        } else if let Some(v) = parse_field(line, "ss = ") {
            // "ss" is the last field per entry — emit a complete vector
            if let (Some(c), Some(s), Some(p), Some(k), Some(t)) =
                (count.take(), seed.take(), pk.take(), sk.take(), ct.take())
            {
                vectors.push(KatVector {
                    count: c,
                    seed: s,
                    pk: p,
                    sk: k,
                    ct: t,
                    ss: v,
                });
            }
        }
    }

    Ok(vectors)
}

/// Runs the full HQC-KEM KAT suite against the reference `.rsp` files, for
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
    for set in HqcParameterSet::ALL {
        let p = set.params();

        // The reference names each file after the decapsulation key size,
        // which `HqcParameters` supplies directly.
        let path = format!(
            "{}/kats/ref/hqc-{}/PQCkemKAT_{}.rsp",
            env!("CARGO_MANIFEST_DIR"),
            set.nist_level(),
            p.dk_bytes
        );
        let vectors = parse_kat_file(&path)
            .unwrap_or_else(|e| panic!("failed to read KAT file {}: {}", path, e));

        assert_eq!(vectors.len(), 100, "{}: incomplete KAT corpus", set.name());

        for (index, v) in vectors.iter().enumerate() {
            assert_eq!(v.count as usize, index);
            assert_eq!(v.seed.len(), 48);
            assert_eq!(v.pk.len(), p.ek_bytes);
            assert_eq!(v.sk.len(), p.dk_bytes);
            assert_eq!(v.ct.len(), p.ct_bytes);
            assert_eq!(v.ss.len(), p.ss_bytes);
            // Single PRNG stream reused for both keypair and enc, as in the C KAT driver
            let mut reader = NistRng::new(v.seed.as_slice().try_into().unwrap());

            // 1. Keypair generation
            let mut pk = vec![0u8; p.ek_bytes];
            let mut sk = vec![0u8; p.dk_bytes];
            crypto_kem_keypair(p, &hash, &mut reader, &mut pk, &mut sk).unwrap();
            assert_eq!(
                pk,
                v.pk,
                "{}: pk mismatch at count = {}",
                set.name(),
                v.count
            );
            assert_eq!(
                sk,
                v.sk,
                "{}: sk mismatch at count = {}",
                set.name(),
                v.count
            );

            // 2. Encapsulation (continues the same PRNG stream)
            let (ct, ss) = crypto_kem_enc(p, &hash, &mut reader, &pk).unwrap();
            assert_eq!(
                ct,
                v.ct,
                "{}: ct mismatch at count = {}",
                set.name(),
                v.count
            );
            assert_eq!(
                &*ss,
                &v.ss[..],
                "{}: ss mismatch at count = {}",
                set.name(),
                v.count
            );

            // 3. Decapsulation (deterministic, no PRNG involved)
            let ss1 = crypto_kem_dec(p, &hash, &ct, &sk).unwrap();
            assert_eq!(
                &*ss1,
                &*ss,
                "{}: decapsulated ss mismatch at count = {}",
                set.name(),
                v.count
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
