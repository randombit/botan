//! Parser for the reference implementation's `intermediates_values` files.
//!
//! One such file ships per parameter set under `kats/<arch>/hqc-<n>/`. Each is
//! a single trace through KEYGEN, ENCAPS and DECAPS recording every value on
//! the data path as hex.
//!
//! This is the backbone of reference testing **without linking any C**: it
//! pins the whole internal data flow for all three parameter sets, where the
//! `.rsp` KAT files pin only the public inputs and outputs. It is therefore
//! the coverage that survives onto the `main` branch, which has no submodule.
//!
//! Labels repeat across sections (`h` and `s` appear in all three), so every
//! lookup is section-scoped.

use crate::parameters::HqcParameterSet;
use std::collections::HashMap;
use std::fmt;

/// The three sections of an `intermediates_values` file.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Stage {
    Keygen,
    Encaps,
    Decaps,
}

impl Stage {
    fn from_header(line: &str) -> Option<Self> {
        match line.trim().trim_matches('#').trim() {
            "KEYGEN" => Some(Self::Keygen),
            "ENCAPS" => Some(Self::Encaps),
            "DECAPS" => Some(Self::Decaps),
            _ => None,
        }
    }
}

impl fmt::Display for Stage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Keygen => "KEYGEN",
            Self::Encaps => "ENCAPS",
            Self::Decaps => "DECAPS",
        })
    }
}

/// A parsed intermediates trace.
pub struct Intermediates {
    set: HqcParameterSet,
    values: HashMap<(Stage, String), Vec<u8>>,
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.is_empty() || s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

impl Intermediates {
    /// Loads the trace for `set` from the reference `ref` implementation.
    ///
    /// Anchored to `CARGO_MANIFEST_DIR`, not the process working directory:
    /// `cargo test` happens to run from the package root, but nothing
    /// guarantees it and a wrong-directory failure is confusing to diagnose.
    pub fn load(set: HqcParameterSet) -> Self {
        Self::load_arch(set, "ref")
    }

    /// Loads the trace for `set` from a named architecture directory
    /// (`"ref"` or `"x86_64/avx256"`).
    pub fn load_arch(set: HqcParameterSet, arch: &str) -> Self {
        let path = format!(
            "{}/kats/{arch}/hqc-{}/intermediates_values",
            env!("CARGO_MANIFEST_DIR"),
            set.nist_level()
        );
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"));
        Self::parse(set, &text)
    }

    /// Parses a trace.
    ///
    /// Lines are either a `### SECTION ###` header or a `label: hexdigits`
    /// pair. The banner and the parameter summary are skipped: a label is
    /// accepted only if it is a lowercase identifier and its value decodes as
    /// hex, which rejects `N: 17669` and similar without special-casing.
    /// A label repeated within a section keeps the first occurrence, matching
    /// the reference's emission order.
    pub fn parse(set: HqcParameterSet, text: &str) -> Self {
        let mut values = HashMap::new();
        let mut stage = None;

        for line in text.lines() {
            let line = line.trim();

            if line.starts_with("###") {
                if let Some(s) = Stage::from_header(line) {
                    stage = Some(s);
                }
                continue;
            }

            let Some(stage) = stage else { continue };
            let Some((label, rest)) = line.split_once(':') else {
                continue;
            };
            if label.is_empty()
                || !label
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
            {
                continue;
            }
            let Some(bytes) = hex_decode(rest) else {
                continue;
            };

            values.entry((stage, label.to_string())).or_insert(bytes);
        }

        assert!(
            !values.is_empty(),
            "no values parsed for {}; file format may have changed",
            set.name()
        );
        Self { set, values }
    }

    /// Returns the recorded value, panicking with a useful message if absent.
    pub fn get(&self, stage: Stage, label: &str) -> &[u8] {
        self.values
            .get(&(stage, label.to_string()))
            .map(Vec::as_slice)
            .unwrap_or_else(|| {
                panic!(
                    "{}: no `{label}` in {stage}; present: {:?}",
                    self.set.name(),
                    self.labels(stage)
                )
            })
    }

    /// Asserts that `actual` matches the recorded value.
    ///
    /// Reports the first differing byte rather than dumping two multi-kilobyte
    /// hex blobs, which is what a bare `assert_eq!` would do here.
    pub fn check(&self, stage: Stage, label: &str, actual: &[u8]) {
        let expected = self.get(stage, label);
        if expected == actual {
            return;
        }
        assert_eq!(
            actual.len(),
            expected.len(),
            "{}/{stage}/{label}: length mismatch",
            self.set.name()
        );
        let i = expected
            .iter()
            .zip(actual)
            .position(|(a, b)| a != b)
            .expect("equal lengths but slices differ");
        panic!(
            "{}/{stage}/{label}: first difference at byte {i} of {}: got {:#04x}, expected {:#04x}",
            self.set.name(),
            expected.len(),
            actual[i],
            expected[i]
        );
    }

    /// Words of a recorded value, for comparing against `[u64]` buffers.
    pub fn get_words(&self, stage: Stage, label: &str) -> Vec<u64> {
        let b = self.get(stage, label);
        let mut w = vec![0u64; b.len().div_ceil(8)];
        for (i, chunk) in b.chunks(8).enumerate() {
            let mut buf = [0u8; 8];
            buf[..chunk.len()].copy_from_slice(chunk);
            w[i] = u64::from_le_bytes(buf);
        }
        w
    }

    /// Labels present in a stage, sorted.
    pub fn labels(&self, stage: Stage) -> Vec<&str> {
        let mut v: Vec<&str> = self
            .values
            .keys()
            .filter(|(s, _)| *s == stage)
            .map(|(_, l)| l.as_str())
            .collect();
        v.sort_unstable();
        v
    }

    /// Number of distinct (stage, label) pairs.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// True when nothing was parsed.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parameters::SEED_BYTES;

    /// Every parameter set's trace parses, and the recorded values have the
    /// sizes the parameters predict. This is a self-check on the parser and
    /// on `HqcParameters` at once: a wrong `vec_n_size_bytes` shows up here.
    #[test]
    fn traces_parse_with_expected_sizes() {
        for set in HqcParameterSet::ALL {
            let p = set.params();
            let im = Intermediates::load(set);

            assert_eq!(im.get(Stage::Keygen, "seed_dk").len(), SEED_BYTES);
            assert_eq!(im.get(Stage::Keygen, "seed_ek").len(), SEED_BYTES);
            assert_eq!(im.get(Stage::Keygen, "seed_kem").len(), SEED_BYTES);
            assert_eq!(im.get(Stage::Decaps, "sigma").len(), p.security_bytes);

            for label in ["x", "y", "h", "s"] {
                assert_eq!(
                    im.get(Stage::Keygen, label).len(),
                    p.vec_n_size_bytes,
                    "{}/{label}",
                    set.name()
                );
            }

            assert_eq!(im.get(Stage::Encaps, "ek_kem").len(), p.ek_bytes);
            assert_eq!(im.get(Stage::Encaps, "c_kem").len(), p.ct_bytes);
            assert_eq!(im.get(Stage::Encaps, "m").len(), p.security_bytes);
            assert_eq!(im.get(Stage::Encaps, "salt").len(), 16);
            assert_eq!(im.get(Stage::Decaps, "m_prime").len(), p.security_bytes);
        }
    }

    /// The secret vectors have exactly the Hamming weight the parameter set
    /// specifies. Independent of any Rust implementation code.
    #[test]
    fn recorded_vectors_have_specified_weights() {
        for set in HqcParameterSet::ALL {
            let p = set.params();
            let im = Intermediates::load(set);

            for (stage, label, want) in [
                (Stage::Keygen, "x", p.omega),
                (Stage::Keygen, "y", p.omega),
                (Stage::Encaps, "r1", p.omega_r),
                (Stage::Encaps, "r2", p.omega_r),
                (Stage::Encaps, "e", p.omega_e),
            ] {
                let w: u32 = im.get(stage, label).iter().map(|b| b.count_ones()).sum();
                assert_eq!(w as usize, want, "{}/{stage}/{label}", set.name());
            }
        }
    }

    /// Decaps must recover the message and shared secret from encaps.
    #[test]
    fn decaps_recovers_encaps_values() {
        for set in HqcParameterSet::ALL {
            let im = Intermediates::load(set);
            assert_eq!(
                im.get(Stage::Encaps, "m"),
                im.get(Stage::Decaps, "m_prime"),
                "{}",
                set.name()
            );
            assert_eq!(
                im.get(Stage::Encaps, "theta"),
                im.get(Stage::Decaps, "theta_prime"),
                "{}",
                set.name()
            );
        }
    }
}
