> Botan integration: this crate is maintained as native Botan source under
> `src/lib/pubkey/hqc/rust`, imported from
> `https://github.com/falko-strenzke/Rust-HQC-fork.git` at revision
> `631414c66bba73d91073f3ab9f5c5c8951c634d5`.
> HQC is disabled by default. From Botan's root, configure with
> `./configure.py --enable-modules=hqc` and build normally. Botan compiles the
> crate directly with `rustc`; Cargo is needed only for standalone crate tests.
> The commands below describe standalone crate development.

# Rust-HQC

A Rust implementation of **HQC**, the code-based key encapsulation mechanism
selected by NIST as a backup to ML-KEM. Ported from the [reference C
implementation](https://gitlab.com/pqc-hqc/hqc.git) and intended for integration
into [Botan](https://botan.randombit.net/). Seed expansion uses variable-time
rejection sampling; see the timing notes below before integrating decapsulation.

In contrast to the C reference implementation, the parameter set, HQC-1, HQC-3,
or HQC-5, is selected **at run time**. So, one binary library serves all three.

The Rust port tracks HQC `next-release` reference commit
`71090d4679837a0de1e6946284818184994d952a`, superseding the parameters and
encoding in the **2025-08-22** specification (v5.0.0). It uses the salted
Fujisaki–Okamoto transform with implicit rejection.

This revision changes sampling weights, GF(256) representation, Reed–Muller
bit ordering, XOF domain separation, and secret-key serialization. It is
**incompatible with previous keys and ciphertexts**, even though public-key
and ciphertext lengths are unchanged. All serialized decapsulation keys are
now **32-byte master seeds**.

The `main`-branch has **no C dependency** and serves as the preparation for the
Botan integration. Differential tests against the C reference live on the
`ffi-testing-update` branch (the previous revision remains on `ffi-testing`).

## HQC Parameter Sets

|       | NIST level  |      n |    ek | dk |     ct | ss |
|-------|-------------|-------:|------:|---:|-------:|---:|
| HQC-1 | 1 (128-bit) | 17 669 | 2 241 | 32 |  4 433 | 32 |
| HQC-3 | 3 (192-bit) | 35 851 | 4 514 | 32 |  8 978 | 32 |
| HQC-5 | 5 (256-bit) | 57 637 | 7 237 | 32 | 14 421 | 32 |

Sizes in bytes, matching the tracked reference revision. They are derived in
`parameters.rs` and pinned there by compile-time assertions.

## Modules

| Module        | Purpose                                                                                                                                                      |
|---------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `api`         | **Public API.** `Hqc` handle, caller-provided buffers, `Result` returns, length accessors. Start here.                                                       |
| `capi`        | **C ABI** for Botan. Stateless `extern "C"` entry points, `catch_unwind` on every one, integer error codes. Declared for C in `include/hqc_c_api.h`.        |
| `hash`        | Provider traits (`HashProvider`, `SecureAllocator`, `Callbacks`) and `CallbackProvider`, the implementation over the C callbacks.                       |
| `secmem`      | Secret memory: `SecureBuffer` (provider memory), `SecretVec` (heap, volatile zeroize on drop), `zeroize_slice`.                                          |
| `error`       | `HqcError` and the crate's `Result` alias.                                                                                                                   |
| `nist`        | The NIST `api.h` constants (`CRYPTO_SECRETKEYBYTES` …), one module per parameter set, pinned against the reference.                                          |
| `parameters`  | `HqcParameterSet`, `HqcParameters`, and the three `const` instances. Everything parameter-dependent originates here, including the generated α-power tables. |
| `kem`         | HQC-KEM: keygen, encapsulation, decapsulation. The salted FO transform with implicit rejection.                                                              |
| `pke`         | HQC-PKE underneath the KEM: keygen, encrypt, decrypt.                                                                                                        |
| `code`        | The concatenated code: `reed_solomon` (external, over GF(256)) and `reed_muller` (internal, duplicated RM(1,7)).                                             |
| `gf`          | GF(2⁸) arithmetic. Parameter-independent — identical for all three sets.                                                                                     |
| `fft`         | Additive FFT used to find the roots of the error-locator polynomial.                                                                                         |
| `gf2x`        | Polynomial multiplication mod X<sup>n</sup>−1: Karatsuba plus reduction.                                                                                     |
| `vector`      | Fixed-weight and uniform vector sampling, constant-time vector operations.                                                                                   |
| `parsing`     | Serialisation of keys and ciphertexts to and from byte strings.                                                                                              |
| `symmetric`   | SHAKE256 XOF and the domain-separated hashes G, H, I, J.                                                                                                     |
| `testvectors` | *(test only)* Parser for the reference's `intermediates_values` traces.                                                                                      |

## Run the Tests

```sh
cd src/lib/pubkey/hqc/rust
cargo test -j<NUM_THREADS>
```

With verbosity:
```
> RUST_BACKTRACE=1 cargo test -j<NUM_THREADS> -- --show-output
```

What they cover:

| Suite                        | What it checks                                                                                                                                                                                  |
|------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `kem::tests_kat`             | The full 100-vector NIST KAT suite **for all three parameter sets**, against the vendored `PQCkemKAT_32.rsp` files using a Rust NIST AES-256 CTR_DRBG. The strongest single check in the crate. |
| `testvectors::intermediates` | The reference's own trace of every internal value through keygen/encaps/decaps — `x`, `y`, `h`, `s`, `r1`, `r2`, `e`, `theta`, `c_kem`, `K` — for all three sets.                               |
| `parameters::tests`          | Regenerates the alpha-power tables from GF(2^8) arithmetic; checks ordering and RS generator polynomials.                                                                                       |
| `api::tests`                 | Round-trip per parameter set, `dk` equals the seed, `public_key` reproduces `ek`; randomness, buffer and key length errors; cross-parameter-set rejection.                                       |
| `capi::tests`                | The C ABI round-trip and its error codes; pins the enumerators in `include/hqc_c_api.h` against the Rust constants.                                                                              |
| `nist::tests`                | Static `CRYPTO_*` constants against the runtime accessors.                                                                                                                                      |
| `vector::tests`              | `barrett_reduce` against `x % n` over the full 24-bit sampler domain, all three sets.                                                                                                           |

These tests use vendored data and Rust dependencies only; no C reference,
CMake, or OpenSSL is needed. AES is a test-only dependency.

Useful subsets:

```sh
cargo test test_hqc_kem_kat_vectors   # KAT suite, all three sets
cargo test testvectors                # internal-value traces
cargo test --release                  # KATs are ~10x faster
```

## Using the Crate from Rust

```rust
use rust_hqc::api::Hqc;
use rust_hqc::parameters::HqcParameterSet;

// `cb` implements `hash::Callbacks` (SHA3, SHAKE256, secure memory)
let hqc = Hqc::new(HqcParameterSet::Hqc3, &cb);

// The API is derandomized: the caller draws exactly the bytes the
// specification's KeyGen and Encaps take from the RNG.
let seed = rng.random_bytes(hqc.keypair_randomness_len());        // 32: the master seed = dk
let mut ek = vec![0u8; hqc.encapsulation_key_len()];
let mut dk = vec![0u8; hqc.decapsulation_key_len()];
hqc.keypair(&mut ek, &mut dk, &seed)?;

let randomness = rng.random_bytes(hqc.encapsulation_randomness_len()); // m || salt
let mut ct = vec![0u8; hqc.ciphertext_len()];
let mut ss = vec![0u8; hqc.shared_secret_len()];
hqc.encapsulate(&mut ct, &mut ss, &ek, &randomness)?;

let mut ss2 = vec![0u8; hqc.shared_secret_len()];
hqc.decapsulate(&mut ss2, &ct, &dk)?;
assert_eq!(ss, ss2);
```

### Expanded keys and timing

Key generation and seed-key decapsulation use variable-time rejection
sampling to reproduce the reference's exact seed mapping. For repeated Rust
decapsulation, expand the seed once and retain the parameter-bound key:

```rust
let expanded = hqc.expand_decapsulation_key(&dk)?;
expanded.decapsulate(&mut ss2, &ct)?;
assert_eq!(ss, ss2);
```

Expansion remains variable-time. The expanded path avoids secret-dependent
sampling during repeated decapsulation and zeroizes cached secret buffers on
drop. Compiler and target timing properties still require separate validation.

## Integrating with Botan

### 1. Build a static library

```toml
[lib]
crate-type = ["lib", "staticlib"]
```

```sh
cargo build --release          # target/release/librust_hqc.a
```

### 2. The C ABI

Six functions, defined in `src/capi.rs` and declared for C in
`include/hqc_c_api.h`. The header is named to avoid a clash with a
Botan-internal `hqc.h`. **Stateless** — the parameter set is a `uint8_t`
discriminant (1, 3 or 5; `HQC_PARAM_SET_1/3/5` in the header) and the hash
callbacks are passed on every call. There is no handle to create or free,
because `HqcParameters` instances are `'static`; a `Botan::HQC_PublicKey`
needs to hold nothing beyond the enum.

```c
int32_t hqc_sizes     (uint8_t ps, size_t *ek, size_t *dk, size_t *ct, size_t *ss);
int32_t hqc_randomness_lengths(uint8_t ps, size_t *keypair, size_t *encaps);
int32_t hqc_keypair   (uint8_t ps, const hqc_callbacks_t *cb,
                                   uint8_t *ek, size_t ek_len,
                                   uint8_t *dk, size_t dk_len,
                             const uint8_t *seed, size_t seed_len);
int32_t hqc_public_key(uint8_t ps, const hqc_callbacks_t *cb,
                                   uint8_t *ek, size_t ek_len,
                             const uint8_t *dk, size_t dk_len);
int32_t hqc_encaps    (uint8_t ps, const hqc_callbacks_t *cb,
                                   uint8_t *ct, size_t ct_len,
                                   uint8_t *ss, size_t ss_len,
                             const uint8_t *ek, size_t ek_len,
                             const uint8_t *randomness, size_t randomness_len);
int32_t hqc_decaps    (uint8_t ps, const hqc_callbacks_t *cb,
                                   uint8_t *ss, size_t ss_len,
                             const uint8_t *ct, size_t ct_len,
                             const uint8_t *dk, size_t dk_len);
```

**Randomness.** Key generation and encapsulation are *derandomized*: the
caller passes exactly the bytes the specification draws from the random
number generator, and the crate does not expand them. `hqc_keypair` takes the
32-byte master seed, which *is* the decapsulation key (`dk` receives a copy);
`hqc_encaps` takes the message `m` (16, 24 or 32 bytes) followed by the
16-byte salt. `hqc_randomness_lengths` reports both lengths. A caller that
feeds the output of the NIST KAT DRBG, as Botan's PQC KAT tests do, reproduces
the reference known answer tests for key generation, encapsulation and
decapsulation.

**Keys.** `hqc_sizes` returns `dk = 32` for every parameter set, the stored
private key is the master seed, and `hqc_public_key` derives the encapsulation
key from it when a private key is loaded. The stateless `hqc_decaps` expands
the seed on each call; like key generation this includes variable-time
rejection sampling. The cached expanded-key API is currently available only
through Rust.

**Hash callbacks.** The crate contains no hash function. `hqc_callbacks_t`
carries a `version` (`HQC_CALLBACKS_VERSION`, currently 2) and a `hash`
section with a `ctx` pointer (passed unchanged to every callback) and five
functions: `sha3_256` and `sha3_512` are one-shot over an array of
`hqc_buffer_t` parts that are hashed as if concatenated; `shake256_init`
absorbs such parts and returns an opaque `hqc_xof_t*`, `shake256_squeeze`
produces the next bytes of its output stream, and `shake256_free` releases it.
Callbacks return 0 on success. Botan implements them with its own
`SHA-3(256)`, `SHA-3(512)` and `SHAKE-256` objects; the crate's tests implement
them with the `sha3` crate (`src/test_support.rs`, a dev-dependency only), so
`cargo test` exercises the same path as the Botan build. The domain-separation
bytes of HQC stay inside the crate; a provider knows nothing about HQC.

**Secure memory callbacks.** The `alloc` section (version 2) carries its own
`ctx` and two functions: `secure_alloc(ctx, len)` returns `len` bytes of
zero-filled memory aligned for any integer type up to 8 bytes (NULL on
failure, reported as `HQC_ERR_ALLOC`), and `secure_free(ctx, ptr, len)` scrubs
and releases it. The crate keeps key material and per-message secrets there:
seeds, σ, m, θ, K, dk_pke, the secret vectors x, y, r1, r2, e, and the
sampler's index list (`src/secmem.rs`, `SecureBuffer`). Botan serves these
from its mlock'ed pool for requests up to 256 bytes and from `calloc` above,
and scrubs them on release. Arithmetic and decoder temporaries stay on the
Rust heap and are zeroized with volatile writes on drop (`SecretVec`); the
crate has no runtime dependency on the `zeroize` crate any more.

Return codes. The header names them in `enum hqc_error_t`, in the style of
Botan's own `ffi.h`; the functions return a plain `int32_t`, since C does not
fix an enum's underlying type:

|      |                              |                                                          |
|------|------------------------------|----------------------------------------------------------|
| `0`  | `HQC_OK`                     | success                                                  |
| `-1` | `HQC_ERR_BUFFER_LENGTH`      | buffer length wrong for the parameter set                |
| `-2` | `HQC_ERR_INVALID_KEY`        | invalid key                                              |
| `-3` | `HQC_ERR_INVALID_CIPHERTEXT` | invalid ciphertext                                       |
| `-4` | `HQC_ERR_RANDOMNESS`         | randomness failure                                       |
| `-5` | `HQC_ERR_INTERNAL`           | internal error, or a caught panic                        |
| `-6` | `HQC_ERR_BAD_PARAMETER_SET`  | parameter set not 1, 3 or 5                              |
| `-7` | `HQC_ERR_NULL_POINTER`       | null pointer                                             |
| `-8` | `HQC_ERR_HASH_CALLBACK`      | a hash callback returned non-zero                        |
| `-9` | `HQC_ERR_BAD_CALLBACKS`      | callback struct null, member null, or unsupported version |
| `-10`| `HQC_ERR_ALLOC`              | the secure_alloc callback returned NULL                  |

A test in `capi::tests` reads the header and checks every enumerator and the
layout of the callback struct against the Rust definitions, so the two cannot
drift apart unnoticed.

### 3. Mapping onto Botan

| Botan                                             | Here                                      |
|---------------------------------------------------|-------------------------------------------|
| `Public_Key::key_length()`                        | `hqc_sizes` -> `ek`                       |
| `KEM_Encryption::encapsulated_key_length()`       | `hqc_sizes` -> `ct`                       |
| `KEM_Encryption::shared_key_length()`             | `hqc_sizes` -> `ss`                       |
| `HQC_PrivateKey(rng, mode)`                       | `hqc_keypair` (32 bytes from `rng`)       |
| `HQC_PrivateKey(span, mode)`                      | `hqc_public_key`                          |
| `KEM_Encryption::kem_encrypt(span, span, rng, …)` | `hqc_encaps` (`m \|\| salt` from `rng`) |
| `KEM_Decryption::kem_decrypt(span, span, …)`      | `hqc_decaps`                              |

Botan's `std::span` maps directly: `span.data()` and `span.size()` are the
pointer/length pairs above. Nothing is allocated on the Rust side and returned
across the boundary.

### 4. Four Properties to Preserve

**Never unwind into C++.** Every entry point already wraps its work in
`catch_unwind` and converts a panic to `-5`. Do not add an FFI function that
bypasses that.

**`hqc_decaps` never reports a decryption failure.** HQC uses the FO transform
with implicit rejection: an invalid ciphertext yields a pseudo-random shared
secret derived from the rejection key, and reporting it would hand an attacker
the oracle that construction exists to remove. A non-zero return means the
*inputs were structurally wrong* — wrong length, null pointer, bad parameter
set, unusable callbacks — never "decryption failed". Do not "improve" this by
adding a verification failure code.

**Every XOF state is released.** The crate wraps each `hqc_xof_t*` it obtains
from `shake256_init` in a type whose `Drop` calls `shake256_free`, so the
provider gets every state back, also when a later callback fails or a panic is
caught. A provider must never free a state itself.

**The crate never zeroizes provider memory itself.** Buffers from
`secure_alloc` are returned through `secure_free` with their exact length and
scrubbed by the provider; the crate does not write zeros into them first, so
there is no double zeroization. Conversely the provider must never free a
buffer the crate has not returned, and the crate never hands provider memory
to the caller.

### 5. Smoke Test

`botan_abi_smoketest.c` includes `hqc_c_api.h`, links the static
library and exercises the structural checks of the ABI from plain C (sizes,
parameter-set and callback validation, null pointers). Plain C has no SHA3 at
hand, so the round trip through real callbacks is left to `cargo test` and to
Botan's test suite.

```sh
gcc -O2 -Iinclude botan_abi_smoketest.c -o smoketest \
    -L target/release -lrust_hqc -lpthread -ldl -lm
./smoketest
```

```
HQC-1  ek=2241 dk=32 ct=4433 ss=32  randomness: keypair=32 encaps=32
HQC-3  ek=4514 dk=32 ct=8978 ss=32  randomness: keypair=32 encaps=40
HQC-5  ek=7237 dk=32 ct=14421 ss=32  randomness: keypair=32 encaps=48
error paths:
  ...
```

### The Botan side

Botan's opt-in module `hqc` (`src/lib/pubkey/hqc/`, algorithm name `HQCr4`)
wraps this C ABI in `hqc_ffi.cpp`, implements the callbacks with Botan's
SHA-3/SHAKE-256 objects and secure allocator, and runs the reference KATs
through its generic PQC KEM KAT test.

## Relationship to the FFI testing branches

`main` contains the Rust library, vendored KATs and traces, and the Botan ABI
smoke test. It has no C reference submodule, reference build script, or
reference differential-test files. The optional smoke test is a C consumer
of the Rust static library, not a dependency of the crate.

`ffi-testing-update` carries the C reference and differential tests for the
tracked revision; `ffi-testing` retains the previous revision. The reserved
`ref-ffi` feature and gated module declarations remain for those branches,
as in the original split. Do not enable `ref-ffi` on `main`.

This integration brings the library changes and updated test vectors from
`ffi-testing-update` onto `main` while excluding its C test infrastructure.
For future development, make library changes on `main` and carry them forward
to the testing branch. Any integration back must preserve this separation.
