:orphan:

Release Notes: 0.7.0 to 1.11.34
========================================

Version 1.10.17, 2017-10-02
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Address a side channel affecting modular exponentiation. An attacker
  capable of a local or cross-VM cache analysis attack may be able
  to recover bits of secret exponents as used in RSA, DH, etc.
  CVE-2017-14737

* Workaround a miscompilation bug in GCC 7 on x86-32 affecting GOST-34.11
  hash function. (GH #1192 #1148 #882)

* Add SecureVector::data() function which returns the start of the
  buffer. This makes it slightly simpler to support both 1.10 and 2.x
  APIs in the same codebase.

* When compiled by a C++11 (or later) compiler, a template typedef of
  SecureVector, secure_vector, is added. In 2.x this class is a
  std::vector with a custom allocator, so has a somewhat different
  interface than SecureVector in 1.10. But this makes it slightly
  simpler to support both 1.10 and 2.x APIs in the same codebase.

* Fix a bug that prevented `configure.py` from running under Python3

* Botan 1.10.x does not support the OpenSSL 1.1 API. Now the build
  will `#error` if OpenSSL 1.1 is detected. Avoid `--with-openssl`
  if compiling against 1.1 or later. (GH #753)

* Import patches from Debian adding basic support for building on
  aarch64, ppc64le, or1k, and mipsn32 platforms.

Version 1.10.16, 2017-04-04
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Fix a bug in X509 DN string comparisons that could result in out of bound
  reads. This could result in information leakage, denial of service, or
  potentially incorrect certificate validation results. (CVE-2017-2801)

* Avoid throwing during a destructor since this is undefined in C++11
  and rarely a good idea. (GH #930)

Version 1.10.15, 2017-01-12
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Fix a bug causing modular exponentiations done modulo even numbers
  to almost always be incorrect, unless the values were small. This
  bug is not known to affect any cryptographic operation in Botan. (GH #754)

* Avoid use of C++11 std::to_string in some code added in 1.10.14 (GH #747 #834)

Version 1.11.34, 2016-11-28
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Fix integer overflow during BER decoding, found by Falko Strenzke.
  This bug is not thought to be directly exploitable but upgrading ASAP
  is advised. (CVE-2016-9132)

* Add post-quantum signature scheme XMSS. Provides either 128 or 256 bit
  (post-quantum) security, with small public and private keys, fast
  verification, and reasonably small signatures (2500 bytes for 128-bit
  security). Signature generation is very slow, on the order of seconds. And
  very importantly the signature scheme is stateful: each leaf index must only
  be used once, or all security is lost. In the appropriate system where
  signatures are rarely generated (such as code signing) XMSS makes an excellent
  choice. (GH #717 #736)

* Add support for CECPQ1 TLS ciphersuites. These use a combination of x25519
  ECDH and NewHope to provide post-quantum security. The ciphersuites are not
  IETF standard, but is compatible with BoringSSL. (GH #729)

* Add support for client-side OCSP stapling to TLS. (GH #738)

* Previously both public and private keys performed automatic self testing after
  generation or loading. However this often caused unexpected application
  performance problems, and so has been removed. Instead applications must call
  check_key explicitly. (GH #704)

* Fix TLS session resumption bugs which caused resumption failures if an
  application used a single session cache for both TLS and DTLS. (GH #688)

* Add SHAKE-128 and SHAKE-256 XOFs as hash functions supporting paramaterized
  output lengths.

* Add MessageAuthenticationCode::start_msg interface, for MACs which require or
  can use a nonce (GH #691)

* Add GMAC, a MAC based on GCM (GH #488 / #691)

* Add ESP block cipher padding from RFC 4304. GH #724

* Incompatible change to HKDF: previously the HKDF type in Botan was only the
  Expand half of HKDF. Now HKDF is the full Extract-then-Expand KDF, and
  HKDF_Extract and HKDF_Expand are available. If you previously used HKDF, you
  must switch to using HKDF_Expand. (GH #723)

* Add Cipher_Mode::reset which resets message-specific state, allowing
  discarding state but allowing continued processing under the same key. (GH #552)

* The ability to add OIDs at runtime has been removed. This additionally removes
  a global lock which was acquired on each OID lookup. (GH #706)

* The default TLS policy now disables static RSA ciphersuites, all DSA
  ciphersuites, and the AES CCM-8 ciphersuites. Disabling static RSA by default
  protects servers from oracle attacks, as well as enforcing a forward secure
  ciphersuite. Some applications may be forced to re-enable RSA for interop
  reasons. DSA and CCM-8 are rarely used, and likely should not be negotiated
  outside of special circumstances.

* The default TLS policy now prefers ChaCha20Poly1305 cipher over any AES mode.

* The default TLS policy now orders ECC curve preferences in order by performance,
  with x25519 first, then P-256, then P-521, then the rest.

* Add a BSD sockets version of the HTTP client code used for OCSP. GH #699

* Export the public key workfactor functions (GH #734) and add tests for them.

* HMAC_DRBG allows configuring maximum number of bytes before reseed check (GH #690)

* Salsa20 now accepts a null IV as equivalent to an all-zero one (GH #697)

* Optimize ECKCDSA verification (GH #700 #701 #702)

* The deprecated RNGs HMAC_RNG and X9.31 RNG have been removed. Now the only
  userspace PRNG included in the library is HMAC_DRBG. (GH #692)

* The entropy sources for EGD and BeOS, as well as the Unix entropy source which
  executed processes to get statistical data have been removed. (GH #692)

* The openpgp module (which just implemented OpenPGP compatible base64 encoding
  and decoding, nothing else) has been removed.

* Added new configure.py argument `--optimize-for-size`. Currently just sets
  the flag for code size optimizations with the compiler, but may have other
  effects in the future.

* Fixed bug in Threaded_Fork causing incorrect computations (GH #695 #716)

* Add DSA deterministic parameter generation test from FIPS 186-3.

* Fix PKCS11_ECDSA_PrivateKey::check_key (GH #712)

* Fixed problems running configure.py outside of the base directory

* The BOTAN_ENTROPY_PROC_FS_PATH value in build.h was being ignored (GH #708)

* Add speed tests for ECGDSA and ECKCDSA (GH #696)

* Fix a crash in speed command for Salsa20 (GH #697)

* Allow a custom ECC curve to be specified at build time, for application or
  system specific curves. (GH #636 #710)

* Use NOMINMAX on Windows to avoid problems in amalgamation build. (GH #740)

* Add support to output bakefiles with new `configure.py` option `--with-bakefile`.
  (GH #360 #720)

* The function `zero_mem` has been renamed `secure_scrub_memory`

* More tests for pipe/filter (GH #689 #693), AEADs (GH #552), KDF::name (GH #727),

* Add a test suite for timing analysis for TLS CBC decryption, OAEP decryption,
  and PKCS #1 v1.5 decryption. These operations all have the feature that if an
  attacker can distinguish internal operations, such as through a variance in
  timing, they can use this oracle to decrypt arbitrary ciphertexts. GH #733

* Add a test suite for testing and fuzzing with TLS-Attacker, a tool for
  analyzing TLS libraries. (https://github.com/RUB-NDS/TLS-Attacker)

* Add a fuzzing framework. Supports fuzzing some APIs using AFL and libFuzzer.

* Added documentation for PKCS #11 (GH #725)

* The LibraryInitializer type is no longer needed and is now deprecated.

* The license and news files were moved from doc to the top level directory.
  There should not be any other visible change (eg, to the installed version)
  as a result of this move.

* Fixed some problems when running configure.py outside of the base directory,
  especially when using relative paths.

* Add (back) the Perl XS wrapper and sqlite encryption code.

Version 1.10.14, 2016-11-28
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* NOTE WELL: Botan 1.10.x is supported for security patches only until
  2017-12-31

* Fix integer overflow during BER decoding, found by Falko Strenzke.
  This bug is not thought to be directly exploitable but upgrading ASAP
  is advised. (CVE-2016-9132)

* Fix two cases where (in error situations) an exception would be
  thrown from a destructor, causing a call to std::terminate.

* When RC4 is disabled in the build, also prevent it from being
  included in the OpenSSL provider. (GH #638)

Version 1.11.33, 2016-10-26
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Avoid side channel during OAEP decryption. (CVE-2016-8871)

* A countermeasure for the Lucky13 timing attack against CBC-based TLS
  ciphersuites has been added. (GH #675)

* Added X25519-based key exchange for TLS (GH #673)

* Add Certificate_Store_In_SQL which supports storing certs, keys, and
  revocation information in a SQL database. Subclass Certificate_Store_In_SQLite
  specializes with support for SQLite3 databases. (GH #631)

* The Certificate_Store interface has been changed to deal with
  ``std::shared_ptrs`` instead of raw pointers (GH #471 #631)

* Add support for official SHA-3. Keccak-1600 was already supported
  but used different padding from FIPS 202. (GH #669)

* Add SHAKE-128 based stream cipher. (GH #669)

* NewHope key exchange now supports the SHA-256/AES-128-CTR scheme
  used by BoringSSL in addition to the SHA-3/SHAKE-128 parameters used
  by the reference implementation. (GH #669)

* Add support for the TLS Supported Point Formats Extension from RFC 4492. Adds
  ``TLS::Policy::use_ecc_point_compression`` policy option. If supported on both
  sides, ECC points can be sent in compressed format which saves a few bytes
  during the handshake. (GH #645)

* Fix entropy source selection bug on Windows, which caused the CryptoAPI
  entropy source to be not available under its normal name "win32_cryptoapi" but
  instead "dev_random". GH #644

* Accept read-only access to ``/dev/urandom``. System_RNG previously required
  read-write access, to allow applications to provide inputs to the system
  PRNG. But local security policies might only allow read-only access, as is the
  case with Ubuntu's AppArmor profile for applications in the Snappy binary
  format. If opening read/write fails, System_RNG silently backs down to
  read-only, in which case calls to ``add_entropy`` on that object will fail.
  (GH #647 #648)

* Fix use of Win32 CryptoAPI RNG as an entropy source, which was accidentally
  disabled due to empty list of acceptable providers being specified. Typically
  the library would fall back to gathering entropy from OS functions returning
  statistical information, but if this functionality was disabled in the build a
  ``PRNG_Unseeded`` exception would result. (GH #655)

* Add support for building the library as part of the IncludeOS unikernel.
  This included making filesystem and threading support optional. (GH #665)

* Added ISA annotations so that with GCC (all supported versions) and
  Clang (since 3.7) it is no longer required to compile amalgamation
  files with ABI specific flags such as ``-maes``. (GH #665)

* Internal cleanups to TLS CBC record handling. TLS CBC ciphersuites
  can now be disabled by disabling ``tls_cbc`` module. (GH #642 #659)

* Internal cleanups to the object lookup code eliminates most global locks and
  all use of static initializers (GH #668 #465)

* Avoid ``static_assert`` triggering under MSVC debug builds (GH #646)

* The antique PBKDF1 password hashing scheme is deprecated and will be
  removed in a future release. It was only used to support the equally
  ancient PBES1 private key encryption scheme, which was removed in 1.11.8.

* Added MSVC debug/checked iterator builds (GH #666 #667)

* Added Linux ppc64le cross compile target to Travis CI (GH #654)

* If RC4 is disabled, also disable it coming from the OpenSSL provider (GH #641)

* Add TLS message parsing tests (GH #640)

* Updated BSI policy to prohibit DES, HKDF, HMAC_RNG (GH #649)

* Documentation improvements (GH #660 #662 #663 #670)

Version 1.11.32, 2016-09-28
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Add support for the NewHope Ring-LWE key encapsulation algorithm. This scheme
  provides an estimated ~200 bit security level against a quantum attacker while
  also being very fast and requiring only modest message sizes of 1824 and 2048
  bytes for initiator and responder, resp. This version is tested as having
  bit-for-bit identical output as the reference implementation by the authors.

  Be warned that NewHope is still a very new scheme and may yet fall to analysis.
  For best assurance, NewHope should be used only in combination with another
  key exchange mechanism, such as ECDH.

* New TLS callbacks API. Instead of numerous std::function callbacks, the
  application passes an object implementing the TLS::Callbacks interface, which
  has virtual functions matching the previous callbacks (plus some extras).
  Full source compatability with previous versions is maintained for now, but
  the old interface is deprecated and will be removed in a future release.  The
  manual has been updated to reflect the changes. (GH #457 and #567)

* Add support for TLS Encrypt-then-MAC extension (GH #492 and #578), which fixes
  the known issues in the TLS CBC-HMAC construction.

* The format of the TLS session struct has changed (to support EtM), so old
  TLS session caches will be invalidated.

* How the library presents optimized algorithm implementations has changed.  For
  example with the algorithm AES-128, previously there were three BlockCipher
  classes AES_128, AES_128_SSSE3, and AES_128_NI which used (resp) a table-based
  implementation vulnerable to side channels, a constant time version using
  SSSE3 SIMD extensions on modern x86, and x86 AES-NI instructions. Using the
  correct version at runtime required using ``BlockCipher::create``. Now, only
  the class AES_128 is presented, and the best available version is always used
  based on CPUID checks. The tests have been extended to selectively disable
  CPUID bits to ensure all available versions are tested. (GH #477 #623)

  Removes API classes AES_128_NI, AES_192_NI, AES_256_NI, AES_128_SSSE3,
  AES_192_SSSE3 AES_256_SSSE3, IDEA_SSE2, Noekeon_SIMD, Serpent_SIMD,
  Threefish_512_AVX2, SHA_160_SSE2

* The deprecated algorithms Rabin-Williams, Nyberg-Rueppel, MARS, RC2, RC5, RC6,
  SAFER-SK, TEA, MD2, HAS-160, and RIPEMD-128 have been removed. (GH #580)

* A new Cipher_Mode interface ``process`` allows encryption/decryption of
  buffers without requiring copying into ``secure_vector`` first. (GH #516)

* Fix verification of self-issued certificates (GH #634)

* SSE2 optimizations for ChaCha, 60% faster on both Westmere and Skylake (GH #616)

* The HMAC_RNG constructor added in 1.11.31 that took both an RNG and an
  entropy source list ignored the entropy sources.

* The configure option ``--via-amalgamation`` was renamed to ``--amalgamation``.
  The configure option ``--gen-amalgamation`` was removed. It did generate
  amalgamations but build Botan without amalgamation. Users should migrate to
  ``--amalgamation``. (GH #621)

* DH keys did not automatically self-test after being generated, contrary to
  the current behavior for other key types.

* Add tests for TLS 1.2 PRF (GH #628)

Version 1.11.31, 2016-08-30
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Fix undefined behavior in Curve25519 on platforms without a native 128-bit
  integer type. This was known to produce incorrect results on 32-bit ARM
  under Clang. GH #532 (CVE-2016-6878)

* If X509_Certificate::allowed_usage was called with more than one Key_Usage
  set in the enum value, the function would return true if *any* of the allowed
  usages were set, instead of if *all* of the allowed usages are set.
  GH #591 (CVE-2016-6879)

* Incompatible changes in DLIES: Previously the input to the KDF was
  the concatenation of the (ephemeral) public key and the secret value
  derived by the key agreement operation. Now the input is only the
  secret value obtained by the key agreement operation. That's how it
  is specified in the original paper "DHIES: An encryption scheme
  based on Diffie-Hellman Problem" or in BSI technical guideline
  TR-02102-1 for example. In addition to the already present
  XOR-encrypion/decryption mode it's now possible to use DLIES with a
  block cipher.  Furthermore the order of the output was changed from
  {public key, tag, ciphertext} to {public key, ciphertext, tag}. Both
  modes are compatible with BouncyCastle.

* Add initial PKCS #11 support (GH #507). Currently includes a low level
  wrapper to all of PKCS #11 (p11.h) and high level code for RSA and ECDSA
  signatures and hardware RNG access.

* Add ECIES encryption scheme, compatible with BouncyCastle (GH #483)

* Add ECKCDSA signature algorithm (GH #504)

* Add KDF1 from ISO 18033 (GH #483)

* Add FRP256v1 curve (GH #551)

* Changes for userspace PRNGs HMAC_DRBG and HMAC_RNG (GH #520 and #593)

  These RNGs now derive from Stateful_RNG which handles issues like periodic
  reseeding and (on Unix) detecting use of fork. Previously these measures were
  included only in HMAC_RNG.

  Stateful_RNG allows reseeding from another RNG and/or a specified set of
  entropy sources. For example it is possible to configure a HMAC_DRBG to reseed
  using a PKCS #11 token RNG, the CPU's RDSEED instruction, and the system RNG
  but disabling all other entropy polls.

* AutoSeeded_RNG now uses NIST SP800-90a HMAC_DRBG(SHA-384). (GH #520)

* On Windows and Unix systems, the system PRNG is used as the sole reseeding
  source for a default AutoSeeded_RNG, completely skipping the standard entropy
  polling code. New constructors allow specifying the reseed RNG and/or entropy
  sources. (GH #520)

* The `hres_timer` entropy source module has been removed. Timestamp inputs to
  the RNG are now handled as additional_data inputs to HMAC_DRBG.

* Add RDRAND_RNG which directly exposes the CPU RNG (GH #543)

* Add PKCS #1 v1.5 id for SHA-512/256 (GH #554)

* Add X509_Time::to_std_timepoint (GH #560)

* Fix a bug in ANSI X9.23 padding mode, which returned one byte more
  than the given block size (GH #529).

* Fix bug in SipHash::clear, which did not reset all state (GH #547)

* Fixes for FreeBSD (GH #517) and OpenBSD (GH #523). The compiler defaults
  to Clang on FreeBSD now.

* SonarQube static analysis integration (GH #592)

* Switched Travis CI to Ubuntu 14.04 LTS (GH #592)

* Added ARM32, ARM64, PPC32, PPC64, and MinGW x86 cross compile targets to Travis CI (GH #608)

* Clean up in TLS ciphersuite handling (GH #583)

* Threefish-512 AVX2 optimization work (GH #581)

* Remove build configuration host and timestamp from build.h
  This makes this header reproducible and allows using ccache's direct mode
  (GH #586 see also #587)

* Prevent building for x86-64 with x86-32 compiler and the reverse (GH #585)

* Avoid build problem on 32-bit userspace ARMv8 (GH #563)

* Refactor of internal MP headers (GH #549)

* Avoid MSVC C4100 warning (GH #525)

* Change botan.exe to botan-cli.exe on Windows to workaround VC issue (GH #584)

* More tests for RSA-KEM (GH #538), DH (GH #556), EME (GH #553),
  cipher mode padding (GH #529), CTS mode (GH #531),
  KDF1/ISO18033 (GH #537), OctetString (GH #545), OIDs (GH #546),
  parallel hash (GH #548), charset handling (GH #555),
  BigInt (GH #558), HMAC_DRBG (GH #598 #600)

* New deprecations. See the full list in doc/deprecated.txt

  The X9.31 and HMAC_RNG RNGs are deprecated.
  If you need a userspace PRNG, use HMAC_DRBG (or AutoSeeded_RNG
  which is HMAC_DRBG with defaults).

  Support for getting entropy from EGD is deprecated, and will be
  removed in a future release. The developers believe that it is
  unlikely that any modern system requires EGD and so the code is now
  dead weight. If you rely on EGD support, you should contact the
  developers by email or GitHub ASAP.

  The TLS ciphersuites using 3DES and SEED are deprecated and will be
  removed in a future release.

  ECB mode Cipher_Mode is deprecated and will be removed in a future
  release.

  Support for BeOS/Haiku has not been tested in 5+ years and is in an
  unknown state.  Unless reports are received of successful builds and
  use on this platform, support for BeOS/Haiku will be removed in a
  future release.

Version 1.11.30, 2016-06-19
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* In 1.11.23 a bug was introduced such that CBC-encrypted TLS packets
  containing no plaintext bytes at all were incorrectly rejected with
  a MAC failure. Records like this are used by OpenSSL in TLS 1.0
  connections in order to randomize the IV.

* A bug in GCM caused incorrect results if the 32-bit counter field
  overflowed. This bug has no implications on the security but affects
  interoperability.

  With a 96-bit nonce, this could only occur if at least 2**32 128-bit
  blocks (64 GiB) were encrypted. This actually exceeds the maximum
  allowable length of a GCM plaintext; when messages longer than
  2**32 - 2 blocks are encrypted, GCM loses its security properties.

  In addition to 96-bit nonces, GCM also supports nonces of arbitrary
  length using a different method which hashes the provided nonce
  under the authentication key. When using such a nonce, the last 4
  bytes of the resulting CTR input might be near the overflow
  boundary, with the probability of incorrect overflow increasing with
  longer messages. when encrypting 256 MiB of data under a random 128
  bit nonce, an incorrect result would be produced about 1/256 of the
  time. With 1 MiB texts, the probability of error is reduced to 1/65536.

  Since TLS uses GCM with 96 bit nonces and limits the length of any
  record to far less than 64 GiB, TLS GCM ciphersuites are not
  affected by this bug.

  Reported by Juraj Somorovsky, described also in "Nonce-Disrespecting
  Adversaries: Practical Forgery Attacks on GCM in TLS"
  (https://eprint.iacr.org/2016/475.pdf)

* Previously when generating a new self-signed certificate or PKCS #10
  request, the subject DN was required to contain both common name
  (CN) and country (C) fields. These restrictions have been removed.
  GH #496

* The Transform and Keyed_Transform interfaces has been removed. The
  two concrete implementations of these interfaces were Cipher_Mode
  and Compressor_Transform. The Cipher_Mode interface remains unchanged
  as the Transform and Keyed_Transform signatures have moved to it;
  no changes to Cipher_Mode usage should be necessary. Any uses of
  Transform& or Keyed_Transform& to refer to a cipher should be replaced
  by Cipher_Mode&. The compression algorithm interface has changed; the start
  function now takes the per-message compression ratio to use. Previously the
  compression level to use had to be set once, at creation time, and
  the required ``secure_vector`` argument to ``start`` was required to be empty.
  The new API is documented in `compression.rst` in the manual.

* Add IETF versions of the ChaCha20Poly1305 TLS ciphersuites from
  draft-ietf-tls-chacha20-poly1305-04. The previously implemented
  (non-standard) ChaCha20Poly1305 ciphersuites from
  draft-agl-tls-chacha20poly1305 remain but are deprecated.

* The OCB TLS ciphersuites have been updated to use the new nonce
  scheme from draft-zauner-tls-aes-ocb-04. This is incompatible with
  previous versions of the draft, and the ciphersuite numbers used for
  the (still experimental) OCB ciphersuites have changed.

* Previously an unknown critical extension caused X.509 certificate
  parsing to fail; such a cert could not be created at all. Now
  parsing succeeds and the certificate validation fails with
  an error indicating an unknown critical extension. GH #469

* X509_CRL previously had an option to cause it to ignore unknown
  critical extensions. This has been removed.

* Added StreamCipher::seek allowing seeking to arbitrary position
  in the key stream. Currently only implemented for ChaCha. (GH #497)

* Added support for ChaCha stream cipher with 8 or 12 rounds.

* Add ECGDSA signature algorithm (GH #479)

* Add support for label argument to KDFs (GH #495)

* Add NIST SP800-108 and 56C KDFs (GH #481)

* Support for Card Verifiable Certificates and the obsolete EMSA1_BSI
  signature padding scheme have been removed. (GH #487)

* A bug in the IETF version of ChaCha20Poly1305 (with 96 bit nonces)
  caused incorrect computation when the plaintext or AAD was exactly
  a multiple of 16 bytes.

* Fix return type of TLS_Reader::get_u32bit, which was truncated to
  16 bits. This only affected decoding of session ticket lifetimes.
  GH #478

* Fix OS X dylib naming problem (GH #468 #467)

* Fix bcrypt function under Python 3 (GH #461)

* The ``unix_procs`` entropy source is deprecated and will be removed
  in a future release. This entropy source attempts to get entropy by
  running Unix programs like ``arp``, ``netstat``, and ``dmesg`` which
  produce information which may be difficult for a remote attacker to
  guess. This exists primarily as a last-ditch for Unix systems
  without ``/dev/random``. But at this point such systems effectively
  no longer exist, and the use of ``fork`` and ``exec`` by the library
  complicates effective application sandboxing.

* Changes to avoid implicit cast warnings in Visual C++ (GH #484)

Version 1.10.13, 2016-04-23
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Use constant time modular inverse algorithm to avoid possible
  side channel attack against ECDSA (CVE-2016-2849)

* Use constant time PKCS #1 unpadding to avoid possible side channel
  attack against RSA decryption (CVE-2015-7827)

* Avoid a compilation problem in OpenSSL engine when ECDSA was
  disabled. Gentoo bug 542010

Version 1.11.29, 2016-03-20
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* CVE-2016-2849 DSA and ECDSA used a modular inverse function which
  had input dependent loops. It is possible a side channel attack on
  this function could be used to recover sufficient information about
  the nonce k to mount a lattice attack and recover the private key.
  Found by Sean Devlin.

* CVE-2016-2850 The TLS client did not check that the signature
  algorithm or ECC curve a v1.2 server used was actually acceptable by
  the policy. This would allow a server who ignored the preferences
  indicated in the client to use a weak algorithm, and may allow MITM
  attacks by an attacker who can break MD5 signatures or 160 bit ECC
  in real time. The server similarly failed to check on the hash a
  client used during client certificate authentication.

* Reject empty TLS records at the record processing layer since such a
  record is not valid regardless of the record type. Later checks
  already correctly rejected empty records, but during processing such
  a record, a pointer to the end of the vector was created, causing a
  assertion failure under checked iterators. Found by Juraj Somorovsky.

* Add PK_Decryptor::decrypt_or_random which allows an application to
  atomically (in constant time) check that a decrypted ciphertext has
  the expected length and/or apply content checks on the result. This
  is used by the TLS server for decrypting PKCS #1 v1.5 RSA ciphertexts.
  Previously the server used a implementation which was potentially
  vulnerable to side channels.

* Add support for processing X.509 name constraint extension during
  path validation. GH #454

* Add X509_Certificate::v3_extensions which allows retreiving the
  raw binary of all certificate extensions, including those which
  are not known to the library. This allows processing of custom
  extensions. GH #437

* Add support for module policies which are a preconfigured set of
  acceptable or prohibited modules. A policy based on BSI TR-02102-1
  is included. GH #439 #446

* Support for the deprecated TLS heartbeat extension has been removed.

* Support for the deprecated TLS minimum fragment length extension has
  been removed.

* SRP6 support is now optional in TLS

* Support for negotiating MD5 and SHA-224 signatures in TLS v1.2 has
  been removed. MD5 signatures are demonstratably insecure in TLS,
  SHA-224 is rarely used.

* Support for negotiating ECC curves secp160r1, secp160r2, secp160k1,
  secp192k1, secp192r1 (P-192), secp224k1, secp224r1 (P-224), and
  secp256k1 have been removed from the TLS implementation. All were
  already disabled in the default policy.

* HMAC_RNG now has an explicit check for fork using pid comparisons.
  It also includes the pid and system and CPU clocks into the PRF
  computation to help reduce the risk of pid wraparound. Even so,
  applications using fork and userspace RNGs should explicitly reseed
  all such RNGs whenever possible.

* Deprecation warning: support for DSA certificates in TLS is
  deprecated and will be removed in a future release.

* Deprecation warning: in addition to the algorithms deprecated in
  1.11.26, the following algorithms are now deprecated and will be
  removed in a future release: Rabin-Williams signatures, TEA, XTEA.

* Deprecation warning: the library has a number of compiled in MODP
  and ECC DL parameters. All MODP parameter sets under 2048 bits and
  all ECC parameters under 256 bits are deprecated and will be removed
  in a future release. This includes the MODP groups "modp/ietf/1024",
  "modp/srp/1024", "modp/ietf/1536", "modp/srp/1536" and the ECC
  groups "secp160k1", "secp160r1", "secp160r2", "secp192k1",
  "secp192r1", "secp224k1", "secp224r1", "brainpool160r1",
  "brainpool192r1", "brainpool224r1", "x962_p192v2", "x962_p192v3",
  "x962_p239v1", "x962_p239v2" and "x962_p239v3". Additionally all
  compiled in DSA parameter sets ("dsa/jce/1024", "dsa/botan/2048",
  and "dsa/botan/3072") are also deprecated.

* RDSEED/RDRAND polling now retries if the operation fails. GH #373

* Fix various minor bugs found by static analysis with PVS-Studio (GH#421),
  Clang analyzer (GH #441), cppcheck (GH #444, #445), and Coverity.

* Add --with-valgrind configure option to enable building against the
  valgrind client API. This currently enables checking of const time
  operations using memcheck.

* Fix remaining Wshadow warnings. Enable Wshadow in build. GH #427

* Use noexcept in VS 2015 GH #429

* On Windows allow the user to explicitly request symlinks be used
  as part of the build. Likely only useful for someone working on
  the library itself. GH #430

* Remove use of TickCount64 introduced in 1.11.27 which caused problem
  with downstream distributors/users building XP compatiable binaries
  which is still an option even in VS 2015

* MCEIES requires KDF1 at runtime but did not require it be enabled
  in the build. GH #369

* Small optimizations to Keccak hash

* Support for locking allocator on Windows using VirtualLock. GH #450

Version 1.8.15, 2016-02-13
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
* NOTE WELL: Botan 1.8 is not supported for security issues anymore.
  Moving to 1.10 or 1.11 is certainly recommended.
* Fix CVE-2014-9742: Insufficient randomness in Miller-Rabin primality check
* Fix CVE-2016-2194: Infinite loop in modulur square root algorithm
* Fix CVE-2015-5726: Crash in BER decoder
* Fix CVE-2015-5727: Excess memory allocation in BER decoder
  Note: Unlike the fix in 1.10 which checks that the source actually
  contains enough data to satisfy the read before allocating the
  memory, 1.8.15 simply rejects all ASN.1 blocks larger than 1 MiB.
  This simpler check avoids the problem without breaking ABI.

Version 1.10.12, 2016-02-03
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* In 1.10.11, the check in PointGFp intended to check the affine y
  argument actually checked the affine x again. Reported by Remi Gacogne

  The CVE-2016-2195 overflow is not exploitable in 1.10.11 due to an
  additional check in the multiplication function itself which was
  also added in that release, so there are no security implications
  from the missed check. However to avoid confusion the change was
  pushed in a new release immediately.

  The 1.10.11 release notes incorrectly identified CVE-2016-2195 as CVE-2016-2915

Version 1.10.11, 2016-02-01
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Resolve heap overflow in ECC point decoding. CVE-2016-2195

* Resolve infinite loop in modular square root algorithm.
  CVE-2016-2194

* Correct BigInt::to_u32bit to not fail on integers of exactly 32 bits.
  GH #239

Version 1.11.28, 2016-02-01
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* One of the checks added while addressing CVE-2016-2195 was incorrect
  and could cause needless assertion failures.

Version 1.11.27, 2016-02-01
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* SECURITY: Avoid heap overflow in ECC point decoding. This could
  likely result in remote code execution. CVE-2016-2195

* SECURITY: Avoid one word heap overflow in P-521 reduction function.
  This could potentially lead to remote code execution or other
  attack. CVE-2016-2196.

* SECURITY: Avoid infinite or near-infinite loop during modular square
  root algorithm with invalid inputs. CVE-2016-2194

* Add Blake2b hash function. GH #413

* Use ``m_`` prefix on all member variables. GH #398 and #407

* Use final qualifier on many classes. GH #408

* Use noreturn attribute on assertion failure function to assist
  static analysis. GH #403

* Use TickCount64 and MemoryStatusEx in the Windows entropy source.
  Note these calls are only available in Vista/Server 2008. No
  accomodations are made for XP or Server 2003, both of which are
  no longer patched by the vendor. GH #365

Version 1.11.26, 2016-01-04
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Deprecation warnings: Nyberg-Rueppel signatures, MARS, RC2, RC5,
  RC6, SAFER, HAS-160, RIPEMD-128, MD2 and support for the TLS minimum
  fragment length extensions are all being considered for removal in a
  future release. If there is a compelling use case for keeping any of
  them in the library, please open a discussion ticket on GitHub.

* Support for the TLS extended master secret extension (RFC 7627) has
  been added.

* The format of serialized TLS sessions has changed to add a flag
  indicating support for the extended master secret flag, which is
  needed for proper handling of the extension.

* Root all exceptions thrown by the library in the ``Botan::Exception`` class.
  Previously the library would in many cases throw ``std::runtime_error``
  or ``std::invalid_argument`` exceptions which would make it hard to
  determine the source of the error in some cases.

* The command line interface has been mostly rewritten. The syntax of
  many of the sub-programs has changed, and a number have been
  extended with new features and options.

* Correct an error in PointGFp multiplication when multiplying a point
  by the scalar value 3. PointGFp::operator* would instead erronously
  compute it as if the scalar was 1 instead.

* Enable RdRand entropy source on Windows/MSVC. GH #364

* Add Intel's RdSeed as entropy source. GH #370

* Add preliminary support for accessing TPM v1.2 devices. Currently
  random number generation, RSA key generation, and signing are
  supported. Tested using Trousers and an ST TPM

* Add generalized interface for KEM (key encapsulation) techniques. Convert
  McEliece KEM to use it. The previous interfaces McEliece_KEM_Encryptor and
  McEliece_KEM_Decryptor have been removed. The new KEM interface now uses a KDF
  to hash the resulting keys; to get the same output as previously provided by
  McEliece_KEM_Encryptor, use "KDF1(SHA-512)" and request exactly 64 bytes.

* Add support for RSA-KEM from ISO 18033-2

* Add support for ECDH in the OpenSSL provider

* Fix a bug in DataSource::discard_next() which could cause either an
  infinite loop or the discarding of an incorrect number of bytes.
  Reported on mailing list by Falko Strenzke.

* Previously if BOTAN_TARGET_UNALIGNED_MEMORY_ACCESS_OK was defined,
  the code doing low level loads/stores would use pointer casts to
  access larger words out of a (potentially misaligned) byte array,
  rather than using byte-at-a-time accesses. However even on platforms
  such as x86 where this works, it triggers UBSan errors under Clang.
  Instead use memcpy, which the C standard says is usable for such
  purposes even with misaligned values. With recent GCC and Clang, the
  same code seems to be emitted for either approach.

* Avoid calling memcpy, memset, or memmove with a length of zero to
  avoid undefined behavior, as calling these functions with an invalid
  or null pointer, even with a length of zero, is invalid. Often there
  are corner cases where this can occur, such as pointing to the very
  end of a buffer.

* The function ``RandomNumberGenerator::gen_mask`` (added in 1.11.20)
  had undefined behavior when called with a bits value of 32 or
  higher, and was tested to behave in unpleasant ways (such as
  returning zero) when compiled by common compilers. This function was
  not being used anywhere in the library and rather than support
  something without a use case to justify it it seemed simpler to
  remove it. Undefined behavior found by Daniel Neus.

* Support for using ``ctgrind`` for checking const time blocks has
  been replaced by calling the valgrind memcheck APIs directly. This
  allows const-time behavior to be tested without requiring a modified
  valgrind binary. Adding the appropriate calls requires defining
  BOTAN_HAS_VALGRIND in build.h. A binary compiled with this flag set
  can still run normally (though with some slight runtime overhead).

* Export MGF1 function mgf1_mask GH #380

* Work around a problem with some antivirus programs which causes the
  ``shutil.rmtree`` and ``os.makedirs`` Python calls to occasionally
  fail. The could prevent ``configure.py`` from running sucessfully
  on such systems. GH #353

* Let ``configure.py`` run under CPython 2.6. GH #362

Version 1.11.25, 2015-12-07
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* In this release the test suite has been largely rewritten. Previously the
  tests had internally used several different test helper frameworks created or
  adopted over time, each of which was insufficient on its own for testing the
  entire library. These have been fully converged on a new framework which
  suffices for all of the tests. There should be no user-visible change as a
  result of this, except that the output format of `botan-test` has changed.

* Improved side channel countermeasures for the table based AES implementation.
  The 4K T tables are computed (once) at runtime to avoid various cache based
  attacks which are possible due to shared VMM mappings of read only tables.
  Additionally every cache line of the table is read from prior to processing
  the block(s).

* Support for the insecure ECC groups secp112r1, secp112r2, secp128r1, and
  secp128r2 has been removed.

* The portable version of GCM has been changed to run using only
  constant time operations.

* Work around a bug in MSVC 2013 std::mutex which on some Windows
  versions can result in a deadlock during static initialization. On
  Windows a CriticalSection is used instead. Analysis and patch from
  Matej Kenda (TopIT d.o.o.). GH #321

* The OpenSSL implementation of RC4 would return the wrong value from `name` if
  leading bytes of the keystream had been skipped in the output.

* Fixed the signature of the FFI function botan_pubkey_destroy, which took the
  wrong type and was not usable.

* The TLS client would erronously reject any server key exchange packet smaller
  than 6 bytes. This prevented negotiating a plain PSK TLS ciphersuite with an
  empty identity hint. ECDHE_PSK and DHE_PSK suites were not affected.

* Fixed a bug that would cause the TLS client to occasionally reject a valid
  server key exchange message as having an invalid signature. This only affected
  DHE and SRP ciphersuites.

* Support for negotiating use of SHA-224 in TLS has been disabled in the
  default policy.

* Added `remove_all` function to the `TLS::Session_Manager` interface

* Avoid GCC warning in pedantic mode when including bigint.h GH #330

Version 1.11.24, 2015-11-04
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* When the bugs affecting X.509 path validation were fixed in 1.11.23, a check
  in Credentials_Manager::verify_certificate_chain was accidentally removed
  which caused path validation failures not to be signaled to the TLS layer.
  Thus in 1.11.23 certificate authentication in TLS is bypassed.
  Reported by Florent Le Coz in GH #324

* Fixed an endian dependency in McEliece key generation which caused
  keys to be generated differently on big and little endian systems,
  even when using a deterministic PRNG with the same seed.

* In `configure,py`, the flags for controlling use of debug, sanitizer, and
  converage information have been split out into individual options
  `--with-debug-info`, `--with-sanitizers`, and `--with-coverage`. These allow
  enabling more than one in a build in a controlled way. The `--build-mode` flag
  added in 1.11.17 has been removed.

Version 1.11.23, 2015-10-26
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* CVE-2015-7824: An information leak allowed padding oracle attacks against
  TLS CBC decryption. Found in a review by Sirrix AG and 3curity GmbH.

* CVE-2015-7825: Validating a malformed certificate chain could cause an
  infinite loop. Found in a review by Sirrix AG and 3curity GmbH.

* CVE-2015-7826: X.509 path validation violated RFC 6125 and would accept
  certificates which should not validate under those rules. In particular botan
  would accept wildcard certificates as matching in situations where it should
  not (for example it would erroneously accept ``*.example.com`` as a valid
  wildcard for ``foo.bar.example.com``)

* CVE-2015-7827: The routines for decoding PKCS #1 encryption and OAEP blocks
  have been rewritten to run without secret indexes or branches. These
  cryptographic operations are vulnerable to oracle attacks, including via side
  channels such as timing or cache-based analysis. In theory it would be
  possible to attack the previous implementations using such a side channel,
  which could allow an attacker to mount a plaintext recovery attack.

  By writing the code such that it does not depend on secret inputs for branch
  or memory indexes, such a side channel would be much less likely to exist.

  The OAEP code has previously made an attempt at constant time operation, but
  it used a construct which many compilers converted into a conditional jump.

* Add support for using ctgrind (https://github.com/agl/ctgrind) to test that
  sections of code do not use secret inputs to decide branches or memory indexes.
  The testing relies on dynamic checking using valgrind.

  So far PKCS #1 decoding, OAEP decoding, Montgomery reduction, IDEA, and
  Curve25519 have been notated and confirmed to be constant time on Linux/x86-64
  when compiled by gcc.

* Public key operations can now be used with specified providers by passing an
  additional parameter to the constructor of the PK operation.

* OpenSSL RSA provider now supports signature creation and verification.

* The blinding code used for RSA, Diffie-Hellman, ElGamal and Rabin-Williams now
  periodically reinitializes the sequence of blinding values instead of always
  deriving the next value by squaring the previous ones. The reinitializion
  interval can be controlled by the build.h parameter BOTAN_BLINDING_REINIT_INTERVAL.

* A bug decoding DTLS client hellos prevented session resumption for succeeding.

* DL_Group now prohibits creating a group smaller than 1024 bits.

* Add System_RNG type. Previously the global system RNG was only accessible via
  `system_rng` which returned a reference to the object. However is at times
  useful to have a unique_ptr<RandomNumberGenerator> which will be either the
  system RNG or an AutoSeeded_RNG, depending on availability, which this
  additional type allows.

* New command line tools `dl_group` and `prime`

* The `configure.py` option `--no-autoload` is now also available
  under the more understandable name `--minimized-build`.

* Note: 1.11.22 was briefly released on 2015-10-26. The only difference between
  the two was a fix for a compilation problem in the OpenSSL RSA code.  As the
  1.11.22 release had already been tagged it was simpler to immediately release
  1.11.23 rather than redo the release.

Version 1.11.21, 2015-10-11
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Add new methods for creating types such as BlockCiphers or HashFunctions,
  T::providers() returning list of provider for a type, and T::create() creating
  a new object of a specified provider. The functions in lookup.h forward to
  these new APIs. A change to the lookup system in 1.11.14 had caused problems
  with static libraries (GH #52). These problems have been fixed as part of these
  changes. GH #279

* Fix loading McEliece public or private keys with PKCS::load_key / X509::load_key

* Add `mce` command line tool for McEliece key generation and file encryption

* Add Darwin_SecRandom entropy source which uses `SecRandomCopyBytes`
  API call for OS X and iOS, as this call is accessible even from a
  sandboxed application. GH #288

* Add new HMAC_DRBG constructor taking a name for the MAC to use, rather
  than a pointer to an object.

* The OCaml module is now a separate project at
  https://github.com/randombit/botan-ocaml

* The encrypted sqlite database support in contrib has moved to
  https://github.com/randombit/botan-sqlite

* The Perl XS module has been removed as it was no longer maintained.

Version 1.11.20, 2015-09-07
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Additional countermeasures were added to ECC point multiplications
  including exponent blinding and randomization of the point
  representation to help protect against side channel attacks.

* An ECDSA provider using OpenSSL has been added.

* The ordering of algorithm priorities has been reversed. Previously
  255 was the lowest priority and 0 was the highest priority. Now it
  is the reverse, with 0 being lowest priority and 255 being highest.
  The default priority for the base algorithms is 100. This only
  affects external providers or applications which directly set
  provider preferences.

* On OS X, rename libs to avoid trailing version numbers, e.g.
  libbotan-1.11.dylib.19 -> libbotan-1.11.19.dylib. This was requested
  by the Homebrew project package audit. GH #241, #260

* Enable use of CPUID interface with clang. GH #232

* Add support for MSVC 2015 debug builds by satisfying C++ allocator
  requirements. SO 31802806, GH #236

* Make `X509_Time` string parsing and `to_u32bit()` more strict to avoid
  integer overflows and other potentially dangerous misinterpretations.
  GH #240, #243

* Remove all 'extern "C"' declarations from src/lib/math/mp/ because some
  of those did throw exceptions and thus cannot be C methods. GH #249

* Fix build configuration for clang debug on Linux. GH #250

* Fix zlib error when compressing an empty buffer. GH #265

* Fix iOS builds by allowing multiple compiler flags with the same name.
  GH #266

* Fix Solaris build issue caused by `RLIMIT_MEMLOCK`. GH #262

Version 1.11.19, 2015-08-03
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* SECURITY: The BER decoder would crash due to reading from offset 0
  of an empty vector if it encountered a BIT STRING which did not
  contain any data at all. As the type requires a 1 byte field this is
  not valid BER but could occur in malformed data. Found with afl.
  CVE-2015-5726

* SECURITY: The BER decoder would allocate a fairly arbitrary amount
  of memory in a length field, even if there was no chance the read
  request would succeed. This might cause the process to run out of
  memory or invoke the OOM killer. Found with afl.
  CVE-2015-5727

* The TLS heartbeat extension is deprecated and unless strong arguments
  are raised in its favor it will be removed in a future release.
  Comment at https://github.com/randombit/botan/issues/187

* The x86-32 assembly versions of MD4, MD5, SHA-1, and Serpent and the
  x86-64 version of SHA-1 have been removed. With compilers from this
  decade the C++ versions are significantly faster. The SSE2 versions
  of SHA-1 and Serpent remain, as they are still the fastest version
  for processors with SIMD extensions. GH #216

* BigInt::to_u32bit would fail if the value was exactly 32 bits.
  GH #220

* Botan is now fully compaitible with _GLIBCXX_DEBUG. GH #73

* BigInt::random_integer distribution was not uniform. GH #108

* Added unit testing framework Catch. GH #169

* Fix `make install`. GH #181, #186

* Public header `fs.h` moved to `internal/filesystem.h`. Added filesystem
  support for MSVC 2013 when boost is not available, allowing tests to run on
  those systems. GH #198, #199

* Added os "android" and fix Android compilation issues. GH #203

* Drop support for Python 2.6 for all Botan Python scripts. GH #217

Version 1.10.10, 2015-08-03
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* SECURITY: The BER decoder would crash due to reading from offset 0
  of an empty vector if it encountered a BIT STRING which did not
  contain any data at all. As the type requires a 1 byte field this is
  not valid BER but could occur in malformed data. Found with afl.
  CVE-2015-5726

* SECURITY: The BER decoder would allocate a fairly arbitrary amount
  of memory in a length field, even if there was no chance the read
  request would succeed. This might cause the process to run out of
  memory or invoke the OOM killer. Found with afl.
  CVE-2015-5727

* Due to an ABI incompatible (though not API incompatible) change in
  this release, the version number of the shared object has been
  increased.

* The default TLS policy no longer allows RC4.

* Fix a signed integer overflow in Blue Midnight Wish that may cause
  incorrect computations or undefined behavior.

Version 1.11.18, 2015-07-05
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* In this release Botan has switched VCS from ``monotone`` to ``git``,
  and is now hosted on github at https://github.com/randombit/botan

* The TLS client called ``std::set_difference`` on an invalid iterator
  pair. This could potentially lead to a crash depending on the
  compiler and STL implementation. It also would trigger assertion
  failures when using checked iterators. GH #73

* Remove code constructs which triggered errors under MSVC and GCC
  debug iterators. The primary of these was an idiom of ``&vec[x]`` to
  create a pointer offset of a ``std::vector``. This failed when x was
  set equal to ``vec.size()`` to create the one-past-the-end address.
  The pointer in question was never dereferenced, but it triggered
  the iterator debugging checks which prevented using these valuble
  analysis tools. From Simon Warta and Daniel Seither. GH #125

* Several incorrect or missing module dependencies have been fixed. These
  often prevented a successful build of a minimized amalgamation when
  only a small set of algorithms were specified. GH #71
  From Simon Warta.

* Add an initial binding to OCaml. Currently only hashes, RNGs, and
  bcrypt are supported.

* The default key size generated by the ``keygen`` tool has increased
  to 2048 bits. From Rene Korthaus.

* The ``Botan_types`` namespace, which contained ``using`` declarations
  for (just) ``Botan::byte`` and ``Botan::u32bit``, has been removed.
  Any use should be replaced by ``using`` declarations for those types
  directly.

Version 1.11.17, 2015-06-18
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* All support for the insecure RC4 stream cipher has been removed
  from the TLS implementation.

* Fix decoding of TLS maximum fragment length. Regardless of what
  value was actually negotiated, TLS would treat it as a negotiated
  limit of 4096.

* Fix the configure.py flag ``--disable-aes-ni`` which did nothing of
  the sort.

* Fixed nmake clean target. GitHub #104

* Correct buffering logic in ``Compression_Filter``. GitHub #93 and #95

Version 1.11.16, 2015-03-29
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* TLS has changed from using the non-standard NPN extension to the IETF
  standardized ALPN extension for negotiating an application-level protocol.
  Unfortunately the semantics of the exchange have changed with ALPN. Using
  NPN, the server offered a list of protocols it advertised, and then the
  client chose its favorite. With ALPN, the client offers a list of protocols
  and the server chooses. The signatures of both the TLS::Client and
  TLS::Server constructors have changed to support this new flow.

* Optimized ECDSA signature verification thanks to an observation by
  Dr. Falko Strenzke. On some systems verifications are between 1.5
  and 2 times faster than in 1.11.15.

* RSA encrypt and decrypt operations using OpenSSL have been added.

* Public key operation types now handle all aspects of the operation,
  such as hashing and padding for signatures. This change allows
  supporting specialized implementations which only support particular
  padding types.

* Added global timeout to HMAC_RNG entropy reseed. The defaults are
  the values set in the build.h macros ``BOTAN_RNG_AUTO_RESEED_TIMEOUT``
  and ``BOTAN_RNG_RESEED_DEFAULT_TIMEOUT``, but can be overriden
  on a specific poll with the new API call reseed_with_timeout.

* Fixed Python cipher update_granularity() and default_nonce_length()
  functions

* The library now builds on Visual C++ 2013

* The GCM update granularity was reduced from 4096 to 16 bytes.

* Fix a bug that prevented building the amalgamation until a non-amalgamation
  configuration was performed first in the same directory.

* Add Travis CI integration. Github pull 60.

Version 1.11.15, 2015-03-08
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Support for RC4 in TLS, already disabled by default, is now deprecated.
  The RC4 ciphersuites will be removed entirely in a future release.

* A bug in ffi.cpp meant Python could only encrypt. Github issue 53.

* When comparing two ASN.1 algorithm identifiers, consider empty and
  NULL parameters the same.

* Fixed memory leaks in TLS and cipher modes introduced in 1.11.14

* MARK-4 failed when OpenSSL was enabled in the build in 1.11.14
  because the OpenSSL version ignored the skip parameter.

* Fix compilation problem on OS X/clang

* Use BOTAN_NOEXCEPT macro to work around lack of noexcept in VS 2013

Version 1.11.14, 2015-02-27
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* The global state object previously used by the library has been removed.
  This includes the global PRNG. The library can be safely initialized
  multiple times without harm.

  The engine code has also been removed, replaced by a much lighter-weight
  object registry system which provides lookups in faster time and with less
  memory overhead than the previous approach.

  One caveat of the current system with regards to static linking: because only
  symbols already mentioned elsewhere in the program are included in the final
  link step, few algorithms will be available through the lookup system by
  default, even though they were compiled into the library. Your application
  must explicitly reference the types you require or they will not end up
  being available in the final binary. See also Github issue #52

  If you intend to build your application against a static library and don't
  want to explicitly reference each algo object you might attempt to look up by
  string, consider either building with ``--via-amalgamation``, or else (much
  simpler) using the amalgamation directly.

* The new ``ffi`` submodule provides a simple C API/ABI for a number of useful
  operations (hashing, ciphers, public key operations, etc) which is easily
  accessed using the FFI modules included in many languages.

* A new Python wrapper (in ``src/lib/python/botan.py``) using ``ffi`` and the Python
  ``ctypes`` module is available. The old Boost.Python wrapper has been removed.

* Add specialized reducers for P-192, P-224, P-256, and P-384

* OCB mode, which provides a fast and constant time AEAD mode without requiring
  hardware support, is now supported in TLS, following
  draft-zauner-tls-aes-ocb-01. Because this specification is not yet finalized
  is not yet enabled by the default policy, and the ciphersuite numbers used are
  in the experimental range and may conflict with other uses.

* Add ability to read TLS policy from a text file using ``TLS::Text_Policy``.

* The amalgamation now splits off any ISA specific code (for instance, that
  requiring SSSE3 instruction sets) into a new file named (for instance)
  ``botan_all_ssse3.cpp``. This allows the main amalgamation file to be compiled
  without any special flags, so ``--via-amalgamation`` builds actually work now.
  This is disabled with the build option ``--single-amalgamation-file``

* PBKDF and KDF operations now provide a way to write the desired output
  directly to an application-specified area rather than always allocating a new
  heap buffer.

* HKDF, previously provided using a non-standard interface, now uses the
  standard KDF interface and is retrievable using get_kdf.

* It is once again possible to build the complete test suite without requiring
  any boost libraries. This is currently only supported on systems supporting
  the readdir interface.

* Remove use of memset_s which caused problems with amalgamation on OS X.
  Github 42, 45

* The memory usage of the counter mode implementation has been reduced.
  Previously it encrypted 256 blocks in parallel as this leads to a slightly
  faster counter increment operation. Instead CTR_BE simply encrypts a buffer
  equal in size to the advertised parallelism of the cipher implementation.
  This is not measurably slower, and dramatically reduces the memory use of
  CTR mode.

* The memory allocator available on Unix systems which uses mmap and mlock to
  lock a pool of memory now checks environment variable BOTAN_MLOCK_POOL_SIZE
  and interprets it as an integer. If the value set to a smaller value then the
  library would originally have allocated (based on resource limits) the user
  specified size is used instead. You can also set the variable to 0 to
  disable the pool entirely. Previously the allocator would consume all
  available mlocked memory, this allows botan to coexist with an application
  which wants to mlock memory for its own uses.

* The botan-config script previously installed on Unix systems has been
  removed.  Its functionality is replaced by the ``config`` command of the
  ``botan`` tool executable, for example ``botan config cflags`` instead of
  ``botan-config --cflags``.

* Added a target for POWER8 processors

Version 1.11.13, 2015-01-11
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* All support for the insecure SSLv3 protocol and the server support
  for processing SSLv2 client hellos has been removed.

* The command line tool now has ``tls_proxy`` which negotiates TLS with
  clients and forwards the plaintext to a specified port.

* Add MCEIES, a McEliece-based integrated encryption system using
  AES-256 in OCB mode for message encryption/authentication.

* Add DTLS-SRTP negotiation defined in RFC 5764

* Add SipHash

* Add SHA-512/256

* The format of serialized TLS sessions has changed. Additiionally, PEM
  formatted sessions now use the label of "TLS SESSION" instead of "SSL SESSION"

* Serialized TLS sessions are now encrypted using AES-256/GCM instead of a
  CBC+HMAC construction.

* The cryptobox_psk module added in 1.11.4 and previously used for TLS session
  encryption has been removed.

* When sending a TLS heartbeat message, the number of pad bytes to use can now
  be specified, making it easier to use for PMTU discovery.

* If available, zero_mem now uses RtlSecureZeroMemory or memset_s instead of a
  byte-at-a-time loop.

* The functions base64_encode and base64_decode would erroneously
  throw an exception if passed a zero-length input. Github issue 37.

* The Python install script added in version 1.11.10 failed to place the
  headers into a versioned subdirectory.

* Fix the install script when running under Python3.

* Avoid code that triggers iterator debugging asserts under MSVC 2013. Github
  pull 36 from Simon Warta.

Version 1.11.12, 2015-01-02
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Add Curve25519. The implementation is based on curve25519-donna-c64.c
  by Adam Langley. New (completely non-standard) OIDs and formats for
  encrypting Curve25519 keys under PKCS #8 and including them in
  certificates and CRLs have been defined.

* Add Poly1305, based on the implementation poly1305-donna by Andrew Moon.

* Add the ChaCha20Poly1305 AEADs defined in draft-irtf-cfrg-chacha20-poly1305-03
  and draft-agl-tls-chacha20poly1305-04.

* Add ChaCha20Poly1305 ciphersuites for TLS compatible with Google's servers
  following draft-agl-tls-chacha20poly1305-04

* When encrypted as PKCS #8 structures, Curve25519 and McEliece
  private keys default to using AES-256/GCM instead of AES-256/CBC

* Define OIDs for OCB mode with AES, Serpent and Twofish.

Version 1.11.11, 2014-12-21
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* The Sqlite3 wrapper has been abstracted to a simple interface for
  SQL dbs in general, though Sqlite3 remains the only implementation.
  The main logic of the TLS session manager which stored encrypted
  sessions to a Sqlite3 database (``TLS::Session_Manager_SQLite``) has
  been moved to the new ``TLS::Session_Manager_SQL``. The Sqlite3
  manager API remains the same but now just subclasses
  ``TLS::Session_Manager_SQL`` and has a constructor instantiate the
  concrete database instance.

  Applications which would like to use a different db can now do so
  without having to reimplement the session cache logic simply by
  implementing a database wrapper subtype.

* The CryptGenRandom entropy source is now also used on MinGW.

* The system_rng API is now also available on systems with CryptGenRandom

* With GCC use -fstack-protector for linking as well as compiling,
  as this is required on MinGW. Github issue 34.

* Fix missing dependency in filters that caused compilation problem
  in amalgamation builds. Github issue 33.

* SSLv3 support is officially deprecated and will be removed in a
  future release.

Version 1.10.9, 2014-12-13
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Fixed EAX tag verification to run in constant time

* The default TLS policy now disables SSLv3.

* A crash could occur when reading from a blocking random device if
  the device initially indicated that entropy was available but
  a concurrent process drained the entropy pool before the
  read was initiated.

* Fix decoding indefinite length BER constructs that contain a context
  sensitive tag of zero. Github pull 26 from Janusz Chorko.

* The ``botan-config`` script previously tried to guess its prefix from
  the location of the binary. However this was error prone, and now
  the script assumes the final installation prefix matches the value
  set during the build. Github issue 29.

Version 1.11.10, 2014-12-10
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* An implementation of McEliece code-based public key encryption based
  on INRIA's HyMES and secured against a variety of side-channels was
  contributed by cryptosource GmbH. The original version is LGPL but
  cryptosource has secured permission to release an adaptation under a
  BSD license. A CCA2-secure KEM scheme is also included.

  The implementation is further described in
  http://www.cryptosource.de/docs/mceliece_in_botan.pdf and
  http://cryptosource.de/news_mce_in_botan_en.html

* DSA and ECDSA now create RFC 6979 deterministic signatures.

* Add support for TLS fallback signaling (draft-ietf-tls-downgrade-scsv-00).
  Clients will send a fallback SCSV if the version passed to the Client
  constructor is less than the latest version supported by local policy, so
  applications implementing fallback are protected. Servers always check the
  SCSV.

* In previous versions a TLS::Server could service either TLS or DTLS
  connections depending on policy settings and what type of client hello it
  received. This has changed and now a Server object is initialized for
  either TLS or DTLS operation. The default policy previously prohibited
  DTLS, precisely to prevent a TCP server from being surprised by a DTLS
  connection.  The default policy now allows TLS v1.0 or higher or DTLS v1.2.

* Fixed a bug in CCM mode which caused it to produce incorrect tags when used
  with a value of L other than 2. This affected CCM TLS ciphersuites, which
  use L=3. Thanks to Manuel Pégourié-Gonnard for the anaylsis and patch.
  Bugzilla 270.

* DTLS now supports timeouts and handshake retransmits. Timeout checking
  is triggered by the application calling the new TLS::Channel::timeout_check.

* Add a TLS policy hook to disable putting the value of the local clock in hello
  random fields.

* All compression operations previously available as Filters are now
  performed via the Transformation API, which minimizes memory copies.
  Compression operations are still available through the Filter API
  using new general compression/decompression filters in comp_filter.h

* The zlib module now also supports gzip compression and decompression.

* Avoid a crash in low-entropy situations when reading from /dev/random, when
  select indicated the device was readable but by the time we start the read the
  entropy pool had been depleted.

* The Miller-Rabin primality test function now takes a parameter allowing the
  user to directly specify the maximum false negative probability they are
  willing to accept.

* PKCS #8 private keys can now be encrypted using GCM mode instead of
  unauthenticated CBC. The default remains CBC for compatibility.

* The default PKCS #8 encryption scheme has changed to use PBKDF2 with
  SHA-256 instead of SHA-1

* A specialized reducer for P-521 was added.

* On Linux the mlock allocator will use MADV_DONTDUMP on the pool so
  that the contents are not included in coredumps.

* A new interface for directly using a system-provided PRNG is
  available in system_rng.h. Currently only systems with /dev/urandom
  are supported.

* Fix decoding indefinite length BER constructs that contain a context sensitive
  tag of zero. Github pull 26 from Janusz Chorko.

* The GNU MP engine has been removed.

* Added AltiVec detection for POWER8 processors.

* Add a new install script written in Python which replaces shell hackery in the
  makefiles.

* Various modifications to better support Visual C++ 2013 and 2015. Github
  issues 11, 17, 18, 21, 22.

Version 1.10.8, 2014-04-10
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* SECURITY: Fix a bug in primality testing introduced in 1.8.3 which
  caused only a single random base, rather than a sequence of random
  bases, to be used in the Miller-Rabin test. This increased the
  probability that a non-prime would be accepted, for instance a 1024
  bit number would be incorrectly classed as prime with probability
  around 2^-40. Reported by Jeff Marrison. CVE-2014-9742

* The key length limit on HMAC has been raised to 512 bytes, allowing
  the use of very long passphrases with PBKDF2.

Version 1.11.9, 2014-04-10
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* SECURITY: Fix a bug in primality testing introduced in 1.8.3 which
  caused only a single random base, rather than a sequence of random
  bases, to be used in the Miller-Rabin test. This increased the
  probability that a non-prime would be accepted, for instance a 1024
  bit number would be incorrectly classed as prime with probability
  around 2^-40. Reported by Jeff Marrison. CVE-2014-9742

* X.509 path validation now returns a set of all errors that occurred
  during validation, rather than immediately returning the first
  detected error. This prevents a seemingly innocuous error (such as
  an expired certificate) from hiding an obviously serious error
  (such as an invalid signature). The Certificate_Status_Code enum is
  now ordered by severity, and the most severe error is returned by
  Path_Validation_Result::result(). The entire set of status codes is
  available with the new all_statuses call.

* Fixed a bug in OCSP response decoding which would cause an error
  when attempting to decode responses from some widely used
  responders.

* An implementation of HMAC_DRBG RNG from NIST SP800-90A has been
  added. Like the X9.31 PRNG implementation, it uses another
  underlying RNG for seeding material.

* An implementation of the RFC 6979 deterministic nonce generator has
  been added.

* Fix a bug in certificate path validation which prevented successful
  validation if intermediate certificates were presented out of order.

* Fix a bug introduced in 1.11.5 which could cause crashes or other
  incorrect behavior when a cipher mode filter was followed in the
  pipe by another filter, and that filter had a non-empty start_msg.

* The types.h header now uses stdint.h rather than cstdint to avoid
  problems with Clang on OS X.

Version 1.11.8, 2014-02-13
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* The ``botan`` command line application introduced in 1.11.7 is now
  installed along with the library.

* A bug in certificate path validation introduced in 1.11.6 which
  caused all CRL signature checks to fail has been corrected.

* The ChaCha20 stream cipher has been added.

* The ``Transformation`` class no longer implements an interface for keying,
  this has been moved to a new subclass ``Keyed_Transformation``.

* The ``Algorithm`` class, which previously acted as a global base for
  various types (ciphers, hashes, etc) has been removed.

* CMAC now supports 256 and 512 bit block ciphers, which also allows
  the use of larger block ciphers with EAX mode. In particular this
  allows using Threefish in EAX mode.

* The antique PBES1 private key encryption scheme (which only supports
  DES or 64-bit RC2) has been removed.

* The Square, Skipjack, and Luby-Rackoff block ciphers have been removed.

* The Blue Midnight Wish hash function has been removed.

* Skein-512 no longer supports output lengths greater than 512 bits.

* Skein did not reset its internal state properly if clear() was
  called, causing it to produce incorrect results for the following
  message. It was reset correctly in final() so most usages should not
  be affected.

* A number of public key padding schemes have been renamed to match
  the most common notation; for instance EME1 is now called OAEP and
  EMSA4 is now called PSSR. Aliases are set which should allow all
  current applications to continue to work unmodified.

* A bug in CFB encryption caused a few bytes past the end of the final
  block to be read. The actual output was not affected.

* Fix compilation errors in the tests that occurred with minimized
  builds. Contributed by Markus Wanner.

* Add a new ``--destdir`` option to ``configure.py`` which controls
  where the install target will place the output. The ``--prefix``
  option continues to set the location where the library expects to be
  eventually installed.

* Many class destructors which previously deleted memory have been
  removed in favor of using ``unique_ptr``.

* Various portability fixes for Clang, Windows, Visual C++ 2013, OS X,
  and x86-32.

Version 1.11.7, 2014-01-10
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Botan's basic numeric types are now defined in terms of the
  C99/C++11 standard integer types. For instance ``u32bit`` is now a
  typedef for ``uint32_t``, and both names are included in the library
  namespace. This should not result in any application-visible
  changes.

* There are now two executable outputs of the build, ``botan-test``,
  which runs the tests, and ``botan`` which is used as a driver to call
  into various subcommands which can also act as examples of library
  use, much in the manner of the ``openssl`` command. It understands the
  commands ``base64``, ``asn1``, ``x509``, ``tls_client``, ``tls_server``,
  ``bcrypt``, ``keygen``, ``speed``, and various others. As part of this
  change many obsolete, duplicated, or one-off examples were removed,
  while others were extended with new functionality. Contributions of
  new subcommands, new bling for exising ones, or documentation in any
  form is welcome.

* Fix a bug in Lion, which was broken by a change in 1.11.0. The
  problem was not noticed before as Lion was also missing a test vector
  in previous releases.

Version 1.10.7, 2013-12-29
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* OAEP had two bugs, one of which allowed it to be used even if the
  key was too small, and the other of which would cause a crash during
  decryption if the EME data was too large for the associated key.

Version 1.11.6, 2013-12-29
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* The Boost filesystem and asio libraries are now being used by default.
  Pass ``--without-boost`` to ``configure.py`` to disable.

* The default TLS policy no longer allows SSLv3 or RC4.

* OAEP had two bugs, one of which allowed it to be used even if the
  key was too small, and the other of which would cause a crash during
  decryption if the EME data was too large for the associated key.

* GCM mode now uses the Intel clmul instruction when available

* Add the Threefish-512 tweakable block cipher, including an AVX2 version

* Add SIV (from :rfc:`5297`) as a nonce-based AEAD

* Add HKDF (from :rfc:`5869`) using an experimental PRF interface

* Add HTTP utility functions and OCSP online checking

* Add TLS::Policy::acceptable_ciphersuite hook to disable ciphersuites
  on an ad-hoc basis.

* TLS::Session_Manager_In_Memory's constructor now requires a RNG

Version 1.10.6, 2013-11-10
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* The device reading entropy source now attempts to read from all
  available devices. Previously it would break out early if a partial
  read from a blocking source occurred, not continuing to read from a
  non-blocking device. This would cause the library to fall back on
  slower and less reliable techniques for collecting PRNG seed
  material. Reported by Rickard Bellgrim.

* HMAC_RNG (the default PRNG implementation) now automatically reseeds
  itself periodically. Previously reseeds only occurred on explicit
  application request.

* Fix an encoding error in EC_Group when encoding using EC_DOMPAR_ENC_OID.
  Reported by fxdupont on github.

* In EMSA2 and Randpool, avoid calling name() on objects after deleting them if
  the provided algorithm objects are not suitable for use.  Found by Clang
  analyzer, reported by Jeffrey Walton.

* If X509_Store was copied, the u32bit containing how long to cache validation
  results was not initialized, potentially causing results to be cached for
  significant amounts of time. This could allow a certificate to be considered
  valid after its issuing CA's cert expired. Expiration of the end-entity cert
  is always checked, and reading a CRL always causes the status to be reset, so
  this issue does not affect revocation. Found by Coverity scanner.

* Avoid off by one causing a potentially unterminated string to be passed to
  the connect system call if the library was configured to use a very long path
  name for the EGD socket. Found by Coverity Scanner.

* In PK_Encryptor_EME, PK_Decryptor_EME, PK_Verifier, and PK_Key_Agreement,
  avoid dereferencing an unitialized pointer if no engine supported operations
  on the key object given. Found by Coverity scanner.

* Avoid leaking a file descriptor in the /dev/random and EGD entropy sources if
  stdin (file descriptor 0) was closed. Found by Coverity scanner.

* Avoid a potentially undefined operation in the bit rotation operations.  Not
  known to have caused problems under any existing compiler, but might have
  caused problems in the future. Caught by Clang sanitizer, reported by Jeffrey
  Walton.

* Increase default hash iterations from 10000 to 50000 in PBES1 and PBES2

* Add a fix for mips64el builds from Brad Smith.

Version 1.11.5, 2013-11-10
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* The TLS callback signatures have changed - there are now two distinct
  callbacks for application data and alerts. TLS::Client and TLS::Server have
  constructors which continue to accept the old callback and use it for both
  operations.

* The entropy collector that read from randomness devices had two bugs - it
  would break out of the poll as soon as any read succeeded, and it selected on
  each device individually. When a blocking source was first in the device list
  and the entropy pool was running low, the reader might either block in select
  until eventually timing out (continuing on to read from /dev/urandom instead),
  or read just a few bytes, skip /dev/urandom, fail to satisfy the entropy
  target, and the poll would continue using other (slower) sources. This caused
  substantial performance/latency problems in RNG heavy applications. Now all
  devices are selected over at once, with the effect that a full read from
  urandom always occurs, along with however much (if any) output is available
  from blocking sources.

* Previously AutoSeeded_RNG referenced a globally shared PRNG instance.
  Now each instance has distinct state.

* The entropy collector that runs Unix programs to collect statistical
  data now runs multiple processes in parallel, greatly reducing poll
  times on some systems.

* The Randpool RNG implementation was removed.

* All existing cipher mode implementations (such as CBC and XTS) have been
  converted from filters to using the interface previously provided by
  AEAD modes which allows for in-place message
  processing. Code which directly references the filter objects will break, but
  an adaptor filter allows usage through get_cipher as usual.

* An implementation of CCM mode from RFC 3601 has been added, as well as CCM
  ciphersuites for TLS.

* The implementation of OCB mode now supports 64 and 96 bit tags

* Optimized computation of XTS tweaks, producing a substantial speedup

* Add support for negotiating Brainpool ECC curves in TLS

* TLS v1.2 will not negotiate plain SHA-1 signatures by default.

* TLS channels now support sending a ``std::vector``

* Add a generic 64x64->128 bit multiply instruction operation in mul128.h

* Avoid potentially undefined operations in the bit rotation operations. Not
  known to have caused problems under existing compilers but might break in the
  future. Found by Clang sanitizer, reported by Jeffrey Walton.

Version 1.11.4, 2013-07-25
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* CPU specific extensions are now always compiled if support for the
  operations is available at build time, and flags enabling use of
  extra operations (such as SSE2) are only included when compiling
  files which specifically request support. This means, for instance,
  that the SSSE3 and AES-NI implementations of AES are always included
  in x86 builds, relying on runtime cpuid checking to prevent their
  use on CPUs that do not support those operations.

* The default TLS policy now only accepts TLS, to minimize surprise
  for servers which might not expect to negotiate DTLS. Previously a
  server would by default negotiate either protocol type (clients
  would only accept the same protocol type as they
  offered). Applications which use DTLS or combined TLS/DTLS need to
  override ``Policy::acceptable_protocol_version``.

* The TLS channels now accept a new parameter specifying how many
  bytes to preallocate for the record handling buffers, which allows
  an application some control over how much memory is used at runtime
  for a particular connection.

* Applications can now send arbitrary TLS alert messages using
  ``TLS::Channel::send_alert``

* A new TLS policy ``NSA_Suite_B_128`` is available, which
  will negotiate only the 128-bit security NSA Suite B. See
  :rfc:`6460` for more information about Suite B.

* Adds a new interface for benchmarking, ``time_algorithm_ops``,
  which returns a map of operations to operations per second. For
  instance now both encrypt and decrypt speed of a block cipher can be
  checked, as well as the key schedule of all keyed algorithms. It
  additionally supports AEAD modes.

* Rename ARC4 to RC4

Version 1.11.3, 2013-04-11
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Add a new interface for AEAD modes (``AEAD_Mode``).

* Implementations of the OCB and GCM authenticated cipher modes are
  now included.

* Support for TLS GCM ciphersuites is now available.

* A new TLS policy mechanism
  ``TLS::Policy::server_uses_own_ciphersuite_preferences``
  controls how a server chooses a ciphersuite. Previously it always
  chose its most preferred cipher out of the client's list, but this
  can allow configuring a server to choose by the client's preferences
  instead.

* ``Keyed_Filter`` now supports returning a
  ``Key_Length_Specification`` so the full details of what
  keylengths are supported is now available in keyed filters.

* The experimental and rarely used Turing and WiderWAKE stream ciphers
  have been removed

* New functions for symmetric encryption are included in cryptobox.h
  though interfaces and formats are subject to change.

* A new function ``algorithm_kat_detailed`` returns a string
  providing information about failures, instead of just a pass/fail
  indicator as in ``algorithm_kat``.

Version 1.10.5, 2013-03-02
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* A potential crash in the AES-NI implementation of the AES-192 key
  schedule (caused by misaligned loads) has been fixed.

* A previously conditional operation in Montgomery multiplication and
  squaring is now always performed, removing a possible timing
  channel.

* Use correct flags for creating a shared library on OS X under Clang.

* Fix a compile time incompatibility with Visual C++ 2012.

Version 1.11.2, 2013-03-02
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* A bug in the release script caused the ``botan_version.py`` included
  in 1.11.1`` to be invalid, which required a manual edit to fix
  (Bugzilla 226)

* Previously ``clear_mem`` was implemented by an inlined call to
  ``std::memset``. However an optimizing compiler might notice cases
  where the memset could be skipped in cases allowed by the standard.
  Now ``clear_mem`` calls ``zero_mem`` which is compiled separately and
  which zeros out the array through a volatile pointer. It is possible
  some compiler with some optimization setting (especially with
  something like LTO) might still skip the writes. It would be nice if
  there was an automated way to test this.

* The new filter ``Threaded_Fork`` acts like a normal
  ``Fork``, sending its input to a number of different
  filters, but each subchain of filters in the fork runs in its own
  thread. Contributed by Joel Low.

* The default TLS policy formerly preferred AES over RC4, and allowed
  3DES by default. Now the default policy is to negotiate only either
  AES or RC4, and to prefer RC4.

* New TLS ``Blocking_Client`` provides a thread per
  connection style API similar to that provided in 1.10

* The API of ``Credentials_Manager::trusted_certificate_authorities``
  has changed to return a vector of ``Certificate_Store*`` instead of
  ``X509_Certificate``. This allows the list of trusted CAs to be
  more easily updated dynamically or loaded lazily.

* The ``asn1_int.h`` header was split into ``asn1_alt_name.h``,
  ``asn1_attribute.h`` and ``asn1_time.h``.

Version 1.10.4, 2013-01-07
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Avoid a conditional operation in the power mod implementations on if
  a nibble of the exponent was zero or not. This may help protect
  against certain forms of side channel attacks.

* The SRP6 code was checking for invalid values as specified in RFC
  5054, specifically values equal to zero mod p. However SRP would
  accept negative A/B values, or ones larger than p, neither of which
  should occur in a normal run of the protocol. These values are now
  rejected. Credits to Timothy Prepscius for pointing out these values
  are not normally used and probably signal something fishy.

* The return value of version_string is now a compile time constant
  string, so version information can be more easily extracted from
  binaries.

Version 1.11.1, 2012-10-30
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Initial support for DTLS (both v1.0 and v1.2) is available in this
release, though it should be considered highly experimental. Currently
timeouts and retransmissions are not handled.

The ``TLS::Client`` constructor now takes the version to
offer to the server. The policy hook ``TLS::Policy`` function
`pref_version``, which previously controlled this, has been removed.

`TLS::Session_Manager_In_Memory`` now chooses a random
256-bit key at startup and encrypts all sessions (using the existing
`TLS::Session::encrypt`` mechanism) while they are stored in
memory. This is primarily to reduce pressure on locked memory, as each
session normally requires 48 bytes of locked memory for the master
secret, whereas now only 32 bytes are needed total. This change may
also make it slightly harder for an attacker to extract session data
from memory dumps (eg with a cold boot attack).

The keys used in TLS session encryption were previously uniquely
determined by the master key. Now the encrypted session blob includes
two 80 bit salts which are used in the derivation of the cipher and
MAC keys.

The ``secure_renegotiation`` flag is now considered an aspect of the
connection rather than the session, which matches the behavior of
other implementations. As the format has changed, sessions saved to
persistent storage by 1.11.0 will not load in this version and vice
versa. In either case this will not cause any errors, the session will
simply not resume and instead a full handshake will occur.

New policy hooks ``TLS::Policy::acceptable_protocol_version``,
`TLS::Policy::allow_server_initiated_renegotiation``, and
`TLS::Policy::negotiate_heartbeat_support`` were added.

TLS clients were not sending a next protocol message during a session
resumption, which would cause resumption failures with servers that
support NPN if NPN was being offered by the client.

A bug caused heartbeat requests sent by the counterparty during a
handshake to be passed to the application callback as if they were
heartbeat responses.

Support for TLS key material export as specified in :rfc:`5705` has
been added, available via ``TLS::Channel::key_material_export``

A new function ``Public_Key::estimated_strength`` returns
an estimate for the upper bound of the strength of the key. For
instance for an RSA key, it will return an estimate of how many
operations GNFS would take to factor the key.

A new ``Path_Validation_Result`` code has been added
``SIGNATURE_METHOD_TOO_WEAK``. By default signatures created with keys
below 80 bits of strength (as estimated by ``estimated_strength``) are
rejected. This level can be modified using a parameter to the
``Path_Validation_Restrictions`` constructor.

The SRP6 code was checking for invalid values as specified in
:rfc:`5054`, ones equal to zero mod p, however it would accept
negative A/B values, or ones larger than p, neither of which should
occur in a normal run of the protocol. These values are now
rejected. Credits to Timothy Prepscius for pointing out these values
are not normally used and probably signal something fishy.

Several ``BigInt`` functions have been removed, including
``operator[]``, ``assign``, ``get_reg``, and ``grow_reg``. The version
of ``data`` that returns a mutable pointer has been renamed
``mutable_data``.  Support for octal conversions has been removed.

The constructor ``BigInt(NumberType type, size_t n)`` has been
removed, replaced by ``BigInt::power_of_2``.

In 1.11.0, when compiled by GCC, the AES-NI implementation of AES-192
would crash if the mlock-based allocator was used due to an alignment
issue.

Version 1.11.0, 2012-07-19
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. note::

  In this release, many new features of C++11 are being used in the
  library. Currently GCC 4.7 and Clang 3.1 are known to work well.
  This version of the library cannot be compiled by or used with a
  C++98 compiler.

There have been many changes and improvements to TLS.  The interface
is now purely event driven and does not directly interact with
sockets.  New TLS features include TLS v1.2 support, client
certificate authentication, renegotiation, session tickets, and
session resumption. Session information can be saved in memory or to
an encrypted SQLite3 database. Newly supported TLS ciphersuite
algorithms include using SHA-2 for message authentication, pre shared
keys and SRP for authentication and key exchange, ECC algorithms for
key exchange and signatures, and anonymous DH/ECDH key exchange.

Support for OCSP has been added. Currently only client-side support
exists.

The API for X.509 path validation has changed, with
``x509_path_validate`` in x509path.h now handles path validation and
``Certificate_Store`` handles storage of certificates and CRLs.

The memory container types have changed substantially.  The
``MemoryVector`` and ``SecureVector`` container types have been
removed, and an alias of ``std::vector`` using an allocator that
clears memory named ``secure_vector`` is used for key material, with
plain ``std::vector`` being used for everything else.

The technique used for mlock'ing memory on Linux and BSD systems is
much improved. Now a single page-aligned block of memory (the exact
limit of what we can mlock) is mmap'ed, with allocations being done
using a best-fit allocator and all metadata held outside the mmap'ed
range, in an effort to make best use of the very limited amount of
memory current Linux kernels allow unpriveledged users to lock.

A filter using LZMA was contributed by Vojtech Kral. It is available
if LZMA support was enabled at compilation time by passing
``--with-lzma`` to ``configure.py``.

:rfc:`5915` adds some extended information which can be included in
ECC private keys which the ECC key decoder did not expect, causing an
exception when such a key was loaded. In particular, recent versions
of OpenSSL use these fields. Now these fields are decoded properly,
and if the public key value is included it is used, as otherwise the
public key needs to be rederived from the private key. However the
library does not include these fields on encoding keys for
compatibility with software that does not expect them (including older
versions of botan).

Version 1.8.14, 2012-07-18
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* The malloc allocator would return null instead of throwing in the
  event of an allocation failure, which could cause an application
  crash due to null pointer dereference where normally an exception
  would occur.

* Recent versions of OpenSSL include extra information in ECC private
  keys, the presence of which caused an exception when such a key was
  loaded by botan. The decoding of ECC private keys has been changed to
  ignore these fields if they are set.

* AutoSeeded_RNG has been changed to prefer ``/dev/random`` over
  ``/dev/urandom``

* Fix detection of s390x (Debian bug 638347)

Version 1.10.3, 2012-07-10
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

A change in 1.10.2 accidentally broke ABI compatibility with 1.10.1
and earlier versions, causing programs compiled against 1.10.1 to
crash if linked with 1.10.2 at runtime.

Recent versions of OpenSSL include extra information in ECC private
keys, the presence of which caused an exception when such a key was
loaded by botan. The decoding of ECC private keys has been changed to
ignore these fields if they are set.

Version 1.10.2, 2012-06-17
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Several TLS bugs were fixed in this release, including a major
omission that the renegotiation extension was not being used.  As the
1.10 implementation of TLS does not properly support renegotiation,
the approach in this release is simply to send the renegotiation
extension SCSV, which should protect the client against any handshake
splicing. In addition renegotiation attempts are handled properly
instead of causing handshake failures - all hello requests, and all
client hellos after the initial negotiation, are ignored. Some
bugs affecting DSA server authentication were also fixed.

By popular request, ``Pipe::reset`` no longer requires that message
processing be completed, a requirement that caused problems when a
Filter's end_msg call threw an exception, after which point the Pipe
object was no longer usable.

Support for getting entropy using the rdrand instruction introduced in
Intel's Ivy Bridge processors has been added. In previous releases,
the ``CPUID::has_rdrand`` function was checking the wrong cpuid bit,
and would false positive on AMD Bulldozer processors.

An implementation of SRP-6a compatible with the specification in RFC
5054 is now available in ``srp6.h``. In 1.11, this is being used for
TLS-SRP, but may be useful in other environments as well.

An implementation of the Camellia block cipher was added, again largely
for use in TLS.

If ``clock_gettime`` is available on the system, hres_timer will poll all
the available clock types.

AltiVec is now detected on IBM POWER7 processors and on OpenBSD systems.
The OpenBSD support was contributed by Brad Smith.

The Qt mutex wrapper was broken and would not compile with any recent
version of Qt. Taking this as a clear indication that it is not in use,
it has been removed.

Avoid setting the soname on OpenBSD, as it doesn't support it (Bugzilla 158)

A compilation problem in the dynamic loader that prevented using
dyn_load under MinGW GCC has been fixed.

A common error for people using MinGW is to target GCC on Windows,
however the 'Windows' target assumes the existence of Visual C++
runtime functions which do not exist in MinGW. Now, configuring for
GCC on Windows will cause the configure.py to warn that likely you
wanted to configure for either MinGW or Cygwin, not the generic
Windows target.

A bug in configure.py would cause it to interpret ``--cpu=s390x`` as
``s390``. This may have affected other CPUs as well. Now configure.py
searches for an exact match, and only if no exact match is found will
it search for substring matches.

An incompatibility in configure.py with the subprocess module included
in Python 3.1 has been fixed (Bugzilla 157).

The exception catching syntax of configure.py has been changed to the
Python 3.x syntax. This syntax also works with Python 2.6 and 2.7, but
not with any earlier Python 2 release. A simple search and replace
will allow running it under Python 2.5:
``perl -pi -e 's/except (.*) as (.*):/except $1, $2:/g' configure.py``

Note that Python 2.4 is not supported at all.

Version 1.10.1, 2011-07-11
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* A race condition in ``Algorithm_Factory`` could cause crashes in
  multithreaded code.

* The return value of ``name`` has changed for GOST 28147-89 and
  Skein-512.  GOST's ``name`` now includes the name of the sbox, and
  Skein's includes the personalization string (if nonempty). This
  allows an object to be properly roundtripped, which is necessary to
  fix the race condition described above.

* A new distribution script is now included, as
  ``src/build-data/scripts/dist.py``

* The ``build.h`` header now includes, if available, an identifier of
  the source revision that was used. This identifier is also included
  in the result of ``version_string``.

Version 1.8.13, 2011-07-02
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* A race condition in ``Algorithm_Factory`` could cause crashes in
  multithreaded code.

Version 1.10.0, 2011-06-20
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Detection for the rdrand instruction being added to upcoming Intel
  Ivy Bridge processors has been added.

* A template specialization of std::swap was added for the memory
  container types.

Version 1.8.12, 2011-06-20
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
* If EMSA3(Raw) was used for more than one signature, it would produce
  incorrect output.

* Fix the --enable-debug option to configure.py

* Improve OS detection on Cygwin

* Fix compilation under Sun Studio 12 on Solaris

* Fix a memory leak in the constructors of DataSource_Stream and
  DataSink_Stream which would occur if opening the file failed (Bugzilla 144)

Version 1.9.18, 2011-06-03
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Fourth release candidate for 1.10.0

* The GOST 34.10 verification operation was not ensuring that s and r
  were both greater than zero. This could potentially have meant it
  would have accepted an invalid all-zero signature as valid for any
  message. Due to how ECC points are internally represented it instead
  resulted in an exception being thrown.

* A simple multiexponentation algorithm is now used in ECDSA and
  GOST-34.10 signature verification, leading to 20 to 25% improvements
  in ECDSA and 25% to 40% improvements in GOST-34.10 verification
  performance.

* The internal representation of elliptic curve points has been
  modified to use Montgomery representation exclusively, resulting in
  reduced memory usage and a 10 to 20% performance improvement for
  ECDSA and ECDH.

* In OAEP decoding, scan for the delimiter bytes using a loop that is
  written without conditionals so as to help avoid timing analysis.
  Unfortunately GCC at least is 'smart' enough to compile it to
  jumps anyway.

* The SSE2 implementation of IDEA did not work correctly when compiled
  by Clang, because the trick it used to emulate a 16 bit unsigned
  compare in SSE (which doesn't contain one natively) relied on signed
  overflow working in the 'usual' way. A different method that doesn't
  rely on signed overflow is now used.

* Add support for compiling SSL using Visual C++ 2010's TR1
  implementation.

* Fix a bug under Visual C++ 2010 which would cause ``hex_encode`` to
  crash if given a zero-sized input to encode.

* A new build option ``--via-amalgamation`` will first generate the
  single-file amalgamation, then build the library from that single
  file. This option requires a lot of memory and does not parallelize,
  but the resulting library is smaller and may be faster.

* On Unix, the library and header paths have been changed to allow
  parallel installation of different versions of the library. Headers
  are installed into ``<prefix>/include/botan-1.9/botan``, libraries
  are named ``libbotan-1.9``, and ``botan-config`` is now namespaced
  (so in this release ``botan-config-1.9``). All of these embedded
  versions will be 1.10 in the upcoming stable release.

* The soname system has been modified. In this release the library
  soname is ``libbotan-1.9.so.0``, with the full library being named
  ``libbotan-1.9.so.0.18``. The ``0`` is the ABI version, and will be
  incremented whenever a breaking ABI change is made.

* TR1 support is not longer automatically assumed under older versions
  of GCC

* Functions for base64 decoding that work standalone (without needing
  to use a pipe) have been added to ``base64.h``

* The function ``BigInt::to_u32bit`` was inadvertently removed in 1.9.11
  and has been added back.

* The function ``BigInt::get_substring`` did not work correctly with a
  *length* argument of 32.

* The implementation of ``FD_ZERO`` on Solaris uses ``memset`` and
  assumes the caller included ``string.h`` on its behalf. Do so to
  fix compilation in the ``dev_random`` and ``unix_procs`` entropy
  sources. Patch from Jeremy C. Reed.

* Add two different configuration targets for Atom, since some are
  32-bit and some are 64-bit. The 'atom' target now refers to the
  64-bit implementations, use 'atom32' to target the 32-bit
  processors.

* The (incomplete) support for CMS and card verifiable certificates
  are disabled by default; add ``--enable-modules=cms`` or
  ``--enable-modules=cvc`` during configuration to turn them back on.

Version 1.9.17, 2011-04-29
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Third release candidate for 1.10.0

* The format preserving encryption method currently available was
  presented in the header ``fpe.h`` and the functions ``fpe_encrypt``
  and ``fpe_decrypt``. These were renamed as it is likely that other
  FPE schemes will be included in the future. The header is now
  ``fpe_fe1.h``, and the functions are named ``fe1_encrypt`` and
  ``fe1_decrypt``.

* New options to ``configure.py`` control what tools are used for
  documentation generation. The ``--with-sphinx`` option enables using
  Sphinx to convert ReST into HTML; otherwise the ReST sources are
  installed directly. If ``--with-doxygen`` is used, Doxygen will run
  as well. Documentation generation can be triggered via the ``docs``
  target in the makefile; it will also be installed by the install
  target on Unix.

* A bug in 1.9.16 effectively disabled support for runtime CPU feature
  detection on x86 under GCC in that release.

* A mostly internal change, all references to "ia32" and "amd64" have
  been changed to the vendor neutral and probably easier to understand
  "x86-32" and "x86-64". For instance, the "mp_amd64" module has been
  renamed "mp_x86_64", and the macro indicating x86-32 has changed
  from ``BOTAN_TARGET_ARCH_IS_IA32`` to
  ``BOTAN_TARGET_ARCH_IS_X86_32``. The classes calling assembly have
  also been renamed.

* Similiarly to the above change, the AES implemenations using the
  AES-NI instruction set have been renamed from AES_XXX_Intel to
  AES_XXX_NI.

* Systems that are identified as ``sun4u`` will default to compiling for
  32-bit SPARCv9 code rather than 64-bit. This matches the still
  common convention for 32-bit SPARC userspaces. If you want 64-bit
  code on such as system, use ``--cpu=sparc64``.

* Some minor fixes for compiling botan under the BeOS
  clone/continuation `Haiku <http://haiku-os.org>`_.

* Further updates to the documentation

Version 1.9.16, 2011-04-11
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Second release candidate for 1.10.0

* The documentation, previously written in LaTeX, is now in
  reStructuredText suitable for processing by `Sphinx
  <http://sphinx.pocoo.org>`_, which can generate nicely formatted
  HTML and PDFs. The documentation has also been greatly updated and
  expanded.

* The class ``EC_Domain_Params`` has been renamed ``EC_Group``, with a
  typedef for backwards compatibility.

* The ``EC_Group`` string constructor didn't understand the standard
  names like "secp160r1", forcing use of the OIDs.

* Two constructors for ECDSA private keys, the one that creates a new
  random key, and the one that provides a preset private key as a
  ``BigInt``, have been merged. This matches the existing interface
  for DSA and DH keys. If you previously used the version taking a
  ``BigInt`` private key, you'll have to additionally pass in a
  ``RandomNumberGenerator`` object starting in this release.

* It is now possible to create ECDH keys with a preset ``BigInt``
  private key; previously no method for this was available.

* The overload of ``generate_passhash9`` that takes an explicit
  algorithm identifier has been merged with the one that does not.
  The algorithm identifier code has been moved from the second
  parameter to the fourth.

* Change shared library versioning to match the normal Unix
  conventions. Instead of ``libbotan-X.Y.Z.so``, the shared lib is
  named ``libbotan-X.Y.so.Z``; this allows the runtime linker to do
  its runtime linky magic. It can be safely presumed that any change
  in the major or minor version indicates ABI incompatibility.

* Remove the socket wrapper code; it was not actually used by anything
  in the library, only in the examples, and you can use whatever kind
  of (blocking) socket interface you like with the SSL/TLS code. It's
  available as socket.h in the examples directory if you want to use
  it.

* Disable the by-default 'strong' checking of private keys that are
  loaded from storage. You can always request key material sanity
  checking using Private_Key::check_key.

* Bring back removed functions ``min_keylength_of``,
  ``max_keylength_of``, ``keylength_multiple_of`` in ``lookup.h`` to
  avoid breaking applications written against 1.8

Version 1.9.15, 2011-03-21
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* First release candidate for 1.10.0

* Modify how message expansion is done in SHA-256 and SHA-512.
  Instead of expanding the entire message at the start, compute them
  in the minimum number of registers. Values are computed 15 rounds
  before they are needed. On a Core i7-860, GCC 4.5.2, went from 143
  to 157 MiB/s in SHA-256, and 211 to 256 MiB/s in SHA-512.

* Pipe will delete empty output queues as soon as they are no longer
  needed, even if earlier messages still have data unread. However an
  (empty) entry in a deque of pointers will remain until all prior
  messages are completely emptied.

* Avoid reading the SPARC ``%tick`` register on OpenBSD as unlike the
  Linux and NetBSD kernels, it will not trap and emulate it for us,
  causing a illegal instruction crash.

* Improve detection and autoconfiguration for ARM processors. Thanks
  go out to the `Tahoe-LAFS Software Foundation
  <http://tahoe-lafs.org>`_, who donated a Sheevaplug that I'll be
  using to figure out how to make the cryptographic primitives
  Tahoe-LAFS relies on faster, particularly targeting the ARMv5TE.

Version 1.9.14, 2011-03-01
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Add support for bcrypt, OpenBSD's password hashing scheme.

* Add support for NIST's AES key wrapping algorithm, as described in
  :rfc:`3394`. It is available by including ``rfc3394.h``.

* Fix an infinite loop in zlib filters introduced in 1.9.11 (Bugzilla 142)

Version 1.9.13, 2011-02-19
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

GOST 34.10 signatures were being formatted in a way that was not
compatible with other implemenations, and specifically how GOST is
used in DNSSEC.

The Keccak hash function was updated to the tweaked variant proposed
for round 3 of the NIST hash competition. This version is not
compatible with the previous algorithm.

A new option ``--distribution-info`` was added to the configure
script. It allows the user building the library to set any
distribution-specific notes on the build, which are available as a
macro ``BOTAN_DISTRIBUTION_INFO``. The default value is
'unspecified'. If you are building an unmodified version of botan
(especially for distribution), and want to indicate to applications
that this is the case, consider using
``--distribution-info=pristine``. If you are making any patches or
modifications, it is recommended to use
``--distribution-info=[Distribution Name] [Version]``, for instance
'FooNix 1.9.13-r3'.

Some bugs preventing compilation under Clang 2.9 and Sun Studio 12
were fixed.

The DER/BER codecs use ``size_t`` instead of ``u32bit`` for small
integers

Version 1.9.12, 2010-12-13
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Add the Keccak hash function
* Fix compilation problems in Python wrappers
* Fix compilation problem in OpenSSL engine
* Update SQLite3 database encryption codec

Version 1.9.11, 2010-11-29
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* The TLS API has changed substantially and now relies heavily on
  TR1's ``std::function`` is now required. Additionally, it is
  required that all callers derive a subclass of TLS_Policy and pass
  it to a client or server object. Please remember that the TLS
  interface/API is currently unstable and will very likely change
  further before TLS is included in a stable release. A handshake
  failure that occurred when RC4 was negotiated has also been fixed.

* Some possible timing channels in the implementations of Montgomery
  reduction and the IDEA key schedule were removed. The table-based
  AES implementation uses smaller tables in the first round to help
  make some timing/cache attacks harder.

* The library now uses size_t instead of u32bit to represent
  lengths. Also the interfaces for the memory containers have changed
  substantially to better match STL container interfaces;
  MemoryRegion::append, MemoryRegion::destroy, and MemoryRegion::set
  were all removed, and several other functions, like clear and
  resize, have changed meaning.

* Update Skein-512 to match the v1.3 specification
* Fix a number of CRL encoding and decoding bugs
* Counter mode now always encrypts 256 blocks in parallel
* Use small tables in the first round of AES
* Removed AES class: app must choose AES-128, AES-192, or AES-256
* Add hex encoding/decoding functions that can be used without a Pipe
* Add base64 encoding functions that can be used without a Pipe
* Add to_string function to X509_Certificate
* Add support for dynamic engine loading on Windows
* Replace BlockCipher::BLOCK_SIZE attribute with function block_size()
* Replace HashFunction::HASH_BLOCK_SIZE attribute with hash_block_size()
* Move PBKDF lookup to engine system
* The IDEA key schedule has been changed to run in constant time
* Add Algorithm and Key_Length_Specification classes
* Switch default PKCS #8 encryption algorithm from AES-128 to AES-256
* Allow using PBKDF2 with empty passphrases
* Add compile-time deprecation warnings for GCC, Clang, and MSVC
* Support use of HMAC(SHA-256) and CMAC(Blowfish) in passhash9
* Improve support for Intel Atom processors
* Fix compilation problems under Sun Studio and Clang

Version 1.8.11, 2010-11-02
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Fix a number of CRL encoding and decoding bugs
* When building a debug library under VC++, use the debug runtime
* Fix compilation under Sun Studio on Linux and Solaris
* Add several functions for compatibility with 1.9
* In the examples, read most input files as binary
* The Perl build script has been removed in this release

Version 1.8.10, 2010-08-31
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Switch default PKCS #8 encryption algorithm from 3DES to AES-256
* Increase default hash iterations from 2048 to 10000 in PBES1 and PBES2
* Use small tables in the first round of AES
* Add PBKDF typedef and get_pbkdf for better compatibility with 1.9
* Add version of S2K::derive_key taking salt and iteration count
* Enable the /proc-walking entropy source on NetBSD
* Fix the doxygen makefile target

Version 1.9.10, 2010-08-12
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Add a constant-time AES implementation using SSSE3. This code is
  based on public domain assembly written by `Mike Hamburg
  <http://crypto.stanford.edu/vpaes/>`_, and described in his CHES
  2009 paper "Accelerating AES with Vector Permute Instructions". In
  addition to being constant time, it is also significantly faster
  than the table-based implementation on some processors. The current
  code has been tested with GCC 4.5, Visual C++ 2008, and Clang 2.8.

* Support for dynamically loading Engine objects at runtime was also
  added. Currently only system that use ``dlopen``-style dynamic
  linking are supported.

* On GCC 4.3 and later, use the byteswap intrinsic functions.

* Drop support for building with Python 2.4

* Fix benchmarking of block ciphers in ECB mode

* Consolidate the two x86 assembly engines

* Rename S2K to PBKDF

Version 1.9.9, 2010-06-28
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

A new pure virtual function has been added to ``Filter``, ``name``
which simply returns some useful identifier for the object. Any
out-of-tree ``Filter`` implementations will need to be updated.

Add ``Keyed_Filter::valid_iv_length`` which makes it possible to query
as to what IV length(s) a particular filter allows. Previously,
partially because there was no such query mechanism, if a filter did
not support IVs at all, then calls to ``set_iv`` would be silently
ignored. Now an exception about the invalid IV length will be thrown.

The default iteration count for the password based encryption schemes
has been increased from 2048 to 10000. This should make
password-guessing attacks against private keys encrypted with versions
after this release somewhat harder.

New functions for encoding public and private keys to binary,
``X509::BER_encode`` and ``PKCS8::BER_encode`` have been added.

Problems compiling under Apple's version of GCC 4.2.1 and on 64-bit
MIPS systems using GCC 4.4 or later were fixed.

The coverage of Doxygen documentation comments has significantly
improved in this release.

Version 1.8.9, 2010-06-16
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Use constant time multiplication in IDEA

* Avoid possible timing attack against OAEP decoding

* Add new X509::BER_encode and PKCS8::BER_encode

* Enable DLL builds under Windows

* Add Win32 installer support

* Add support for the Clang compiler

* Fix problem in semcem.h preventing build under Clang or GCC 3.4

* Fix bug that prevented creation of DSA groups under 1024 bits

* Fix crash in GMP_Engine if library is shutdown and reinitialized and
  a PK algorithm was used after the second init

* Work around problem with recent binutils in x86-64 SHA-1

* The Perl build script is no longer supported and refuses to run by
  default. If you really want to use it, pass
  ``--i-know-this-is-broken`` to the script.

Version 1.9.8, 2010-06-14
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Add support for wide multiplications on 64-bit Windows
* Use constant time multiplication in IDEA
* Avoid possible timing attack against OAEP decoding
* Removed FORK-256; rarely used and it has been broken
* Rename ``--use-boost-python`` to ``--with-boost-python``
* Skip building shared libraries on MinGW/Cygwin
* Fix creation of 512 and 768 bit DL groups using the DSA kosherizer
* Fix compilation on GCC versions before 4.3 (missing cpuid.h)
* Fix compilation under the Clang compiler

Version 1.9.7, 2010-04-27
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* TLS: Support reading SSLv2 client hellos
* TLS: Add support for SEED ciphersuites (RFC 4162)
* Add Comb4P hash combiner function

* Fix checking of EMSA_Raw signatures with leading 0 bytes, valid
  signatures could be rejected in certain scenarios.

Version 1.9.6, 2010-04-09
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* TLS: Add support for TLS v1.1
* TLS: Support server name indicator extension
* TLS: Fix server handshake
* TLS: Fix server using DSA certificates
* TLS: Avoid timing channel between CBC padding check and MAC verification

Version 1.9.5, 2010-03-29
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Numerous ECC optimizations
* Fix GOST 34.10-2001 X.509 key loading
* Allow PK_Signer's fault protection checks to be toggled off
* Avoid using pool-based locking allocator if we can't mlock
* Remove all runtime options
* New BER_Decoder::{decode_and_check, decode_octet_string_bigint}
* Remove SecureBuffer in favor of SecureVector length parameter
* HMAC_RNG: Perform a poll along with user-supplied entropy
* Fix crash in MemoryRegion if Allocator::get failed
* Fix small compilation problem on FreeBSD

Version 1.9.4, 2010-03-09
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Add the Ajisai SSLv3/TLSv1.0 implementation

* Add GOST 34.10-2001 public key signature scheme
* Add SIMD implementation of Noekeon

* Add SSE2 implementation of IDEA

* Extend Salsa20 to support longer IVs (XSalsa20)

* Perform XTS encryption and decryption in parallel where possible

* Perform CBC decryption in parallel where possible

* Add SQLite3 db encryption codec, contributed by Olivier de Gaalon

* Add a block cipher cascade construction

* Add support for password hashing for authentication (passhash9.h)

* Add support for Win32 high resolution system timers

* Major refactoring and API changes in the public key code

* PK_Signer class now verifies all signatures before releasing them to
  the caller; this should help prevent a wide variety of fault
  attacks, though it does have the downside of hurting signature
  performance, particularly for DSA/ECDSA.

* Changed S2K interface: derive_key now takes salt, iteration count

* Remove dependency on TR1 shared_ptr in ECC and CVC code

* Renamed ECKAEG to its more usual name, ECDH

* Fix crash in GMP_Engine if library is shutdown and reinitialized

* Fix an invalid memory read in MD4

* Fix Visual C++ static builds

* Remove Timer class entirely

* Switch default PKCS #8 encryption algorithm from 3DES to AES-128

* New configuration option, ``--gen-amalgamation``, creates a pair of
  files (``botan_all.cpp`` and ``botan_all.h``) which contain the
  contents of the library as it would have normally been compiled
  based on the set configuration.

* Many headers are now explicitly internal-use-only and are not installed

* Greatly improve the Win32 installer

* Several fixes for Visual C++ debug builds

Version 1.9.3, 2009-11-19
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Add new AES implementation using Intel's AES instruction intrinsics
* Add an implementation of format preserving encryption
* Allow use of any hash function in X.509 certificate creation
* Optimizations for MARS, Skipjack, and AES
* Set macros for available SIMD instructions in build.h
* Add support for using InnoSetup to package Windows builds
* By default build a DLL on Windows

Version 1.8.8, 2009-11-03
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Alter Skein-512 to match the tweaked 1.2 specification
* Fix use of inline asm for access to x86 bswap function
* Allow building the library without AES enabled
* Add 'powerpc64' alias to ppc64 arch for Gentoo ebuild

Version 1.9.2, 2009-11-03
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Add SIMD version of XTEA
* Support both SSE2 and AltiVec SIMD for Serpent and XTEA
* Optimizations for SHA-1 and SHA-2
* Add AltiVec runtime detection
* Fix x86 CPU identification with Intel C++ and Visual C++

Version 1.9.1, 2009-10-23
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Better support for Python and Perl wrappers
* Add an implementation of Blue Midnight Wish (Round 2 tweak version)
* Modify Skein-512 to match the tweaked 1.2 specification
* Add threshold secret sharing (draft-mcgrew-tss-02)
* Add runtime cpu feature detection for x86/x86-64
* Add code for general runtime self testing for hashes, MACs, and ciphers
* Optimize XTEA; twice as fast as before on Core2 and Opteron
* Convert CTR_BE and OFB from filters to stream ciphers
* New parsing code for SCAN algorithm names
* Enable SSE2 optimizations under Visual C++
* Remove all use of C++ exception specifications
* Add support for GNU/Hurd and Clang/LLVM

Version 1.8.7, 2009-09-09
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Fix processing multiple messages in XTS mode
* Add --no-autoload option to configure.py, for minimized builds

Version 1.9.0, 2009-09-09
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Add support for parallel invocation of block ciphers where possible
* Add SSE2 implementation of Serpent
* Add Rivest's package transform (an all or nothing transform)
* Minor speedups to the Turing key schedule
* Fix processing multiple messages in XTS mode
* Add --no-autoload option to configure.py, for minimized builds
* The previously used configure.pl script is no longer supported

Version 1.8.6, 2009-08-13
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Add Cryptobox, a set of simple password-based encryption routines
* Only read world-readable files when walking /proc for entropy
* Fix building with TR1 disabled
* Fix x86 bswap support for Visual C++
* Fixes for compilation under Sun C++
* Add support for Dragonfly BSD (contributed by Patrick Georgi)
* Add support for the Open64 C++ compiler
* Build fixes for MIPS systems running Linux
* Minor changes to license, now equivalent to the FreeBSD/NetBSD license

Version 1.8.5, 2009-07-23
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Change configure.py to work on stock Python 2.4
* Avoid a crash in Skein_512::add_data processing a zero-length input
* Small build fixes for SPARC, ARM, and HP-PA processors
* The test suite now returns an error code from main() if any tests failed

Version 1.8.4, 2009-07-12
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Fix a bug in nonce generation in the Miller-Rabin test

Version 1.8.3, 2009-07-11
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Add a new Python configuration script
* Add the Skein-512 SHA-3 candidate hash function
* Add the XTS block cipher mode from IEEE P1619
* Fix random_prime when generating a prime of less than 7 bits
* Improve handling of low-entropy situations during PRNG seeding
* Change random device polling to prefer /dev/urandom over /dev/random
* Use an input insensitive implementation of same_mem instead of memcmp
* Correct DataSource::discard_next to return the number of discarded bytes
* Provide a default value for AutoSeeded_RNG::reseed
* Fix Gentoo bug 272242

Version 1.8.2, 2009-04-07
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Make entropy polling more flexible and in most cases faster
* GOST 28147 now supports multiple sbox parameters
* Added the GOST 34.11 hash function
* Fix botan-config problems on MacOS X

Version 1.8.1, 2009-01-20
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Avoid a valgrind warning in es_unix.cpp on 32-bit Linux
* Fix memory leak in PKCS8 load_key and encrypt_key
* Relicense api.tex from CC-By-SA 2.5 to BSD
* Fix botan-config on MacOS X, Solaris

Version 1.8.0, 2008-12-08
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Fix compilation on Solaris with GCC

Version 1.7.24, 2008-12-01
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Fix a compatibility problem with SHA-512/EMSA3 signature padding
* Fix bug preventing EGD/PRNGD entropy poller from working
* Fix integer overflow in Pooling_Allocator::get_more_core (bug id #27)
* Add EMSA3_Raw, a variant of EMSA3 called CKM_RSA_PKCS in PKCS #11
* Add support for SHA-224 in EMSA2 and EMSA3 PK signature padding schemes
* Add many more test vectors for RSA with EMSA2, EMSA3, and EMSA4
* Wrap private structs in SSE2 SHA-1 code in anonymous namespace
* Change configure.pl's CPU autodetection output to be more consistent
* Disable using OpenSSL's AES due to crashes of unknown cause
* Fix warning in /proc walking entropy poller
* Fix compilation with IBM XLC for Cell 0.9-200709

Version 1.7.23, 2008-11-23
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Change to use TR1 (thus enabling ECDSA) with GCC and ICC
* Optimize almost all hash functions, especially MD4 and Tiger
* Add configure.pl options --{with,without}-{bzip2,zlib,openssl,gnump}
* Change Timer to be pure virtual, and add ANSI_Clock_Timer
* Cache socket descriptors in the EGD entropy source
* Avoid bogging down startup in /proc walking entropy source
* Remove Buffered_EntropySource helper class
* Add a Default_Benchmark_Timer typedef in benchmark.h
* Add examples using benchmark.h and Algorithm_Factory
* Add ECC tests from InSiTo
* Minor documentation updates

Version 1.7.22, 2008-11-17
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Add provider preferences to Algorithm_Factory
* Fix memory leaks in PBE_PKCS5v20 and get_pbe introduced in 1.7.21
* Optimize AES encryption and decryption (about 10% faster)
* Enable SSE2 optimized SHA-1 implementation on Intel Prescott CPUs
* Fix nanoseconds overflow in benchmark code
* Remove Engine::add_engine

Version 1.7.21, 2008-11-11
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Make algorithm lookup much more configuable
* Add facilities for runtime performance testing of algorithms
* Drop use of entropy estimation in the PRNGs
* Increase intervals between HMAC_RNG automatic reseeding
* Drop InitializerOptions class, all options but thread safety

Version 1.7.20, 2008-11-09
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Namespace pkg-config file by major and minor versions
* Cache device descriptors in Device_EntropySource
* Split base.h into {block_cipher,stream_cipher,mac,hash}.h
* Removed get_mgf function from lookup.h

Version 1.7.19, 2008-11-06
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Add HMAC_RNG, based on a design by Hugo Krawczyk
* Optimized the Turing stream cipher (about 20% faster on x86-64)
* Modify Randpool's reseeding algorithm to poll more sources
* Add a new AutoSeeded_RNG in auto_rng.h
* OpenPGP_S2K changed to take hash object instead of name
* Add automatic identification for Intel's Prescott processors

Version 1.7.18, 2008-10-22
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Add Doxygen comments from InSiTo
* Add ECDSA and ECKAEG benchmarks
* Add configure.pl switch --with-tr1-implementation
* Fix configure.pl's --with-endian and --with-unaligned-mem options
* Added support for pkg-config
* Optimize byteswap with x86 inline asm for Visual C++ by Yves Jerschow
* Use const references to avoid copying overhead in CurveGFp, GFpModulus

Version 1.7.17, 2008-10-12
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Add missing ECDSA object identifiers
* Fix error in x86 and x86-64 assembler affecting GF(p) math
* Remove Boost dependency from GF(p) math
* Modify botan-config to not print -L/usr/lib or -L/usr/local/lib
* Add BOTAN_DLL macro to over 30 classes missing it
* Rename the two SHA-2 base classes for consistency

Version 1.7.16, 2008-10-09
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Add several missing pieces needed for ECDSA and ECKAEG
* Add Card Verifiable Certificates from InSiTo
* Add SHA-224 from InSiTo
* Add BSI variant of EMSA1 from InSiTo
* Add GF(p) and ECDSA tests from InSiTo
* Split ECDSA and ECKAEG into distinct modules
* Allow OpenSSL and GNU MP engines to be built with public key algos disabled
* Rename sha256.h to sha2_32.h and sha_64.h to sha2_64.h

Version 1.7.15, 2008-10-07
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Add GF(p) arithmetic from InSiTo
* Add ECDSA and ECKAEG implementations from InSiTo
* Minimize internal dependencies, allowing for smaller build configurations
* Add new User Manual and Architecture Guide from FlexSecure GmbH
* Alter configure.pl options for better autotools compatibility
* Update build instructions for recent changes to configure.pl
* Fix CPU detection using /proc/cpuinfo

Version 1.7.14, 2008-09-30
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Split library into parts allowing modular builds
* Add (very preliminary) CMS support to the main library
* Some constructors now require object pointers instead of names
* Support multiple implementations of the same algorithm
* Build support for Pentium-M processors, from Derek Scherger
* Build support for MinGW/MSYS, from Zbigniew Zagorski
* Use inline assembly for bswap on 32-bit x86

Version 1.7.13, 2008-09-27
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Add SSLv3 MAC, SSLv3 PRF, and TLS v1.0 PRF from Ajisai
* Allow all examples to compile even if compression not enabled
* Make CMAC's polynomial doubling operation a public class method
* Use the -m64 flag when compiling with Sun Forte on x86-64
* Clean up and slightly optimize CMAC::final_result

Version 1.7.12, 2008-09-18
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Add x86 assembly for Visual Studio C++, by Luca Piccarreta
* Add a Perl XS module, by Vaclav Ovsik
* Add SWIG-based wrapper for Botan
* Add SSE2 implementation of SHA-1, by Dean Gaudet
* Remove the BigInt::sig_words cache due to bugs
* Combined the 4 Blowfish sboxes, suggested by Yves Jerschow
* Changed BigInt::grow_by and BigInt::grow_to to be non-const
* Add private assignment operators to classes that don't support assignment
* Benchmark RSA encryption and signatures
* Added test programs for random_prime and ressol
* Add high resolution timers for IA-64, HP-PA, S390x
* Reduce use of the RNG during benchmarks
* Fix builds on STI Cell PPU
* Add support for IBM's XLC compiler
* Add IETF 8192 bit MODP group

Version 1.7.11, 2008-09-11
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Added the Salsa20 stream cipher
* Optimized Montgomery reduction, Karatsuba squaring
* Added 16x16->32 word Comba multiplication and squaring
* Use a much larger Karatsuba cutoff point
* Remove bigint_mul_add_words
* Inlined several BigInt functions
* Add useful information to the generated build.h
* Rename alg_{ia32,amd64} modules to asm_{ia32,amd64}
* Fix the Windows build

Version 1.7.10, 2008-09-05
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Public key benchmarks run using a selection of random keys
* New benchmark timer options are clock_gettime, gettimeofday, times, clock
* Including reinterpret_cast optimization for xor_buf in default header
* Split byte swapping and word rotation functions into distinct headers
* Add IETF modp 6144 group and 2048 and 3072 bit DSS groups
* Optimizes BigInt right shift
* Add aliases in DL_Group::Format enum
* BigInt now caches the significant word count

Version 1.6.5, 2008-08-27
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Add noexec stack marker for GNU linker in assembly code
* Fix autoconfiguration problem on x86 with GCC 4.2 and 4.3

Version 1.7.9, 2008-08-27
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Make clear() in most algorithm base classes a pure virtual
* Add noexec stack marker for GNU linker in assembly code
* Avoid string operations in ressol
* Compilation fixes for MinGW and Visual Studio C++ 2008
* Some autoconfiguration fixes for Windows

Version 1.7.8, 2008-07-15
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Added the block cipher Noekeon
* Remove global deref_alias function
* X509_Store takes timeout options as constructor arguments
* Add Shanks-Tonelli algorithm, contributed by FlexSecure GmbH
* Extend random_prime() for generating primes of any bit length
* Remove Config class
* Allow adding new entropy via base RNG interface
* Reseeding a X9.31 PRNG also reseeds the underlying PRNG

Version 1.7.7, 2008-06-28
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Remove the global PRNG object
* The PK filter objects were removed
* Add a test suite for the ANSI X9.31 PRNG
* Much cleaner and (mostly) thread-safe reimplementation of es_ftw
* Remove both default arguments to ANSI_X931_RNG's constructor
* Remove the randomizing version of OctetString::change
* Make the cipher and MAC to use in Randpool configurable
* Move RandomNumberGenerator declaration to rng.h
* RSA_PrivateKey will not generate keys smaller than 1024 bits
* Fix an error decoding BER UNIVERSAL types with special taggings

Version 1.7.6, 2008-05-05
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Initial support for Windows DLLs, from Joel Low
* Reset the position pointer when a new block is generated in X9.32 PRNG
* Timer objects are now treated as entropy sources
* Moved several ASN.1-related enums from enums.h to an appropriate header
* Removed the AEP module, due to inability to test
* Removed Global_RNG and rng.h
* Removed system_clock
* Removed Library_State::UI and the pulse callback logic

Version 1.7.5, 2008-04-12
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* The API of X509_CA::sign_request was altered to avoid race conditions
* New type Pipe::message_id to represent the Pipe message number
* Remove the Named_Mutex_Holder for a small performance gain
* Removed several unused or rarely used functions from Config
* Ignore spaces inside of a decimal string in BigInt::decode
* Allow using a std::istream to initialize a DataSource_Stream object
* Fix compilation problem in zlib compression module
* The chunk sized used by Pooling_Allocator is now a compile time setting
* The size of random blinding factors is now a compile time setting
* The install target no longer tries to set a particular owner/group

Version 1.7.4, 2008-03-10
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Use unaligned memory read/writes on systems that allow it, for performance
* Assembly for x86-64 for accessing the bswap instruction
* Use larger buffers in ARC4 and WiderWAKE for significant throughput increase
* Unroll loops in SHA-160 for a few percent increase in performance
* Fix compilation with GCC 3.2 in es_ftw and es_unix
* Build fix for NetBSD systems
* Prevent es_dev from being built except on Unix systems

Version 1.6.4, 2008-03-08
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Fix a compilation problem with Visual Studio C++ 2003

Version 1.7.3, 2008-01-23
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* New invocation syntax for configure.pl with several new options
* Support for IPv4 addresses in a subject alternative name
* New fast poll for the generic Unix entropy source (es_unix)
* The es_file entropy source has been replaced by the es_dev module
* The malloc allocator does not inherit from Pooling_Allocator anymore
* The path that es_unix will search in are now fully user-configurable
* Truncate X9.42 PRF output rather than allow counter overflow
* PowerPC is now assumed to be big-endian

Version 1.7.2, 2007-10-13
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Initialize the global library state lazily
* Add plain CBC-MAC for backwards compatibility with old systems
* Clean up some of the self test code
* Throw a sensible exception if a DL_Group is not found
* Truncate KDF2 output rather than allowing counter overflow
* Add newly assigned OIDs for SHA-2 and DSA with SHA-224/256
* Fix a Visual Studio compilation problem in x509stat.cpp

Version 1.6.3, 2007-07-23
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Fix a race condition in the algorithm lookup cache
* Fix problems building the memory pool on some versions of Visual C++

Version 1.7.1, 2007-07-23
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Fix a race condition in the algorithm object cache
* HMAC key schedule optimization
* The build header sets a macro defining endianness, if known
* New word load/store abstraction allowing further optimization
* Modify most of the library to avoid use the C-style casts
* Use higher resolution timers in symmetric benchmarks

Version 1.7.0, 2007-05-19
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* DSA parameter generation now follows FIPS 186-3
* Added OIDs for Rabin-Williams and Nyberg-Rueppel
* Somewhat better support for out of tree builds
* Minor optimizations for RC2 and Tiger
* Documentation updates
* Update the todo list

Version 1.6.2, 2007-03-24
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Fix autodection on Athlon64s running Linux
* Fix builds on QNX and compilers using STLport
* Remove a call to abort() that crept into production

Version 1.6.1, 2007-01-20
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Fix some base64 decoder bugs
* Add a new option to base64 encoding, to always append a newline
* Fix some build problems under Visual Studio with debug enabled
* Fix a bug in BER_Decoder that was triggered under some compilers

Version 1.6.0, 2006-12-17
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Minor cleanups versus 1.5.13

Version 1.5.13, 2006-12-10
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Compilation fixes for the bzip2, zlib, and GNU MP modules
* Better support for Intel C++ and EKOpath C++ on x86-64

Version 1.5.12, 2006-10-27
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Cleanups in the initialization routines
* Add some x86-64 assembly for multiply-add
* Fix problems generating very small (below 384 bit) RSA keys
* Support out of tree builds
* Bring some of the documentation up to date
* More improvements to the Python bindings

Version 1.5.11, 2006-09-10
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Removed the Algorithm base class
* Various cleanups in the public key inheritance hierarchy
* Major overhaul of the configure/build setup
* Added x86 assembler implementations of Serpent and low-level MPI code
* Optimizations for the SHA-1 x86 assembler
* Various improvements to the Python wrappers
* Work around a Visual Studio compiler bug

Version 1.5.10, 2006-08-13
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Add x86 assembler versions of MD4, MD5, and SHA-1
* Expand InitializerOptions' language to support on/off switches
* Fix definition of OID 2.5.4.8; was accidentally changed in 1.5.9
* Fix possible resource leaks in the mmap allocator
* Slightly optimized buffering in MDx_HashFunction
* Initialization failures are dealt with somewhat better
* Add an example implementing Pollard's Rho algorithm
* Better option handling in the test/benchmark tool
* Expand the xor_ciph example to support longer keys
* Some updates to the documentation

Version 1.5.9, 2006-07-12
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Fixed bitrot in the AEP engine
* Fix support for marking certificate/CRL extensions as critical
* Significant cleanups in the library state / initialization code
* LibraryInitializer takes an explicit InitializerOptions object
* Make Mutex_Factory an abstract class, add Default_Mutex_Factory
* Change configuration access to using global_state()
* Add support for global named mutexes throughout the library
* Add some STL wrappers for the delete operator
* Change how certificates are created to be more flexible and general

Version 1.5.8, 2006-06-23
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Many internal cleanups to the X.509 cert/CRL code
* Allow for application code to support new X.509 extensions
* Change the return type of X509_Certificate::{subject,issuer}_info
* Allow for alternate character set handling mechanisms
* Fix a bug that was slowing squaring performance somewhat
* Fix a very hard to hit overflow bug in the C version of word3_muladd
* Minor cleanups to the assembler modules
* Disable es_unix module on FreeBSD due to build problem on FreeBSD 6.1
* Support for GCC 2.95.x has been dropped in this release

Version 1.5.7, 2006-05-28
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Further, major changes to the BER/DER coding system
* Updated the Qt mutex module to use Mutex_Factory
* Moved the library global state object into an anonymous namespace
* Drop the Visual C++ x86 assembly module due to bugs

Version 1.5.6, 2006-03-01
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* The low-level DER/BER coding system was redesigned and rewritten
* Portions of the certificate code were cleaned up internally
* Use macros to substantially clean up the GCC assembly code
* Added 32-bit x86 assembly for Visual C++ (by Luca Piccarreta)
* Avoid a couple of spurious warnings under Visual C++
* Some slight cleanups in X509_PublicKey::key_id

Version 1.5.5, 2006-02-04
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Fixed a potential infinite loop in the memory pool code (Matt Johnston)
* Made Pooling_Allocator::Memory_Block an actual class of sorts
* Some small optimizations to the division and modulo computations
* Cleaned up the implementation of some of the BigInt operators
* Reduced use of dynamic memory allocation in low-level BigInt functions
* A few simplifications in the Randpool mixing function
* Removed power(), as it was not particularly useful (or fast)
* Fixed some annoying bugs in the benchmark code
* Added a real credits file

Version 1.5.4, 2006-01-29
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Integrated x86 and amd64 assembly code, contributed by Luca Piccarreta
* Fixed a memory access off-by-one in the Karatsuba code
* Changed Pooling_Allocator's free list search to a log(N) algorithm
* Merged ModularReducer with its only subclass, Barrett_Reducer
* Fixed sign-handling bugs in some of the division and modulo code
* Renamed the module description files to modinfo.txt
* Further cleanups in the initialization code
* Removed BigInt::add and BigInt::sub
* Merged all the division-related functions into just divide()
* Modified the <mp_asmi.h> functions to allow for better optimizations
* Made the number of bits polled from an EntropySource user configurable
* Avoid including <algorithm> in <botan/secmem.h>
* Fixed some build problems with Sun Forte
* Removed some dead code from bigint_modop
* Fix the definition of same_mem

Version 1.5.3, 2006-01-24
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Many optimizations in the low-level multiple precision integer code
* Added hooks for assembly implementations of the MPI code
* Support for the X.509 issuer alternative name extension in new certs
* Fixed a bug in the decompression modules; found and patched by Matt Johnston
* New Windows mutex module (mux_win32), by Luca Piccarreta
* Changed the Windows timer module to use QueryPerformanceCounter
* mem_pool.cpp was using std::set iterators instead of std::multiset ones
* Fixed a bug in X509_CA preventing users from disabling particular extensions
* Fixed the mp_asm64 module, which was entirely broken in 1.5.2
* Fixed some module build problems on FreeBSD and Tru64

Version 1.4.12, 2006-01-15
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Fixed an off-by-one memory read in MISTY1::key()
* Fixed a nasty memory leak in Output_Buffers::retire()
* Changed maximum HMAC keylength to 1024 bits
* Fixed a build problem in the hardware timer module on 64-bit PowerPC

Version 1.5.2, 2006-01-15
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Fixed an off-by-one memory read in MISTY1::key()
* Fixed a nasty memory leak in Output_Buffers::retire()
* Reimplemented the memory allocator from scratch
* Improved memory caching in Montgomery exponentiation
* Optimizations for multiple precision addition and subtraction
* Fixed a build problem in the hardware timer module on 64-bit PowerPC
* Changed default Karatsuba cutoff to 12 words (was 14)
* Removed MemoryRegion::bits(), which was unused and incorrect
* Changed maximum HMAC keylength to 1024 bits
* Various minor Makefile and build system changes
* Avoid using std::min in <secmem.h> to bypass Windows libc macro pollution
* Switched checks/clock.cpp back to using clock() by default
* Enabled the symmetric algorithm tests, which were accidentally off in 1.5.1
* Removed the Default_Mutex's unused clone() member function

Version 1.5.1, 2006-01-08
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Implemented Montgomery exponentiation
* Implemented generalized Karatsuba multiplication and squaring
* Implemented Comba squaring for 4, 6, and 8 word inputs
* Added new Modular_Exponentiator and Power_Mod classes
* Removed FixedBase_Exp and FixedExponent_Exp
* Fixed a performance regression in get_allocator introduced in 1.5.0
* Engines can now offer S2K algorithms and block cipher padding methods
* Merged the remaining global 'algolist' code into Default_Engine
* The low-level MPI code is linked as C again
* Replaced BigInt's get_nibble with the more general get_substring
* Some documentation updates

Version 1.5.0, 2006-01-01
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Moved all global/shared library state into a single object
* Mutex objects are created through mutex factories instead of a global
* Removed ::get_mutex(), ::initialize_mutex(), and Mutex::clone()
* Removed the RNG_Quality enum entirely
* There is now only a single global-use PRNG
* Removed the no_aliases and no_oids options for LibraryInitializer
* Removed the deprecated algorithms SEAL, ISAAC, and HAVAL
* Change es_ftw to use unbuffered I/O

Version 1.4.11, 2005-12-31
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Changed Whirlpool diffusion matrix to match updated algorithm spec
* Fixed several engine module build errors introduced in 1.4.10
* Fixed two build problems in es_capi; reported by Matthew Gregan
* Added a constructor to DataSource_Memory taking a std::string
* Placing the same Filter in multiple Pipes triggers an exception
* The configure script accepts --docdir and --libdir
* Merged doc/rngs.txt into the main API document
* Thanks to Joel Low for several bug reports on early tarballs of 1.4.11

Version 1.4.10, 2005-12-18
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Added an implementation of KASUMI, the block cipher used in 3G phones
* Refactored Pipe; output queues are now managed by a distinct class
* Made certain Filter facilities only available to subclasses of Fanout_Filter
* There is no longer any overhead in Pipe for a message that has been read out
* It is now possible to generate RSA keys as small as 128 bits
* Changed some of the core classes to derive from Algorithm as a virtual base
* Changed Randpool to use HMAC instead of a plain hash as the mixing function
* Fixed a bug in the allocators; found and fixed by Matthew Gregan
* Enabled the use of binary file I/O, when requested by the application
* The OpenSSL engine's block cipher code was missing some deallocation calls
* Disabled the es_ftw module on NetBSD, due to header problems there
* Fixed a problem preventing tm_hard from building on MacOS X on PowerPC
* Some cleanups for the modules that use inline assembler
* config.h is now stored in build/ instead of build/include/botan/
* The header util.h was split into bit_ops.h, parsing.h, and util.h
* Cleaned up some redundant include directives

Version 1.4.9, 2005-11-06
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Added the IBM-created AES candidate algorithm MARS
* Added the South Korean block cipher SEED
* Added the stream cipher Turing
* Added the new hash function FORK-256
* Deprecated the ISAAC stream cipher
* Twofish and RC6 are significantly faster with GCC
* Much better support for 64-bit PowerPC
* Added support for high-resolution PowerPC timers
* Fixed a bug in the configure script causing problems on FreeBSD
* Changed ANSI X9.31 to support arbitrary block ciphers
* Make the configure script a bit less noisy
* Added more test vectors for some algorithms, including all the AES finalists
* Various cosmetic source code cleanups

Version 1.4.8, 2005-10-16
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Resolved a bad performance problem in the allocators; fix by Matt Johnston
* Worked around a Visual Studio 2003 compilation problem introduced in 1.4.7
* Renamed OMAC to CMAC to match the official NIST naming
* Added single byte versions of update() to PK_Signer and PK_Verifier
* Removed the unused reverse_bits and reverse_bytes functions

Version 1.4.7, 2005-09-25
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Fixed major performance problems with recent versions of GNU C++
* Added an implementation of the X9.31 PRNG
* Removed the X9.17 and FIPS 186-2 PRNG algorithms
* Changed defaults to use X9.31 PRNGs as global PRNG objects
* Documentation updates to reflect the PRNG changes
* Some cleanups related to the engine code
* Removed two useless headers, base_eng.h and secalloc.h
* Removed PK_Verifier::valid_signature
* Fixed configure/build system bugs affecting MacOS X builds
* Added support for the EKOPath x86-64 compiler
* Added missing destructor for BlockCipherModePaddingMethod
* Fix some build problems with Visual C++ 2005 beta
* Fix some build problems with Visual C++ 2003 Workshop

Version 1.4.6, 2005-03-13
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Fix an error in the shutdown code introduced in 1.4.5
* Setting base/pkcs8_tries to 0 disables the builtin fail-out
* Support for XMPP identifiers in X.509 certificates
* Duplicate entries in X.509 DNs are removed
* More fixes for Borland C++, from Friedemann Kleint
* Add a workaround for buggy iostreams

Version 1.4.5, 2005-02-26
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Add support for AES encryption of private keys
* Minor fixes for PBES2 parameter decoding
* Internal cleanups for global state variables
* GCC 3.x version detection was broken in non-English locales
* Work around a Sun Forte bug affecting mem_pool.h
* Several fixes for Borland C++ 5.5, from Friedemann Kleint
* Removed inclusion of init.h into base.h
* Fixed a major bug in reading from certificate stores
* Cleaned up a couple of mutex leaks
* Removed some left-over debugging code
* Removed SSL3_MAC, SSL3_PRF, and TLS_PRF

Version 1.4.4, 2004-12-02
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Further tweaks to the pooling allocator
* Modified EMSA3 to support SSL/TLS signatures
* Changes to support Qt/QCA, from Justin Karneges
* Moved mux_qt module code into mod_qt
* Fixes for HP-UX from Mike Desjardins

Version 1.4.3, 2004-11-06
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Split up SecureAllocator into Allocator and Pooling_Allocator
* Memory locking allocators are more likely to be used
* Fixed the placement of includes in some modules
* Fixed broken installation procedure
* Fixes in configure script to support alternate install programs
* Modules can specify the minimum version they support

Version 1.4.2, 2004-10-31
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Fixed a major CRL handling bug
* Cipher and hash operations can be offloaded to engines
* Added support for cipher and hash offload in OpenSSL engine
* Improvements for 64-bit CPUs without a widening multiply instruction
* Support for SHA2-* and Whirlpool with EMSA2
* Fixed a long-standing build problem with conflicting include files
* Fixed some examples that hadn't been updated for 1.4.x
* Portability fixes for Solaris, BSD, HP-UX, and others
* Lots of fixes and cleanups in the configure script
* Updated the Gentoo ebuild file

Version 1.4.1, 2004-10-10
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Fixed major errors in the X.509 and PKCS #8 copy_key functions
* Added a LAST_MESSAGE meta-message number for Pipe
* Added new aliases (3DES and DES-EDE) for Triple-DES
* Added some new functions to PK_Verifier
* Cleaned up the KDF interface
* Disabled tm_posix on BSD due to header issues
* Fixed a build problem on PowerPC with GNU C++ pre-3.4

Version 1.4.0, 2004-06-26
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Added the FIPS 186 RNG back
* Added copy_key functions for X.509 public keys and PKCS #8 private keys
* Fixed PKCS #1 signatures with RIPEMD-128
* Moved some code around to avoid warnings with Sun ONE compiler
* Fixed a bug in botan-config affecting OpenBSD
* Fixed some build problems on Tru64, HP-UX
* Fixed compile problems with Intel C++, Compaq C++

Version 1.3.14, 2004-06-12
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Added support for AEP's AEP1000/AEP2000 crypto cards
* Added a Mutex module using Qt, from Justin Karneges
* Added support for engine loading in LibraryInitializer
* Tweaked SecureAllocator, giving 20% better performance under heavy load
* Added timer and memory locking modules for Win32 (tm_win32, ml_win32)
* Renamed PK_Engine to Engine_Core
* Improved the Karatsuba cutoff points
* Fixes for compiling with GCC 3.4 and Sun C++ 5.5
* Fixes for Linux/s390, OpenBSD, and Solaris
* Added support for Linux/s390x
* The configure script was totally broken for 'generic' OS
* Removed Montgomery reduction due to bugs
* Removed an unused header, pkcs8alg.h
* check --validate returns an error code if any tests failed
* Removed duplicate entry in Unix command list for es_unix
* Moved the Cert_Usage enumeration into X509_Store
* Added new timing methods for PK benchmarks, clock_gettime and RDTSC
* Fixed a few minor bugs in the configure script
* Removed some deprecated functions from x509cert.h and pkcs10.h
* Removed the 'minimal' module, has to be updated for Engine support
* Changed MP_WORD_BITS macro to BOTAN_MP_WORD_BITS to clean up namespace
* Documentation updates

Version 1.3.13, 2004-05-15
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Major fixes for Cygwin builds
* Minor MacOS X install fixes
* The configure script is a little better at picking the right modules
* Removed ml_unix from the 'unix' module set for Cygwin compatibility
* Fixed a stupid compile problem in pkcs10.h

Version 1.3.12, 2004-05-02
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Added ability to remove old entries from CRLs
* Swapped the first two arguments of X509_CA::update_crl()
* Added an < operator for MemoryRegion, so it can be used as a std::map key
* Changed X.509 searching by DNS name from substring to full string compares
* Renamed a few X509_Certificate and PKCS10_Request member functions
* Fixed a problem when decoding some PKCS #10 requests
* Hex_Decoder would not check inputs, reported by Vaclav Ovsik
* Changed default CRL expire time from 30 days to 7 days
* X509_CRL's default PEM header is now "X509 CRL", for OpenSSL compatibility
* Corrected errors in the API doc, fixes from Ken Perano
* More documentation about the Pipe/Filter code

Version 1.3.11, 2004-04-01
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Fixed two show-stopping bugs in PKCS10_Request
* Added some sanity checks in Pipe/Filter
* The DNS and URI entries would get swapped in subjectAlternativeNames
* MAC_Filter is now willing to not take a key at creation time
* Setting the expiration times of certs and CRLs is more flexible
* Fixed problems building on AIX with GCC
* Fixed some problems in the tutorial pointed out by Dominik Vogt
* Documentation updates

Version 1.3.10, 2004-03-27
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Added support for OpenPGP's ASCII armor format
* Cleaned up the RNG system; seeding is much more flexible
* Added simple autoconfiguration abilities to configure.pl
* Fixed a GCC 2.95.x compile problem
* Updated the example configuration file
* Documentation updates

Version 1.3.9, 2004-03-07
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Added an engine using OpenSSL (requires 0.9.7 or later)
* X509_Certificate would lose email addresses stored in the DN
* Fixed a missing initialization in a BigInt constructor
* Fixed several Visual C++ compile problems
* Fixed some BeOS build problems
* Fixed the WiderWake benchmark

Version 1.3.8, 2003-12-30
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Initial introduction of engine support, which separates PK keys from
  the underlying operations. An engine using GNU MP was added.

* DSA, DH, NR, and ElGamal constructors accept taking just the private
  key again since the public key is easily derived from it.

* Montgomery reduction support was added.
* ElGamal keys now support being imported/exported as ASN.1 objects
* Added Montgomery reductions
* Added an engine that uses GNU MP (requires 4.1 or later)
* Removed the obsolete mp_gmp module
* Moved several initialization/shutdown functions to init.h
* Major refactoring of the memory containers
* New non-locking container, MemoryVector
* Fixed 64-bit problems in BigInt::set_bit/clear_bit
* Renamed PK_Key::check_params() to check_key()
* Some incompatible changes to OctetString
* Added version checking macros in version.h
* Removed the fips140 module pending rewrite
* Added some functions and hooks to help GUIs
* Moved more shared code into MDx_HashFunction
* Added a policy hook for specifying the encoding of X.509 strings

Version 1.3.7, 2003-12-12
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Fixed a big security problem in es_unix (use of untrusted PATH)
* Fixed several stability problems in es_unix
* Expanded the list of programs es_unix will try to use
* SecureAllocator now only preallocates blocks in special cases
* Added a special case in Global_RNG::seed for forcing a full poll
* Removed the FIPS 186 RNG added in 1.3.5 pending further testing
* Configure updates for PowerPC CPUs
* Removed the (never tested) VAX support
* Added support for S/390 Linux

Version 1.3.6, 2003-12-07
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Added a new module 'minimal', which disables most algorithms
* SecureAllocator allocates a few blocks at startup
* A few minor MPI cleanups
* RPM spec file cleanups and fixes

Version 1.3.5, 2003-11-30
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Major improvements in ASN.1 string handling
* Added partial support for ASN.1 UTF8 STRINGs and BMP STRINGs
* Added partial support for the X.509v3 certificate policies extension
* Centralized the handling of character set information
* Added FIPS 140-2 startup self tests
* Added a module (fips140) for doing extra FIPS 140-2 tests
* Added FIPS 186-2 RNG
* Improved ASN.1 BIT STRING handling
* Removed a memory leak in PKCS10_Request
* The encoding of DirectoryString now follows PKIX guidelines
* Fixed some of the character set dependencies
* Fixed a DER encoding error for tags greater than 30
* The BER decoder can now handle tags larger than 30
* Fixed tm_hard.cpp to recognize SPARC on more systems
* Workarounds for a GCC 2.95.x bug in x509find.cpp
* RPM changed to install into /usr instead of /usr/local
* Added support for QNX

Version 1.2.8, 2003-11-21
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Merged several important bug fixes from 1.3.x

Version 1.3.4, 2003-11-21
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Added a module that does certain MPI operations using GNU MP
* Added the X9.42 Diffie-Hellman PRF
* The Zlib and Bzip2 objects now use custom allocators
* Added member functions for directly hashing/MACing SecureVectors
* Minor optimizations to the MPI addition and subtraction algorithms
* Some cleanups in the low-level MPI code
* Created separate AES-{128,192,256} objects

Version 1.3.3, 2003-11-17
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* The library can now be repeatedly initialized and shutdown without crashing
* Fixed an off-by-one error in the CTS code
* Fixed an error in the EMSA4 verification code
* Fixed a memory leak in mutex.cpp (pointed out by James Widener)
* Fixed a memory leak in Pthread_Mutex
* Fixed several memory leaks in the testing code
* Bulletproofed the EMSA/EME/KDF/MGF retrieval functions
* Minor cleanups in SecureAllocator
* Removed a needless mutex guarding the (stateless) global timer
* Fixed a piece of bash-specific code in botan-config
* X.509 objects report more information about decoding errors
* Cleaned up some of the exception handling
* Updated the example config file with new OIDSs
* Moved the build instructions into a separate document, building.tex

Version 1.3.2, 2003-11-13
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Fixed a bug preventing DSA signatures from verifying on X.509 objects
* Made the X509_Store search routines more efficient and flexible
* Added a function to X509_PublicKey to do easy public/private key matching
* Added support for decoding indefinite length BER data
* Changed Pipe's peek() to take an offset
* Removed Filter::set_owns in favor of the new incr_owns function
* Removed BigInt::zero() and BigInt::one()
* Renamed the PEM related options from base/pem_* to pem/*
* Added an option to specify the line width when encoding PEM
* Removed the "rng/safe_longterm" option; it's always on now
* Changed the cipher used for RNG super-encryption from ARC4 to WiderWake4+1
* Cleaned up the base64/hex encoders and decoders
* Added an ASN.1/BER decoder as an example
* AES had its internals marked 'public' in previous versions
* Changed the value of the ASN.1 NO_OBJECT enum
* Various new hacks in the configure script
* Removed the already nominal support for SunOS

Version 1.3.1, 2003-11-04
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Generalized a few pieces of the DER encoder
* PKCS8::load_key would fail if handed an unencrypted key
* Added a failsafe so PKCS #8 key decoding can't go into an infinite loop

Version 1.3.0, 2003-11-02
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Major redesign of the PKCS #8 private key import/export system
* Added a small amount of UI interface code for getting passphrases
* Added heuristics that tell if a key, cert, etc is stored as PEM or BER
* Removed CS-Cipher, SHARK, ThreeWay, MD5-MAC, and EMAC
* Removed certain deprecated constructors of RSA, DSA, DH, RW, NR
* Made PEM decoding more forgiving of extra text before the header

Version 1.2.7, 2003-10-31
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Added support for reading configuration files
* Added constructors so NR and RW keys can be imported easily
* Fixed mp_asm64, which was completely broken in 1.2.6
* Removed tm_hw_ia32 module; replaced by tm_hard
* Added support for loading certain oddly formed RSA certificates
* Fixed spelling of NON_REPUDIATION enum
* Renamed the option default_to_ca to v1_assume_ca
* Fixed a minor bug in X.509 certificate generation
* Fixed a latent bug in the OID lookup code
* Updated the RPM spec file
* Added to the tutorial

Version 1.2.6, 2003-07-04
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Major performance increase for PK algorithms on most 64-bit systems
* Cleanups in the low-level MPI code to support asm implementations
* Fixed build problems with some versions of Compaq's C++ compiler
* Removed useless constructors for NR public and private keys
* Removed support for the patch_file directive in module files
* Removed several deprecated functions

Version 1.2.5, 2003-06-22
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Fixed a tricky and long-standing memory leak in Pipe
* Major cleanups and fixes in the memory allocation system
* Removed alloc_mlock, which has been superseded by the ml_unix module
* Removed a denial of service vulnerability in X509_Store
* Fixed compilation problems with VS .NET 2003 and Codewarrior 8
* Added another variant of PKCS8::load_key, taking a memory buffer
* Fixed various minor/obscure bugs which occurred when MP_WORD_BITS != 32
* BigInt::operator%=(word) was a no-op if the input was a power of 2
* Fixed portability problems in BigInt::to_u32bit
* Fixed major bugs in SSL3-MAC
* Cleaned up some messes in the PK algorithms
* Cleanups and extensions for OMAC and EAX
* Made changes to the entropy estimation function
* Added a 'beos' module set for use on BeOS
* Officially deprecated a few X509:: and PKCS8:: functions
* Moved the contents of primes.h to numthry.h
* Moved the contents of x509opt.h to x509self.h
* Removed the (empty) desx.h header
* Documentation updates

Version 1.2.4, 2003-05-29
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Fixed a bug in EMSA1 affecting NR signature verification
* Fixed a few latent bugs in BigInt related to word size
* Removed an unused function, mp_add2_nc, from the MPI implementation
* Reorganized the core MPI files

Version 1.2.3, 2003-05-20
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Fixed a bug that prevented DSA/NR key generation
* Fixed a bug that prevented importing some root CA certs
* Fixed a bug in the BER decoder when handing optional bit or byte strings
* Fixed the encoding of authorityKeyIdentifier in X509_CA
* Added a sanity check in PBKDF2 for zero length passphrases
* Added versions of X509::load_key and PKCS8::load_key that take a file name
* X509_CA generates 128 bit serial numbers now
* Added tests to check PK key generation
* Added a simplistic X.509 CA example
* Cleaned up some of the examples

Version 1.2.2, 2003-05-13
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Add checks to prevent any BigInt bugs from revealing an RSA or RW key
* Changed the interface of Global_RNG::seed
* Major improvements for the es_unix module
* Added another Win32 entropy source, es_win32
* The Win32 CryptoAPI entropy source can now poll multiple providers
* Improved the BeOS entropy source
* Renamed pipe_unixfd module to fd_unix
* Fixed a file descriptor leak in the EGD module
* Fixed a few locking bugs

Version 1.2.1, 2003-05-06
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Added ANSI X9.23 compatible CBC padding
* Added an entropy source using Win32 CryptoAPI
* Removed the Pipe I/O operators taking a FILE*
* Moved the BigInt encoding/decoding functions into the BigInt class
* Integrated several fixes for VC++ 7 (from Hany Greiss)
* Fixed the configure.pl script for Windows builds

Version 1.2.0, 2003-04-28
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Tweaked the Karatsuba cut-off points
* Increased the allowed keylength of HMAC and Blowfish
* Removed the 'mpi_ia32' module, pending rewrite
* Workaround a GCC 2.95.x bug in eme1.cpp

Version 1.1.13, 2003-04-22
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Added OMAC
* Added EAX authenticated cipher mode
* Diffie-Hellman would not do blinding in some cases
* Optimized the OFB and CTR modes
* Corrected Skipjack's word ordering, as per NIST clarification
* Support for all subject/issuer attribute types required by RFC 3280
* The removeFromCRL CRL reason code is now handled correctly
* Increased the flexibility of the allocators
* Renamed Rijndael to AES, created aes.h, deleted rijndael.h
* Removed support for the 'no_timer' LibraryInitializer option
* Removed 'es_pthr' module, pending further testing
* Cleaned up get_ciph.cpp

Version 1.1.12, 2003-04-15
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Fixed a ASN.1 string encoding bug
* Fixed a pair of X509_DN encoding problems
* Base64_Decoder and Hex_Decoder can now validate input
* Removed support for the LibraryInitializer option 'egd_path'
* Added tests for DSA X.509 and PKCS #8 key formats
* Removed a long deprecated feature of DH_PrivateKey's constructor
* Updated the RPM .spec file
* Major documentation updates

Version 1.1.11, 2003-04-07
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Added PKCS #10 certificate requests
* Changed X509_Store searching interface to be more flexible
* Added a generic Certificate_Store interface
* Added a function for generating self-signed X.509 certs
* Cleanups and changes to X509_CA
* New examples for PKCS #10 and self-signed certificates
* Some documentation updates

Version 1.1.10, 2003-04-03
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* X509_CA can now generate new X.509 CRLs
* Added blinding for RSA, RW, DH, and ElGamal to prevent timing attacks
* More certificate and CRL extensions/attributes are supported
* Better DN handling in X.509 certificates/CRLs
* Added a DataSink hierarchy (suggested by Jim Darby)
* Consolidated SecureAllocator and ManagedAllocator
* Many cleanups and generalizations
* Added a (slow) pthreads based EntropySource
* Fixed some threading bugs

Version 1.1.9, 2003-02-25
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Added support for using X.509v2 CRLs
* Fixed several bugs in the path validation algorithm
* Certificates can be verified for a particular usage
* Algorithm for comparing distinguished names now follows X.509
* Cleaned up the code for the es_beos, es_ftw, es_unix modules
* Documentation updates

Version 1.1.8, 2003-01-29
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Fixes for the certificate path validation algorithm in X509_Store
* Fixed a bug affecting X509_Certificate::is_ca_cert()
* Added a general configuration interface for policy issues
* Cleanups and API changes in the X.509 CA, cert, and store code
* Made various options available for X509_CA users
* Changed X509_Time's interface to work around time_t problems
* Fixed a theoretical weakness in Randpool's entropy mixing function
* Fixed problems compiling with GCC 2.95.3 and GCC 2.96
* Fixed a configure bug (reported by Jon Wilson) affecting MinGW

Version 1.0.2, 2003-01-12
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Fixed an obscure SEGFAULT causing bug in Pipe
* Fixed an obscure but dangerous bug in SecureVector::swap

Version 1.1.7, 2003-01-12
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Fixed an obscure but dangerous bug in SecureVector::swap
* Consolidated SHA-384 and SHA-512 to save code space
* Added SSL3-MAC and SSL3-PRF
* Documentation updates, including a new tutorial

Version 1.1.6, 2002-12-10
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Initial support for X.509v3 certificates and CAs
* Major redesign/rewrite of the ASN.1 encoding/decoding code
* Added handling for DSA/NR signatures encoded as DER SEQUENCEs
* Documented the generic cipher lookup interface
* Added an (untested) entropy source for BeOS
* Various cleanups and bug fixes

Version 1.1.5, 2002-11-17
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Added the discrete logarithm integrated encryption system (DLIES)
* Various optimizations for BigInt
* Added support for assembler optimizations in modules
* Added BigInt x86 optimizations module (mpi_ia32)

Version 1.1.4, 2002-11-10
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Speedup of 15-30% for PK algorithms
* Implemented the PBES2 encryption scheme
* Fixed a potential bug in decoding RSA and RW private keys
* Changed the DL_Group class interface to handle different formats better
* Added support for PKCS #3 encoded DH parameters
* X9.42 DH parameters use a PEM label of 'X942 DH PARAMETERS'
* Added key pair consistency checking
* Fixed a compatibility problem with gcc 2.96 (pointed out by Hany Greiss)
* A botan-config script is generated at configure time
* Documentation updates

Version 1.1.3, 2002-11-03
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Added a generic public/private key loading interface
* Fixed a small encoding bug in RSA, RW, and DH
* Changed the PK encryption/decryption interface classes
* ECB supports using padding methods
* Added a function-based interface for library initialization
* Added support for RIPEMD-128 and Tiger PKCS#1 v1.5 signatures
* The cipher mode benchmarks now use 128-bit AES instead of DES
* Removed some obsolete typedefs
* Removed OpenCL support (opencl.h, the OPENCL_* macros, etc)
* Added tests for PKCS #8 encoding/decoding
* Added more tests for ECB and CBC

Version 1.1.2, 2002-10-21
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Support for PKCS #8 encoded RSA, DSA, and DH private keys
* Support for Diffie-Hellman X.509 public keys
* Major reorganization of how X.509 keys are handled
* Added PKCS #5 v2.0's PBES1 encryption scheme
* Added a generic cipher lookup interface
* Added the WiderWake4+1 stream cipher
* Added support for sync-able stream ciphers
* Added a 'paranoia level' option for the LibraryInitializer
* More security for RNG output meant for long term keys
* Added documentation for some of the new 1.1.x features
* CFB's feedback argument is now specified in bits
* Renamed CTR class to CTR_BE
* Updated the RSA and DSA examples to use X.509 and PKCS #8 key formats

Version 1.1.1, 2002-10-15
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Added the Korean hash function HAS-160
* Partial support for RSA and DSA X.509 public keys
* Added a mostly functional BER encoder/decoder
* Added support for non-deterministic MAC functions
* Initial support for PEM encoding/decoding
* Internal cleanups in the PK algorithms
* Several new convenience functions in Pipe
* Fixed two nasty bugs in Pipe
* Messed with the entropy sources for es_unix
* Discrete logarithm groups are checked for safety more closely now
* For compatibility with GnuPG, ElGamal now supports DSA-style groups

Version 1.0.1, 2002-09-14
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Fixed a minor bug in Randpool::random()
* Added some new aliases and typedefs for 1.1.x compatibility
* The 4096-bit RSA benchmark key was decimal instead of hex
* EMAC was returning an incorrect name

Version 1.1.0, 2002-09-14
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Added entropy estimation to the RNGs
* Improved the overall design of both Randpool and ANSI_X917_RNG
* Added a separate RNG for nonce generation
* Added window exponentiation support in power_mod
* Added a get_s2k function and the PKCS #5 S2K algorithms
* Added the TLSv1 PRF
* Replaced BlockCipherModeIV typedef with InitializationVector class
* Renamed PK_Key_Agreement_Scheme to PK_Key_Agreement
* Renamed SHA1 -> SHA_160 and SHA2_x -> SHA_x
* Added support for RIPEMD-160 PKCS#1 v1.5 signatures
* Changed the key agreement scheme interface
* Changed the S2K and KDF interfaces
* Better SCAN compatibility for HAVAL, Tiger, MISTY1, SEAL, RC5, SAFER-SK
* Added support for variable-pass Tiger
* Major speedup for Rabin-Williams key generation

Version 1.0.0, 2002-08-26
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Octal I/O of BigInt is now supported
* Fixed portability problems in the es_egd module
* Generalized IV handling in the block cipher modes
* Added Karatsuba multiplication and k-ary exponentiation
* Fixed a problem in the multiplication routines

Version 0.9.2, 2002-08-18
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* DH_PrivateKey::public_value() was returning the wrong value
* Various BigInt optimizations
* The filters.h header now includes hex.h and base64.h
* Moved Counter mode to ctr.h
* Fixed a couple minor problems with VC++ 7
* Fixed problems with the RPM spec file

Version 0.9.1, 2002-08-10
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Grand rename from OpenCL to Botan
* Major optimizations for the PK algorithms
* Added ElGamal encryption
* Added Whirlpool
* Tweaked memory allocation parameters
* Improved the method of seeding the global RNG
* Moved pkcs1.h to eme_pkcs.h
* Added more test vectors for some algorithms
* Fixed error reporting in the BigInt tests
* Removed Default_Timer, it was pointless
* Added some new example applications
* Removed some old examples that weren't that interesting
* Documented the compression modules

Version 0.9.0, 2002-08-03
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* EMSA4 supports variable salt size
* PK_* can take a string naming the encoding method to use
* Started writing some internals documentation

Version 0.8.7, 2002-07-30
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Fixed bugs in EME1 and EMSA4
* Fixed a potential crash at shutdown
* Cipher modes returned an ill-formed name
* Removed various deprecated types and headers
* Cleaned up the Pipe interface a bit
* Minor additions to the documentation
* First stab at a Visual C++ makefile (doc/Makefile.vc7)

Version 0.8.6, 2002-07-25
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Added EMSA4 (aka PSS)
* Brought the manual up to date; many corrections and additions
* Added a parallel hash function construction
* Lookup supports all available algorithms now
* Lazy initialization of the lookup tables
* Made more discrete logarithm groups available through get_dl_group()
* StreamCipher_Filter supports seeking (if the underlying cipher does)
* Minor optimization for GCD calculations
* Renamed SAFER_SK128 to SAFER_SK
* Removed many previously deprecated functions
* Some now-obsolete functions, headers, and types have been deprecated
* Fixed some bugs in DSA prime generation
* DL_Group had a constructor for DSA-style prime gen but it wasn't defined
* Reversed the ordering of the two arguments to SEAL's constructor
* Fixed a threading problem in the PK algorithms
* Fixed a minor memory leak in lookup.cpp
* Fixed pk_types.h (it was broken in 0.8.5)
* Made validation tests more verbose
* Updated the check and example applications

Version 0.8.5, 2002-07-21
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Major changes to constructors for DL-based cryptosystems (DSA, NR, DH)
* Added a DL_Group class
* Reworking of the pubkey internals
* Support in lookup for aliases and PK algorithms
* Renamed CAST5 to CAST_128 and CAST256 to CAST_256
* Added EMSA1
* Reorganization of header files
* LibraryInitializer will install new allocator types if requested
* Fixed a bug in Diffie-Hellman key generation
* Did a workaround in pipe.cpp for GCC 2.95.x on Linux
* Removed some debugging code from init.cpp that made FTW ES useless
* Better checking for invalid arguments in the PK algorithms
* Reduced Base64 and Hex default line length (if line breaking is used)
* Fixes for HP's aCC compiler
* Cleanups in BigInt

Version 0.8.4, 2002-07-14
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Added Nyberg-Rueppel signatures
* Added Diffie-Hellman key exchange (kex interface is subject to change)
* Added KDF2
* Enhancements to the lookup API
* Many things formerly taking pointers to algorithms now take names
* Speedups for prime generation
* LibraryInitializer has support for seeding the global RNG
* Reduced SAFER-SK128 memory consumption
* Reversed the ordering of public and private key values in DSA constructor
* Fixed serious bugs in MemoryMapping_Allocator
* Fixed memory leak in Lion
* FTW_EntropySource was not closing the files it read
* Fixed line breaking problem in Hex_Encoder

Version 0.8.3, 2002-06-09
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Added DSA and Rabin-Williams signature schemes
* Added EMSA3
* Added PKCS#1 v1.5 encryption padding
* Added Filters for PK algorithms
* Added a Keyed_Filter class
* LibraryInitializer processes arguments now
* Major revamp of the PK interface classes
* Changed almost all of the Filters for non-template operation
* Changed HMAC, Lion, Luby-Rackoff to non-template classes
* Some fairly minor BigInt optimizations
* Added simple benchmarking for PK algorithms
* Added hooks for fixed base and fixed exponent modular exponentiation
* Added some examples for using RSA
* Numerous bugfixes and cleanups
* Documentation updates

Version 0.8.2, 2002-05-18
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Added an (experimental) algorithm lookup interface
* Added code for directly testing BigInt
* Added SHA2-384
* Optimized SHA2-512
* Major optimization for Adler32 (thanks to Dan Nicolaescu)
* Various minor optimizations in BigInt and related areas
* Fixed two bugs in X9.19 MAC, both reported by Darren Starsmore
* Fixed a bug in BufferingFilter
* Made a few fixes for MacOS X
* Added a workaround in configure.pl for GCC 2.95.x
* Better support for PowerPC, ARM, and Alpha
* Some more cleanups

Version 0.8.1, 2002-05-06
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Major code cleanup (check doc/deprecated.txt)
* Various bugs fixed, including several portability problems
* Renamed MessageAuthCode to MessageAuthenticationCode
* A replacement for X917 is in x917_rng.h
* Changed EMAC to non-template class
* Added ANSI X9.19 compatible CBC-MAC
* TripleDES now supports 128 bit keys

Version 0.8.0, 2002-04-24
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Merged BigInt: many bugfixes and optimizations since alpha2
* Added RSA (rsa.h)
* Added EMSA2 (emsa2.h)
* Lots of new interface code for public key algorithms (pk_base.h, pubkey.h)
* Changed some interfaces, including SymmetricKey, to support the global rng
* Fixed a serious bug in ManagedAllocator
* Renamed RIPEMD128 to RIPEMD_128 and RIPEMD160 to RIPEMD_160
* Removed some deprecated stuff
* Added a global random number generator (rng.h)
* Added clone functions to most of the basic algorithms
* Added a library initializer class (init.h)
* Version macros in version.h
* Moved the base classes from opencl.h to base.h
* Renamed the bzip2 module to comp_bzip2 and zlib to comp_zlib
* Documentation updates for the new stuff (still incomplete)
* Many new deprecated things: check doc/deprecated.txt

Version 0.7.10, 2002-04-07
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Added EGD_EntropySource module (es_egd)
* Added a file tree walking EntropySource (es_ftw)
* Added MemoryLocking_Allocator module (alloc_mlock)
* Renamed the pthr_mux, unix_rnd, and mmap_mem modules
* Changed timer mechanism; the clock method can be switched on the fly.
* Renamed MmapDisk_Allocator to MemoryMapping_Allocator
* Renamed ent_file.h to es_file.h (ent_file.h is around, but deprecated)
* Fixed several bugs in MemoryMapping_Allocator
* Added more default sources for Unix_EntropySource
* Changed SecureBuffer to use same allocation methods as SecureVector
* Added bigint_divcore into mp_core to support BigInt alpha2 release
* Removed some Pipe functions deprecated since 0.7.8
* Some fixes for the configure program

Version 0.7.9, 2002-03-19
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Memory allocation substantially revamped
* Added memory allocation method based on mmap(2) in the mmap_mem module
* Added ECB and CTS block cipher modes (ecb.h, cts.h)
* Added a Mutex interface (mutex.h)
* Added module pthr_mux, implementing the Mutex interface
* Added Threaded Filter interface (thr_filt.h)
* All algorithms can now by keyed with SymmetricKey objects
* More testing occurs with --validate (expected failures)
* Fixed two bugs reported by Hany Greiss, in Luby-Rackoff and RC6
* Fixed a buffering bug in Bzip_Decompress and Zlib_Decompress
* Made X917 safer (and about 1/3 as fast)
* Documentation updates

Version 0.7.8, 2002-02-28
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* More capabilities for Pipe, inspired by SysV STREAMS, including peeking,
  better buffering, and stack ops. NOT BACKWARDS COMPATIBLE: SEE DOCUMENTATION
* Added a BufferingFilter class
* Added popen() based EntropySource for generic Unix systems (unix_rnd)
* Moved 'devrand' module into main distribution (ent_file.h), renamed to
  File_EntropySource, and changed interface somewhat.
* Made Randpool somewhat more conservative and also 25% faster
* Minor fixes and updates for the configure script
* Added some tweaks for memory allocation
* Documentation updates for the new Pipe interface
* Fixed various minor bugs
* Added a couple of new example programs (stack and hasher2)

Version 0.7.7, 2001-11-24
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Filter::send now works in the constructor of a Filter subclass
* You may now have to include <opencl/pipe.h> explicitly in some code
* Added preliminary PK infrastructure classes in pubkey.h and pkbase.h
* Enhancements to SecureVector (append, destroy functions)
* New infrastructure for secure memory allocation
* Added IEEE P1363 primitives MGF1, EME1, KDF1
* Rijndael optimizations and cleanups
* Changed CipherMode<B> to BlockCipherMode(B*)
* Fixed a nasty bug in pipe_unixfd
* Added portions of the BigInt code into the main library
* Support for VAX, SH, POWER, PowerPC-64, Intel C++

Version 0.7.6, 2001-10-14
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Fixed several serious bugs in SecureVector created in 0.7.5
* Square optimizations
* Fixed shared objects on MacOS X and HP-UX
* Fixed static libs for KCC 4.0; works with KCC 3.4g as well
* Full support for Athlon and K6 processors using GCC
* Added a table of prime numbers < 2**16 (primes.h)
* Some minor documentation updates

Version 0.7.5, 2001-08-19
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Split checksum.h into adler32.h, crc24.h, and crc32.h
* Split modes.h into cbc.h, cfb.h, and ofb.h
* CBC_wPadding* has been replaced by CBC_Encryption and CBC_Decryption
* Added OneAndZeros and NoPadding methods for CBC
* Added Lion, a very fast block cipher construction
* Added an S2K base class (s2k.h) and an OpenPGP_S2K class (pgp_s2k.h)
* Basic types (ciphers, hashes, etc) know their names now (call name())
* Changed the EntropySource type somewhat
* Big speed-ups for ISAAC, Adler32, CRC24, and CRC32
* Optimized CAST-256, DES, SAFER-SK, Serpent, SEAL, MD2, and RIPEMD-160
* Some semantics of SecureVector have changed slightly
* The mlock module has been removed for the time being
* Added string handling functions for hashes and MACs
* Various non-user-visible cleanups
* Shared library soname is now set to the full version number

Version 0.7.4, 2001-07-15
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* New modules: Zlib, gettimeofday and x86 RTC timers, Unix I/O for Pipe
* Fixed a vast number of errors in the config script/makefile/specfile
* Pipe now has a stdio(3) interface as well as C++ iostreams
* ARC4 supports skipping the first N bytes of the cipher stream (ala MARK4)
* Bzip2 supports decompressing multiple concatenated streams, and flushing
* Added a simple 'overall average' score to the benchmarks
* Fixed a small bug in the POSIX timer module
* Removed a very-unlikely-to-occur bug in most of the hash functions
* filtbase.h now includes <iosfwd>, not <iostream>
* Minor documentation updates

Version 0.7.3, 2001-06-08
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Fix build problems on Solaris/SPARC
* Fix build problems with Perl versions < 5.6
* Fixed some stupid code that broke on a few compilers
* Added string handling functions to Pipe
* MISTY1 optimizations

Version 0.7.2, 2001-06-03
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Build system supports modules
* Added modules for mlock, a /dev/random EntropySource, POSIX1.b timers
* Added Bzip2 compression filter, contributed by Peter Jones
* GNU make no longer required (tested with 4.4BSD pmake and Solaris make)
* Fixed minor bug in several of the hash functions
* Various other minor fixes and changes
* Updates to the documentation

Version 0.7.1, 2001-05-16
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Rewrote configure script: more consistent and complete
* Made it easier to find out parameters of types at run time (opencl.h)
* New functions for finding the version being used (version.h)
* New SymmetricKey interface for Filters (symkey.h)
* InvalidKeyLength now records what the invalid key length was
* Optimized DES, CS-Cipher, MISTY1, Skipjack, XTEA
* Changed GOST to use correct S-box ordering (incompatible change)
* Benchmark code was almost totally rewritten
* Many more entries in the test vector file
* Fixed minor and idiotic bug in check.cpp

Version 0.7.0, 2001-03-01
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* First public release
