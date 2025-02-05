Release Notes
========================================

Version 3.7.1, 2025-02-05
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Revert a change that prevented ``build.h`` from being usable from
  C applications. (GH #4636 #4637)

Version 3.7.0, 2025-02-04
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Add post-quantum scheme Classic McEliece (GH #3883 #4448 #4458 #4508 #4605)

* In TLS enable the hybrid x25519/ML-KEM-768 post quantum secure key
  exchange by default for clients and servers. (GH #4305)

* Support for the pre-standard Kyber-r3 key exchange has been removed from TLS
  (GH #4507 #4403)

* In TLS add support for "pure" ML-KEM key exchange, in addition
  to the existing hybrid ML-KEM + EC suites. (GH #4393)

* Add new EC key constructors (GH #4437 #4563)

* Internal EC optimizations and improvements (GH #4385 #4432 #4436
  #4492 #4479 #4510 #4511 #4512 #4517 #4518 #4532 #4533 #4549 #4550
  #4552 #4556 #4557 #4564 #4566 #4570 #4601 #4604 #4608 #4619 #4624 #4626)

* An important note relating to EC groups, especially for users who do not build
  the library using the default module settings (ie using ``--minimized-build``
  or ``--disable-deprecated-features``). Until 3.7.0, including support for an
  elliptic curve algorithm such as ECDSA also implicitly pulled in support for
  all elliptic curves. This is no longer the case. You can re-enable support for
  specific named curves by adding a ``pcurves`` module, for example
  ``pcurves_secp256r1`` or ``pcurves_brainpool384r1``. Also in 3.7.0, the old
  BigInt based EC arithemtic implementation was moved to ``legacy_ec_point``,
  which is marked as deprecated. Disabling this module will disable support for
  certain (also deprecated) elliptic curves such as "x962_p239v1" and
  "secp224k1". It will also disable support for application specific
  curves. Depending on your usage you may need to enable the ``legacy_ec_point``
  module. (GH #4027)

* Change OID formatting and PK signature padding naming to avoid
  obsolete IEEE 1363 naming (GH #4600)

* Improve performance of RSA private key parsing (GH #4588)

* Fix a regression introduced in 3.6.0 which would cause many P-521
  secret keys to be rejected as invalid due to not having the expected
  length. (GH #4541 #4539)

* Add new operations to EC_AffinePoint (GH #4433 #4503 #4618)

* Add support for PSS-signed certificates using SHA-3 (GH #4610)

* Expose ``PSS_Params`` type (GH #3867 #4606)

* Optimize modular inversions (GH #4569)

* KDF internals modernization (GH #4455)

* Split compiler.h into api.h and compiler.h (GH #4599)

* Deprecate creating uninitialized DL_Group or EC_Group (GH #4598)

* Extend SP800-108 KDFs to support variable length fields (GH #4551)

* TPM 2.0 improvements (GH #4429 #4430 #4482)

* Add support for invoking Entropy Source and DRNG Manager (ESDM) RNG (GH #4309)

* Improve support for baremetal environments (GH #4519 #4521 #4531)

* Fix a bug preventing parsing of OCSP responses containing more than
  one pinned certificate (GH #4536)

* Expand constant-time testing in CI to cover both GCC and Clang,
  and multiple optimization levels. (GH #4421)

* Allow configuring at build time how constant-time value barriers
  are implemented. (GH #4447)

* GCM/GHASH internal cleanups (GH #4469)

* Documentation updates (GH #4586)

* Internal cleanups related to calling ``getauxval`` (GH #4471)

* Add a ``--timer-unit=`` option to ``botan speed`` (GH #4456 #4490)

* Rename the ``nist`` policy to ``fips140`` to more accurately reflect
  usage. Update with regards to latest NIST standards. (GH #4614)

* Update the Limbo test suite (GH #4406)

* Mark several classes not intended for derivation as ``final`` (GH #4419)

* Add iterator debugging to CI (GH #4413)

* Starting in 3.6.0, ``configure.py`` would pass through any values set as
  ``CXXFLAGS`` into the link invocation as well. This was done to support
  LTO style options. However it causes build regressions, especially with MSVC,
  and so has been reverted. Using the new option ``--lto-cxxflags-to-ldflags``
  will cause this passthrough behavior to continue. (GH #4196 #4200 #4451 #4452)

* Fix an iterator error in the test suite (GH #4413)

* Fix build issues caused by incompatible changes in Boost 1.87 (GH #4484)

* Fix a build issue when AVX2 support is disabled (GH #4493)

* Fix a build issue when compiling with MSVC on ARM (GH #4483)

* Address some new warnings from Clang 19 (GH #4544 #4545 #4548)

Version 3.6.1, 2024-10-26
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Notice: Botan 3.7.0 will remove support for the currently supported
  experimental Kyber r3 TLS ciphersuites, leaving only the standardized
  ML-KEM suites. (GH #4407 #4403)

* Fix a bug in x86 CPUID detection introduced in 3.6.0 which would cause
  crashes on systems which have BMI1 but not BMI2. (GH #4402 #4401)

* Fix a bug in SLH-DSA signing, which did not default to the FIPS
  required randomized variant. (GH #4398)

* Modify how elliptic curve blinding is performed, reducing the number
  of self-additions that may occur during multiplication. (GH #4408)

* In ``speed`` command line utility, also iterate keygen several times.
  (GH #4381)

Version 3.6.0, 2024-10-21
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Fully integrate and further optimize the new ECC library first introduced in
  3.5.0. For common curves, operations are 2 to 3 times faster. This also
  introduces a new API for low level EC operations, such a point multiplication,
  using ``EC_Scalar`` and ``EC_AffinePoint`` types.
  (GH   #4042 #4113 #4147 #4190 #4191 #4113 #4143 #4171 #4203 #4205 #4207
  #4209 #4210 #4211 #4212 #4213 #4215 #4217 #4218 #4221 #4225 #4226 #4235
  #4237 #4240 #4242 #4256 #4257 #4261 #4264 #4276 #4284 #4300)

* Add support for FIPS 203 ML-KEM, the NIST standardized version of Kyber (GH #3893)

* Add support for FIPS 204 ML-DSA, the NIST standardized version of Dilithium (GH #4270)

* Add support for FIPS 205 SLH-DSA, the NIST standardized version of SPHINCS+ (GH #4291)

* Add support for TPM2 hardware (GH #4337 #4357 #4361)

* Add support for jitterentropy RNG (GH #4325)

* Constant time programming improvements including ``CT::Option``
  (GH #4175 #4197 #4198 #4204 #4207 #4254 #4260)

* Improve performance of hex (GH #4275) and base64 (GH #4271)

* In ECDSA blind the constant time inversion of the nonce, as an extra precaution
  against side channel attacks. (GH #4259)

* Add support for AVX2-VAES instructions (GH #4286 #4287)

* Add GFNI-AVX2 acceleration for SM4 (GH #4289)

* Add support for elliptic curve numsp512d1 (GH #4251)

* Apply const-time checking annotations to Dilithium and Kyber (GH #4223),
  X448/Ed448 (GH #4204), FrodoKEM (GH #4198), LMS (GH #4272)

* Refactor internals of Dilithium and Kyber to share common elements (GH #4024)

* Add a test suite for validating the const-time annotations (GH #4182)

* Internal refactorings of public key encryption to improve memory
  safety and side channel resistance. (GH #4238 #4239)

* Cache the DER encoding of the OID format of an elliptic curve (GH #4193)

* Correct inconsistencies with use of ``BOTAN_CLEAR_CPUID`` where dependent
  instruction sets were not always disabled. (GH #4290)

* Deprecate the x25519/Kyber-512-r3 TLS ciphersuite. (GH #4347)

* Add CI nightly test using Intel SDE to test AVX-512 (GH #4296)

* Fix armv7/aarch64 CPU feature detection on FreeBSD (GH #4315)

* Add support for armv7/aarch64/ppc64 CPU feature detection on OpenBSD,
  using a new API added in OpenBSD 7.6 (GH #4312)

* Fix a bug in the ``speed`` cli utility which caused it to report incorrect
  values, especially for ciphers/hashes with small input sizes. (GH #4311)

* Fix a bug where CMake and pkg-config files might be installed to the
  wrong path (GH #4236 #4231)

* Fix certificate validation when the trust root is a self-signed MD2 cert.
  (GH #4247 #4248)

* Internal "strong types" improvments (GH #4170)

* Refactor the ``speed`` cli utility (GH #4364 #4367 #4369)

* Fix a test that was somewhat brittle and would fail if a specific
  certificate was not in the system trust root store. (GH #4280)

* Update some documentation comments (GH #4185)

* In Argon2, avoid instantiating a thread pool when ``p == 1`` (GH #4195 #4199)

* Disable the thread pool by default on Emscripten target (GH #4195 #4199)

* Add compile time option to disable all use of inline assembly (GH #4273 #4265)

Version 3.5.0, 2024-07-08
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* CVE-2024-34702: Fix a DoS caused by excessive name constraints. (GH #4186)

* CVE-2024-39312: Fix a name constraint processing error, where if
  permitted and excluded rules both applied to a certificate, only the
  permitted rules would be checked.

* Add a new much faster elliptic curve implementation. In this release,
  this implementation is only used for hash2curve. (GH #3979)

* Add support for LMS hash based signatures (GH #3716 #4059)

* Add support for SSLKEYLOGFILE logging (GH #4043)

* Optimize processing in FFI ``botan_cipher_update`` (GH #3951)

* Add ``Public_Key::raw_public_key_bits`` (GH #3985)

* Optimize XTS mode (GH #4047)

* Optimize name constraint processing (GH #4047)

* Optimize FrodoKEM-AES (GH #4176 #4174 #4173)

* The build system now distinguishes between LLVM Clang and XCode's Clang
  fork. For the latter, use compiler target "xcode". (GH #4010)

* Fix a bug in ``scrypt`` autotune where, if it was called with a
  nominal maximum memory limit of zero (meant to indicate no limit)
  would only ever return parameters using 1 MB.

* Constant time programming improvements including ``CT::value_barrier``
  and ``CT::Choice`` (GH #4154 #4115 #4096 #4108)

* Refactor and optimize AlternativeName. This includes a new API.
  The old API is retained but deprecated. (GH #4034)

* Kyber internals refactoring (GH #3887)

* Generate Kuznyechik tables at compile time instead of hard coding them.
  (GH #4017)

* Enable using ``sysctlbyname`` on iOS (GH #4018)

* Previously Curve25519 was used to refer to key exchange over the Montgomery
  curve modulo 2**255-19. This is now called X25519 in all cases. Typedefs and a
  deprecated header are retained for compatibility with older versions. (GH
  #4012)

* Fix several bugs related to encoding and decoding ASN.1 object identifiers
  when the second arc is larger than 40. (GH #4063 #4023)

* Avoid sending IP addresses in the Server Name Indicator TLS extension, if
  an IP address is used to initialize the TLS_Server_Info struct. (GH #4059)

* During X.509 certificate verification, first verify the entire sequence
  of signatures, then do other validation. (GH #4045)

* In DTLS fix a bug affecting retransmission of client hellos. (GH #4037)

* Fix a number of bugs related to name constraint processing. (GH #4074)

* Add support for parsing TNAuthList (secure telephony identity credentials
  extension) from RFC 8226. (GH #4116)

* Add One-Step KDF from SP 800-56C (GH #4121)

* Fix a bug in RFC 6979 mode ECDSA. This only caused problems when
  testing with certain curves and does not have any security or interop
  implications. (GH #4040)

* Previously elliptic curve private keys could be of any size, with the
  effective key reduced modulo the group order. Now during decoding the
  private key must be in the specified bound. (GH #4040)

* Elliptic curve groups now verify that the prime and group order are
  related in the manner expected. (GH #4039 #4041)

* Add a script to run the Limbo X.509 path validation test suite.

* Update the BoGo TLS test suite (GH #4078)

* Deprecate various low level BigInt and elliptic curve interfaces (GH #4038 #4056)

* In 3.3.0, support for application specific curves in EC_Group with
  parameters larger than 521 bits was deprecated. This release expands
  that deprecation to further restrict future use of application
  specific curves (see deprecated.rst for details). Add a new EC_Group
  constructor which enforces these restrictions. (GH #4038)

* Fix a bug when creating a PKCS10 request or X.509 self signed certificate
  when SubjectAlternativeName was included in the provided extensions. If
  this occurred, any other values (eg opts.dns) would be ignored. (GH #4032)

* Various low level multi precision integer refactorings and improvements.
  (GH #4156 #4149 #4007 #4008 #3989 #3987)

* Increase the maximum supported key length of KMAC to 192 bytes (GH #4109)

* Improve the utilities for checked (overflow safe) addition and multiplication.
  (GH #3999)

* Optimize parsing of IPv4 dotted quad strings (GH #4058)

* A system for marking modules as deprecated was introduced in 3.4.0, but it did
  not mark any modules as deprecated. This has now been applied to various
  modules, which will then be disabled if ``--disable-deprecated-features``
  option is used at build time. (GH #4050)

* Fix a bug in ``configure.py`` that caused ``--with-stack-protector`` to not
  work. (GH #3996)

* Upgrade CI to use XCode 15.2 on x86-64 and XCode 15.3 on aarch64. (GH #4005)

* Update most CI builds to run on Ubuntu 24.04 (GH #4098)

* Various ``clang-tidy`` fixes (GH #4070 #4075)

* Fixes for GCC 14 (GH #4046)

* Fix Roughtime to not reference a deprecated Cloudflare server. (GH #4002 #3937)

Version 3.4.0, 2024-04-08
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Add Ed448 signatures and X448 key exchange (GH #3933)

* X.509 certificate verification now can optionally ignore the
  expiration date of root certificates. (GH #3938)

* Support for "hybrid" EC point encoding is now deprecated. (GH #3981)

* Support for creating EC_Group objects with parameters larger than
  521 bits is now deprecated (GH #3980)

* Add new build options to disable deprecated features, and to enable
  experimental features. (GH #3910)

* Fix a bug affecting use of SIV and CCM ciphers in the FFI interface.
  (GH #3971)

* Add new FFI interface ``botan_cipher_requires_entire_message`` (GH #3969)

* Internal refactorings of the mp layer to support a new elliptic
  curve library. (GH #3973 #3977 #3962 #3957 #3964 #3956 #3961 #3950)

* Use a new method for constant time division in Kyber to avoid a possible
  side channel where the compiler inserts use of a variable time division.
  (GH #3959)

* Refactor test RNG usage to improve reproducibility. (GH #3920)

* Add ``std::span`` interfaces to ``BigInt`` (GH #3866)

* Refactorings and improvements to low level load/store utility
  functions. (GH #3869)

* Fix the amalgamation build on ARM64 (GH #3931)

* Add Mac ARM based CI build (GH #3931)

* Fix a thread serialization bug that caused sporadic test failures.
  (GH #3922)

* Update GH Actions to v4 (GH #3923)

* Add examples of password based encryption and HTTPS+ASIO client.
  (GH #3935 #3910)

Version 3.3.0, 2024-02-20
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* CVE-2024-34703 Fix a potential denial of service caused by accepting
  arbitrary length primes as potential elliptic curve parameters in
  ASN.1 encodings. With very large inputs the primality verification
  can become computationally expensive. Now any prime field larger
  than 1024 bits is rejected immediately. Reported by Bing Shi. (GH #3913)

* Add FrodoKEM post-quantum KEM (GH #3679 #3807 #3892)

* Add support for Blake2s (GH #3796)

* Add support for RFC 7250 in TLS 1.3 to allow authenticating peers
  using raw public keys (GH #3771)

* Update the BSI TLS policy to match the latest TR, particularly
  enabling support for TLS 1.3 (GH #3809)

* Add AsymmetricKey::generate_another() to generate a new key of the
  same type and parameters as an existing key (GH #3770 #3786)

* Add Private_Key::remaining_operations() that indicates the number of
  remaining signatures for stateful hash-based signatures (GH #3821)

* Add implementation of EC_PrivateKey::check_key() (GH #3782 #3804)

* Add hardware acceleration for SHA-512 on ARMv8 (GH #3860 #3864)

* X.509 certificates that contain Authority Information Access (AIA)
  extensions can now be encoded (GH #3784)

* Various functions defined in ``mem_ops.h`` are now deprecated
  for public use (GH #3759 #3752 #3757)

* The ASIO TLS stream can now be used with C++20 coroutines (GH #3764)

* New public header asio_compat.h to check compatibility of the ASIO
  TLS stream with the available boost version (1.73.0+) (GH #3765)

* Flatten input buffer sequences in the ASIO TLS stream to avoid
  creating unnecessarily small TLS records (GH #3839)

* Hard-rename the potentially harmful build configuration flag
  --terminate-on-asserts to --unsafe-terminate-on-asserts (GH #3755)

* Use modern SQLite3 APIs with integer width annotations from SQLite3 3.37
  (GH #3788 #3793)

* Generate and install a CMake package config file (botan-config.cmake)
  (GH #3722 #3827 #3830 #3825)

* Add TLS::Channel::is_handshake_complete() predicate method (GH #3762)

* Add support for setting thread names on Haiku OS and DragonflyBSD
  (GH #3758 #3785)

* Use /Zc:throwingNew with MSVC (GH #3858)

* Work around a warning in GCC 13 (GH #3852)

* Add a CLI utility for testing RSA side channels using the MARVIN
  toolkit (GH #3749)

* CLI utility 'tls_http_server' is now based on Boost Beast
  (GH #3763 #3791)

* CLI utility 'tls_client_hello' can detect and handle TLS 1.3 messages
  (GH #3820)

* Add a detailed migration guide for users of OpenSSL 1.1 (GH #3815)

* Various updates to the documentation and code examples
  (GH #3777 #3805 #3802 #3794 #3815 #3823 #3828 #3842 #3841 #3849 #3745)

* Fixes and improvements to the build experience using ``ninja``
  (GH #3751 #3750 #3769 #3798 #3848)

* Fix handling of cofactors when performing scalar blinding in EC (GH #3803)

* Fix potential timing side channels in Kyber (GH #3846 #3874)

* Fix a potential dangling reference resulting in a crash in the OCB
  mode of operation (GH #3814)

* Fix validity checks in the construction of the ASIO TLS stream
  (GH #3766)

* Fix error code handling in ASIO TLS stream (GH #3795 #3801 #3773)

* Fix a TLS 1.3 assertion failure that would trigger if the
  application callback returned an empty certificate chain. (GH #3754)

* Fix a RFC 7919 conformance bug introduced in 3.2.0, where the TLS
  server would fail to reject a client hello that advertised (only)
  FFDHE groups that are not known to us. (GH #3743 #3742 #3729)

* Fix that modifications made in TLS::Callbacks::tls_modify_extensions()
  for the TLS 1.3 Certificate message were not being applied. (GH #3792)

* Fix string mapping of the PKCS#11 mechanism RSA signing mechanism that
  use SHA-384 (GH #3868)

* Fix a build issue on NetBSD (GH #3767)

* Fix the configure.py to avoid recursing out of our source tree (GH #3748)

* Fix various clang-tidy warnings (GH #3822)

* Fix CLI tests on windows and enable them in CI (GH #3845)

* Use ``BufferStuffer`` and ``concat`` helpers in public key code
  (GH #3756 #3753)

* Add a nightly test to ensure hybrid TLS 1.3 PQ/T compatibility with
  external implementations (GH #3740)

* Internal memory operation helpers are now memory container agnostic
  using C++20 ranges (GH #3715 #3707)

* Public and internal headers are now clearly separated in the build
  directory. That restricts the examples build target to public headers.
  (GH #3880)

* House keeping for better code formatting with clang-format
  (GH #3862 #3865)

* Build documentation in CI and fail on warnings or errors (GH #3838)

* Work around a GitHub Actions CI issue (actions/runner-images#8659)
  (GH #3783 #3833 #3888)

Version 3.2.0, 2023-10-09
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Add support for (experimental!) post-quantum secure key exchange
  in TLS 1.3 (GH #3609 #3732 #3733 #3739)

* Add support for TLS PSK (GH #3618)

* Add a first class interface for XOFs (GH #3671 #3672 #3701)

* Add KMAC from NIST SP 800-185 (GH #3689)

* Add cSHAKE XOF; currently this is not exposed to library users but
  is only for deriving further cSHAKE derived functions. (GH #3671)

* Add improved APIs for key encapsulation (GH #3611 #3652 #3653)

* As Kyber's 90s mode is not included in the NIST draft specification,
  and most implementations only support the SHAKE based mechanism,
  the Kyber 90s mode is now deprecated. (GH #3695)

* Previously ``KyberMode`` enums had elements like ``Kyber512`` to identify the
  scheme. These have changed to have ``_R3`` suffixes (like ``Kyber512_R3``) to
  clearly indicate these are not the final version but is instead the version
  from round3 of the PQC competition. The old names continue on as (deprecated)
  aliases. (GH #3695)

* Fix bugs in various signature algorithms where if a signature
  operation was used after the key object had been deleted, a use
  after free would occur. (GH #3702)

* The types defined in pubkey.h can now be moved (GH #3655)

* Add the Russian block cipher Kuznyechik (GH #3680 #3724)

* The ``TLS::Group_Params`` enum is now a class which emulates the
  behavior of the enumeration. (GH #3729)

* Implement serialization for the Certificate Authority TLS extension
  (GH #3687)

* Refactored the internal buffering logic of most hash functions
  (GH #3705 #3693 #3736)

* Add OS support for naming threads; now Botan thread pool threads
  are identified by name. (GH #3628 #3738)

* Updated the TLS documentation to reflect TLS 1.3 support and
  the removal of TLS 1.0 and 1.1. (GH #3708)

* Upon deserialization, the ``EC_Group`` type now tracks the encoding
  which was used to create it. This is necessary to implement policies
  which prohibit use of explicit curve encodings (which are in any case
  deprecated). (GH #3665)

* If compiling against an old glibc which does not support the ``getrandom``
  call, now the raw syscall is used instead. (GH #3688 #3685)

* On MinGW the global thread pool is disabled by default (GH #3726 #2582)

* Various internal functions now use ``std::span`` instead of raw pointers
  plus length field. NOTE: any implementations of ``BlockCipher``, ``HashFunction``
  etc that live outside the library will have to be updated. This is not covered
  by the SemVer guarantee; see ``doc/sem_ver.rst`` (GH #3684 #3681 #3713 #3714
  #3698 #3696)

* Add helper for buffer alignment, and adopt it within the hash function
  implementations. (GH #3693)

* Added support for encoding CRL Distribution Points extension in new
  certificates (GH #3712)

* Internal refactoring of SHA-3 to support further SHA-3 derived functionality
  (GH #3673)

* Add support for testing using TLS-Anvil (GH #3651) and fix a few cases
  where the TLS implementation sent the incorrect alert type in various
  error cases which were discovered using TLS-Anvil (GH #3676)

* Add initial (currently somewhat experimental) support for using the ninja
  build system as an alternative to make. (GH #3677)

* Remove an unused variable in BLAKE2b (GH #3624)

* Fix a number of clang-tidy warnings in the headers (GH #3646)

* Add checks for invalid length AD in Argon2 (GH #3626)

* CI now uses Android NDK 26, and earlier NDKs are not supported
  due to limitations of the C++ library in earlier NDKs (GH #3718)

* Improve support for IBM's XLC compiler (GH #3730)

* Avoid compilation failures when using ``-Werror`` mode with GCC 12
  due to spurious warnings in that version. (GH #3711 #3709)

Version 3.1.1, 2023-07-13
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Fix two tests which were insufficiently serialized. This would
  cause sporadic test failures, particularly on machines with
  many cores. (GH #3625 #3623)

Version 3.1.0, 2023-07-11
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Add SPHINCS+ post quantum hash based signature scheme (GH #3564 #3549)

* Several small TLS compliance fixes, primarily around rejecting
  invalid behavior from the peer (GH #3520 #3537)

* Adapt TLS 1.3 to use a KEM interface to prepare for PQ key exchange
  (GH #3608)

* Fix custom key exchange logic integration for TLS 1.2 server (GH #3539)

* Add initial wrappers for using AVX-512, and implement AVX-512 versions
  of ChaCha and Serpent. (GH #3206 #3536)

* Add support for an environmental variable which can disable CPU extensions
  (GH #3535)

* Update the BSI policy to match the latest TR (GH #3482)

* Update the BoringSSL test suite shim (GH #3616)

* Add FFI functions relating to Kyber key management (GH #3546)

* The entire codebase has been reformatted using ``clang-format``.
  (GH #3502 #3558 #3559)

* Fix many warnings generated from ``clang-tidy``.

* ``BigInt::random_integer`` could take a long time if requested to
  generate a number within a small range between two large integers.
  (GH #3594)

* Fix bugs related to ``--library-suffix`` option. (GH #3511)

* Improve cli handling of PBKDF configuration (GH #3518)

* Fix the cli to properly update stateful keys (namely XMSS) when using such
  a key to sign a X.509 certificate (GH #3579)

* Add support for using PSK in the TLS CLI utilities (GH #3552)

* Add an example of hybrid RSA+symmetric encryption (GH #3551)

* In the Python module, the pbkdf function defaulted to 10K iterations.
  This has been changed to 100K.

* Switch to using coveralls.io for coverage report (GH #3512)

* Add a script to analyze the output of ``botan timing_test``

* Due to problems that arise if the build directory and source
  directory are on different filesystems, now hardlinks are only
  used during the build if explicitly requested. (GH #3504)

* The ``ffi.h`` header no longer depends on the ``compiler.h`` header.
  (GH #3531)

* Avoid using varargs macros for ``BOTAN_UNUSED`` (GH #3530)

* Small base64 encoding optimization (GH #3528)

* If the build system detects that the compiler in use is not supported,
  it will error immediately rather than allow a failing build. Currently
  this is only supported for GCC, Clang, and MSVC. (GH #3526)

* The examples are now a first class build target; include
  ``examples`` in the set provided to ``--build-targets=`` option in
  order to enable them. (GH #3527)

* Remove the (undocumented, unsupported) support for CMake (GH #3501)

Version 3.0.0, 2023-04-11
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Botan is now a C++20 codebase; compiler requirements have been
  increased to GCC 11, Clang 14, or MSVC 2022. (GH #2455 #3086)

Breaking Changes
----------------------------------------

* Remove many deprecated headers. In particular all algorithm specific
  headers (such as ``aes.h``) are no longer available; instead objects
  must be created through the base class ``create`` functions. (GH #2456)

* Removed most functions previously marked as deprecated.

* Remove several deprecated algorithms including CAST-256, MISTY1, Kasumi,
  DESX, XTEA, PBKDF1, MCEIES, CBC-MAC, Tiger, NEWHOPE, and CECPQ1 (GH #2434 #3094)

* Remove the entropy source which walked ``/proc`` as it is no longer
  required on modern systems. (GH #2692)

* Remove the entropy source which reads from ``/dev/random`` as it is
  supplanted by the extant source one which reads from the system RNG.
  (GH #2636)

* Remove use of ``shared_ptr`` from certificate store API, as since
  2.4.0 ``X509_Certificate`` is internally a ``shared_ptr``. (GH #2484)

* Several enums including ``DL_Group::Format``, ``EC_Group_Formatting``,
  ``CRL_Code``, ``ASN1_Tag``, ``Key_Constraints`` and ``Signature_Format`` are
  now ``enum class``.  The ``ASN1_Tag`` enum has been split into ``ASN1_Type``
  and ``ASN1_Class``.  (GH #2551 #2552 #3084 #2584 #3225)

* Avoid using or returning raw pointers whenever possible. (GH #2683 #2684
  #2685 #2687 #2688 #2690 #2691 #2693 #2694 #2695 #2696 #2697 #2700 #2703 #2708
  #3220)

* Remove support for HP and Pathscale compilers, Google NaCL (GH #2455),
  and IncludeOS (GH #3406)

* Remove deprecated ``Data_Store`` class (GH #2461)

* Remove deprecated public member variables of ``OID``, ``Attribute``,
  ``BER_Object``, and ``AlgorithmIdentifier``. (GH #2462)

* "SHA-160" and "SHA1" are no longer recognized as names for "SHA-1"
  (GH #3186)

TLS Changes
----------------------------------------

* Added support for TLS v1.3

* Support for TLS 1.0, TLS 1.1, and DTLS 1.0 have been removed (GH #2631)

* Remove several deprecated features in TLS including DSA ciphersuites (GH #2505),
  anonymous ciphersuites (GH #2497), SHA-1 signatures in TLS 1.2 (GH #2537),
  SRP ciphersuites (GH #2506), SEED ciphersuites (GH #2509),
  Camellia CBC ciphersuites (GH #2509), AES-128 OCB ciphersuites (GH #2511),
  DHE_PSK suites (GH #2512), CECPQ1 ciphersuites (GH #3094)

New Cryptographic Algorithms
----------------------------------------

* Add support for Kyber post-quantum KEM (GH #2872 #2500)

* Add support for Dilithium lattice based signatures (GH #2973 #3212)

* Add support for hashing onto an elliptic curve using the SSWU
  technique of draft-irtf-cfrg-hash-to-curve (GH #2726)

* Add support for keyed BLAKE2b (GH #2524)

New APIs
----------------------------------------

* Add new interface ``T::new_object`` which supplants ``T::clone``. The
  difference is that ``new_object`` returns a ``unique_ptr<T>`` instead of a raw
  pointer ``T*``. ``T::clone`` is retained but simply releases the result of
  ``new_object``. (GH #2689 #2704)

* Add an API to ``PasswordHash`` accepting an AD and/or secret key, allowing
  those facilities to be used without using an algorithm specific API (GH #2707)

* Add new ``X509_DN::DER_encode`` function. (GH #2472)

* New API ``Public_Key::get_int_field`` for getting the integer fields of a public
  (or private) key by name (GH #3200)

* New ``Cipher_Mode`` APIs ``ideal_granularity`` and ``requires_entire_message``
  (GH #3172 #3168)

* New ``Private_Key::public_key`` returns a new object containing the public
  key associated with that private key. (GH #2520)

* ``SymmetricAlgorithm::has_keying_material`` allows checking if a key has
  already been set on an object (GH #3295)

* Many new functions in the C89 interface; see the API reference for more details.

Implementation Improvements
----------------------------------------

* Add AVX2 implementation of Argon2 (GH #3205)

* Use smaller tables in the implementations of Camellia, ARIA, SEED, DES,
  and Whirlpool (GH #2534 #2558)

* Modify DES/3DES to use a new implementation which avoids most
  cache-based side channels. (GH #2565 #2678)

* Optimizations for SHACAL2, especially improving ARMv8 and POWER (GH #2556 #2557)

* Add a fast path for inversion modulo ``2*o`` with ``o`` odd, and modify RSA
  key generation so that ``phi(n)`` is always of this form. (GH #2634)

* Use constant-time code instead of table lookups when computing parity bits
  (GH #2560), choosing ASN.1 string type (GH #2559) and when converting to/from
  the bcrypt variant of base64 (GH #2561)

* Change how DL exponents are sized; now exponents are slightly larger and
  are always chosen to be 8-bit aligned. (GH #2545)

Other Improvements
----------------------------------------

* Changes to ``TLS::Stream`` to make it compatible with generic completion tokens.
  (GH #2667 #2648)

* When creating an ``EC_Group`` from parameters, cause the OID to be set if it
  is a known group. (GH #2654 #2649)

* Fix bugs in GMAC and SipHash where they would require a fresh key be
  provided for each message. (GH #2908)

Older Versions
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* The release notes for versions 2.0.0 through 2.19.5 can be found in
  ``doc/news_2x.rst``

* The release notes for versions 0.7.0 through 1.11.34 can be found in
  ``doc/old_news.rst``
