Release Notes
========================================

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
  deprecated header are retained for compatability with older versions. (GH
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
  this occured, any other values (eg opts.dns) would be ignored. (GH #4032)

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

* Fix a bug in ``configure.py`` that caused `--with-stack-protector`` to not
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

Version 2.19.4, 2024-02-20
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* CVE-2024-34703 Fix a potential denial of service caused by accepting
  arbitrary length primes as potential elliptic curve parameters in
  ASN.1 encodings. With very large inputs the primality verification
  can become computationally expensive. Now any prime field larger
  than 1024 bits is rejected immediately. Reported by Bing Shi. (GH #3914)

* Switch to using a constant time binary algorithm for computing
  GCD (GH #3912)

* Fix a bug in SHAKE_Cipher which could cause incorrect output
  if set_key was called multiple times. (GH #3192)

* Fix a bug in RSA-KEM encryption where the shared secret key
  was incorrectly not padded to exactly the byte length of the
  modulus. This would cause an incorrect shared key with ~1/256
  probability. (GH #3380)

* In RSA decryption and signature verification, reject bytestrings
  which are longer than the public modulus. Previously, otherwise
  valid signatures/ciphertexts with additional leading zero bytes
  would also be accepted. (GH #3380)

* Add support for short nonces in XTS (GH #3384 #3336)

* Fix NIST keywrap which was incorrect when wrapping 64-bit keys
  (GH #3384 #3340)

* Fix nonce handling bug in EAX (GH #3382 #3335)

* Fix a bug in PKCS11 AttributeContainer where adding an attribute
  that already existed could cause incorrect references to the
  existing attributes. (GH #3185)

* Apply patches which allow GCC 4.7 to compile Botan 2.x. Previously
  at least GCC 4.8 had been required. (GH #3273)

* Fix a build time problem affecting VCpkg (GH #3071)

* Fix a build problem affecting Windows ARM with Visual C++ (GH #3871)

Version 2.19.3, 2022-11-16
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* CVE-2022-43705: A malicious OCSP responder could forge OCSP
  responses due to a failure to validate that an embedded certificate
  was issued by the end-entity issuing certificate authority.

Version 2.19.2, 2022-06-03
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Add support for parallel computation in Argon2 (GH #2937 #2926)

* Add SSSE3 implementation of Argon2 (GH #2937 #2927)

* The OpenSSL provider was incompatible with OpenSSL 3.0.
  It has been removed (GH #2902)

* Avoid using reserve in secure_vector appending, which caused
  a performance problem (GH #2945 #2920)

* Fix TLS::Text_Policy behavior when X25519 is disabled
  at build time (GH #2894)

* Fix several warnings from Clang (#2888 #2886)

Version 2.19.1, 2022-01-21
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Fix a compilation problem affecting macOS XCode (GH #2880)

* Fix a build problem preventing amalgamation builds in 2.19.0
  (GH #2879)

Version 2.19.0, 2022-01-19
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Add a forward error correction code compatible with the
  zfec library (GH #2868 #2866)

* Improve Emscripten build (GH #2864)

* Always use ``-L`` before build flags (GH #2858 2848)

* Fix compilation issue on earlier macOS versions (GH #2851)

* Add a GCC 4.8 CI target to prevent build regressions (GH #2869)

* Add support for Loongarch64 (GH #2877)

* Check OSXSAVE flag before using AVX2 instructions (GH #2878)

Version 2.18.2, 2021-10-25
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Avoid using short exponents when encrypting in ElGamal, as some PGP
  implementations generate keys with parameters that are weak when
  short exponents are used (GH #2794)

* Fix a low risk OAEP decryption side channel (GH #2797)

* Work around a miscompilation of SHA-3 caused by a bug in Clang 12
  and XCode 13. (GH #2826)

* Remove support in OpenSSL provider for algorithms which are
  disabled by default in OpenSSL 3.0 (GH #2823, #2814)

* Add CI based on GitHub actions to replace Travis CI (GH #2632)

* Fix the online OCSP test, as the certificate involved had expired.
  (GH #2799)

* Fix some test failures induced by the expiration of the trust root
  "DST Root CA X3" (GH #2820)

Version 2.18.1, 2021-05-09
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Fix a build regression in 2.18.0 which caused linker flags which
  contain ``-l`` within them (such as ``-fuse-linker-plugin``) to
  be misinterpreted. (GH #2715)

* Fix a bug which caused decoding a certificate which contained
  more than one name in a single RDN. (GH #2611 #2630 #2724)

* Fix a bug which caused OID lookup failures when run in a locale
  which uses thousands separators (pt_BR was reported as having
  this issue). (GH #2732 #2730 #2237)

* DNS names in name constraints were compared with case sensitivity, which
  could cause valid certificates to be rejected. (GH #2739 #2735)

* X.509 name constraint extensions were rejected if non-critical. RFC 5280
  requires conforming CAs issue such extensions as critical, but not all
  certificates are compliant, and all other known implementations do not
  require this. (GH #2739 #2736)

* X.509 name constraints were incorrectly applied to the certificate which
  included the constraint. (GH #2739 #2737)

Version 2.18.0, 2021-04-15
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Add support for implementing custom RNG objects through the
  FFI interface (GH #2627 #2600)

* Improve safegcd bounds, improving runtime performance (GH #2628 #2619)

* Fix a bug introduced in 2.9.0 where BigInt::operator< would return
  an incorrect result if both operands were negative. (GH #2641 #2638)

* Reject non-TLS messages as quickly as possible without waiting for
  a full record. (GH #2676)

* Add build support for RISC-V 32

* Fixes for TLS::Stream::async_shutdown (GH #2673)

* Fix a regression introduced in 2.17.0 where LDFLAGS which add an extra
  library (such as ``-latomic`` needed on SPARC) were not always applied
  effectively. (GH #2622 #2623 #2625)

Version 2.17.3, 2020-12-21
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* CVE-2021-24115 Change base64, base58, base32, and hex encoding and
  decoding operations to run in constant time (GH #2549)

* Fix a build problem on PPC64 building with Clang (GH #2547)

* Fix an install problem introduced in 2.17.2 affecting MSVC 2015

* Fix use of -L flag in linking when configured using ``--with-external-libdir``
  (GH #2496)

* Fix a build problem on big-endian PowerPC related to VSX instructions
  in the AES code. (GH #2515)

Version 2.17.2, 2020-11-13
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Fix an build problem on ppc64 introduced with certain recent
  versions of GCC or binutils where using the DARN instruction
  requires using an appropriate -mcpu flag to enable the instruction
  in the assembler. (GH #2481 2463)

* Resolve an issue in the modular square root algorithm where a loop
  to find a quadratic non-residue could, for a carefully chosen
  composite modulus, not terminate in a timely manner. (GH #2482 #2476)

* Fix a regression in MinGW builds introduced in 2.17.1

Version 2.17.1, 2020-11-07
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Fix a build problem that could occur if Python was not in the PATH.
  This was known to occur on some installations of macOS.

* Re-enable support for the x86 CLMUL instruction on Visual C++, which was
  accidentally disabled starting in 2.12.0. (GH #2460)

Version 2.17.0, 2020-11-05
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Fix a bug in ECDSA which could occur when the group size and hash length
  differ. In this case, on occasion the generated signature would not be
  accepted by other ECDSA implementations. This was particularly likely to
  affect users of 160-bit or 239-bit curves. (GH #2433 #2415)

* Fix a bug in ECDSA verification when the public key was chosen to be
  a small multiple of the group generator. In that case, verification
  would fail even if the signature was actually valid. (GH #2425)

* SIV's functionality of supporting multiple associated data inputs has been
  generalized onto the AEAD_Mode interface. However at the moment SIV is the
  only AEAD implemented which supports more than one AD. (GH #2440)

* The contents of ASN.1 headers ``asn1_str.h``, ``asn1_time.h``, ``asn1_oid.h``
  and ``alg_id.h`` have been moved to ``asn1_obj.h``. The header files remain
  but simply forward the include to ``asn1_obj.h``. These now-empty header files
  are deprecated, and will be removed in a future major release. (GH #2441)

* The contents of X.509/PKIX headers ``asn1_attribute.h`` ``asn1_alt_name.h``
  ``name_constraint.h`` ``x509_dn.h`` ``cert_status.h`` and ``key_constraint.h``
  have been merged into ``pkix_enums.h`` (for enumerations) and ``pkix_types.h``
  (for all other definitions). The previous header files remain but simply
  forward the include to the new header containing the definition. These
  now-empty header files are deprecated, and will be removed in a future major
  release. (GH #2441)

* A number of other headers including those related to HOTP/TOTP, XMSS,
  PKCS11, PSK_DB have also been merged. Any now deprecated/empty headers
  simply include the new header and issue a deprecation warning.
  (GH #2443 #2446 #2447 2448 #2449)

* Small optimizations in the non-hardware assisted AES key generation
  code path (GH #2417 #2418)

* Move the GHASH code to a new module in utils, making it possible
  to build GMAC support without requiring GCM (GH #2416)

* Add more detection logic for AVX-512 features (GH #2430)

* Avoid std::is_pod which is deprecated in C++20 (GH #2429)

* Fix a bug parsing deeply nested cipher names (GH #2426)

* Add support for ``aarch64_be`` target CPU (GH #2422)

* Fix order of linker flags so they are always applied effectively (GH #2420)

* Prevent requesting DER encoding of signatures when the algorithm
  did not support it (GH #2419)

Version 2.16.0, 2020-10-06
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Now userspace PRNG objects (such as AutoSeeded_RNG and HMAC_DRBG)
  use an internal lock, which allows safe concurrent use. This however
  is purely a precaution in case of accidental sharing of such RNG
  objects; for performance reasons it is always preferable to use
  a RNG per thread if a userspace RNG is needed. (GH #2399)

* DL_Group and EC_Group objects now track if they were created from a
  known trusted group (such as P-256 or an IPsec DH parameter).  If
  so, then verification tests can be relaxed, as compared to
  parameters which may have been maliciously constructed in order to
  pass primality checks. (GH #2409)

* RandomNumberGenerator::add_entropy_T assumed its input was a POD
  type but did not verify this. (GH #2403)

* Support OCSP responders that live on a non-standard port (GH #2401)

* Add support for Solaris sandbox (GH #2385)

* Support suffixes on release numbers for alpha/beta releases (GH #2404)

* Fix a bug in EAX which allowed requesting a 0 length tag, which had
  the effect of using a full length tag. Instead omit the length field,
  or request the full tag length explicitly. (GH #2392 #2390)

* Fix a memory leak in GCM where if passed an unsuitable block cipher
  (eg not 128 bit) it would throw an exception and leak the cipher
  object. (GH #2392 #2388)

Version 2.15.0, 2020-07-07
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Fix a bug where the name constraint extension did not constrain the
  alternative DN field which can be included in a subject alternative name. This
  would allow a corrupted sub-CA which was otherwise constrained by a name
  constraint to issue a certificate with a prohibited DN.

* Fix a bug in the TLS server during client authentication where where
  if a (disabled by default) static RSA ciphersuite was selected, then
  no certificate request would be sent. This would have an equivalent
  effect to a client which simply replied with an empty Certificate
  message. (GH #2367)

* Replace the T-Tables implementation of AES with a 32-bit bitsliced
  version. As a result AES is now constant time on all processors.
  (GH #2346 #2348 #2353 #2329 #2355)

* In TLS, enforce that the key usage given in the server certificate
  allows the operation being performed in the ciphersuite. (GH #2367)

* In X.509 certificates, verify that the algorithm parameters are
  the expected NULL or empty. (GH #2367)

* Change the HMAC key schedule to attempt to reduce the information
  leaked from the key schedule with regards to the length of the key,
  as this is at times (as for example in PBKDF2) sensitive information.
  (GH #2362)

* Add Processor_RNG which wraps RDRAND or the POWER DARN RNG
  instructions. The previous RDRAND_RNG interface is deprecated.
  (GH #2352)

* The documentation claimed that mlocked pages were created with a
  guard page both before and after. However only a trailing guard page
  was used. Add a leading guard page. (GH #2334)

* Add support for generating and verifying DER-encoded ECDSA signatures
  in the C and Python interfaces. (GH #2357 #2356)

* Workaround a bug in GCC's UbSan which triggered on a code sequence
  in XMSS (GH #2322)

* When building documentation using Sphinx avoid parallel builds with
  version 3.0 due to a bug in that version (GH #2326 #2324)

* Fix a memory leak in the CommonCrypto block cipher calls (GH #2371)

* Fix a flaky test that would occasionally fail when running the tests
  with a large number of threads. (GH #2325 #2197)

* Additional algorithms are now deprecated: XTEA, GOST, and Tiger.
  They will be removed in a future major release.

Version 2.14.0, 2020-04-06
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Add support for using POWER8+ VPSUMD instruction to accelerate GCM
  (GH #2247)

* Optimize the vector permute AES implementation, especially improving
  performance on ARMv7, Aarch64, and POWER. (GH #2243)

* Use a new algorithm for modular inversions which is both faster and
  more resistant to side channel attacks. (GH #2287 #2296 #2301)

* Address an issue in CBC padding which would leak the length of the
  plaintext which was being padded. Unpadding during decryption was
  not affected. Thanks to Maximilian Blochberger for reporting this.
  (GH #2312)

* Optimize NIST prime field reductions, improving ECDSA by 3-9% (GH #2295)

* Increase the size of the ECC blinding mask and scale it based on the
  size of the group order. (GH #880 #893 #2308)

* Add server side support for the TLS asio wrapper. (GH #2229)

* Add support for using Windows certificate store on MinGW (GH #2280)

* Use the library thread pool instead of a new thread for RSA computations,
  improving signature performance by up to 20%. (GH #2257)

* Precompute and cache additional fields in ``X509_Certificate`` (GH #2250)

* Add a CLI utility ``cpu_clock`` which estimates the speed of the
  processor cycle counter. (GH #2251)

* Fix a bug which prevented using DER-encoded ECDSA signatures with a PKCS11
  key (GH #2293)

* Enable use of raw block ciphers from CommonCrypto (GH #2278)

* Support for splitting up the amalgamation file by ABI extension has
  been removed. Instead only ``botan_all.cpp`` and ``botan_all.h`` are
  generated. (GH #2246)

* Improve support for baremetal systems with no underlying OS, with
  target OS ``none`` (GH #2303 #2304 #2305)

* The build system now avoids using ``-rpath=$ORIGIN`` or (on macOS)
  install_name which allowed running the tests from the build
  directory without setting ``LD_LIBRARY_PATH``/``DYLD_LIBRARY_PATH``
  environment variables. Instead set the dynamic linker variables
  appropriately, or use ``make check``. (GH #2294 #2302)

* Add new option ``--name-amalgamation`` which allows naming the
  amalgamation output, instead of the default ``botan_all``. (GH #2246)

* Avoid using symbolic links on Windows (GH #2288 #2286 #2285)

* Fix a bug that prevented compilation of the amalgamation on ARM and
  POWER processors (GH #2245 #2241)

* Fix some build problems under Intel C++ (GH #2260)

* Remove use of Toolhelp Windows library, which was known to trigger
  false positives under some antivirus systems. (GH #2261)

* Fix a compilation problem when building on Windows in Unicode mode.
  Add Unicode build to CI to prevent regressions. (GH #2254 #2256)

* Work around a GCC bug affecting old libc (GH #2235)

* Workaround a bug in macOS 10.15 which caused a test to crash.
  (GH #2279 #2268)

* Avoid a crash in PKCS8::load_key due to a bug in Clang 8.
  (GH #2277)

Version 2.13.0, 2020-01-06
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Add Roughtime client (GH #2143 #1842)

* Add support for XMSS X.509 certificates (GH #2172)

* Add support for X.509 CRLs in FFI layer and Python wrapper (GH #2213)

* It is now possible to disable TLS v1.0/v1.1 and DTLS v1.0 at build time.
  (GH #2188)

* The format of encrypted TLS sessions has changed, which will invalidate all
  existing session tickets. The new format will make it easier to support ticket
  key rotation in the future. (GH #2225)

* Improve RSA key generation performance (GH #2148)

* Make gcd computation constant-time (GH #2147)

* Add AVX2 implementation of SHACAL2 (GH #2196)

* Update BSI policy to reflect 2019 update of TR 02102-2 (GH #2195)

* Support more functionality for X.509 in the Python API (GH #2165)

* Add ``generic`` CPU target useful when building for some new or unusual
  platform.

* Disable MD5 in BSI or NIST modes (GH #2188)

* Disable stack protector on MinGW as it causes crashes with some recent
  versions. (GH #2187)

* On Windows the DLL is now installed into the binary directory (GH #2233)

* Previously Windows required an explicit ``.lib`` suffix be added when
  providing an explicit library name, as is used for example for Boost.
  Now the ``.lib`` suffix is implicit, and should be omitted.

* Remove the 32-bit x86 inline asm for Visual C++ as it seemed to not offer
  much in the way of improved performance. (GH #2204 #256)

* Resolve all compile time warnings generated by GCC, Clang and MSVC.
  Modify CI to compile with warnings-as-errors. (GH #2170 #2206 #2211 #2212)

* Fix bugs linking to 3rd party libraries on Windows due to invalid
  link specifiers. (GH #2210 #2215)

* Add long input and NIST Monte-Carlo hash function tests.

* Fix a bug introduced in 2.12.0 where ``TLS::Channel::is_active`` and
  ``TLS::Channel::is_closed`` could simultaneously return true.
  (GH #2174 #2171)

* Use ``std::shared_ptr`` instead of ``boost::shared_ptr`` in some examples.
  (GH #2155)

Version 2.12.1, 2019-10-14
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Fix a bug that prevented building with nmake (GH #2142 #2141)

* Fix an issue where make install would attempt to build targets which
  were disabled. (GH #2140)

* If the option ``--without-documentation`` is used, avoid invoking the
  documentation build script. (GH #2138)

* Fix a bug that prevented compilation on x86-32 using GCC 4.9 (GH #2139)

* Fix a bug in CCM encryption, where it was possible to call ``finish`` without
  ever setting a nonce (GH #2151 #2150)

* Improve ECIES/DLIES interfaces. If no initialization vector was set, they
  would typically produce hard to understand exceptions. (GH #2151 #2150)

Version 2.12.0, 2019-10-07
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Many currently public headers are being deprecated. If any such header is
  included by an application, a warning is issued at compile time. Headers
  issuing this warning will be made internal in a future major release.
  (GH #2061)

* RSA signature performance improvements (GH #2068 #2070)

* Performance improvements for GCM (GH #2024 #2099 #2119), OCB (#2122),
  XTS (#2123) and ChaCha20Poly1305 (GH #2117), especially for small messages.

* Add support for constant time AES using NEON and AltiVec (GH #2093 #2095 #2100)

* Improve performance of POWER8 AES instructions (GH #2096)

* Add support for the POWER9 hardware random number generator (GH #2026)

* Add support for 64-bit version of RDRAND, doubling performance on x86-64 (GH #934 #2022)

* In DTLS server, support a client crashing and then reconnecting from
  the same source port, as described in RFC 6347 sec 4.2.8 (GH #2029)

* Optimize DTLS MTU splitting to split precisely to the set MTU (GH #2042)

* Add support for the TLS v1.3 downgrade indicator. (GH #2027)

* Improve the error messages generated when an invalid TLS state transition occurs
  (GH #2030)

* Fix some edge cases around TLS close_notify support. (GH #2054)

* Modifications to support GOST 34.10-2012 signatures (GH #2055 #2056 #1860 #1897)

* Add some new APIs on ``OID`` objects (GH #2057)

* Properly decode OCSP responses which indicate an error (GH #2110)

* Add a function to remove an X.509 extension from an Extensions object.
  (GH #2101 #2073 #2065)

* Support Argon2 outputs longer than 64 bytes (GH #2079 #2078)

* Correct a bug in CAST-128 which caused incorrect computation using
  11, 13, 14, or 15 byte keys. (GH #2081)

* Fix a bug which would cause Streebog to produce incorrect outputs for
  certain messages (GH #2082 #2083)

* Fix a bug that prevented loading EC points with an affine x or y
  value of 0. For certain curves such points can exist. (GH #2102)

* Fix a bug which would cause PBKDF2 to go into a very long loop if
  it was requested to use an iteration count of 0. (GH #2090 #2088)

* The BearSSL provider has been removed (GH #2020)

* Add a new ``entropy`` cli which allows sampling the output of the entropy sources.

* Add new ``base32_enc`` and ``base32_dec`` cli for base32 encoding operations. (GH #2111)

* Support setting TLS policies in CLIs like ``tls_client`` and ``tls_proxy_server`` (GH #2047)

* The tests now run in multithreaded mode by default. Provide option ``--test-threads=1`` to
  return to previous single-threaded behavior. (GH #2071 #2075)

* Cleanups in TLS record layer (GH #2021)

* Fix typos in some OCSP enums which used "OSCP" instead. (GH #2048)

* In the Python module, avoid trying to load DLLs for names that don't match the current
  platform (GH #2062 #2059)

* In the Python module, also look for ``botan.dll`` so Python wrapper can run on Windows.
  (GH #2059 #2060)

* Add support for TOTP algorithm to the Python module. (GH #2112)

* Now the minimum Windows target is set to Windows 7 (GH #2036 #2028)

* Add ``BOTAN_FORCE_INLINE`` macro to resolve a performance issue with BLAKE2b on MSVC
  (GH #2092 #2089)

* Avoid using ``__GNUG__`` in headers that may be consumed by a C compiler (GH #2013)

* Improve the PKCS11 tests (GH #2115)

* Fix a warning from Klocwork (GH #2128 #2129)

* Fix a bug which caused amalgamation builds to fail on iOS (GH #2045)

* Support disabling thread local storage, needed for building on old iOS (GH #2045)

* Add a script to help with building for Android, using Docker (GH #2016 #2033 #513)

* Add Android NDK build to Travis CI (GH #2017)

Version 2.11.0, 2019-07-01
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Add Argon2 PBKDF and password hash (GH #459 #1981 #1987)

* Add Bcrypt-PBKDF (GH #1990)

* Add a libsodium compat layer in sodium.h (GH #1996)

* XMSS now follows RFC 8391 which is incompatible with previous versions, which
  had followed draft 6. (GH #1858 #2003)

* Add server side support for issuing DTLS HelloVerifyRequest messages
  (GH #1999)

* Add a shim allowing testing Botan against the BoringSSL test suite,
  and fix a number of bugs in TLS found using it.
  (GH #1954 #1955 #1956 #1959 #1966 #1970)

* Add support for the TLS v1.3 supported_versions extension. (GH #1976)

* Add Ed25519ph compatible with RFC 8032 (GH #1699 #2000)

* Add support for OCSP stapling on server side. (GH #1703 #1967)

* Add a ``boost::asio`` TLS stream compatible with ``boost::asio::ssl``.
  (GH #1839 #1927 #1992)

* Add a certificate store for Linux/Unix systems. (GH #1885 #1936)

* Add a certificate store for Windows systems. (GH #1931)

* Add a generic ``System_Certificate_Store`` which wraps Windows, macOS,
  and Linux certificate stores. (GH #1893)

* Fix verification rooted in a v1 certificate which previously would fail.
  (GH #1890)

* Add ability to specify the maximum age of an OCSP response which does not
  have the nextUpdate field set. (GH #1974 #1995)

* Fix X509_DN::operator< which could erroneously return true in both
  directions (ie, DN1 < DN2 && DN2 < DN1). This would break STL
  containers using a DN as the key. (GH #1938)

* It is now possible to create intermediate CA certificates using the
  command line interface. (GH #1879 #1889)

* Add a new build time option to set where the system stores trusted
  certificates. (GH #1888)

* New ``trust_roots`` CLI that examines the system certificate store.
  (GH #1893)

* Fix bugs and add many new features in the Python wrapper.
  (GH #1899 #1900 #1901 #1902 #1903 #1904 #1906 #1907 #1915)

* Various FFI interfaces which are redundant with other APIs are now
  deprecated. The deprecation message suggests the alternate API to use.
  (GH #1915)

* Fix decoding of RSA-OAEP certificates. (GH #1943 #1944)

* Allow setting multiple organization unit fields in a certificate or
  certificate request. (GH #1939)

* Increase the maximum allowed year in ASN1_Time to 3100. This works
  around a problem parsing certs in AppVeyor's trust store.

* Add ``--format`` option to ``rng`` CLI command allowing to format
  as base64, base58 or binary in addition to hex. (GH #1945)

* Remove use of table lookups for IP/FP transforms in DES (GH #1928)

* Improve the tests for SRP6 (GH #1917 #1923)

* Document the build system

* When available use POSIX ``sysconf`` to detect the number of CPUs (GH #1877)

* Add functionality to handle Boost naming conventions on different platforms,
  especially affecting Windows. Enable Boost in AppVeyor builds. (GH #1964)

* Add alternate implementation of ``getauxval`` for older Android (GH #1962)

* Add ``configure.py`` option allowing to set arbitrary macros during build.
  (GH #1960)

* Use FreeBSD's ``elf_aux_info`` to detect ARM and POWER CPU features
  (GH #1895)

* Use FreeBSD's ``PROT_MAX`` to prevent mmap regions from being made executable
  later. (GH #2001)

* Fix a memory leak in the tests (GH #1886)

* Fix an issue building with the new Boost 1.70 (GH #1881 #1880)

* Fix an issue with UbSan in the tests (GH #1892)

* Remove use of ``-mabi`` flag when building on MIPS64 (GH #1918)

* Make it possible to specify additional libraries in ``LDFLAGS`` (GH #1916)

* Fix some warnings from Clang 8 (GH #1941)

* Fix the makefile .PHONY syntax (GH #1874)

* Fix build issue with SoftHSM 2.5.0 (GH #1986)

Version 2.10.0, 2019-03-30
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Notice: the developers plan to switch from gzip to xz compression for
  releases starting in 2.11. If this is a problem please comment at
  https://github.com/randombit/botan/issues/1872

* Warning: XMSS currently implements draft-06 which is not compatible with the
  final RFC 8391 specification. A PR is open to fix this, however it will break
  all current uses of XMSS. If you are currently using XMSS please comment at
  https://github.com/randombit/botan/pull/1858. Otherwise the PR will be merged
  and support for draft-06 will be removed starting in 2.11.

* Added a new certificate store implementation that can access the
  MacOS keychain certificate store. (GH #1830)

* Redesigned ``Memory_Pool`` class, which services allocations out of a
  set of pages locked into memory (using ``mlock``/``VirtualLock``). It is now
  faster and with improved exploit mitigations. (GH #1800)

* Add BMI2 implementations of SHA-512 and SHA-3 which improve performance by
  25-35% on common CPUs. (GH #1815)

* Unroll SHA-3 computation improving performance by 10-12% (GH #1838)

* Add a ``Thread_Pool`` class. It is now possible to run the tests in multiple
  threads with ``--test-threads=N`` flag to select the number of threads to use.
  Use ``--test-threads=0`` to run with as many CPU cores as are available on the
  current system. The default remains single threaded. (GH #1819)

* XMSS signatures now uses a global thread pool instead of spawning new threads
  for each usage. This improves signature generation performance by between 10%
  and 60% depending on architecture and core count. (GH #1864)

* Some functions related to encoding and decoding BigInts have been deprecated.
  (GH #1817)

* Binary encoding and decoding of BigInts has been optimized by performing
  word-size operations when possible. (GH #1817)

* Rename the exception ``Integrity_Failure`` to ``Invalid_Authentication_Tag`` to make
  its meaning and usage more clear. The old name remains as a typedef. (GH #1816)

* Support for using Boost ``filesystem`` and MSVC's ``std::filesystem`` have been
  removed, since already POSIX and Win32 versions had to be maintained for
  portability. (GH #1814)

* Newly generated McEliece and XMSS keys now default to being encrypted using
  SIV mode, support for which was added in 2.8.0. Previously GCM was used by
  default for these algorithms.

* Use ``arc4random`` on Android systems (GH #1851)

* Fix the encoding of PGP-S2K iteration counts (GH #1853 #1854)

* Add a facility for sandboxing the command line util. Currently FreeBSD
  (Capsicum) and OpenBSD (``pledge``) sandboxes are supported. (GH #1808)

* Use ``if constexpr`` when available.

* Disable building shared libs on iOS as it was broken and it is not clear shared
  libraries are ever useful on iOS (GH #1865)

* Renamed the ``darwin`` build target to ``macos``. This should not cause any
  user-visible change. (GH #1866)

* Add support for using ``sccache`` to cache the Windows CI build (GH #1807)

* Add ``--extra-cxxflags`` option which allows adding compilation flags without
  overriding the default set. (GH #1826)

* Add ``--format=`` option to the ``hash`` cli which allows formatting the output
  as base64 or base58, default output remains hex.

* Add ``base58_enc`` and ``base58_dec`` cli utils for base58 encoding/decoding.
  (GH #1848)

* Enable ``getentropy`` by default on macOS (GH #1862)

* Avoid using ``-momit-leaf-frame-pointer`` flags, since ``-fomit-frame-pointer``
  is already the default with recent versions of GCC.

* Fix XLC sanitizer flags.

* Rename ``Blake2b`` class to ``BLAKE2b`` to match the official name. There is
  a typedef for compat.

* Fix a bug where loading a raw ``Ed25519_PublicKey`` of incorrect length would
  lead to a crash. (GH #1850)

* Fix a bug that caused compilation problems using CryptoNG PRNG. (GH #1832)

* Extended SHAKE-128 cipher to support any key between 1 and 160 bytes, instead
  of only multiples of 8 bytes.

* Minor HMAC optimizations.

* Build fixes for GNU/Hurd.

* Fix a bug that prevented generating or verifying Ed25519 signatures in the CLI
  (GH #1828 #1829)

* Fix a compilation error when building the amalgamation outside of the original
  source directory when AVX2 was enabled. (GH #1812)

* Fix a crash when creating the amalgamation if a header file was edited on
  Windows but then the amalgamation was built on Linux (GH #1763)

Version 2.9.0, 2019-01-04
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* CVE-2018-20187 Address a side channel during ECC key generation,
  which used an unblinded Montgomery ladder. As a result, a timing
  attack can reveal information about the high bits of the secret key.

* Fix bugs in TLS which caused negotiation failures when the client
  used an unknown signature algorithm or version (GH #1711 #1709 #1708)

* Fix bug affecting GCM, EAX and ChaCha20Poly1305 where if the associated data
  was set after starting a message, the new AD was not reflected in the produced
  tag. Now with these modes setting an AD after beginning a message throws an
  exception.

* Use a smaller sieve which improves performance of prime generation.

* Fixed a bug that caused ChaCha to produce incorrect output after encrypting
  256 GB. (GH #1728)

* Add NEON and AltiVec implementations of ChaCha (GH #1719 #1728 #1729)

* Optimize AVX2 ChaCha (GH #1730)

* Many more operations in BigInt, ECC and RSA code paths are either fully const time
  or avoid problematic branches that could potentially be exploited in a side
  channel attack. (GH #1738 #1750 #1754 #1755 #1757 #1758 #1759 #1762 #1765
  #1770 #1773 #1774 #1779 #1780 #1794 #1795 #1796 #1797)

* Several optimizations for BigInt and ECC, improving ECDSA performance by as
  much as 30%. (GH #1734 #1737 #1777 #1750 #1737 #1788)

* Support recovering an ECDSA public key from a message/signature pair (GH #664 #1784)

* Add base58 encoding/decoding functions (GH #1783)

* In the command line interface, add support for reading passphrases from the
  terminal with echo disabled (GH #1756)

* Add ``CT::Mask`` type to simplify const-time programming (GH #1751)

* Add new configure options ``--disable-bmi2``, ``--disable-rdrand``,
  and ``--disable-rdseed`` to prevent use of those instruction sets.

* Add ``error_type`` and ``error_code`` functions to Exception type (GH #1744)

* Now on POSIX systems ``posix_memalign`` is used instead of ``mmap`` for
  allocating the page-locked memory pool. This avoids issues with ``fork``.
  (GH #602 #1798)

* When available, use RDRAND to generate the additional data in
  ``Stateful_RNG::randomize_with_ts_input``

* Use vzeroall/vzeroupper intrinsics to avoid AVX2/SSE transition penalties.

* Support for Visual C++ 2013 has been removed (GH #1557 #1697)

* Resolve a memory leak when verifying ECDSA signatures with versions
  of OpenSSL before 1.1.0 (GH #1698)

* Resolve a memory leak using ECDH via OpenSSL (GH #1767)

* Fix an error in XTS which prohibited encrypting values which were
  exactly the same length as the underlying block size. Messages of
  this size are allowed by the standard and other XTS implementations.
  (GH #1706)

* Resolve a bug in TSS which resulted in it using an incorrect length
  field in the shares. Now the correct length is encoded, but either
  correct or buggy lengths are accepted when decoding. (GH #1722)

* Correct a bug when reducing a negative ``BigInt`` modulo a small power of 2.
  (GH #1755)

* Add CLI utils for threshold secret splitting. (GH #1722)

* Fix a bug introduced in 2.8.0 that caused compilation failure if using
  a single amalgamation file with AVX2 enabled. (GH #1700)

* Add an explicit OS target for Emscripten and improve support for it.
  (GH #1702)

* Fix small issues when building for QNX

* Switch the Travis CI build to using Ubuntu 16.04 (GH #1767)

* Add options to ``configure.py`` to disable generation of ``pkg-config``
  file, and (for systems where ``pkg-config`` support defaults to off,
  like Windows), to enable generating it. (GH #1268)

* Modify ``configure.py`` to accept empty lists or trailing/extra commas.
  (GH #1705)

Version 2.8.0, 2018-10-01
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Add support for using Apple CommonCrypto library for hashing (GH #1667),
  cipher modes (GH #1674) and block ciphers (GH #1673).

* Support for negotiating TLS versions 1.0 and 1.1 is disabled in the default
  TLS policy. In addition, support for negotiating TLS ciphersuites using CBC or
  CCM mode is disabled by default. Applications which need to interop with old
  peers must enable these in their TLS policy object. (GH #1651)

* During primality testing, use a Lucas test in addition to Miller-Rabin. It is
  possible to construct a composite integer which passes n Miller-Rabin tests
  with probability (1/4)^n. So for a incautious verifier using a small number
  of tests (under 16 or so) it is possible if unlikely they would accept such a
  composite as prime. Adding a Lucas test precludes such an attack. (GH #1636)

* Add XChaCha and XChaCha20Poly1305 (GH #1640)

* Add AVX2 implementations of ChaCha (GH #1662) and Serpent (GH #1660)

* Add a new password hashing interface in pwdhash.h (GH #1670)

* C binding improvements. Added functions to get name and supported
  keylengths of cipher, hash and MAC objects, support for FE1 format
  preserving encryption (GH #1625 #1646), functions to load and save
  RSA keys in PKCS #1 format (GH #1621), HOTP and TOTP algorithms,
  scrypt, certificate verification (GH #1647), functions to get the
  output length of public key operations (GH #1642), and functions for
  loading and serializing X25519 keys (GH #1681)

* Support for building with BOTAN_MP_WORD_BITS set to 8 or 16 has been removed.

* Previously SM2 had two distinct key types, one for signatures and another for
  encryption. They have now been merged into a single key type since in practice
  it seems the same key is at times used for both operations. (GH #1637)

* The ``Cipher_Mode`` class now derives from ``SymmetricAlgorithm`` (GH #1639)

* Add support for using the ARMv8 instructions for SM4 encryption (GH #1622)

* The entropy source using ``SecRandomCopyBytes`` has been removed as it was
  redundant with other entropy sources (GH #1668)

* The Python module has much better error checking and reporting, and offers new
  functionality such as scrypt, MPI and FPE. (GH #1643 #1646)

* Fixed a bug that caused CCM to fail with an exception when used with L=8
  (GH #1631 #1632)

* The default bcrypt work factor has been increased from 10 to 12.

* The default algorithm used in passhash9 has changed from SHA-256 to SHA-512,
  and the default work factor increased from 10 to 15.

* In ECC private keys, include the public key data for compatibility with
  GnuTLS (GH #1634 #1635)

* Add support for using Linux ``getrandom`` syscall to access the system PRNG.
  This is disabled by default, use ``--with-os-feature=getrandom`` to enable.

* It is now possible to encrypt private keys using SIV mode.

* The FFI function botan_privkey_load now ignores its rng argument.

* Resolve a problem when building under Visual C++ 15.8 (GH #1624)

* Fix a bug in XSalsa20 (192-bit Salsa nonces) where if set_iv was called twice
  without calling set_key, the resulting encryption was incorrect. (GH #1640)

* Handle an error seen when verifying invalid ECDSA signatures using LibreSSL
  on non x86-64 platforms (GH #1627 #1628)

* Fix bugs in PKCS7 and X9.23 CBC padding schemes, which would ignore
  the first byte in the event the padding took up the entire block. (GH #1690)

* Correct bugs which would cause CFB, OCB, and GCM modes to crash when they
  were used in an unkeyed state. (GH #1639)

* Optimizations for SM4 and Poly1305

* Avoid a cache side channel in the AES key schedule

* Add ``pk_encrypt`` and ``pk_decrypt`` CLI operations

* Now ``asn1print`` CLI defaults to printing context-specific fields.

* Use codec_base for Base64, which matches how Base32 is implemented (GH #1597)

* The ``cast`` module has been split up into ``cast128`` and ``cast256`` (GH #1685)

* When building under Visual C++ 2013, the user must acknowledge the upcoming
  removal of support using the configure.py flag ``--ack-vc2013-deprecated``
  (GH #1557)

Version 2.7.0, 2018-07-02
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* CVE-2018-12435 Avoid a side channel in ECDSA signature generation (GH #1604)

* Avoid a side channel in RSA key generation due to use of a non-constant time
  gcd algorithm. (GH #1542 #1556)

* Optimize prime generation, especially improving RSA key generation. (GH #1542)

* Make Karatsuba multiplication, Montgomery field operations, Barrett reduction
  and Montgomery exponentiation const time (GH #1540 #1606 #1609 #1610)

* Optimizations for elliptic curve operations especially improving reductions
  and inversions modulo NIST primes (GH #1534 #1538 #1545 #1546 #1547 #1550)

* Add 24 word wide Comba multiplication, improving 3072-bit RSA and DH by ~25%.
  (GH #1564)

* Unroll Montgomery reduction for specific sizes (GH #1603)

* Improved performance of signature verification in ECGDSA, ECKCDSA,
  SM2 and GOST by 10-15%.

* XMSS optimizations (GH #1583 #1585)

* Fix an error that meant XMSS would only sign half as many signatures as is
  allowed (GH #1582)

* Add support for base32 encoding/decoding (GH #1541)

* Add BMI2 optimized version of SHA-256, 40% faster on Skylake (GH #1584)

* Allow the year to be up to 2200 in ASN.1 time objects. Previously this
  was limited to 2100. (GH #1536)

* Add support for Scrypt password hashing (GH #1570)

* Add support for using Scrypt for private key encryption (GH #1574)

* Optimizations for DES/3DES, approx 50% faster when used in certain modes such
  as CBC decrypt or CTR.

* XMSS signature verification did not check that the signature was of
  the expected length which could lead to a crash. (GH #1537)

* The bcrypt variants 2b and 2y are now supported.

* Support for 192-bit Suite B TLS profile is now implemented, as the 128-bit
  Suite B is since 2015 not allowed anymore.

* Previously botan allowed GCM to be used with an empty nonce, which is not
  allowed by the specification. Now such nonces are rejected.

* Avoid problems on Windows when compiling in Unicode mode (GH #1615 #1616)

* Previously for ASN.1 encoded signatures (eg ECDSA) Botan would accept any
  valid BER encoding. Now only the single valid DER encoding is accepted.

* Correct an error that could in rare cases cause an internal error exception
  when doing computations with the P-224 curve.

* Optimizations to reduce allocations/copies during DER encoding and BER
  decoding (GH #1571 #1572 #1600)

* Botan generates X.509 subject key IDs by hashing the public key with whatever
  hash function is being used to sign the certificate. However especially for
  SHA-512 this caused SKIDs that were far longer than necessary. Now all SKIDs
  are truncated to 192 bits.

* In the test suite use ``mkstemp`` to create temporary files instead of
  creating them in the current working directory. (GH #1533 #1530)

* It is now possible to safely override ``CXX`` when invoking make in addition
  to when ``configure.py`` is run. (GH #1579)

* OIDs for Camellia and SM4 in CBC and GCM mode are now defined, making it
  possible to use this algorithms for private key encryption.

* Avoid creating symlinks to the shared object on OpenBSD (#1535)

* The ``factor`` command runs much faster on larger inputs now.

* Support for Windows Phone/UWP was deprecated starting in 2.5. This deprecation
  has been reversed as it seems UWP is still actively used. (GH #1586 #1587)

* Support for Visual C++ 2013 is deprecated, and will be removed in Jan 2019.

* Added support for GCC's --sysroot option to configure.py for cross-compiling.

Version 2.6.0, 2018-04-10
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* CVE-2018-9860 Fix a bug decrypting TLS CBC ciphertexts which could
  for a malformed ciphertext cause the decryptor to read and HMAC an
  additional 64K bytes of data which is not part of the record. This
  could cause a crash if the read went into unmapped memory. No
  information leak or out of bounds write occurs.

* Add support for OAEP labels (GH #1508)

* RSA signing is about 15% faster (GH #1523) and RSA verification is
  about 50% faster.

* Add exponent blinding to RSA (GH #1523)

* Add ``Cipher_Mode::create`` and ``AEAD_Mode::create`` (GH #1527)

* Fix bug in TLS server introduced in 2.5 which caused connection to
  fail if the client offered any signature algorithm not known to the
  server (for example RSA/SHA-224).

* Fix a bug in inline asm that would with GCC 7.3 cause incorrect
  computations and an infinite loop during the tests. (GH #1524 #1529)

Version 2.5.0, 2018-04-02
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Fix error in certificate wildcard matching (CVE-2018-9127), where a
  wildcard cert for ``b*.example.com`` would be accepted as a match for
  any host with name ``*b*.example.com`` (GH #1519)

* Add support for RSA-PSS signatures in TLS (GH #1285)

* Ed25519 certificates are now supported (GH #1501)

* Many optimizations in ECC operations. ECDSA signatures are 8-10 times faster.
  ECDSA verification is about twice as fast. ECDH key agreement is 3-4 times
  faster. (GH #1457 #1478)

* Implement product scanning Montgomery reduction, which improves Diffie-Hellman
  and RSA performance by 10 to 20% on most platforms. (GH #1472)

* DSA signing and verification performance has improved by 30-50%.

* Add a new Credentials_Manager callback that specifies which CAs the server
  has indicated it trusts (GH #1395 fixing #1261)

* Add new TLS::Callbacks methods that allow creating or removing extensions,
  as well as examining extensions sent by the peer (GH #1394 #1186)

* Add new TLS::Callbacks methods that allow an application to
  negotiate use of custom elliptic curves. (GH #1448)

* Add ability to create custom elliptic curves (GH #1441 #1444)

* Add support for POWER8 AES instructions (GH #1459 #1393 #1206)

* Fix DSA/ECDSA handling of hashes longer than the group order (GH #1502 #986)

* The default encoding of ECC public keys has changed from compressed
  to uncompressed point representation. This improves compatibility with
  some common software packages including Golang's standard library.
  (GH #1480 #1483)

* It is now possible to create DNs with custom components. (GH #1490 #1492)

* It is now possible to specify the serial number of created certificates,
  instead of using the default 128-bit random integer. (GH #1489 #1491)

* Change DL_Group and EC_Group to store their data as shared_ptr for
  fast copying. Also both classes precompute additional useful values
  (eg for modular reductions). (GH #1435 #1454)

* On Windows platforms RtlGenRandom is now used in preference to CryptoAPI
  or CryptoNG libraries. (GH #1494)

* Make it possible for PKCS10 requests to include custom extensions. This also
  makes it possible to use multiple SubjectAlternativeNames of a single type in
  a request, which was previously not possible. (GH #1429 #1428)

* Add new optimized interface for FE1 format preserving encryption. By caching a
  number of values computed in the course of the FPE calculation, it provides a
  6-7x speedup versus the old API. (GH #1469)

* Add DSA and ElGamal keygen functions to FFI (#1426)

* Add ``Pipe::prepend_filter`` to replace deprecated ``Pipe::prepend`` (GH #1402)

* Fix a memory leak in the OpenSSL block cipher integration, introduced in 2.2.0

* Use an improved algorithm for generating safe primes which is several tens of
  times faster. Also, fix a bug in the prime sieving algorithm which caused
  standard prime generation (like for RSA keys) to be slower than necessary.
  (GH #1413 #1411)

* Correct the return value of ``PK_Encryptor::maximum_input_size`` which
  reported a much too small value (GH #1410)

* Remove use of CPU specific optimization flags, instead the user should set
  these via CXXFLAGS if desired. (GH #1392)

* Resolve an issue that would cause a crash in the tests if they were run on
  a machine without SSE2/NEON/VMX instructions. (GH #1495)

* The Python module now tries to load DLLs from a list of names and
  uses the first one which successfully loads and indicates it
  supports the desired API level. (GH #1497)

* Various minor optimizations for SHA-3 (GH #1433 #1434)

* The output of ``botan --help`` has been improved (GH #1387)

* Add ``--der-format`` flag to command line utils, making it possible verify
  DSA/ECDSA signatures generated by OpenSSL command line (GH #1409)

* Add support for ``--library-suffix`` option to ``configure.py`` (GH #1405 #1404)

* Use feature flags to enable/disable system specific code (GH #1378)

* Add ``--msvc-runtime`` option to allow using static runtime (GH #1499 #210)

* Add ``--enable-sanitizers=`` option to allow specifying which sanitizers to
  enable. The existing ``--with-sanitizers`` option just enables some default
  set which is known to work with the minimum required compiler versions.

* Use either ``rst2man`` or ``rst2man.py`` for generating man page as
  distributions differ on where this program is installed (GH #1516)

* The threefish module has been renamed threefish_512 since that is the
  algorithm it provides. (GH #1477)

* The Perl XS based wrapper has been removed, as it was unmaintained and
  broken. (GH #1412)

* The sqlite3 encryption patch under ``contrib`` has been removed. It
  is still maintained by the original author at
  https://github.com/OlivierJG/botansqlite3

* Support for Windows Phone is deprecated.

Version 2.4.0, 2018-01-08
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Several build improvements requested by downstream packagers, including the
  ability to disable building the static library. All makefile constructs that
  were specific to nmake or GNU make have been eliminated, thus the option
  ``--makefile-style`` which was previously used to select the makefile type has
  also been removed. (GH #1230 #1237 #1300 #1318 #1319 #1324 #1325 #1346)

* Support for negotiating the DH group as specified in RFC 7919 is now available
  in TLS (GH #1263)

* Support for ARIA-GCM ciphersuites are now available in TLS. They are disabled
  by default. (GH #1284)

* Add support for generating and verifying X.509 objects (certificates, CRLs,
  etc) using RSA-PSS signatures (GH #1270 and #1368)

* Add support for AES key wrapping with padding, as specified in RFC 5649 and
  NIST SP 800-38F (GH #1301)

* OCSP requests made during certificate verification had the potential to hang
  forever. Now the sockets are non-blocking and a timeout is enforced. (GH #1360
  fixing GH #1326)

* Add ``Public_Key::fingerprint_public`` which allows fingerprinting the public key.
  The previously available ``Private_Key::fingerprint`` is deprecated, now
  ``Private_Key::fingerprint_private`` should be used if this is required.
  (GH #1357)

* ECC certificates generated by Botan used an invalid encoding for the
  parameters field, which was rejected by some certificate validation libraries
  notably BouncyCastle. (GH #1367)

* Loading an ECC key which used OID encoding for the domain parameters, then
  saving it, would result in a key using the explicit parameters encoding.
  Now the OID encoding is retained. (GH #1365)

* Correct various problems in certificate path validation that arose when
  multiple paths could be constructed leading to a trusted root but due to
  other constraints only some of them validated. (GH #1363)

* It is now possible for certificate validation to return warning indicators,
  such as that the distinguished name is not within allowed limits or that a
  certificate with a negative serial number was observed. (GH #1363 #1359)

* XMSS signatures now are multi-threaded for improved performance (GH #1267)

* Fix a bug that caused the TLS peer cert list to be empty on a resumed session.
  (GH #1303 #1342)

* Increase the maximum HMAC key length from 512 bytes to 4096 bytes. This allows
  using a DH key exchange in TLS with a group greater than 4096 bits. (GH #1316)

* Fix a bug in the TLS server where, on receiving an SSLv3 client hello, it
  would attempt to negotiate TLS v1.2. Now a protocol_version alert is sent.
  Found with tlsfuzzer. (GH #1316)

* Fix several bugs related to sending the wrong TLS alert type in various error
  scenarios, caught with tlsfuzzer.

* Add support for a ``tls_http_server`` command line utility which responds to
  simple GET requests. This is useful for testing against a browser, or various
  TLS test tools which expect the underlying protocol to be HTTP. (GH #1315)

* Add an interface for generic PSK data stores, as well as an implementation
  which encrypts stored values with AES key wrapping. (GH #1302)

* Optimize GCM mode on systems both with and without carryless multiply
  support. This includes a new base case implementation (still constant time), a
  new SSSE3 implementation for systems with SSSE3 but not clmul, and better
  algorithms for systems with clmul and pmull. (GH #1253 #1263)

* Various optimizations for OCB, CFB, CTR, SM3, SM4, GMAC, BLAKE2b, Blowfish,
  Twofish, CAST-128, and CRC24 (GH #1281)

* Salsa20 now supports the seek operation.

* Add ``EC_Group::known_named_groups`` (GH #1339)

* Symmetric algorithms (block ciphers, stream ciphers, MACs) now verify that a
  key was set before accepting data. Previously attempting to use an unkeyed
  object would instead result in either a crash or invalid outputs. (GH #1279)

* The X509 certificate, CRL and PKCS10 types have been heavily refactored
  internally. Previously all data of these types was serialized to strings, then
  in the event a more complicated data structure (such as X509_DN) was needed,
  it would be recreated from the string representation. However the round trip
  process was not perfect and could cause fields to become lost. This approach
  is no longer used, fixing several bugs (GH #1010 #1089 #1242 #1252). The
  internal data is now stored in a ``shared_ptr``, so copying such objects is
  now very cheap. (GH #884)

* ASN.1 string objects previously held their contents as ISO 8859-1 codepoints.
  However this led to certificates which contained strings outside of this
  character set (eg in Cyrillic, Greek, or Chinese) being rejected. Now the
  strings are always converted to UTF-8, which allows representing any
  character. In addition, UCS-4 strings are now supported.
  (GH #1113 #1250 #1287 #1289)

* It is now possible to create an uninitialized X509_Certificate object. Such an
  object will throw if any attempt to access its members is made. (GH #1335)

* In BER decoder, avoid unbounded stack recursion when parsing nested indefinite
  length values. Now at most 16 nested indefinite length values are accepted,
  anything deeper resulting in a decoding error.  (GH #1304 OSS-Fuzz 4353).

* A new ASN.1 printer API allows generating a string representation of arbitrary
  BER data. This is used in the ``asn1print`` command line utility and may be
  useful in other applications, for instance for debugging.

* New functions for bit rotations that distinguish rotating by a compile-time
  constant vs a runtime variable rotation. This allows better optimizations in
  both cases. Notably performance of CAST-128 and CAST-256 are substantially
  improved. (GH #1247)

* TLS CBC ciphersuites now are implemented using the standard CBC code, instead
  of reimplementing CBC inside the TLS stack. This allows for parallel
  decryption of TLS CBC ciphertexts, and improves performance especially when
  using AES hardware support. (GH #1269)

* Add callbacks to make it possible for an application using TLS to provide
  custom implementations of signature schemes, eg when offloading the
  computations to another device. (GH #1332)

* Use a direct calculation for calendar computations instead of relying on
  non-portable operating system interfaces. (GH #1336)

* Fix a bug in the amalgamation generation which could cause build failures on
  some systems including macOS. (GH #1264 #1265)

* A particular code sequence in TLS handshake would always (with an ECC
  ciphersuite) result in an exception being thrown and then caught.  This has
  changed so no exception is thrown. (GH #1275)

* The code for byteswapping has been improved for ARMv7 and for Windows x86-64
  systems using MSVC. (GH #1274)

* The GMAC class no longer derives from GHASH. This should not cause any
  noticeable change for applications. (GH #1253)

* The base implementation of AES now uses a single 4K table, instead of 4 such
  tables. This offers a significant improvement against cache-based side
  channels without hurting performance too much. In addition the table is now
  guaranteed to be aligned on a cache line, which ensures the additional
  countermeasure of reading each cache line works as expected. (GH #1255)

* In TLS client resumption, avoid sending a OCSP stapling request. This caused
  resumption failures with some servers. (GH #1276)

* The overhead of making a call through the FFI layer has been reduced.

* The IDs for SHA-3 PKCSv1.5 signatures added in 2.3.0 were incorrect. They have
  been changed to use the correct encoding, and a test added to ensure such
  errors do not recur.

* Counter mode allows setting a configurable width of the counter. Previously it
  was allowed for a counter of even 8 bits wide, which would mean the keystream
  would repeat after just 256 blocks. Now it requires the width be at least 32
  bits. The only way this feature could be used was by manually constructing a
  ``CTR_BE`` object and setting the second parameter to something in the range
  of 1 to 3.

* A new mechanism for formatting ASN.1 data is included in ``asn1_print.h``.
  This is the same functionality used by the command line ``asn1print`` util,
  now cleaned up and moved to the library.

* Add ``Pipe::append_filter``. This is like the existing (deprecated)
  ``Pipe::append``, the difference being that ``append_filter`` only
  allows modification before the first call to ``start_msg``. (GH #1306 #1307)

* The size of ASN1_Tag is increased to 32 bits. This avoids a problem
  with UbSan (GH #751)

* Fix a bug affecting bzip2 compression. In certain circumstances, compression
  would fail with ``BZ_SEQUENCE_ERROR`` due to calling bzlib in an way it does
  not support. (GH #1308 #1309)

* In 2.3.0, final annotations were added to many classes including the TLS
  policies (like ``Strict_Policy`` and ``BSI_TR_02102_2``). However it is
  reasonable and useful for an application to derive from one of these policies, so
  as to create an application specific policy that is based on a library-provided
  policy, but with a few tweaks. So the final annotations have been removed on
  these classes. (GH #1292)

* A new option ``--with-pdf`` enables building a PDF copy of the handbook.
  (GH #1337)

* A new option ``--with-rst2man`` enables building a man page for the
  command line util using Docutils rst2man. (GH #1349)

* Support for NEON is now enabled under Clang.

* Now the compiler version is detected using the preprocessor, instead of trying
  to parse the output of the compiler's version string, which was subject to
  problems with localization. (GH #1358)

* By default the gzip compressor will not include a timestamp in the header.
  The timestamp can be set by passing it to the ``Gzip_Compression``
  constructor.

* Resolve a performance regression on Windows involving the system stats
  entropy source. (GH #1369)

* Add an OID for RIPEMD-160

* Fixes for CMake build (GH #1251)

* Avoid some signed overflow warnings (GH #1220 #1245)

* As upstream support for Native Client has been deprecated by Google, support
  is now also deprecated in Botan and will be removed in a future release.

* The Perl-XS wrapper has not been maintained in many years. It is now deprecated,
  and if no attempts are made to revive it, it will be removed in a future release.

* Support for building on IRIX has been removed.

Version 2.3.0, 2017-10-02
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Address a side channel affecting modular exponentiation. An attacker
  capable of a local or cross-VM cache analysis attack may be able
  to recover bits of secret exponents as used in RSA, DH, etc.
  CVE-2017-14737

* Add the SHACAL2 block cipher, including optimizations using SIMD and SHA-NI
  instructions. (GH #1151)

* Add the ARIA block cipher (GH #1004 and #1157)

* Add support for the ARMv8 AES instructions (GH #1182 and #1146)

* Add support for the ARMv8 PMULL instruction (GH #1181 and #842)

* On macOS and iOS the ``System_RNG`` class is now implemented using ``arc4random``.
  Previously the system RNG class was not available on iOS. (GH #1219)

* Optimized the CMAC polynomial doubling operation, and removed a small timing
  channel due to a conditional operation.

* Added support for the ECDHE_PSK AEAD TLS ciphersuites from
  draft-ietf-tls-ecdhe-psk-aead-05.

* SM2 encryption and signature schemes were previously hardcoded to use SM3
  hash, now any hash is allowed. (GH #1188)

* SM2 encryption in 2.2.0 followed an obsolete version of the standard. The
  format of the ciphertext changed in a more recent revision of the standard,
  and now uses an ASN.1 encoding. Botan has changed to reflect this format,
  which is compatible with GmSSL (GH #1218)

* OCB mode now supports 192, 256 and 512 bit block ciphers. (GH #1205)

* XTS mode now supports 256-bit and 512-bit block ciphers.

* Add ids to allow SHA-3 signatures with PKCSv1.5 (GH #1184)

* Add support for ``PSSR_Raw`` signatures which PSS sign an externally derived
  hash. (GH #1212 #1211)

* GCM now supports truncated tags in the range 96...128 bits. GCM had
  previously supported 64-bit truncated tags, but these are known to
  be insecure and are now deprecated. (GH #1210 #1207)

* Add a new TLS policy hook ``allow_client_initiated_renegotiation`` which is the
  parallel of the existing ``allow_server_initiated_renegotiation``. If set to
  false, servers will reject attempts by the client to renegotiation the
  session, instead sending a ``no_renegotiation`` warning alert. Note that the
  default is ``false``, ie that client renegotiation is now prohibited by default.
  (GH #872)

* Add HKDF-Expand-Label function which is used in TLS v1.3 and QUIC protocols.
  (GH #1226)

* Fix decoding of ECC keys that use extensions from RFC 5915 (GH #1208)

* The entropy source that called CryptGenRandom has been removed, and
  replaced by a version which invokes the system PRNG, which may
  be CryptGenRandom or some other source. (GH #1180)

* Add support for gathering entropy using the Crypt-NG BCryptGenRandom
  API. This is necessary to build for Windows Phone/Windows Store. (GH #1180)

* Extend "Raw" signature padding (which allows signing a hash computed
  externally) to optionally take a hash function name. In this case, it will be
  verified that the input matches the expected hash size.  This also will
  control the hash algorithm used for RFC 6979 deterministic nonces; previously
  SHA-512 was always used for RFC 6979 nonces with "Raw". (GH #1153)

* The advertised FFI API version has increased. This should have happened
  already in 2.2 but was neglected. The ``botan_ffi_supports_api`` call will
  return true for either the current or older versions of the API version since
  no backwards incompatible changes have occurred.

* Add new C89 API functions ``botan_hex_decode``, ``botan_base64_encode``,
  ``botan_base64_decode``, ``botan_constant_time_compare``.

* Add new C89 API functions ``botan_privkey_load_dh``, ``botan_pubkey_load_dh``,
  and ``botan_privkey_create_dh`` (GH #1155)

* Add ``is_passhash9_alg_supported`` (GH #1154)

* The ``power_mod`` function now supports negative bases (GH #1179 #1168)

* Add a new command line utility for examining TLS client hellos.

* Added a new target for LLVM bitcode (GH #1169)

* Improve support for Windows Phone (GH #1180 #796 #794)

* Correct return value of ``botan_pk_op_verify_finish``. In 2.2.0 this function
  returned -1 on invalid signature, instead of 1 which was used in 2.0, 2.1, and
  now again in 2.3. (GH #1189 #1187)

* Allow loading unencrypted private keys via FFI API (GH #1197)

* Add new command line options ``--rng-type=drbg`` and ``--drbg-seed`` which
  allow running commands with a deterministic RNG. (GH #1169)

* Fix a number of warnings seen under Visual C++ (GH #1171 #795)

* Workaround a GCC 7 bug that caused miscompilation of the GOST-34.11 hash
  function on x86-32. (GH #882 #1148)

* Fix a bug in SIMD_4x32 which affected little-endian PowerPC processors.
  This would cause test failures for Serpent, among other problems.

* Fix Altivec runtime detection, which was broken starting in Botan 2.1.0

* Optimized the verification of TLS CBC padding bytes. Previously the check
  examined every byte of the record, even though at most 256 bytes of padding
  may be appended. (GH #1227)

* Simplified definition of ``Botan::secure_allocator``. In particular, not
  defining the ``construct`` and ``destroy`` methods avoids a performance problem
  under MSVC. (GH #1228 and #1229)

* The ``secure_allocator`` class now uses ``calloc`` and ``free`` instead of
  ``new`` and ``delete``. In addition the actual allocation operation is hidden
  inside of compiled functions, which significantly reduces code size. (GH #1231)

* The ``secure_scrub_memory`` function now uses ``explicit_bzero`` on OpenBSD.

* Previously ARM feature detection (NEON, AES, ...) relied on getauxval, which
  is only supported on Linux and Android. Now iOS is supported, by checking the
  model name/version and matching it against known versions. Unfortunately this
  is the best available technique on iOS. On Aarch64 systems that are not iOS or
  Linux/Android, a technique based on trial execution while catching SIGILL is
  used. (GH #1213)

* The output of ``botan config libs`` was incorrect, it produced ``-lbotan-2.X``
  where X is the minor version, instead of the actual lib name ``-lbotan-2``.

* Add ``constant_time_compare`` as better named equivalent of ``same_mem``.

* Silence a Clang warning in ``create_private_key`` (GH #1150)

* The fuzzers have been better integrated with the main build. See the
  handbook for details. (GH #1158)

* The Travis CI and AppVeyor CI builds are now run via a Python script. This
  makes it easier to replicate the behavior of the CI build locally. Also a
  number of changes were made to improve the turnaround time of CI builds.
  (GH #1162 #1199)

* Add support for Win32 filesystem operation, so the tests pass completely
  on MinGW now (GH #1203)

* Added a script to automate running TLS-Attacker tests.

* The distribution script now creates reproducible outputs, by
  forcing all modification times, uids, etc to values fixed by the release date.
  (GH #1217)

* The ``BOTAN_DLL`` macro has been split up into ``BOTAN_PUBLIC_API``,
  ``BOTAN_UNSTABLE_API`` and ``BOTAN_TEST_API`` which allows
  indicating in the header the API stability of the export. All three
  are defined as ``BOTAN_DLL`` so overriding just that macro continues
  to work as before. (GH #1216)

* Optimize ``bigint_divop`` when a double-word type is available. (GH #494)

* Fix several memory leaks in the tests. Additionally a false positive
  leak seen under ``valgrind`` in the ``fork`` tests for the RNG was resolved.

* Export ``CurveGFp_Repr`` type (only used internally) to resolve a
  long standing UBSan warning. (GH #453)

* Now ``-fstack-protector`` and similar flags that affect linking are exported
  in ``botan config ldflags`` as they already were in the ``pkg-config`` output.
  (GH #863)

* Remove double underscore in header guards to avoid using names
  reserved by ISO C++. (GH #512)

* Additions to the SRP documentation (GH #1029)

* The package transform (in ``package.h``) is now deprecated, and will be
  removed in a future release. (GH #1215)

* Add more tests for the const-time utils (GH #1214)

* Fix a bug in FFI tests that caused the test files not to be found when using
  ``--data-dir`` option (GH #1149)

* C++ ``final`` annotations have been added to classes which are not
  intended for derivation. This keyword was already in use but was not
  applied consistently.

* A typedef ``SecureVector`` has been added for the ``secure_vector`` type.
  This makes porting code from 1.10 to 2.x API slightly simpler.

* Header files have been cleaned up to remove unnecessary inclusions. In some
  cases it may be required to include additional botan headers to get all the
  declarations that were previously visible. For example, ``bigint.h`` no longer
  includes ``rng.h``, but just forward declares ``RandomNumberGenerator``.

* Improved support for IBM xlc compiler.

Version 2.2.0, 2017-08-07
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Add the Ed25519 signature scheme (GH #1066)

* The format of x25519 keys, which previously used a non-standard encoding,
  has changed to match the upcoming IETF specification. (GH #1076)

* Add the SM2 signature scheme (GH #1082)

* Add the SM2 public key encryption scheme (GH #1142)

* Add the SM3 hash function (GH #996)

* Add the Streebog (GOST R 34.11-2012) hash function (GH #1114)

* Add the SM4 block cipher (GH #1080)

* Add the PGP S2K algorithm (GH #1060)

* Add SP 800-56A KDF (GH #1040)

* Add ChaCha_RNG which is a very fast and completely non-standard
  random bit generator (GH #1137)

* Add support for SHA-1 and SHA-2 instructions added in Intel Goldmont
  (GH #826)

* Add support for SHA-1 and SHA-2 instructions added in ARMv8 (GH #844)

* Add support for HOTP (RFC 4226) and TOTP (RFC 6238)
  one-time-password algorithms (GH #1054)

* Fix a bug that caused secure_allocator to not fully zeroize blocks
  when sizeof(T) was greater than 1.

* Add HashFunction::copy_state which allows efficiently computing the
  hash of several messages with a common prefix (GH #1056 #1037)

* ECC keys now encode their parameters using an OID instead of a literal
  encoding of the domain parameters. This will lead to smaller public and
  private keys in most instances. (GH #1093)

* The OpenSSL backend now supports the 1.1.0 API (GH #1056)

* Add a preliminary provider using BearSSL, currently EC and hashes supported
  (GH #1094)

* Fix a bug in certificate path length checking that could cause valid
  chains to be rejected. (GH #1053)

* It is possible for CBC, CFB, and stream ciphers to carry over the
  nonce from the previous message, which is needed by some applications.
  This worked in 1.10 but broke in 2.0. (GH #1044 fixing GH #864)

* Avoid recursion in BER_Decoder::get_next_object which could cause
  stack exhaustion. (GH #989)

* Fix missing flush in DataSink_Stream::end_msg. (GH #972 fixing GH #972)

* Allow to seek in the big endian counter mode of operation (GH #999)

* Support loading ElGamal keys through FFI interface (GH #1008)

* Support Windows sockets in ``http_util`` (allowing OCSP checks on Windows),
  as well as in the TLS command line utils (GH #1138).

* The ``--destdir`` flag to ``configure.py`` has been removed. Instead use
  the ``DESTDIR`` environment variable at install time. This change was
  done to more closely match how autoconf handles this case.
  (GH #1139 #1111 #997 #996).

* Many changes to configure.py and botan2.py to make them pylint clean
  (GH #1041 #1002 #984)

* Add command line utils ``hmac`` (GH #1001), ``encryption`` (GH #359),
  ``hex_enc``, and ``hex_dec``.

* Fix an error in ``sign_cert`` command line util, which ignored the
  ``--ca-key-pass`` option. (GH #1106)

* The ``speed`` util can now benchmark multiple buffer sizes (GH #1084)

* Fix return value of FFI botan_bcrypt_is_valid (GH #1033)

* Support generating RSA keys using OpenSSL (GH #1035)

* Add new FFI functions botan_hash_block_size (GH #1036),
  botan_hash_copy_state (GH #1059), botan_scrub_mem

* Add support for RFC 3394 keywrap through FFI (GH #1135)

* Support AES-CBC ciphers via OpenSSL (GH #1022)

* Add function to return certificates included in OCSP response (GH #1123)

* Complete wildcard handling for X.509 certificates (GH #1017)

* Add some missing functions to TLS::Text_Policy (GH #1023)

* It was previously possible to use ``--single-amalgamation-file``
  without ``--amalgamation``, though it did not do anything useful. Now
  ``--single-amalgamation-file`` requires ``--amalgamation`` also be set
  on the command line.

Version 2.1.0, 2017-04-04
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Fix incorrect truncation in Bcrypt. Passwords in length between 56 and 72
  characters were truncated at 56 characters. Found and reported by Solar Designer.
  (CVE-2017-7252) (GH #938)

* Fix a bug in X509 DN string comparisons that could result in out of bound
  reads. This could result in information leakage, denial of service, or
  potentially incorrect certificate validation results. Found independently
  by Cisco Talos team and OSS-Fuzz. (CVE-2017-2801)

* Correct minimum work factor for Bcrypt password hashes. All other
  implementations require the work factor be at least 4. Previously Botan simply
  required it be greater than zero. (GH #938)

* Converge on a single side channel silent EC blinded multiply algorithm.
  Uses Montgomery ladder with order/2 bits scalar blinding and point randomization
  now by default. (GH #893)

* Add ability to search for certificates using the SHA-256 of the distinguished name.
  (GH #900)

* Support a 0-length IV in ChaCha stream cipher. Such an IV is treated
  identically to an 8-byte IV of all zeros.

* Add new interfaces to the C API including multiple precision integers, key
  validity tests, block ciphers, and extracting algorithm specific key parameters
  (such as the modulus and public exponent from RSA public keys). GH #899 #944
  #946 #961 #964

* The PKCS11 module did not require any external dependencies, so it
  has been enabled by default. The ``--with-pkcs11`` and ``--without-pkcs11``
  flags to ``configure.py`` have been removed. PKCS11 can still be disabled
  using ``--disable-modules=pkcs11`` (GH #837)

* Add ``OS::run_cpu_instruction_probe`` for runtime probing of ISA extensions.
  Supporting this requires system-specific techniques, currently Windows SEH and
  Unix signal handling are supported.

* Add support for ARM NEON in the SIMD_4x32 type

* Add support for ARM CPU feature detection using getauxval (GH #843)

* Previously Botan forbid any use of times past 2037 to avoid Y2038 issues.
  Now this restriction is only in place on systems which have a 32-bit
  ``time_t``. (GH #933 fixing #917)

* Add generic type decoder function to BER decoder (GH #897)

* Fix portability or build problems affecting Sun Studio compiler (GH #846),
  Solaris, ppc64le, DragonflyBSD (GH #887)

* Add ``--with-external-libdir`` to configure.py (GH #857 fixing #19 #767)

* Add ``OS::get_high_resolution_clock`` which returns the best resolution
  clock available on the system.

* Change ``OS::get_processor_timestamp`` to return 0 if no hardware
  cycle counter is available. Previously it silently fell back on some
  other clock type.

* Report cycles/byte in the output of ``botan speed``.

* Add speed tests for modular exponentiations and ECC scalar multiplies.

* Avoid using IP address for SNI in ``tls_client``. (GH #942)

* Add command line util ``timing_test`` which enables running
  timing-based side channel analysis of TLS CBC decryption, ECC scalar
  multiplies, OAEP decoding, and other operations which are prone to
  providing an oracle via side channel. This replaces the standalone
  timing test suite added in 1.11.34, which has been removed.

* Various cleanups and refactorings (GH #965)

* Add wrapper of C++14 make_unique (GH #974)

* Fix pkg-config output when --build-dir was used (GH #936)

* Make it possible to disable `-fstack-protector` using a build-time flag.
  GH #863

* Add tests for TLS DSA ciphersuites, more Noekeon tests, others.

* Avoid a GCC warning that triggered on the public key types (GH #849)

* Fix various warnings flagged by pylint and pyflakes linters in
  configure.py and botan.py (GH #832 #836 #839 #962 #975)

* Improve support for OpenBSD including using getentropy (GH #954)
  for PRNG seeding, and arc4random to access system RNG (GH #953)

* Add ability to build through CMake. As of now this is only supported
  for development rather than production builds. (GH #967)

* Rename python wrapper to botan2.py (GH #847)

* Change name constraint test to use a fixed reference time. Test certs have expired.

* Increase Miller-Rabin iterations for DSA primes to match FIPS 186-4. (GH #881)

* Fix possible ISO 9796-2 padding side channel, and add a missing length check (GH #891)

* In command line utility, prefer the system RNG if it is available.

Version 2.0.1, 2017-01-09
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Change an unintended behavior of 2.0.0, which named the include
  directory ``botan-2.0``. Since future release of Botan-2 should be
  compatible with code written against old versions, there does not
  seem to be any reason to version the include directory with the
  minor number. (GH #830 #833)

* Fix a bug which caused an error when building on Cygwin or
  other platforms where shared libraries are not supported.
  (GH #821)

* Enable use of readdir on Cygwin, which allows the tests to run (GH #824)

* Switch to readthedocs Sphinx theme by default (GH #822 #823)

Version 2.0.0, 2017-01-06
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* With this release the project adopts Semantic Versioning (GH #766)

* Fix a longstanding bug in modular exponentiation which caused most
  exponentiations modulo an even number to have an incorrect result; such moduli
  occur only rarely in cryptographic contexts. (GH #754)

* Fix a bug in BigInt multiply operation, introduced in 1.11.30, which could
  cause incorrect results. Found by OSS-Fuzz fuzzing the ressol function, where
  the bug manifested as an incorrect modular exponentiation. OSS-Fuzz bug #287

* Fix a bug that meant the "ietf/modp/6144" and "ietf/modp/8192" discrete log
  groups used an incorrect value for the generator, specifically the value
  (p-1)/2 was used instead of the correct value of 2.

* The DL_Group enum value X942_DH_PARAMETERS has been renamed
  ANSI_X9_42_DH_PARAMETERS to avoid a conflict with Windows headers (GH #482)

* Change default PEM header for X942 DH to match OpenSSL. Either version is
  accepted on reading. (GH #818)

* DL_Group strong generation previously set the generator to 2. However
  sometimes 2 generates the entire group mod p, rather than the subgroup mod q.
  This is invalid by X9.42 standard, and exposes incautious applications to
  small subgroup attacks. Now DL_Group uses the smallest g which is a quadratic
  residue. (GH #818)

* Add iOS build target instead of piggybacking on OS X configuration. (GH #793)

* Changes all Public_Key derived class ctors to take a std::vector instead of a
  secure_vector for the DER encoded public key bits. (GH #768)

* Allow use of custom extensions when creating X.509 certificates (GH #744)

* The default TLS policy now requires 2048 or larger DH groups by default.

* Add BSI_TR_02102_2 TLS::Policy subclass representing BSI TR-02102-2 recommendations.

* The default Path_Validation_Restrictions constructor has changed to
  require at least 110 bit signature strength. This means 1024 bit RSA
  certificates and also SHA-1 certificates are rejected by default.
  Both settings were already the default for certificate validation in
  TLS handshake, but this changes it for applications also.

* Add ISO 9796-2 signature padding schemes DS2 and DS3. These schemes provide
  message recovery (part or all of the plaintext message can be recovered from
  the signature alone) and are used by some industry protocols. (GH #759)

* Rewrite all the code that handles parsing CBC padding bytes to run without
  conditional jumps or loads. (GH #765 #728)

* Fix deref of invalid memory location in TLS client when the server chooses a
  ciphersuite value larger than the largest TLS ciphersuite ID compiled into the
  table. This might conceivably cause a crash in rare circumstances, but does
  not seem to be further exploitable. (GH #758)

* Rename Public_Key::x509_subject_public_key, which does not return a
  X.509 SubjectPublicKey, to public_key_bits. Add a new non-virtual function
  Public_Key::subject_public_key which does exactly that. (GH #685 #757)

* Rename Private_Key::pkcs8_private_key, which does not return a
  PKCS#8 private key, to private_key_bits. Add a new non-virtual function
  Private_Key::private_key_info which does exactly that. (GH #685 #757)

* The deprecated ECB Cipher_Mode class has been removed (GH #756)

* The class SRP6_Authenticator_File (in srp6_files.h) was meant to parse GnuTLS
  SRP files. But it was completely untested, and it turns out due to several
  problems it was completely unable to parse any SRP file correctly. It has
  been removed, with a future replacement planned that can handle both
  flat files (in the actual SRP format) or using a SQL database.

* Fix tests errors when write access to /dev/urandom is prohibited (GH #748)

* Add more Diffie-Hellman tests (GH #790), tests for RSA blinding, others.

* Add `tls_ciphers` command which prints the ciphersuites a client
  hello will contain, depending on the policy specified.

* Prevent TLS from negotiating SHA-2 ciphersuites in TLS v1.0/v1.1. These
  ciphersuites are technically not defined except for v1.2, so disable
  them in older protocols. (GH #496)

* Documentation: add project goals (GH #788) and side channel info (GH #787)

Older Versions
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* The release notes for versions 0.7.0 through 1.11.34 can be found in
  ``doc/old_news.rst``
