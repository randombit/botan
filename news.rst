Release Notes
========================================

Changes between 2.0.1 and 2.0.1-RSCS1, 2017-XX-XX
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* The PKCS11 module did not require any external dependencies, so it has been enabled by default. The -with-pkcs11 and --without-pkcs11 flags to configure.py have been removed. (GH #837)

* Add OS::run_cpu_instruction_probe for runtime probing of ISA extensions. Supporting this requires system-specific techniques, currently Windows SEH and Unix signal handling are supported.

* Add support for ARM NEON in the SIMD_4x32 type

* Add support for ARM CPU feature detection using getauxval (GH #843)

* Fix portability or build problems affecting Sun Studio compiler (GH #846), Solaris, ppc64le, DragonflyBSD (GH #887)

* Add --with-external-libdir to configure.py (GH #857 fixing #19 #767)

* Add OS::get_high_resolution_clock which returns the best resolution clock available on the system.

* Change OS::get_processor_timestamp to return 0 if no hardware cycle counter is available. Previously it silently fell back on some other clock type.

* Report cycles/byte in the output of botan speed.

* Add speed tests for modular exponentiations and ECC scalar multiplies.

* Add command line util timing_test which enables running timing-based side channel analysis of TLS CBC decryption, ECC scalar multiplies, OAEP decoding, and other operations which are prone to providing an oracle via side channel.

* Make it possible to disable -fstack-protector using a build-time flag. GH #863

* Add tests for TLS DSA ciphersuites, more Noekeon tests, others.

* Avoid a GCC warning that triggered on the public key types (GH #849)

* Fix various warnings flagged by pylint and pyflakes linters in configure.py and botan.py (GH #832 #836 #839)

* Rename python wrapper to botan2.py (GH #847)

* Change name constraint test to use a fixed reference time. Test certs have expired.

* Increase miller-rabin iterations for DSA primes (FIPS-186-4) (GH #881)

* Fix possible ISO 9796-2 padding side channel and add a length check (GH #891)

* In CLI, if system RNG is available prefer it

* Converge on a single side channel silent EC blinded multiply algorithm.
  Uses montgomery ladder with order/2 bits scalar blinding and point randomization
  now by default. (GH #893)