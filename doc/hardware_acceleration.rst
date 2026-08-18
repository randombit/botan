Hardware Acceleration
==============================

Botan provides built-in support for hardware acceleration of certain algorithms
on certain platforms. These alternate implementations use special CPU instructions
that are not available on all platforms and either speed up the algorithm
or improve security in terms of side channel resistance.

The following sections list the platforms and algorithms for which hardware acceleration
is available. If the CPU specific optimizations are available at runtime, they are
automatically used if enabled in the build. If not, the base implementation is used.

It is possible to disable CPU-specific optimizations at runtime by setting the
environment variable ``BOTAN_CLEAR_CPUID``. For example
``BOTAN_CLEAR_CPUID=avx2`` will disable use of any AVX2 instructions.

x86
--------------

On x86-64 and x86-32 platforms, the following CPU specific optimizations are available.

.. note::

   AVX-512 codepaths are only used on x86-64 processors that support AVX-512
   extensions similar to Intel Ice Lake or AMD Zen4 (requires AVX-512 F, VL, BW,
   DQ, VBMI, VBMI2, BITALG, IFMA)

+-----------+--------------------------------------------+-------------------------+------------+
| Algorithm | Extension                                  | Module                  | Added in   |
+===========+============================================+=========================+============+
| AES       | VAES-AVX2                                  | ``aes_vaes``            | 3.6.0      |
|           |                                            |                         |            |
|           | AES-NI                                     | ``aes_ni``              | 1.9.3      |
|           |                                            |                         |            |
|           | SSSE3                                      | ``aes_vperm``           | 1.9.10     |
+-----------+--------------------------------------------+-------------------------+------------+
| AES-GCM   | AVX-512 + CLMUL                            | ``ghash_avx512_clmul``  | 3.11.0     |
|           |                                            |                         |            |
|           | CLMUL                                      | ``ghash_cpu``           | 1.11.6     |
|           |                                            |                         |            |
|           | SSSE3                                      | ``ghash_vperm``         | 1.9.10     |
+-----------+--------------------------------------------+-------------------------+------------+
| Argon2    | AVX-512                                    | ``argon2_avx512``       | 3.11.1     |
|           |                                            |                         |            |
|           | AVX2                                       | ``argon2_simd4x64``     | 3.0.0      |
|           |                                            |                         |            |
|           | SSSE3                                      | ``argon2_simd64``       | 2.19.2     |
+-----------+--------------------------------------------+-------------------------+------------+
| ARIA      | AVX-512 + GFNI                             | ``aria_avx512_gfni``    | 3.11.0     |
|           |                                            |                         |            |
|           | AES-NI                                     | ``aria_hwaes``          | 3.11.1     |
+-----------+--------------------------------------------+-------------------------+------------+
| Camellia  | AVX-512 + GFNI                             | ``camellia_avx512_gfni``| 3.11.0     |
|           |                                            |                         |            |
|           | AVX2 + GFNI                                | ``camellia_avx2_gfni``  | 3.9.0      |
|           |                                            |                         |            |
|           | AES-NI                                     | ``camellia_hwaes``      | 3.11.1     |
+-----------+--------------------------------------------+-------------------------+------------+
| ChaCha    | AVX-512                                    | ``chacha_avx512``       | 3.1.0      |
|           |                                            |                         |            |
|           | AVX2                                       | ``chacha_simd8x32``     | 2.8.0      |
|           |                                            |                         |            |
|           | SSSE3                                      | ``chacha_simd32``       | 1.11.32    |
+-----------+--------------------------------------------+-------------------------+------------+
| CTR       | AVX2                                       | ``ctr_simd8x32``        | 3.11.1     |
|           |                                            |                         |            |
|           | SSSE3                                      | ``ctr_simd32``          | 3.11.1     |
+-----------+--------------------------------------------+-------------------------+------------+
| IDEA      | AVX2                                       | ``idea_avx2``           | 3.11.0     |
|           |                                            |                         |            |
|           | SSE2                                       | ``idea_sse2``           | 1.9.4      |
+-----------+--------------------------------------------+-------------------------+------------+
| NOEKEON   | SSSE3                                      | ``noekeon_simd``        | 1.9.4      |
+-----------+--------------------------------------------+-------------------------+------------+
| Poly1305  | AVX-512                                    | ``poly1305_avx512``     | 3.11.0     |
|           |                                            |                         |            |
|           | AVX2                                       | ``poly1305_avx2``       | 3.11.0     |
+-----------+--------------------------------------------+-------------------------+------------+
| RDRAND    | RDRAND                                     | ``processor_rng``       | 1.11.31    |
+-----------+--------------------------------------------+-------------------------+------------+
| RDSEED    | RDSEED                                     | ``rdseed``              | 1.11.36    |
+-----------+--------------------------------------------+-------------------------+------------+
| Salsa20   | AVX-512                                    | ``salsa20_avx512``      | 3.13.0     |
|           |                                            |                         |            |
|           | AVX2                                       | ``salsa20_simd8x32``    | 3.13.0     |
|           |                                            |                         |            |
|           | SSSE3                                      | ``salsa20_simd32``      | 3.13.0     |
+-----------+--------------------------------------------+-------------------------+------------+
| SEED      | AVX-512 + GFNI                             | ``seed_avx512_gfni``    | 3.11.1     |
|           |                                            |                         |            |
|           | AES-NI                                     | ``seed_hwaes``          | 3.11.1     |
+-----------+--------------------------------------------+-------------------------+------------+
| Serpent   | AVX-512                                    | ``serpent_avx512``      | 3.1.0      |
|           |                                            |                         |            |
|           | AVX2                                       | ``serpent_simd8x32``    | 2.8.0      |
|           |                                            |                         |            |
|           | SSSE3                                      | ``serpent_simd``        | 1.9.0      |
+-----------+--------------------------------------------+-------------------------+------------+
| SHACAL2   | Intel SHA Extensions                       | ``shacal2_x86``         | 2.3.0      |
|           |                                            |                         |            |
|           | AVX-512                                    | ``shacal2_avx512``      | 3.9.0      |
|           |                                            |                         |            |
|           | AVX2                                       | ``shacal2_simd8x32``    | 2.13.0     |
+-----------+--------------------------------------------+-------------------------+------------+
| SHA-1     | Intel SHA Extensions                       | ``sha1_x86``            | 2.2.0      |
|           |                                            |                         |            |
|           | AVX2 + BMI2                                | ``sha1_avx2``           | 3.9.0      |
|           |                                            |                         |            |
|           | SSSE3                                      | ``sha1_simd``           | 1.7.12     |
+-----------+--------------------------------------------+-------------------------+------------+
| SHA-256   | Intel SHA Extensions                       | ``sha2_32_x86``         | 2.2.0      |
|           |                                            |                         |            |
|           | AVX2 + BMI2                                | ``sha2_32_avx2``        | 3.8.0      |
|           |                                            |                         |            |
|           | SSSE3                                      | ``sha2_32_simd``        | 3.8.0      |
+-----------+--------------------------------------------+-------------------------+------------+
| SHA-512   | Intel SHA Extensions                       | ``sha2_64_x86``         | 3.8.0      |
|           |                                            |                         |            |
|           | AVX-512 + BMI2                             | ``sha2_64_avx512``      | 3.8.0      |
|           |                                            |                         |            |
|           | AVX2 + BMI2                                | ``sha2_64_avx2``        | 3.8.0      |
+-----------+--------------------------------------------+-------------------------+------------+
| SHA-3 /   | BMI2                                       | ``keccak_perm_bmi2``    | 2.10.0     |
| SHAKE /   |                                            |                         |            |
| KMAC      | AVX-512                                    | ``keccak_perm_avx512``  | 3.11.0     |
+-----------+--------------------------------------------+-------------------------+------------+
| SM3       | AVX2 + BMI2                                | ``sm3_avx2_bmi2``       | 3.11.0     |
|           |                                            |                         |            |
|           | SM3-NI                                     | ``sm3_x86``             | 3.11.0     |
+-----------+--------------------------------------------+-------------------------+------------+
| SM4       | AVX-512 + GFNI                             | ``sm4_avx512``          | 3.11.0     |
|           |                                            |                         |            |
|           | AVX2 + GFNI                                | ``sm4_gfni``            | 3.6.0      |
|           |                                            |                         |            |
|           | SM4-NI                                     | ``sm4_x86``             | 3.8.0      |
|           |                                            |                         |            |
|           | AES-NI                                     | ``sm4_hwaes``           | 3.11.1     |
+-----------+--------------------------------------------+-------------------------+------------+
| Twofish   | AVX-512 + GFNI                             | ``twofish_avx512``      | 3.11.1     |
+-----------+--------------------------------------------+-------------------------+------------+
| Whirlpool | AVX-512                                    | ``whirlpool_avx512``    | 3.11.1     |
|           |                                            |                         |            |
|           | AVX2                                       | ``whirlpool_avx2``      | 3.11.1     |
+-----------+--------------------------------------------+-------------------------+------------+
| XTS       | AVX-512 + CLMUL                            | ``xts_avx512_clmul``    | 3.11.0     |
+-----------+--------------------------------------------+-------------------------+------------+
| ZFEC      | SSSE3                                      | ``zfec_vperm``          | 3.0.0      |
+-----------+--------------------------------------------+-------------------------+------------+

ARM
--------------

On ARM platforms, the following CPU specific optimizations are available.

.. note::

   The ARMv8 cryptography extensions are only used on 64-bit aarch64 systems

+-----------+--------------------------------------------+--------------------+------------+
| Algorithm | Extension                                  | Module             | Added in   |
+===========+============================================+====================+============+
| AES       | ARMv8 Cryptography Extensions              | ``aes_armv8``      | 2.3.0      |
|           |                                            |                    |            |
|           | NEON                                       | ``aes_vperm``      | 2.12.0     |
+-----------+--------------------------------------------+--------------------+------------+
| AES-GCM   | ARMv8 Cryptography Extensions              | ``ghash_cpu``      | 2.3.0      |
+-----------+--------------------------------------------+--------------------+------------+
| ARIA      | ARMv8 Cryptography Extensions              | ``aria_hwaes``     | 3.11.1     |
+-----------+--------------------------------------------+--------------------+------------+
| Camellia  | ARMv8 Cryptography Extensions              | ``camellia_hwaes`` | 3.11.1     |
+-----------+--------------------------------------------+--------------------+------------+
| ChaCha    | NEON                                       | ``chacha_simd32``  | 2.8.0      |
+-----------+--------------------------------------------+--------------------+------------+
| NOEKEON   | NEON                                       | ``noekeon_simd``   | 1.9.4      |
+-----------+--------------------------------------------+--------------------+------------+
| SEED      | ARMv8 Cryptography Extensions              | ``seed_hwaes``     | 3.11.1     |
+-----------+--------------------------------------------+--------------------+------------+
| Serpent   | NEON                                       | ``serpent_simd``   | 1.9.2      |
+-----------+--------------------------------------------+--------------------+------------+
| SHACAL2   | NEON                                       | ``shacal2_simd``   | 2.3.0      |
|           |                                            |                    |            |
|           | ARMv8 Cryptography Extensions              | ``shacal2_armv8``  | 2.13.0     |
+-----------+--------------------------------------------+--------------------+------------+
| SHA-1     | ARMv8 Cryptography Extensions              | ``sha1_armv8``     | 2.2.0      |
|           |                                            |                    |            |
|           | NEON                                       | ``sha1_simd``      | 3.8.0      |
+-----------+--------------------------------------------+--------------------+------------+
| SHA-256   | ARMv8 Cryptography Extensions              | ``sha2_32_armv8``  | 2.2.0      |
|           |                                            |                    |            |
|           | NEON                                       | ``sha2_32_simd``   | 3.8.0      |
+-----------+--------------------------------------------+--------------------+------------+
| SHA-384   | ARMv8 Cryptography Extensions              | ``sha2_64_armv8``  | 3.3.0      |
+-----------+--------------------------------------------+--------------------+------------+
| SHA-512   | ARMv8 Cryptography Extensions              | ``sha2_64_armv8``  | 3.3.0      |
+-----------+--------------------------------------------+--------------------+------------+
| SM3       | ARMv8 Cryptography Extensions              | ``sm3_armv8``      | 3.11.0     |
+-----------+--------------------------------------------+--------------------+------------+
| SM4       | ARMv8 Cryptography Extensions              | ``sm4_armv8``      | 2.8.0      |
|           |                                            |                    |            |
|           | ARMv8 Cryptography Extensions              | ``sm4_hwaes``      | 3.11.1     |
+-----------+--------------------------------------------+--------------------+------------+
| ZFEC      | NEON                                       | ``zfec_vperm``     | 3.0.0      |
+-----------+--------------------------------------------+--------------------+------------+

POWER/PowerPC
--------------

On 64-bit POWER/PowerPC platforms, the following CPU specific optimizations are available:

+-----------+--------------------------------------------+--------------------+------------+
| Algorithm | Extension                                  | Module             | Added in   |
+===========+============================================+====================+============+
| AES       | POWER8/POWER9                              | ``aes_power8``     | 2.14.0     |
|           |                                            |                    |            |
|           | AltiVec                                    | ``aes_vperm``      | 2.12.0     |
+-----------+--------------------------------------------+--------------------+------------+
| ChaCha    | AltiVec                                    | ``chacha_simd32``  | 2.8.0      |
+-----------+--------------------------------------------+--------------------+------------+
| DARN      | POWER9                                     | ``processor_rng``  | 2.15.0     |
+-----------+--------------------------------------------+--------------------+------------+
| Serpent   | AltiVec                                    | ``serpent_simd``   | 1.9.2      |
+-----------+--------------------------------------------+--------------------+------------+
| SHACAL2   | AltiVec                                    | ``shacal2_simd``   | 2.3.0      |
+-----------+--------------------------------------------+--------------------+------------+
| NOEKEON   | AltiVec                                    | ``noekeon_simd``   | 1.9.4      |
+-----------+--------------------------------------------+--------------------+------------+

Loongarch64
--------------

On loongarch64, the LSX extensions are used.

.. note::

   Loongarch64 apparently supports a "crypto" extension, for which hwcaps exist
   for Linux, and there are shipping processors which do support these
   extensions. However no documentation has been so far located. If you are
   aware of any such documentation please do contact the maintainers.

+-----------+--------------------------------------------+--------------------+------------+
| Algorithm | Extension                                  | Module             | Added in   |
+===========+============================================+====================+============+
| AES       | LSX                                        | ``aes_vperm``      | 3.8.0      |
+-----------+--------------------------------------------+--------------------+------------+
| ChaCha    | LSX                                        | ``chacha_simd32``  | 3.8.0      |
+-----------+--------------------------------------------+--------------------+------------+
| Serpent   | LSX                                        | ``serpent_simd``   | 3.8.0      |
+-----------+--------------------------------------------+--------------------+------------+
| SHA-1     | LSX                                        | ``sha1_simd``      | 3.8.0      |
+-----------+--------------------------------------------+--------------------+------------+
| SHACAL2   | LSX                                        | ``shacal2_simd``   | 3.8.0      |
+-----------+--------------------------------------------+--------------------+------------+
| NOEKEON   | LSX                                        | ``noekeon_simd``   | 3.8.0      |
+-----------+--------------------------------------------+--------------------+------------+
| ZFEC      | LSX                                        | ``zfec_vperm``     | 3.8.0      |
+-----------+--------------------------------------------+--------------------+------------+

Wasm
--------------

On Wasm, the SIMD128 extension is used.

.. note::

   To make use of SIMD128, ````simd128`` compilation flag is required.

+-----------+--------------------------------------------+--------------------+------------+
| Algorithm | Extension                                  | Module             | Added in   |
+===========+============================================+====================+============+
| AES       | SIMD128                                    | ``aes_vperm``      | 3.11.0     |
+-----------+--------------------------------------------+--------------------+------------+
| AES-GCM   | SIMD128                                    | ``ghash_vperm``    | 3.11.0     |
+-----------+--------------------------------------------+--------------------+------------+
| Argon2    | SIMD128                                    | ``argon2_simd64``  | 3.11.0     |
+-----------+--------------------------------------------+--------------------+------------+
| ChaCha    | SIMD128                                    | ``chacha_simd32``  | 3.11.0     |
+-----------+--------------------------------------------+--------------------+------------+
| Serpent   | SIMD128                                    | ``serpent_simd``   | 3.11.0     |
+-----------+--------------------------------------------+--------------------+------------+
| SHA-1     | SIMD128                                    | ``sha1_simd``      | 3.11.0     |
+-----------+--------------------------------------------+--------------------+------------+
| SHA-256   | SIMD128                                    | ``sha2_32_simd``   | 3.11.0     |
+-----------+--------------------------------------------+--------------------+------------+
| SHACAL2   | SIMD128                                    | ``shacal2_simd``   | 3.11.0     |
+-----------+--------------------------------------------+--------------------+------------+
| NOEKEON   | SIMD128                                    | ``noekeon_simd``   | 3.11.0     |
+-----------+--------------------------------------------+--------------------+------------+
| ZFEC      | SIMD128                                    | ``zfec_vperm``     | 3.11.0     |
+-----------+--------------------------------------------+--------------------+------------+

Configuring Acceleration
------------------------------

If it is desirable to avoid using some form of acceleration, this can be accomplished
*at build time* by using ``--disable-modules=``. For instance, to remove support
of ARMv8 intrinsics for AES, use ``--disable-modules=aes_armv8``. Note that this is rarely
if ever required; if support for the CPU extension is not available at runtime then the
code using that extension will simply be skipped over. The only reason to do this is when
the code is being deployed to a fixed target (eg the specific board used in your product)
and you know that target does not support such an extension, and you wish to minimize code size.

It is also possible to disable acceleration *at runtime* using
``BOTAN_CLEAR_CPUID`` :doc:`environment variable <api_ref/env_vars>`. This is the preferred
mode of disabling acceleration.
