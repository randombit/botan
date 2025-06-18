Hardware Acceleration
==============================

Botan provides built-in support for hardware acceleration of certain algorithms
on certain platforms. These alternate implementations use special CPU instructions
that are not available on all platforms and either speed up the algorithm
or improve security in terms of side channel resistance.

A “base” software implementation is always provided. For example, for the AES-128
block cipher three implementations are available. All of the AES implementations
are immune to common cache/timing based side channels.

* If AES hardware support is available (AES-NI, POWER8, Aarch64) use that
* If 128-bit SIMD with byte shuffles are available (SSSE3, NEON, or Altivec),
  use the vperm technique published by Mike Hamburg at CHES 2009
* If no hardware or SIMD support, fall back to a constant time bitsliced implementation

The following sections list the platforms and algorithms for which hardware acceleration
is available. If the CPU specific optimizations are available at runtime, they are
automatically used if enabled in the build. If not, the base implementation is used.

It is possible to disable CPU-specific optimizations at runtime by setting the
environment variable ``BOTAN_CLEAR_CPUID``. For example
``BOTAN_CLEAR_CPUID=avx2`` will disable use of any AVX2 instructions.

x86
--------------

On x86-64 and x86-32 platforms, the following CPU specific optimizations are available:

+-----------+--------------------------------------------+--------------------+------------+
| Algorithm | Extension                                  | Module             | Added in   |
+===========+============================================+====================+============+
| AES       | VAES-AVX2                                  | `aes_vaes`         | 3.6.0      |
|           |                                            |                    |            |
|           | AES-NI                                     | `aes_ni`           | 1.9.3      |
|           |                                            |                    |            |
|           | SSSE3                                      | `aes_vperm`        | 1.9.10     |
+-----------+--------------------------------------------+--------------------+------------+
| AES-GCM   | CLMUL                                      | `ghash_cpu`        | 1.11.6     |
|           |                                            |                    |            |
|           | SSSE3                                      | `ghash_vperm`      | 1.9.10     |
+-----------+--------------------------------------------+--------------------+------------+
| Argon2    | AVX2                                       | `argon2_avx2`      | 3.0.0      |
|           |                                            |                    |            |
|           | SSSE3                                      | `argon2_ssse3`     | 2.19.2     |
+-----------+--------------------------------------------+--------------------+------------+
| ChaCha    | AVX512 (x86-64 only)                       | `chacha_avx512`    | 3.1.0      |
|           |                                            |                    |            |
|           | AVX2                                       | `chacha_avx2`      | 2.8.0      |
|           |                                            |                    |            |
|           | SSSE3                                      | `chacha_simd32`    | 1.11.32    |
+-----------+--------------------------------------------+--------------------+------------+
| IDEA      | SSE2                                       | `idea_sse2`        | 1.9.4      |
+-----------+--------------------------------------------+--------------------+------------+
| KMAC      | BMI2                                       | `keccak_perm_bmi2` | 3.2.0      |
+-----------+--------------------------------------------+--------------------+------------+
| NOEKEON   | SSSE3                                      | `noekeon_simd`     | 1.9.4      |
+-----------+--------------------------------------------+--------------------+------------+
| RDRAND    | RDRAND                                     | `processor_rng`    | 1.11.31    |
+-----------+--------------------------------------------+--------------------+------------+
| RDSEED    | RDSEED                                     | `rdseed`           | 1.11.36    |
+-----------+--------------------------------------------+--------------------+------------+
| Serpent   | AVX512 (x86-64 only)                       | `serpent_avx512`   | 3.1.0      |
|           |                                            |                    |            |
|           | AVX2                                       | `serpent_avx2`     | 2.8.0      |
|           |                                            |                    |            |
|           | SSSE3                                      | `serpent_simd`     | 1.9.0      |
+-----------+--------------------------------------------+--------------------+------------+
| SHACAL2   | Intel SHA Extensions                       | `shacal2_x86`      | 2.3.0      |
|           |                                            |                    |            |
|           | AVX2                                       | `shacal2_avx2`     | 2.13.0     |
+-----------+--------------------------------------------+--------------------+------------+
| SHAKE     | BMI2                                       | `keccak_perm_bmi2` | 2.13.0     |
+-----------+--------------------------------------------+--------------------+------------+
| SHA-1     | Intel SHA Extensions                       | `sha1_x86`         | 2.2.0      |
|           |                                            |                    |            |
|           | SSSE3                                      | `sha1_simd`        | 1.7.12     |
+-----------+--------------------------------------------+--------------------+------------+
| SHA-256   | Intel SHA Extensions                       | `sha2_32_x86`      | 2.2.0      |
|           |                                            |                    |            |
|           | SSSE3                                      | `sha2_32_simd`     | 3.8.0      |
|           |                                            |                    |            |
|           | AVX2 + BMI2                                | `sha2_32_avx2`     | 3.8.0      |
+-----------+--------------------------------------------+--------------------+------------+
| SHA-512   | Intel SHA Extensions                       | `sha2_64_x86`      | 3.8.0      |
|           |                                            |                    |            |
|           | AVX2 + BMI2                                | `sha2_64_avx2`     | 3.8.0      |
|           |                                            |                    |            |
|           | AVX-512 + BMI2                             | `sha2_64_avx512`   | 3.8.0      |
+-----------+--------------------------------------------+--------------------+------------+
| SHA-3     | BMI2                                       | `keccak_perm_bmi2` | 2.10.0     |
+-----------+--------------------------------------------+--------------------+------------+
| SM4       | AVX2 + GFNI                                | `sm4_gfni`         | 3.6.0      |
+-----------+--------------------------------------------+--------------------+------------+
| ZFEC      | SSSE3                                      | `zfec_vperm`       | 3.0.0      |
+-----------+--------------------------------------------+--------------------+------------+

ARM
--------------

On arm64 and arm32 platforms, the following CPU specific optimizations are available:

+-----------+--------------------------------------------+--------------------+------------+
| Algorithm | Extension                                  | Module             | Added in   |
+===========+============================================+====================+============+
| AES       | NEON                                       | `aes_armv8`        | 1.9.3      |
+-----------+--------------------------------------------+--------------------+------------+
| AES-GCM   | PMULL (arm64 only)                         | `ghash_cpu`        | 2.3.0      |
+-----------+--------------------------------------------+--------------------+------------+
| ChaCha    | NEON                                       | `chacha_simd32`    | 2.8.0      |
+-----------+--------------------------------------------+--------------------+------------+
| NOEKEON   | NEON                                       | `noekeon_simd`     | 1.9.4      |
+-----------+--------------------------------------------+--------------------+------------+
| Serpent   | NEON                                       | `serpent_simd`     | 1.9.2      |
+-----------+--------------------------------------------+--------------------+------------+
| SHACAL2   | NEON                                       | `shacal2_simd`     | 2.3.0      |
|           |                                            |                    |            |
|           | ARMv8 Cryptography Extensions (arm64 only) | `shacal2_armv8`    | 2.13.0     |
+-----------+--------------------------------------------+--------------------+------------+
| SHA-1     | ARMv8 Cryptography Extensions (arm64 only) | `sha1_armv8`       | 2.2.0      |
|           |                                            |                    |            |
|           | NEON                                       | `sha1_simd`        | 3.8.0      |
+-----------+--------------------------------------------+--------------------+------------+
| SHA-256   | ARMv8 Cryptography Extensions (arm64 only) | `sha2_32_armv8`    | 2.2.0      |
|           |                                            |                    |            |
|           | NEON                                       | `sha2_32_simd`     | 3.8.0      |
+-----------+--------------------------------------------+--------------------+------------+
| SHA-384   | ARMv8 Cryptography Extensions (arm64 only) | `sha2_64_armv8`    | 3.3.0      |
+-----------+--------------------------------------------+--------------------+------------+
| SHA-512   | ARMv8 Cryptography Extensions (arm64 only) | `sha2_64_armv8`    | 3.3.0      |
+-----------+--------------------------------------------+--------------------+------------+
| SM4       | ARMv8 Cryptography Extensions (arm64 only) | `sm4_armv8`        | 2.8.0      |
+-----------+--------------------------------------------+--------------------+------------+
| ZFEC      | NEON                                       | `zfec_vperm`       | 3.0.0      |
+-----------+--------------------------------------------+--------------------+------------+

PowerPC
--------------

On ppc64 and ppc32 platforms, the following CPU specific optimizations are available:

+-----------+--------------------------------------------+--------------------+------------+
| Algorithm | Extension                                  | Module             | Added in   |
+===========+============================================+====================+============+
| AES       | POWER8/POWER9                              | `aes_power8`       | 2.14.0     |
|           |                                            |                    |            |
|           | AltiVec                                    | `aes_vperm`        | 2.12.0     |
+-----------+--------------------------------------------+--------------------+------------+
| ChaCha    | AltiVec                                    | `chacha_simd32`    | 2.8.0      |
+-----------+--------------------------------------------+--------------------+------------+
| DARN      | POWER9                                     | `processor_rng`    | 2.15.0     |
+-----------+--------------------------------------------+--------------------+------------+
| Serpent   | AltiVec                                    | `serpent_simd`     | 1.9.2      |
+-----------+--------------------------------------------+--------------------+------------+
| SHACAL2   | AltiVec                                    | `shacal2_simd`     | 2.3.0      |
+-----------+--------------------------------------------+--------------------+------------+
| NOEKEON   | AltiVec                                    | `noekeon_simd`     | 1.9.4      |
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
| AES       | LSX                                        | `aes_vperm`        | 3.8.0      |
+-----------+--------------------------------------------+--------------------+------------+
| ChaCha    | LSX                                        | `chacha_simd32`    | 3.8.0      |
+-----------+--------------------------------------------+--------------------+------------+
| Serpent   | LSX                                        | `serpent_simd`     | 3.8.0      |
+-----------+--------------------------------------------+--------------------+------------+
| SHA-1     | LSX                                        | `sha1_simd`        | 3.8.0      |
+-----------+--------------------------------------------+--------------------+------------+
| SHACAL2   | LSX                                        | `shacal2_simd`     | 3.8.0      |
+-----------+--------------------------------------------+--------------------+------------+
| NOEKEON   | LSX                                        | `noekeon_simd`     | 3.8.0      |
+-----------+--------------------------------------------+--------------------+------------+
| ZFEC      | LSX                                        | `zfec_vperm`       | 3.8.0      |
+-----------+--------------------------------------------+--------------------+------------+

Configuring Acceleration
------------------------------

If it is desirable to avoid using some form of acceleration, this can be accomplished
*at build time* by using ``--disable-modules=``. For instance, to remove support
of ARMv8 intrinsics for AES, use ``--disable-modules=aes_armv8``.

It is also possible to disable acceleration *at runtime* using
``BOTAN_CLEAR_CPUID`` :doc:`environment variable <api_ref/env_vars>`. This is the preferred
mode of disabling acceleration.
