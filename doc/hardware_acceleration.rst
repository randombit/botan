Hardware Acceleration
==============================

Botan provides built-in support for hardware acceleration of certain algorithms
on certain platforms. These alternate implementations use special CPU instructions
that are not available on all platforms and either speed up the algorithm
or improve security in terms of side channel resistance.

A “base” software implementation is always provided. For example, for the AES-128
block cipher three implementations are available. All of the AES-128 implementations
are immune to common cache/timing based side channels.

* If AES hardware support is available (AES-NI, POWER8, Aarch64) use that
* If 128-bit SIMD with byte shuffles are available (SSSE3, NEON, or Altivec),
  use the vperm technique published by Mike Hamburg at CHES 2009
* If no hardware or SIMD support, fall back to a constant time bitsliced implementation

The following sections list the platforms and algorithms for which hardware acceleration
is available. If the CPU specific optimizations are available at runtime, they are
automatically used if enabled in the build. If not, the base implementation is used.

x86
--------------

On x86-64 and x86-32 platforms, the following CPU specific optimizations are available:

+-----------+--------------------------------------------+--------------------+------------+
| Algorithm | Extension                                  | Module             | Added in   |
+===========+============================================+====================+============+
| AES       | AES-NI                                     | `aes_ni`           | 1.9.3      |
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
|           | SSE2                                       | `chacha_simd32`    | 1.11.32    |
+-----------+--------------------------------------------+--------------------+------------+
| KMAC      | BMI2                                       | `keccak_perm_bmi2` | 3.2.0      |
+-----------+--------------------------------------------+--------------------+------------+
| NOEKEON   | SSE2                                       | `noekeon_simd`     | 1.9.4      |
+-----------+--------------------------------------------+--------------------+------------+
| RDRAND    | RDRAND                                     | `processor_rng`    | 1.11.31    |
+-----------+--------------------------------------------+--------------------+------------+
| RDSEED    | RDSEED                                     | `rdseed`           | 1.11.36    |
+-----------+--------------------------------------------+--------------------+------------+
| Serpent   | AVX512 (x86-64 only)                       | `serpent_avx512`   | 3.1.0      |
|           |                                            |                    |            |
|           | AVX2                                       | `serpent_avx2`     | 2.8.0      |
|           |                                            |                    |            |
|           | SSE2                                       | `serpent_simd`     | 1.9.0      |
+-----------+--------------------------------------------+--------------------+------------+
| SHACAL2   | Intel SHA Extensions                       | `shacal2_x86`      | 2.3.0      |
|           |                                            |                    |            |
|           | AVX2                                       | `shacal2_avx2`     | 2.13.0     |
+-----------+--------------------------------------------+--------------------+------------+
| SHAKE     | BMI2                                       | `keccak_perm_bmi2` | 2.13.0     |
+-----------+--------------------------------------------+--------------------+------------+
| SHA-1     | Intel SHA Extensions                       | `sha1_x86`         | 2.2.0      |
|           |                                            |                    |            |
|           | SSE2                                       | `sha1_sse2`        | 1.7.12     |
+-----------+--------------------------------------------+--------------------+------------+
| SHA-256   | Intel SHA Extensions                       | `sha2_32_x86`      | 2.2.0      |
|           |                                            |                    |            |
|           | BMI2                                       | `sha2_32_bmi2`     | 2.7.0      |
+-----------+--------------------------------------------+--------------------+------------+
| SHA-3     | BMI2                                       | `keccak_perm_bmi2` | 2.10.0     |
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
|           |                                            |                    |            |
|           | NEON                                       | `ghash_vperm`      | 2.12.0     |
+-----------+--------------------------------------------+--------------------+------------+
| ChaCha    | NEON                                       | `chacha_simd32`    | 2.8.0      |
+-----------+--------------------------------------------+--------------------+------------+
| NOEKEON   | NEON                                       | `noekeon_simd`     | 1.9.4      |
+-----------+--------------------------------------------+--------------------+------------+
| Serpent   | NEON                                       | `serpent_simd`     | 1.9.2      |
+-----------+--------------------------------------------+--------------------+------------+
| SHACAL2   | NEON                                       | `shacal2_simd`     | 2.3.0      |
+-----------+--------------------------------------------+--------------------+------------+
| SM4       | ARMv8 Cryptography Extensions (arm64 only) | `sm4_armv8`        | 2.8.0      |
+-----------+--------------------------------------------+--------------------+------------+
| SHA-1     | ARMv8 Cryptography Extensions (arm64 only) | `sha1_armv8`       | 2.2.0      |
+-----------+--------------------------------------------+--------------------+------------+
| SHA-256   | ARMv8 Cryptography Extensions (arm64 only) | `sha2_32_armv8`    | 2.2.0      |
+-----------+--------------------------------------------+--------------------+------------+
| SHA-384   | ARMv8 Cryptography Extensions (arm64 only) | `sha2_64_armv8`    | 3.3.0      |
+-----------+--------------------------------------------+--------------------+------------+
| SHA-512   | ARMv8 Cryptography Extensions (arm64 only) | `sha2_64_armv8`    | 3.3.0      |
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
| AES-GCM   | AltiVec                                    | `ghash_vperm`      | 2.12.0     |
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

Configuring Acceleration
------------------------------

Hardware acceleration can be disabled at during configuring the build
by passing certain ``--disable-*`` options to ``configure.py``.
This will cause the base software implementation to be used instead
of the hardware accelerated one. The following options are currently supported:

``--disable-sse2``
   disable SSE2 intrinsics
``--disable-ssse3``
   disable SSSE3 intrinsics
``--disable-sse4.1``
   disable SSE4.1 intrinsics
``--disable-sse4.2``
   disable SSE4.2 intrinsics
``--disable-avx2``
   disable AVX2 intrinsics
``--disable-bmi2``
   disable BMI2 intrinsics
``--disable-rdrand``
   disable RDRAND intrinsics
``--disable-rdseed``
   disable RDSEED intrinsics
``--disable-aes-ni``
   disable AES-NI intrinsics
``--disable-sha-ni``
   disable SHA-NI intrinsics
``--disable-altivec``
   disable AltiVec intrinsics
``--disable-neon``
   disable NEON intrinsics
``--disable-armv8crypto``
   disable ARMv8 Crypto intrinsics
``--disable-powercrypto``
   disable POWER Crypto intrinsics

Additionally, ``--disable-modules=MODS`` can be used to remove a certain module,
if desirable.

Last but not least, the ``BOTAN_CLEAR_CPUID`` :doc:`environment variable <api_ref/env_vars>`
can be set to a non-empty value *at runtime* to cause Botan to clear the CPUID bits for the CPU
extensions it uses.
