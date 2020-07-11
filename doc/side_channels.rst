Side Channels
=========================

Many cryptographic systems can be easily broken by side channels. This document
notes side channel protections which are currently implemented, as well as areas
of the code which are known to be vulnerable to side channels. The latter are
obviously all open for future improvement.

The following text assumes the reader is already familiar with cryptographic
implementations, side channel attacks, and common countermeasures.

Modular Exponentiation
------------------------

Modular exponentiation uses a fixed window algorithm with Montgomery
representation. A side channel silent table lookup is used to access the
precomputed powers. The caller provides the maximum possible bit length of the
exponent, and the exponent is zero-padded as required. For example, in a DSA
signature with 256-bit q, the caller will specify a maximum length of exponent
of 256 bits, even if the k that was generated was 250 bits. This avoids leaking
the length of the exponent through the number of loop iterations.
See monty_exp.cpp and monty.cpp

Karatsuba multiplication algorithm avoids any conditional branches; in
cases where different operations must be performed it instead uses masked
operations. See mp_karat.cpp for details.

The Montgomery reduction is written to run in constant time.
The final reduction is handled with a masked subtraction. See mp_monty.cpp.

Barrett Reduction
--------------------

The Barrett reduction code is written to avoid input dependent branches. The
Barrett algorithm only works for inputs up to a certain size, and larger values
fall back on a different (slower) division algorithm. This secondary algorithm
is also const time, but the branch allows detecting when a value larger than
2^{2k} was reduced, where k is the word length of the modulus. This leaks only
the size of the two values, and not anything else about their value.

RSA
----------------------

Blinding is always used to protect private key operations (there is no way to
turn it off). Both base blinding and exponent blinding are used.

For base blinding, as an optimization, instead of choosing a new random mask and
inverse with each decryption, both the mask and its inverse are simply squared
to choose the next blinding factor. This is much faster than computing a fresh
value each time, and the additional relation is thought to provide only minimal
useful information for an attacker. Every BOTAN_BLINDING_REINIT_INTERVAL
(default 64) operations, a new starting point is chosen.

Exponent blinding uses new values for each signature, with 64 bit masks.

RSA signing uses the CRT optimization, which is much faster but vulnerable to
trivial fault attacks [RsaFault] which can result in the key being entirely
compromised. To protect against this (or any other computational error which
would have the same effect as a fault attack in this case), after every private
key operation the result is checked for consistency with the public key. This
introduces only slight additional overhead and blocks most fault attacks; it is
possible to use a second fault attack to bypass this verification, but such a
double fault attack requires significantly more control on the part of an
attacker than a BellCore style attack, which is possible if any error at all
occurs during either modular exponentiation involved in the RSA signature
operation.

See blinding.cpp and rsa.cpp.

If the OpenSSL provider is enabled, then no explicit blinding is done; we assume
OpenSSL handles this. See openssl_rsa.cpp.

Decryption of PKCS #1 v1.5 Ciphertexts
----------------------------------------

This padding scheme is used with RSA, and is very vulnerable to errors. In a
scenario where an attacker can repeatedly present RSA ciphertexts, and a
legitimate key holder will attempt to decrypt each ciphertext and simply
indicates to the attacker if the PKCS padding was valid or not (without
revealing any additional information), the attacker can use this behavior as an
oracle to perform iterative decryption of arbitrary RSA ciphertexts encrypted
under that key. This is the famous million message attack [MillionMsg].  A side
channel such as a difference in time taken to handle valid and invalid RSA
ciphertexts is enough to mount the attack [MillionMsgTiming].

As a first step, the PKCS v1.5 decoding operation runs without any
conditional jumps or indexes, with the only variance in runtime being
based on the length of the public modulus, which is public information.

Preventing the attack in full requires some application level changes. In
protocols which know the expected length of the encrypted key, PK_Decryptor
provides the function `decrypt_or_random` which first generates a random fake
key, then decrypts the presented ciphertext, then in constant time either copies
out the random key or the decrypted plaintext depending on if the ciphertext was
valid or not (valid padding and expected plaintext length). Then in the case of
an attack, the protocol will carry on with a randomly chosen key, which will
presumably cause total failure in a way that does not allow an attacker to
distinguish (via any timing or other side channel, nor any error messages
specific to the one situation vs the other) if the RSA padding was valid or
invalid.

One very important user of PKCS #1 v1.5 encryption is the TLS protocol. In TLS,
some extra versioning information is embedded in the plaintext message, along
with the key. It turns out that this version information must be treated in an
identical (constant-time) way with the PKCS padding, or again the system is
broken. [VersionOracle]. This is supported by a special version of
PK_Decryptor::decrypt_or_random that additionally allows verifying one or more
content bytes, in addition to the PKCS padding.

See eme_pkcs.cpp and pubkey.cpp.

Verification of PKCS #1 v1.5 Signatures
----------------------------------------

One way of verifying PKCS #1 v1.5 signature padding is to decode it with an
ASN.1 BER parser. However such a design commonly leads to accepting signatures
besides the (single) valid RSA PKCS #1 v1.5 signature for any given message,
because often the BER parser accepts variations of the encoding which are
actually invalid. It also needlessly exposes the BER parser to untrusted inputs.

It is safer and simpler to instead re-encode the hash value we are expecting
using the PKCS #1 v1.5 encoding rules, and const time compare our expected
encoding with the output of the RSA operation. So that is what Botan does.

See emsa_pkcs.cpp.

OAEP
----------------------

RSA OAEP is (PKCS#1 v2) is the recommended version of RSA encoding standard,
because it is not directly vulnerable to Bleichenbacher attack. However, if
implemented incorrectly, a side channel can be presented to an attacker and
create an oracle for decrypting RSA ciphertexts [OaepTiming].

This attack is avoided in Botan by making the OAEP decoding operation run
without any conditional jumps or indexes, with the only variance in runtime
coming from the length of the RSA key (which is public information).

See eme_oaep.cpp.

ECC point decoding
----------------------

The API function OS2ECP, which is used to convert byte strings to ECC points,
verifies that all points satisfy the ECC curve equation. Points that do not
satisfy the equation are invalid, and can sometimes be used to break
protocols ([InvalidCurve] [InvalidCurveTLS]). See point_gfp.cpp.

ECC scalar multiply
----------------------

There are several different implementations of ECC scalar multiplications which
depend on the API invoked. This include ``PointGFp::operator*``,
``EC_Group::blinded_base_point_multiply`` and
``EC_Group::blinded_var_point_multiply``.

The ``PointGFp::operator*`` implementation uses the Montgomery ladder, which is
fairly resistant to side channels. However it leaks the size of the scalar,
because the loop iterations are bounded by the scalar size. It should not be
used in cases when the scalar is a secret.

Both ``blinded_base_point_multiply`` and ``blinded_var_point_multiply`` apply
side channel countermeasures. The scalar is masked by a multiple of the group
order (this is commonly called Coron's first countermeasure [CoronDpa]),
currently the mask is an 80 bit random value.

Botan stores all ECC points in Jacobian representation. This form allows faster
computation by representing points (x,y) as (X,Y,Z) where x=X/Z^2 and
y=Y/Z^3. As the representation is redundant, for any randomly chosen non-zero r,
(X*r^2,Y*r^3,Z*r) is an equivalent point. Changing the point values prevents an
attacker from mounting attacks based on the input point remaining unchanged over
multiple executions. This is commonly called Coron's third countermeasure, see
again [CoronDpa].

The base point multiplication algorithm is a comb-like technique which
precomputes ``P^i,(2*P)^i,(3*P)^i`` for all ``i`` in the range of valid scalars.
This means the scalar multiplication involves only point additions and no
doublings, which may help against attacks which rely on distinguishing between
point doublings and point additions. The elements of the table are accessed by
masked lookups, so as not to leak information about bits of the scalar via a
cache side channel. However, whenever 3 sequential bits of the (masked) scalar
are all 0, no operation is performed in that iteration of the loop. This exposes
the scalar multiply to a cache-based side channel attack; scalar blinding is
necessary to prevent this attack from leaking information about the scalar.

The variable point multiplication algorithm uses a fixed-window algorithm. Since
this is normally invoked using untrusted points (eg during ECDH key exchange) it
randomizes all inputs to prevent attacks which are based on chosen input
points. The table of precomputed multiples is accessed using a masked lookup
which should not leak information about the secret scalar to an attacker who can
mount a cache-based side channel attack.

See point_gfp.cpp and point_mul.cpp

ECDH
----------------------

ECDH verifies (through its use of OS2ECP) that all input points received from
the other party satisfy the curve equation. This prevents twist attacks. The
same check is performed on the output point, which helps prevent fault attacks.

ECDSA
----------------------

Inversion of the ECDSA nonce k must be done in constant time, as any leak of
even a single bit of the nonce can be sufficient to allow recovering the private
key. In Botan all inverses modulo an odd number are performed using a constant
time algorithm due to Niels Möller.

x25519
----------------------

The x25519 code is independent of the main Weierstrass form ECC code, instead
based on curve25519-donna-c64.c by Adam Langley. The code seems immune to cache
based side channels. It does make use of integer multiplications; on some old
CPUs these multiplications take variable time and might allow a side channel
attack. This is not considered a problem on modern processors.

TLS CBC ciphersuites
----------------------

The original TLS v1.0 CBC Mac-then-Encrypt mode is vulnerable to an oracle
attack. If an attacker can distinguish padding errors through different error
messages [TlsCbcOracle] or via a side channel attack like [Lucky13], they can
abuse the server as a decryption oracle.

The side channel protection for Lucky13 follows the approach proposed in the
Lucky13 paper. It is not perfectly constant time, but does hide the padding
oracle in practice. Tools to test TLS CBC decoding are included in the timing
tests. See https://github.com/randombit/botan/pull/675 for more information.

The Encrypt-then-MAC extension, which completely avoids the side channel, is
implemented and used by default for CBC ciphersuites.

CBC mode padding
----------------------

In theory, any good protocol protects CBC ciphertexts with a MAC. But in
practice, some protocols are not good and cannot be fixed immediately. To avoid
making a bad problem worse, the code to handle decoding CBC ciphertext padding
bytes runs in constant time, depending only on the block size of the cipher.

AES
----------------------

Some x86, ARMv8 and POWER processors support AES instructions which
are fast and are thought to be side channel silent. These instructions
are used when available.

On CPUs which do not have hardware AES instructions but do support SIMD vectors
with a byte shuffle (including x86's SSSE3, ARM's NEON and PowerPC AltiVec), a
version of AES is implemented which is side channel silent. This implementation
is based on code by Mike Hamburg [VectorAes], see aes_vperm.cpp.

On all other processors, a constant time bitsliced implementation is used. This
is typically slower than the vector permute implementation, and additionally for
best performance multiple blocks must be processed in parellel.  So modes such
as CTR, GCM or XTS are relatively fast, but others such as CBC encryption
suffer.

GCM
---------------------

On platforms that support a carryless multiply instruction (ARMv8 and recent x86),
GCM is fast and constant time.

On all other platforms, GCM uses an algorithm based on precomputing all powers
of H from 1 to 128. Then for every bit of the input a mask is formed which
allows conditionally adding that power without leaking information via a cache
side channel. There is also an SSSE3 variant of this algorithm which is somewhat
faster on processors which have SSSE3 but no AES-NI instructions.

OCB
-----------------------

It is straightforward to implement OCB mode in a efficient way that does not
depend on any secret branches or lookups. See ocb.cpp for the implementation.

Poly1305
----------------------

The Poly1305 implementation does not have any secret lookups or conditionals.
The code is based on the public domain version by Andrew Moon.

DES/3DES
----------------------

The DES implementation uses table lookups, and is likely vulnerable to side
channel attacks. DES or 3DES should be avoided in new systems. The proper fix
would be a scalar bitsliced implementation, this is not seen as worth the
engineering investment given these algorithms end of life status.

Twofish
------------------------

This algorithm uses table lookups with secret sboxes. No cache-based side
channel attack on Twofish has ever been published, but it is possible nobody
sufficiently skilled has ever tried.

ChaCha20, Serpent, Threefish, ...
-----------------------------------

Some algorithms including ChaCha, Salsa, Serpent and Threefish are 'naturally'
silent to cache and timing side channels on all recent processors.

IDEA
---------------

IDEA encryption, decryption, and key schedule are implemented to take constant
time regardless of their inputs.

Hash Functions
-------------------------

Most hash functions included in Botan such as MD5, SHA-1, SHA-2, SHA-3, Skein,
and BLAKE2 do not require any input-dependent memory lookups, and so seem to not be
affected by common CPU side channels. However the implementations of Whirlpool
and Streebog use table lookups and probably can be attacked by side channels.

Memory comparisons
----------------------

The function same_mem in header mem_ops.h provides a constant-time comparison
function. It is used when comparing MACs or other secret values. It is also
exposed for application use.

Memory zeroizing
----------------------

There is no way in portable C/C++ to zero out an array before freeing it, in
such a way that it is guaranteed that the compiler will not elide the
'additional' (seemingly unnecessary) writes to zero out the memory.

The function secure_scrub_memory (in mem_ops.cpp) uses some system specific
trick to zero out an array. If possible an OS provided routine (such as
``RtlSecureZeroMemory`` or ``explicit_bzero``) is used.

On other platforms, by default the trick of referencing memset through a
volatile function pointer is used. This approach is not guaranteed to work on
all platforms, and currently there is no systematic check of the resulting
binary function that it is compiled as expected. But, it is the best approach
currently known and has been verified to work as expected on common platforms.

If BOTAN_USE_VOLATILE_MEMSET_FOR_ZERO is set to 0 in build.h (not the default) a
byte at a time loop through a volatile pointer is used to overwrite the array.

Memory allocation
----------------------

Botan's secure_vector type is a std::vector with a custom allocator. The
allocator calls secure_scrub_memory before freeing memory.

Some operating systems support an API call to lock a range of pages
into memory, such that they will never be swapped out (``mlock`` on POSIX,
``VirtualLock`` on Windows). On many POSIX systems ``mlock`` is only usable by
root, but on Linux, FreeBSD and possibly other systems a small amount
of memory can be locked by processes without extra credentials.

If available, Botan uses such a region for storing key material. A page-aligned
block of memory is allocated and locked, then the memory is scrubbed before
freeing. This memory pool is used by secure_vector when available. It can be
disabled at runtime setting the environment variable BOTAN_MLOCK_POOL_SIZE to 0.

Automated Analysis
---------------------

Currently the main tool used by the Botan developers for testing for side
channels at runtime is valgrind; valgrind's runtime API is used to taint memory
values, and any jumps or indexes using data derived from these values will cause
a valgrind warning. This technique was first used by Adam Langley in ctgrind.
See header ct_utils.h.

To check, install valgrind, configure the build with --with-valgrind, and run
the tests.

.. highlight:: shell

There is also a test utility built into the command line util, `timing_test`,
which runs an operation on several different inputs many times in order to
detect simple timing differences. The output can be processed using the
Mona timing report library (https://github.com/seecurity/mona-timing-report).
To run a timing report (here for example pow_mod)::

  $ ./botan timing_test pow_mod > pow_mod.raw

This must be run from a checkout of the source, or otherwise ``--test-data-dir=``
must be used to point to the expected input files.

Build and run the Mona report as::

  $ git clone https://github.com/seecurity/mona-timing-report.git
  $ cd mona-timing-report
  $ ant
  $ java -jar ReportingTool.jar --lowerBound=0.4 --upperBound=0.5 --inputFile=pow_mod.raw --name=PowMod

This will produce plots and an HTML file in subdirectory starting with
``reports_`` followed by a representation of the current date and time.

References
---------------

[Aes256Sc] Neve, Tiri "On the complexity of side-channel attacks on AES-256"
(https://eprint.iacr.org/2007/318.pdf)

[AesCacheColl] Bonneau, Mironov "Cache-Collision Timing Attacks Against AES"
(http://www.jbonneau.com/doc/BM06-CHES-aes_cache_timing.pdf)

[CoronDpa] Coron,
"Resistance against Differential Power Analysis for Elliptic Curve Cryptosystems"
(https://citeseer.ist.psu.edu/viewdoc/summary?doi=10.1.1.1.5695)

[InvalidCurve] Biehl, Meyer, Müller: Differential fault attacks on
elliptic curve cryptosystems
(https://www.iacr.org/archive/crypto2000/18800131/18800131.pdf)

[InvalidCurveTLS] Jager, Schwenk, Somorovsky: Practical Invalid Curve
Attacks on TLS-ECDH
(https://www.nds.rub.de/research/publications/ESORICS15/)

[SafeCurves] Bernstein, Lange: SafeCurves: choosing safe curves for
elliptic-curve cryptography. (https://safecurves.cr.yp.to)

[Lucky13] AlFardan, Paterson "Lucky Thirteen: Breaking the TLS and DTLS Record Protocols"
(http://www.isg.rhul.ac.uk/tls/TLStiming.pdf)

[MillionMsg] Bleichenbacher "Chosen Ciphertext Attacks Against Protocols Based
on the RSA Encryption Standard PKCS1"
(https://citeseerx.ist.psu.edu/viewdoc/summary?doi=10.1.1.19.8543)

[MillionMsgTiming] Meyer, Somorovsky, Weiss, Schwenk, Schinzel, Tews: Revisiting
SSL/TLS Implementations: New Bleichenbacher Side Channels and Attacks
(https://www.nds.rub.de/research/publications/mswsst2014-bleichenbacher-usenix14/)

[OaepTiming] Manger, "A Chosen Ciphertext Attack on RSA Optimal Asymmetric
Encryption Padding (OAEP) as Standardized in PKCS #1 v2.0"
(http://archiv.infsec.ethz.ch/education/fs08/secsem/Manger01.pdf)

[RsaFault] Boneh, Demillo, Lipton
"On the importance of checking cryptographic protocols for faults"
(https://citeseerx.ist.psu.edu/viewdoc/summary?doi=10.1.1.48.9764)

[RandomMonty] Le, Tan, Tunstall "Randomizing the Montgomery Powering Ladder"
(https://eprint.iacr.org/2015/657)

[VectorAes] Hamburg, "Accelerating AES with Vector Permute Instructions"
https://shiftleft.org/papers/vector_aes/vector_aes.pdf

[VersionOracle] Klíma, Pokorný, Rosa "Attacking RSA-based Sessions in SSL/TLS"
(https://eprint.iacr.org/2003/052)
