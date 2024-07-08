
.. highlight:: none

Security Advisories
========================================

If you think you have found a security bug in Botan please contact
Jack Lloyd (jack@randombit.net). If you would like to encrypt your
mail please use::

  pub   rsa3072/57123B60 2015-03-23
        Key fingerprint = 4E60 C735 51AF 2188 DF0A  5A62 78E9 8043 5712 3B60
        uid         Jack Lloyd <jack@randombit.net>

This key can be found in the file ``doc/pgpkey.txt`` or online at
https://keybase.io/jacklloyd and on most PGP keyservers.

2024
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* 2024-07-08 (CVE-2024-34702): Denial of Service Due to Excessive Name Constraints

  Checking name constraints in X.509 certificates is quadratic in the number of
  names and name constraints. An attacker who presented a certificate chain
  which contained a very large number of names in the SubjectAlternativeName,
  signed by a CA certificate which contained a large number of name constraints,
  could cause a denial of service.

  Found and reported by Bing Shi.

* 2024-07-08 (CVE-2024-39312): Authorization Error due to Name Constraint Decoding Bug

  A bug in the parsing of name constraint extensions in X.509 certificates meant
  that if the extension included both permitted subtrees and excluded subtrees,
  only the permitted subtree would be checked. If a certificate included a name
  which was permitted by the permitted subtree but also excluded by excluded
  subtree, it would be accepted.

* 2024-02-20: Kyber side channel

  The Kyber implementation was vulnerable to the KyberSlash1 and
  KyberSlash2 side channel issues.

  Introduced in 3.0.0, fixed in 3.3.0

* 2024-02-20 (CVE-2024-34703): DoS due to oversized elliptic curve parameters

  When decoding an ASN.1 encoded elliptic curve, Botan would verify the `p`
  parameter was actually prime, and at least some minimum size. However it
  failed to check if the prime was far too large (for example thousands of
  bits), in which case checking the prime would take a significant amount of
  computation. Now the maximum size of arbitrary elliptic curves when decoding
  from ASN.1 is limited.

  Reported by Bing Shi

  Fixed in 3.3.0 and 2.19.4

2022
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* 2022-11-16 (CVE-2022-43705): Failure to correctly check OCSP responder embedded certificate

  OCSP responses for some end entity are either signed by the issuing CA certificate of
  the PKI, or an OCSP responder certificate that the PKI authorized to sign responses in
  their name. In the latter case, the responder certificate (and its validation path
  certificate) may be embedded into the OCSP response and clients must verify that such
  certificates are indeed authorized by the CA when validating OCSP responses.

  The OCSP implementation failed to verify that an authorized responder certificate
  embedded in an OCSP response is authorized by the issuing CA. As a result, any valid
  signature by an embedded certificate passed the check and was allowed to make claims
  about the revocation status of certificates of any CA.

  Attackers that are in a position to spoof OCSP responses for a client could therefore
  render legitimate certificates of a 3rd party CA as revoked or even use a compromised
  (and actually revoked) certificate by spoofing an OCSP-"OK" response. E.g. an attacker
  could exploit this to impersonate a legitimate TLS server using a compromised
  certificate of that host and get around the revocation check using OCSP stapling.

  Introduced in 1.11.34, fixed in 2.19.3 and 3.0.0

2020
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* 2020-12-21 (CVE-2021-24115): Codec encoding/decoding was not constant time

  The base64, base32, base58 and hex encoding/decoding routines used lookup
  tables which could leak information via a cache-based side channel attack.
  The encoding tables were small and unlikely to be exploitable, but the
  decoding tables were large enough to cause non-negligible information
  leakage. In particular parsing an unencrypted PEM-encoded private key within
  an SGX enclave could be easily attacked to leak key material.

  Identified and reported by Jan Wichelmann, Thomas Eisenbarth,
  Sebastian Berndt, and Florian Sieck.

  Fixed in 2.17.3

* 2020-07-05: Failure to enforce name constraints on alternative names

  The path validation algorithm enforced name constraints on the primary DN
  included in the certificate but failed to do so against alternative DNs which
  may be included in the subject alternative name. This would allow a corrupted
  sub-CA which was constrained by a name constraints extension in its own
  certificate to issue a certificate containing a prohibited DN. Until 2.15.0,
  there was no API to access these alternative name DNs so it is unlikely that
  any application would make incorrect access control decisions on the basis of
  the incorrect DN. Reported by Mario Korth of Ruhr-Universität Bochum.

  Introduced in 1.11.29, fixed in 2.15.0

* 2020-03-24: Side channel during CBC padding

  The CBC padding operations were not constant time and as a result would leak
  the length of the plaintext values which were being padded to an attacker
  running a side channel attack via shared resources such as cache or branch
  predictor. No information about the contents was leaked, but the length alone
  might be used to make inferences about the contents. This issue affects TLS
  CBC ciphersuites as well as CBC encryption using PKCS7 or other similar padding
  mechanisms. In all cases, the unpadding operations were already constant time
  and are not affected. Reported by Maximilian Blochberger of Universität
  Hamburg.

  Fixed in 2.14.0, all prior versions affected.

2018
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* 2018-12-17 (CVE-2018-20187): Side channel during ECC key generation

  A timing side channel during ECC key generation could leak information about
  the high bits of the secret scalar. Such information allows an attacker to
  perform a brute force attack on the key somewhat more efficiently than they
  would otherwise. Found by Ján Jančár using ECTester.

  Introduced in 1.11.20, fixed in 2.8.0.

* 2018-06-13 (CVE-2018-12435): ECDSA side channel

  A side channel in the ECDSA signature operation could allow a local attacker
  to recover the secret key. Found by Keegan Ryan of NCC Group.

  Bug introduced in 2.5.0, fixed in 2.7.0. The 1.10 branch is not affected.

* 2018-04-10 (CVE-2018-9860): Memory overread in TLS CBC decryption

  An off by one error in TLS CBC decryption meant that for a particular
  malformed ciphertext, the receiver would miscompute a length field and HMAC
  exactly 64K bytes of data following the record buffer as if it was part of the
  message. This cannot be used to leak information since the MAC comparison will
  subsequently fail and the connection will be closed. However it might be used
  for denial of service. Found by OSS-Fuzz.

  Bug introduced in 1.11.32, fixed in 2.6.0

* 2018-03-29 (CVE-2018-9127): Invalid wildcard match

  RFC 6125 wildcard matching was incorrectly implemented, so that a wildcard
  certificate such as ``b*.domain.com`` would match any hosts ``*b*.domain.com``
  instead of just server names beginning with ``b``. The host and certificate
  would still have to be in the same domain name. Reported by Fabian Weißberg of
  Rohde and Schwarz Cybersecurity.

  Bug introduced in 2.2.0, fixed in 2.5.0

2017
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* 2017-10-02 (CVE-2017-14737): Potential side channel using cache information

  In the Montgomery exponentiation code, a table of precomputed values
  is used. An attacker able to analyze which cache lines were accessed
  (perhaps via an active attack such as Prime+Probe) could recover
  information about the exponent. Identified in "CacheD: Identifying
  Cache-Based Timing Channels in Production Software" by Wang, Wang,
  Liu, Zhang, and Wu (Usenix Security 2017).

  Fixed in 1.10.17 and 2.3.0, all prior versions affected.

* 2017-07-16: Failure to fully zeroize memory before free

  The secure_allocator type attempts to zeroize memory before freeing it. Due to
  a error sometimes only a portion of the memory would be zeroed, because of a
  confusion between the number of elements vs the number of bytes that those
  elements use. So byte vectors would always be fully zeroed (since the two
  notions result in the same value), but for example with an array of 32-bit
  integers, only the first 1/4 of the elements would be zeroed before being
  deallocated. This may result in information leakage, if an attacker can access
  memory on the heap. Reported by Roman Pozlevich.

  Bug introduced in 1.11.10, fixed in 2.2.0

* 2017-04-04 (CVE-2017-2801): Incorrect comparison in X.509 DN strings

  Botan's implementation of X.509 name comparisons had a flaw which
  could result in an out of bound memory read while processing a
  specially formed DN. This could potentially be exploited for
  information disclosure or denial of service, or result in incorrect
  validation results. Found independently by Aleksandar Nikolic of
  Cisco Talos, and OSS-Fuzz automated fuzzing infrastructure.

  Bug introduced in 1.6.0 or earlier, fixed in 2.1.0 and 1.10.16

* 2017-03-23 (CVE-2017-7252): Incorrect bcrypt computation

  Botan's implementation of bcrypt password hashing scheme truncated long
  passwords at 56 characters, instead of at bcrypt's standard 72 characters
  limit. Passwords with lengths between these two bounds could be cracked more
  easily than should be the case due to the final password bytes being ignored.
  Found and reported by Solar Designer.

  Bug introduced in 1.11.0, fixed in 2.1.0.

2016
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* 2016-11-27 (CVE-2016-9132) Integer overflow in BER decoder

  While decoding BER length fields, an integer overflow could occur. This could
  occur while parsing untrusted inputs such as X.509 certificates. The overflow
  does not seem to lead to any obviously exploitable condition, but exploitation
  cannot be positively ruled out. Only 32-bit platforms are likely affected; to
  cause an overflow on 64-bit the parsed data would have to be many gigabytes.
  Bug found by Falko Strenzke, cryptosource GmbH.

  Fixed in 1.10.14 and 1.11.34, all prior versions affected.

* 2016-10-26 (CVE-2016-8871) OAEP side channel

  A side channel in OAEP decoding could be used to distinguish RSA ciphertexts
  that did or did not have a leading 0 byte. For an attacker capable of
  precisely measuring the time taken for OAEP decoding, this could be used as an
  oracle allowing decryption of arbitrary RSA ciphertexts. Remote exploitation
  seems difficult as OAEP decoding is always paired with RSA decryption, which
  takes substantially more (and variable) time, and so will tend to mask the
  timing channel. This attack does seems well within reach of a local attacker
  capable of a cache or branch predictor based side channel attack. Finding,
  analysis, and patch by Juraj Somorovsky.

  Introduced in 1.11.29, fixed in 1.11.33

* 2016-08-30 (CVE-2016-6878) Undefined behavior in Curve25519

  On systems without a native 128-bit integer type, the Curve25519 code invoked
  undefined behavior. This was known to produce incorrect results on 32-bit ARM
  when compiled by Clang.

  Introduced in 1.11.12, fixed in 1.11.31

* 2016-08-30 (CVE-2016-6879) Bad result from X509_Certificate::allowed_usage

  If allowed_usage was called with more than one Key_Usage set in the enum
  value, the function would return true if *any* of the allowed usages were set,
  instead of if *all* of the allowed usages are set.  This could be used to
  bypass an application key usage check. Credit to Daniel Neus of Rohde &
  Schwarz Cybersecurity for finding this issue.

  Introduced in 1.11.0, fixed in 1.11.31

* 2016-03-17 (CVE-2016-2849): ECDSA side channel

  ECDSA (and DSA) signature algorithms perform a modular inverse on the
  signature nonce `k`.  The modular inverse algorithm used had input dependent
  loops, and it is possible a side channel attack could recover sufficient
  information about the nonce to eventually recover the ECDSA secret key. Found
  by Sean Devlin.

  Introduced in 1.7.15, fixed in 1.10.13 and 1.11.29

* 2016-03-17 (CVE-2016-2850): Failure to enforce TLS policy

  TLS v1.2 allows negotiating which signature algorithms and hash functions each
  side is willing to accept. However received signatures were not actually
  checked against the specified policy.  This had the effect of allowing a
  server to use an MD5 or SHA-1 signature, even though the default policy
  prohibits it. The same issue affected client cert authentication.

  The TLS client also failed to verify that the ECC curve the server chose to
  use was one which was acceptable by the client policy.

  Introduced in 1.11.0, fixed in 1.11.29

* 2016-02-01 (CVE-2016-2196): Overwrite in P-521 reduction

  The P-521 reduction function would overwrite zero to one word
  following the allocated block. This could potentially result
  in remote code execution or a crash. Found with AFL

  Introduced in 1.11.10, fixed in 1.11.27

* 2016-02-01 (CVE-2016-2195): Heap overflow on invalid ECC point

  The PointGFp constructor did not check that the affine coordinate
  arguments were less than the prime, but then in curve multiplication
  assumed that both arguments if multiplied would fit into an integer
  twice the size of the prime.

  The bigint_mul and bigint_sqr functions received the size of the
  output buffer, but only used it to dispatch to a faster algorithm in
  cases where there was sufficient output space to call an unrolled
  multiplication function.

  The result is a heap overflow accessible via ECC point decoding,
  which accepted untrusted inputs. This is likely exploitable for
  remote code execution.

  On systems which use the mlock pool allocator, it would allow an
  attacker to overwrite memory held in secure_vector objects. After
  this point the write will hit the guard page at the end of the
  mmap'ed region so it probably could not be used for code execution
  directly, but would allow overwriting adjacent key material.

  Found by Alex Gaynor fuzzing with AFL

  Introduced in 1.9.18, fixed in 1.11.27 and 1.10.11

* 2016-02-01 (CVE-2016-2194): Infinite loop in modular square root algorithm

  The ressol function implements the Tonelli-Shanks algorithm for
  finding square roots could be sent into a nearly infinite loop due
  to a misplaced conditional check. This could occur if a composite
  modulus is provided, as this algorithm is only defined for primes.
  This function is exposed to attacker controlled input via the OS2ECP
  function during ECC point decompression. Found by AFL

  Introduced in 1.7.15, fixed in 1.11.27 and 1.10.11

2015
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* 2015-11-04: TLS certificate authentication bypass

  When the bugs affecting X.509 path validation were fixed in 1.11.22, a check
  in Credentials_Manager::verify_certificate_chain was accidentally removed
  which caused path validation failures not to be signaled to the TLS layer.  So
  for affected versions, certificate authentication in TLS is bypassed. As a
  workaround, applications can override the call and implement the correct
  check. Reported by Florent Le Coz in GH #324

  Introduced in 1.11.22, fixed in 1.11.24

* 2015-10-26 (CVE-2015-7824): Padding oracle attack on TLS

  A padding oracle attack was possible against TLS CBC ciphersuites because if a
  certain length check on the packet fields failed, a different alert type than
  one used for message authentication failure would be returned to the sender.
  This check triggering would leak information about the value of the padding
  bytes and could be used to perform iterative decryption.

  As with most such oracle attacks, the danger depends on the underlying
  protocol - HTTP servers are particularly vulnerable. The current analysis
  suggests that to exploit it an attacker would first have to guess several
  bytes of plaintext, but again this is quite possible in many situations
  including HTTP.

  Found in a review by Sirrix AG and 3curity GmbH.

  Introduced in 1.11.0, fixed in 1.11.22

* 2015-10-26 (CVE-2015-7825): Infinite loop during certificate path validation

  When evaluating a certificate path, if a loop in the certificate chain
  was encountered (for instance where C1 certifies C2, which certifies C1)
  an infinite loop would occur eventually resulting in memory exhaustion.
  Found in a review by Sirrix AG and 3curity GmbH.

  Introduced in 1.11.6, fixed in 1.11.22

* 2015-10-26 (CVE-2015-7826): Acceptance of invalid certificate names

  RFC 6125 specifies how to match a X.509v3 certificate against a DNS name
  for application usage.

  Otherwise valid certificates using wildcards would be accepted as matching
  certain hostnames that should they should not according to RFC 6125. For
  example a certificate issued for ``*.example.com`` should match
  ``foo.example.com`` but not ``example.com`` or ``bar.foo.example.com``. Previously
  Botan would accept such a certificate as also valid for ``bar.foo.example.com``.

  RFC 6125 also requires that when matching a X.509 certificate against a DNS
  name, the CN entry is only compared if no subjectAlternativeName entry is
  available. Previously X509_Certificate::matches_dns_name would always check
  both names.

  Found in a review by Sirrix AG and 3curity GmbH.

  Introduced in 1.11.0, fixed in 1.11.22

* 2015-10-26 (CVE-2015-7827): PKCS #1 v1.5 decoding was not constant time

  During RSA decryption, how long decoding of PKCS #1 v1.5 padding took was
  input dependent. If these differences could be measured by an attacker, it
  could be used to mount a Bleichenbacher million-message attack. PKCS #1 v1.5
  decoding has been rewritten to use a sequence of operations which do not
  contain any input-dependent indexes or jumps. Notations for checking constant
  time blocks with ctgrind (https://github.com/agl/ctgrind) were added to PKCS
  #1 decoding among other areas. Found in a review by Sirrix AG and 3curity GmbH.

  Fixed in 1.11.22 and 1.10.13. Affected all previous versions.

* 2015-08-03 (CVE-2015-5726): Crash in BER decoder

  The BER decoder would crash due to reading from offset 0 of an empty vector if
  it encountered a BIT STRING which did not contain any data at all. This can be
  used to easily crash applications reading untrusted ASN.1 data, but does not
  seem exploitable for code execution. Found with afl.

  Fixed in 1.11.19 and 1.10.10, affected all previous versions of 1.10 and 1.11

* 2015-08-03 (CVE-2015-5727): Excess memory allocation in BER decoder

  The BER decoder would allocate a fairly arbitrary amount of memory in a length
  field, even if there was no chance the read request would succeed.  This might
  cause the process to run out of memory or invoke the OOM killer. Found with afl.

  Fixed in 1.11.19 and 1.10.10, affected all previous versions of 1.10 and 1.11

2014
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* 2014-04-10 (CVE-2014-9742): Insufficient randomness in Miller-Rabin primality check

  A bug in the Miller-Rabin primality test resulted in only a single random base
  being used instead of a sequence of such bases. This increased the probability
  that a non-prime would be accepted by is_prime or that a randomly generated
  prime might actually be composite.  The probability of a random 1024 bit
  number being incorrectly classed as prime with a single base is around 2^-40.
  Reported by Jeff Marrison.

  Introduced in 1.8.3, fixed in 1.10.8 and 1.11.9
