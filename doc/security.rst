
Security
========================================

If you think you have found a security bug in Botan please contact
Jack Lloyd (lloyd@randombit.net). If you would like to encrypt your
mail please use::

  pub   rsa3072/57123B60 2015-03-23
        Key fingerprint = 4E60 C735 51AF 2188 DF0A  5A62 78E9 8043 5712 3B60
        uid         Jack Lloyd <lloyd@randombit.net>

This key can be found in the file `pgpkey.txt` or online at
https://keybase.io/jacklloyd and on most PGP keyservers.

Advisories
----------------------------------------

2015
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

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
  example a certificate issued for '*.example.com' should match
  'foo.example.com' but not 'example.com' or 'bar.foo.example.com'. Previously
  Botan would accept such a certificate as valid for 'bar.foo.example.com'.

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

  Fixed in 1.11.22. Affected all previous versions.

* 2015-08-03 (CVE-2015-5726): Crash in BER decoder

  The BER decoder would crash due to reading from offset 0 of an empty vector if
  it encountered a BIT STRING which did not contain any data at all. This can be
  used to easily crash applicatons reading untrusted ASN.1 data, but does not
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
