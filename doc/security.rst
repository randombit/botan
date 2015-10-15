
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

* 2015-08-03 (CVE-2015-5726)

  The BER decoder would crash due to reading from offset 0 of an empty vector if
  it encountered a BIT STRING which did not contain any data at all. This can be
  used to easily crash applicatons reading untrusted ASN.1 data, but does not
  seem exploitable for code execution. Found with afl.

  Fixed in 1.11.19 and 1.10.10, affected all previous versions of 1.10 and 1.11

* 2015-08-03 (CVE-2015-5727)

  The BER decoder would allocate a fairly arbitrary amount of memory in a length
  field, even if there was no chance the read request would succeed.  This might
  cause the process to run out of memory or invoke the OOM killer. Found with afl.

  Fixed in 1.11.19 and 1.10.10, affected all previous versions of 1.10 and 1.11

2014
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* 2014-04-10 (CVE-2014-9742)

  A bug in the Miller-Rabin primality test resulted in only a single random base
  being used instead of a sequence of such bases. This increased the probability
  that a non-prime would be accepted by is_prime or that a randomly generated
  prime might actually be composite.  The probability of a random 1024 bit
  number being incorrectly classed as prime with a single base is around 2^-40.
  Reported by Jeff Marrison.

  Fixed in 1.11.9 and 1.10.8, affected all versions since 1.8.3
